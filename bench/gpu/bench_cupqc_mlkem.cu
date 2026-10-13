// bench_cupqc_mlkem.cu  --  baseline evaluation of NVIDIA cuPQC's ML-KEM (optional)
//
// Built only when OPENPQC_CUPQC_DIR points to a cuPQC SDK (not distributed with OpenPQC).
// NOTE: the cuPQC SDK ships under NVIDIA's evaluation licence, which treats benchmark results
// of cuPQC as NVIDIA confidential information: keep the output of this program internal unless
// NVIDIA has approved publication.
//
// 1. Conformance and interoperability with the OpenPQC CPU library (untimed):
//    - cuPQC keygen with caller-chosen entropy vs keypair_derand (both orders of d and z),
//      cuPQC encaps vs enc_derand, cuPQC decaps vs dec (valid and tampered ciphertexts);
//    - OpenPQC keys -> cuPQC encaps -> OpenPQC decaps, and cuPQC keys -> OpenPQC encaps ->
//      cuPQC decaps.
// 2. Throughput of cuPQC (block dimensions interleaved per configuration), kernel-only and
//    end-to-end, in the CSV format of bench_mlkem_sycl, so that the two can be compared run by
//    run with the same cooling (bench/run_benchmarks.sh):
//    usage: bench_cupqc_mlkem [levels] [batches] [trials] [blockdims=32,64,128,256] [cool_to_c=0]
//    CSV:   impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c
#include <cuda_runtime.h>

#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

#include <pk.hpp>

#include "../../include/ML-KEM/openpqc_mlkem.h"
#include "../bench_common.hpp"

using namespace cupqc;

namespace {

void cuda_check(cudaError_t e, const char* what) {
    if (e != cudaSuccess) {
        std::fprintf(stderr, "CUDA error in %s: %s\n", what, cudaGetErrorString(e));
        std::exit(1);
    }
}
#define CHECK_CUDA(call) cuda_check((call), #call)

struct DeviceBuffer {
    std::uint8_t* p = nullptr;
    explicit DeviceBuffer(std::size_t bytes) { CHECK_CUDA(cudaMalloc(&p, bytes)); }
    ~DeviceBuffer() { cudaFree(p); }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;
};

struct PinnedBuffer {
    std::uint8_t* p = nullptr;
    explicit PinnedBuffer(std::size_t bytes) { CHECK_CUDA(cudaMallocHost(&p, bytes)); }
    ~PinnedBuffer() { cudaFreeHost(p); }
    PinnedBuffer(const PinnedBuffer&) = delete;
    PinnedBuffer& operator=(const PinnedBuffer&) = delete;
};

// seconds per call of op(), timed with CUDA events: `trials` samples of `reps` calls
template <class F>
std::vector<double> time_gpu(cudaStream_t stream, int trials, int reps, F op) {
    cudaEvent_t a, b;
    CHECK_CUDA(cudaEventCreate(&a));
    CHECK_CUDA(cudaEventCreate(&b));
    std::vector<double> out;
    for (int t = 0; t < trials; t++) {
        CHECK_CUDA(cudaEventRecord(a, stream));
        for (int r = 0; r < reps; r++) op();
        CHECK_CUDA(cudaEventRecord(b, stream));
        CHECK_CUDA(cudaEventSynchronize(b));
        float ms = 0;
        CHECK_CUDA(cudaEventElapsedTime(&ms, a, b));
        out.push_back(ms * 1e-3 / reps);
    }
    cudaEventDestroy(a);
    cudaEventDestroy(b);
    return out;
}

template <class KEM, unsigned BD> using KG = decltype(KEM() + Function<function::Keygen>() + Block() + BlockDim<BD>());
template <class KEM, unsigned BD> using EN = decltype(KEM() + Function<function::Encaps>() + Block() + BlockDim<BD>());
template <class KEM, unsigned BD> using DE = decltype(KEM() + Function<function::Decaps>() + Block() + BlockDim<BD>());

template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) kg_kernel(std::uint8_t* pk, std::uint8_t* sk, std::uint8_t* ent,
                                                          std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(pk + i * T::public_key_size, sk + i * T::secret_key_size, ent + i * T::entropy_size,
                ws + i * T::workspace_size, smem);
}
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) en_kernel(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk,
                                                          std::uint8_t* ent, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(ct + i * T::ciphertext_size, ss + i * T::shared_secret_size, pk + i * T::public_key_size,
                ent + i * T::entropy_size, ws + i * T::workspace_size, smem);
}
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) de_kernel(std::uint8_t* ss, const std::uint8_t* ct,
                                                          const std::uint8_t* sk, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(ss + i * T::shared_secret_size, ct + i * T::ciphertext_size, sk + i * T::secret_key_size,
                ws + i * T::workspace_size, smem);
}

struct CpuApi {
    int (*keypair_derand)(std::uint8_t*, std::uint8_t*, const std::uint8_t*);
    int (*enc_derand)(std::uint8_t*, std::uint8_t*, const std::uint8_t*, const std::uint8_t*);
    int (*dec)(std::uint8_t*, const std::uint8_t*, const std::uint8_t*);
};
template <int L> CpuApi cpu();
template <> CpuApi cpu<512>() { return {openpqc_mlkem512_keypair_derand, openpqc_mlkem512_enc_derand, openpqc_mlkem512_dec}; }
template <> CpuApi cpu<768>() { return {openpqc_mlkem768_keypair_derand, openpqc_mlkem768_enc_derand, openpqc_mlkem768_dec}; }
template <> CpuApi cpu<1024>() { return {openpqc_mlkem1024_keypair_derand, openpqc_mlkem1024_enc_derand, openpqc_mlkem1024_dec}; }

template <int L> struct kem_of;
template <> struct kem_of<512> { using type = ML_KEM_512; };
template <> struct kem_of<768> { using type = ML_KEM_768; };
template <> struct kem_of<1024> { using type = ML_KEM_1024; };

std::vector<std::uint8_t> download(const std::uint8_t* d, std::size_t n) {
    std::vector<std::uint8_t> h(n);
    CHECK_CUDA(cudaMemcpy(h.data(), d, n, cudaMemcpyDeviceToHost));
    return h;
}
void upload(std::uint8_t* d, const std::vector<std::uint8_t>& h) {
    CHECK_CUDA(cudaMemcpy(d, h.data(), h.size(), cudaMemcpyHostToDevice));
}
std::size_t mismatches(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b, std::size_t stride) {
    std::size_t bad = 0;
    for (std::size_t i = 0; i + stride <= a.size(); i += stride) bad += std::memcmp(&a[i], &b[i], stride) != 0;
    return bad;
}

// ---------------------------------------------------------------- 1. conformance / interop
template <int L>
bool conformance(std::size_t n) {
    using KEM = typename kem_of<L>::type;
    using TK = KG<KEM, 128>;
    using TE = EN<KEM, 128>;
    using TD = DE<KEM, 128>;
    constexpr std::size_t PK = TK::public_key_size, SK = TK::secret_key_size, CT = TE::ciphertext_size;
    const CpuApi c = cpu<L>();
    bool ok = true;
    const auto coins = bench::random_bytes(64 * n, 100 + L), m = bench::random_bytes(32 * n, 200 + L);

    DeviceBuffer d_ent(64 * n), d_pk(PK * n), d_sk(SK * n), d_ct(CT * n), d_ss(32 * n), d_ws(TD::workspace_size * n);
    std::uint8_t* ws = d_ws.p;  // decaps has the largest workspace

    // CPU reference
    std::vector<std::uint8_t> pk(PK * n), sk(SK * n), ct(CT * n), ss(32 * n);
    for (std::size_t i = 0; i < n; i++) {
        c.keypair_derand(&pk[i * PK], &sk[i * SK], &coins[i * 64]);
        c.enc_derand(&ct[i * CT], &ss[i * 32], &pk[i * PK], &m[i * 32]);
    }

    // (a) cuPQC keygen: entropy slot = d || z ?  (both orders)
    for (int order = 0; order < 2; order++) {
        std::vector<std::uint8_t> ent(coins);
        if (order == 1)
            for (std::size_t i = 0; i < n; i++)
                for (int b = 0; b < 32; b++) std::swap(ent[i * 64 + b], ent[i * 64 + 32 + b]);
        upload(d_ent.p, ent);
        kg_kernel<TK><<<n, TK::BlockDim>>>(d_pk.p, d_sk.p, d_ent.p, ws);
        CHECK_CUDA(cudaDeviceSynchronize());
        const std::size_t bpk = mismatches(pk, download(d_pk.p, PK * n), PK);
        const std::size_t bsk = mismatches(sk, download(d_sk.p, SK * n), SK);
        const auto ent_after = download(d_ent.p, 64 * n);
        std::printf("# ML-KEM-%d cuPQC keygen, entropy = %s: pk mismatches %zu/%zu, sk mismatches %zu/%zu%s\n", L,
                    order == 0 ? "d||z" : "z||d", bpk, n, bsk, n,
                    ent_after == ent ? "" : " (entropy buffer modified by cuPQC)");
        if (order == 0 && (bpk || bsk)) ok = false;
    }
    // (b) cuPQC encaps with entropy = m, on the reference keys
    upload(d_pk.p, pk);
    upload(d_ent.p, m);
    en_kernel<TE><<<n, TE::BlockDim>>>(d_ct.p, d_ss.p, d_pk.p, d_ent.p, ws);
    CHECK_CUDA(cudaDeviceSynchronize());
    const std::size_t bct = mismatches(ct, download(d_ct.p, CT * n), CT);
    const std::size_t bss = mismatches(ss, download(d_ss.p, 32 * n), 32);
    std::printf("# ML-KEM-%d cuPQC encaps (entropy = m): ct mismatches %zu/%zu, ss mismatches %zu/%zu\n", L, bct, n, bss, n);
    ok &= bct == 0 && bss == 0;
    // (c) cuPQC decaps on reference keys and ciphertexts, valid and tampered
    upload(d_sk.p, sk);
    upload(d_ct.p, ct);
    de_kernel<TD><<<n, TD::BlockDim>>>(d_ss.p, d_ct.p, d_sk.p, ws);
    CHECK_CUDA(cudaDeviceSynchronize());
    const std::size_t bdec = mismatches(ss, download(d_ss.p, 32 * n), 32);
    std::vector<std::uint8_t> ct_bad(ct), ss_bad(32 * n);
    for (std::size_t i = 0; i < n; i++) {
        ct_bad[i * CT + (5 * i) % CT] ^= 0x10;
        c.dec(&ss_bad[i * 32], &ct_bad[i * CT], &sk[i * SK]);
    }
    upload(d_ct.p, ct_bad);
    de_kernel<TD><<<n, TD::BlockDim>>>(d_ss.p, d_ct.p, d_sk.p, ws);
    CHECK_CUDA(cudaDeviceSynchronize());
    const std::size_t brej = mismatches(ss_bad, download(d_ss.p, 32 * n), 32);
    std::printf("# ML-KEM-%d cuPQC decaps: valid ss mismatches %zu/%zu, implicit-rejection ss mismatches %zu/%zu\n", L,
                bdec, n, brej, n);
    ok &= bdec == 0 && brej == 0;

    // (d) across libraries: OpenPQC keys -> cuPQC encaps -> OpenPQC decaps, and the reverse
    upload(d_ent.p, m);
    en_kernel<TE><<<n, TE::BlockDim>>>(d_ct.p, d_ss.p, d_pk.p, d_ent.p, ws);   // d_pk: OpenPQC keys
    CHECK_CUDA(cudaDeviceSynchronize());
    const auto cu_ct = download(d_ct.p, CT * n), cu_ss = download(d_ss.p, 32 * n);
    std::size_t bx1 = 0;
    for (std::size_t i = 0; i < n; i++) {
        std::uint8_t key[32];
        c.dec(key, &cu_ct[i * CT], &sk[i * SK]);
        bx1 += std::memcmp(key, &cu_ss[i * 32], 32) != 0;
    }
    upload(d_ent.p, coins);
    kg_kernel<TK><<<n, TK::BlockDim>>>(d_pk.p, d_sk.p, d_ent.p, ws);
    CHECK_CUDA(cudaDeviceSynchronize());
    const auto cu_pk = download(d_pk.p, PK * n);
    std::vector<std::uint8_t> o_ct(CT * n), o_ss(32 * n);
    for (std::size_t i = 0; i < n; i++) c.enc_derand(&o_ct[i * CT], &o_ss[i * 32], &cu_pk[i * PK], &m[i * 32]);
    upload(d_ct.p, o_ct);
    de_kernel<TD><<<n, TD::BlockDim>>>(d_ss.p, d_ct.p, d_sk.p, ws);
    CHECK_CUDA(cudaDeviceSynchronize());
    const std::size_t bx2 = mismatches(o_ss, download(d_ss.p, 32 * n), 32);
    std::printf("# ML-KEM-%d interop: OpenPQC->cuPQC->OpenPQC ss mismatches %zu/%zu, cuPQC->OpenPQC->cuPQC %zu/%zu\n", L,
                bx1, n, bx2, n);
    ok &= bx1 == 0 && bx2 == 0;
    return ok;
}

// ---------------------------------------------------------------- 2. throughput
struct Runner {
    std::string impl;
    const char* op;
    const char* mode;
    std::function<void()> f;
    std::vector<double> samples;
    std::vector<double> mhz;  // SM clock after each sample
};

struct HostInputs {
    std::uint8_t* kg;  // n x 64 coins
    std::uint8_t* en;  // n x pk, then n x 32 m
    std::uint8_t* de;  // n x ct, then n x sk
};

template <int L, unsigned BD>
void add_runners(std::vector<Runner>& rs, cudaStream_t st, std::size_t n, std::uint8_t* pk, std::uint8_t* sk,
                 std::uint8_t* ct, std::uint8_t* ss, std::uint8_t* ent, std::uint8_t* ws, HostInputs h,
                 std::uint8_t* h_out) {
    using KEM = typename kem_of<L>::type;
    using TK = KG<KEM, BD>;
    using TE = EN<KEM, BD>;
    using TD = DE<KEM, BD>;
    const std::string impl = "cupqc-bd" + std::to_string(BD);
    const auto cp = [=](void* d, const void* s, std::size_t b, cudaMemcpyKind k) { CHECK_CUDA(cudaMemcpyAsync(d, s, b, k, st)); };
    const std::size_t PK = TK::public_key_size, SK = TK::secret_key_size, CT = TE::ciphertext_size;
    rs.push_back({impl, "keygen", "kernel", [=] { kg_kernel<TK><<<n, TK::BlockDim, 0, st>>>(pk, sk, ent, ws); }, {}, {}});
    rs.push_back({impl, "encaps", "kernel", [=] { en_kernel<TE><<<n, TE::BlockDim, 0, st>>>(ct, ss, pk, ent, ws); }, {}, {}});
    rs.push_back({impl, "decaps", "kernel", [=] { de_kernel<TD><<<n, TD::BlockDim, 0, st>>>(ss, ct, sk, ws); }, {}, {}});
    rs.push_back({impl, "keygen", "e2e", [=] {
                      cp(ent, h.kg, 64 * n, cudaMemcpyHostToDevice);
                      kg_kernel<TK><<<n, TK::BlockDim, 0, st>>>(pk, sk, ent, ws);
                      cp(h_out, pk, PK * n, cudaMemcpyDeviceToHost);
                      cp(h_out + PK * n, sk, SK * n, cudaMemcpyDeviceToHost);
                  }, {}, {}});
    rs.push_back({impl, "encaps", "e2e", [=] {
                      cp(pk, h.en, PK * n, cudaMemcpyHostToDevice);
                      cp(ent, h.en + PK * n, 32 * n, cudaMemcpyHostToDevice);
                      en_kernel<TE><<<n, TE::BlockDim, 0, st>>>(ct, ss, pk, ent, ws);
                      cp(h_out, ct, CT * n, cudaMemcpyDeviceToHost);
                      cp(h_out + CT * n, ss, 32 * n, cudaMemcpyDeviceToHost);
                  }, {}, {}});
    rs.push_back({impl, "decaps", "e2e", [=] {
                      cp(ct, h.de, CT * n, cudaMemcpyHostToDevice);
                      cp(sk, h.de + CT * n, SK * n, cudaMemcpyHostToDevice);
                      de_kernel<TD><<<n, TD::BlockDim, 0, st>>>(ss, ct, sk, ws);
                      cp(h_out, ss, 32 * n, cudaMemcpyDeviceToHost);
                  }, {}, {}});
}

template <int L>
void throughput(const std::vector<std::size_t>& batches, int trials, const std::vector<std::size_t>& blockdims,
                unsigned cool_to_c, const bench::GpuMonitor& mon) {
    using KEM = typename kem_of<L>::type;
    using TD = DE<KEM, 128>;
    constexpr std::size_t PK = KG<KEM, 128>::public_key_size, SK = KG<KEM, 128>::secret_key_size,
                          CT = EN<KEM, 128>::ciphertext_size;
    const CpuApi c = cpu<L>();
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    cudaStream_t st;
    CHECK_CUDA(cudaStreamCreateWithFlags(&st, cudaStreamNonBlocking));
    DeviceBuffer pk(PK * nmax), sk(SK * nmax), ct(CT * nmax), ss(32 * nmax), ent(64 * nmax),
            ws(TD::workspace_size * nmax);
    PinnedBuffer h_kg(64 * nmax), h_en((PK + 32) * nmax), h_de((CT + SK) * nmax), h_out((PK + SK + CT + 64) * nmax);
    // valid keys and ciphertexts from the CPU library
    const auto coins = bench::random_bytes(64 * nmax, 7);
    std::memcpy(h_kg.p, coins.data(), 64 * nmax);
    for (std::size_t i = 0; i < nmax; i++) {
        std::uint8_t key[32];
        c.keypair_derand(h_en.p + i * PK, h_de.p + CT * nmax + i * SK, &coins[i * 64]);
        c.enc_derand(h_de.p + i * CT, key, h_en.p + i * PK, &coins[i * 32]);
    }
    std::memcpy(h_en.p + PK * nmax, coins.data(), 32 * nmax);
    CHECK_CUDA(cudaMemcpy(ent.p, coins.data(), 64 * nmax, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(pk.p, h_en.p, PK * nmax, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(ct.p, h_de.p, CT * nmax, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(sk.p, h_de.p + CT * nmax, SK * nmax, cudaMemcpyHostToDevice));
    const HostInputs hin{h_kg.p, h_en.p, h_de.p};

    for (const std::size_t n : batches) {
        std::vector<Runner> rs;
        for (const std::size_t bd : blockdims) {
            if (bd == 32) add_runners<L, 32>(rs, st, n, pk.p, sk.p, ct.p, ss.p, ent.p, ws.p, hin, h_out.p);
            if (bd == 64) add_runners<L, 64>(rs, st, n, pk.p, sk.p, ct.p, ss.p, ent.p, ws.p, hin, h_out.p);
            if (bd == 128) add_runners<L, 128>(rs, st, n, pk.p, sk.p, ct.p, ss.p, ent.p, ws.p, hin, h_out.p);
            if (bd == 256) add_runners<L, 256>(rs, st, n, pk.p, sk.p, ct.p, ss.p, ent.p, ws.p, hin, h_out.p);
        }
        // warm-up, then interleave: each round runs every runner once (one sample each)
        mon.cool_down(cool_to_c);
        const auto sync = [&] { CHECK_CUDA(cudaStreamSynchronize(st)); };
        for (auto& r : rs) bench::warm_up(0.1, r.f, sync);
        std::vector<int> reps(rs.size());
        for (std::size_t i = 0; i < rs.size(); i++)
            reps[i] = bench::reps_for(bench::summarize(time_gpu(st, 3, 1, rs[i].f)).median);
        for (int t = 0; t < trials; t++) {
            mon.cool_down(cool_to_c);
            for (std::size_t j = 0; j < rs.size(); j++) {
                const std::size_t i = (t % 2 == 0) ? j : rs.size() - 1 - j;  // alternate the order
                rs[i].samples.push_back(time_gpu(st, 1, reps[i], rs[i].f)[0]);
                rs[i].mhz.push_back(mon.sm_clock_mhz());
            }
        }
        for (auto& r : rs) {
            const auto s = bench::summarize(r.samples);
            std::printf("%s,%d,%s,%s,%zu,%.9g,%.9g,%.9g,%.6g,%.0f,%u\n", r.impl.c_str(), L, r.op, r.mode, n, s.median,
                        s.p10, s.p90, static_cast<double>(n) / s.median, bench::summarize(r.mhz).median,
                        mon.temperature_c());
        }
        std::fflush(stdout);
    }
    cudaStreamDestroy(st);
}

} // namespace

int main(int argc, char** argv) {
    const auto levels = bench::parse_list(argc > 1 ? argv[1] : "512,768,1024");
    const auto batches = bench::parse_list(argc > 2 ? argv[2] : "1,32,128,512,2048,8192,32768");
    const int trials = argc > 3 ? std::atoi(argv[3]) : 15;
    const auto blockdims = bench::parse_list(argc > 4 ? argv[4] : "32,64,128,256");
    const unsigned cool_to_c = argc > 5 ? static_cast<unsigned>(std::atoi(argv[5])) : 0;
    bench::GpuMonitor mon;
    bool ok = true;
    for (auto l : levels) {
        if (l == 512) ok &= conformance<512>(2048);
        if (l == 768) ok &= conformance<768>(2048);
        if (l == 1024) ok &= conformance<1024>(2048);
    }
    std::printf("# conformance: %s\n", ok ? "cuPQC agrees with the OpenPQC CPU library" : "MISMATCH (see above)");
    std::printf("impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c\n");
    for (auto l : levels) {
        if (l == 512) throughput<512>(batches, trials, blockdims, cool_to_c, mon);
        if (l == 768) throughput<768>(batches, trials, blockdims, cool_to_c, mon);
        if (l == 1024) throughput<1024>(batches, trials, blockdims, cool_to_c, mon);
    }
    return ok ? 0 : 1;
}
