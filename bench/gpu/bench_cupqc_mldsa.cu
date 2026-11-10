// bench_cupqc_mldsa.cu  --  baseline evaluation of NVIDIA cuPQC's ML-DSA (optional)
//
// Built only when OPENPQC_CUPQC_DIR points to a cuPQC SDK (not distributed with OpenPQC).
// NOTE: the cuPQC SDK ships under NVIDIA's evaluation licence, which treats benchmark results
// of cuPQC as NVIDIA confidential information: keep the output of this program internal unless
// NVIDIA has approved publication.
//
// 1. Conformance and interoperability with the OpenPQC CPU library (untimed). cuPQC's Sign and
//    Verify have one overload without a context string and one with (context, context_length);
//    the program finds out which FIPS 204 function each computes:
//    - cuPQC keygen with caller-chosen entropy vs keypair_derand (entropy = xi);
//    - cuPQC sign without a context string, entropy = rnd, vs sign_derand with an empty
//      context string (external ML-DSA, M' = 0 || 0 || M) and vs sign_internal (M' = M);
//    - cuPQC sign with a 13-byte context string vs sign_derand with the same one;
//    - cuPQC verify on OpenPQC signatures of each kind and on tampered ones, and OpenPQC
//      verify / verify_internal on cuPQC's signatures.
// 2. Throughput of cuPQC (block dimensions interleaved per configuration), kernel-only and
//    end-to-end, in the CSV format of bench_mldsa_sycl (64-byte messages, rnd given, the same
//    messages and keys in every call), so that the two can be compared run by run:
//    usage: bench_cupqc_mldsa [levels=44,65,87] [batches] [trials] [blockdims=32,64,128,256] [cool_to_c=0]
//    CSV:   impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c
#include <cuda_runtime.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include <pk.hpp>

#include "../../include/ML/DSA/openpqc_mldsa.h"
#include "../../include/openpqc/testing.h"   // sign_derand, sign_internal, verify_internal (openpqc_mldsa has them in a build with the benchmarks)
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
    explicit DeviceBuffer(std::size_t bytes) { CHECK_CUDA(cudaMalloc(&p, std::max<std::size_t>(bytes, 8))); }
    ~DeviceBuffer() { cudaFree(p); }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;
};

struct PinnedBuffer {
    std::uint8_t* p = nullptr;
    explicit PinnedBuffer(std::size_t bytes) { CHECK_CUDA(cudaMallocHost(&p, std::max<std::size_t>(bytes, 8))); }
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

template <class DSA, unsigned BD> using KG = decltype(DSA() + Function<function::Keygen>() + Block() + BlockDim<BD>());
template <class DSA, unsigned BD> using SG = decltype(DSA() + Function<function::Sign>() + Block() + BlockDim<BD>());
template <class DSA, unsigned BD> using VF = decltype(DSA() + Function<function::Verify>() + Block() + BlockDim<BD>());

constexpr std::size_t MSG = 64;   // message length, as in bench_mldsa_sycl
__host__ __device__ constexpr std::size_t pad8(std::size_t x) { return (x + 7) / 8 * 8; }   // 8-byte strides

template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) kg_kernel(std::uint8_t* pk, std::uint8_t* sk, std::uint8_t* ent,
                                                          std::size_t ent_stride, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(pk + i * T::public_key_size, sk + i * T::secret_key_size, ent + i * ent_stride,
                ws + i * T::workspace_size, smem);
}
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) sg_kernel(std::uint8_t* sig, const std::uint8_t* msg, std::size_t mlen,
                                                          const std::uint8_t* sk, std::uint8_t* ent,
                                                          std::size_t ent_stride, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(sig + i * pad8(T::signature_size), msg + i * pad8(mlen), mlen, sk + i * T::secret_key_size,
                ent + i * ent_stride, ws + i * T::workspace_size, smem);
}
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) vf_kernel(bool* valid, const std::uint8_t* sig, const std::uint8_t* msg,
                                                          std::size_t mlen, const std::uint8_t* pk, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    const bool ok = T().execute(msg + i * pad8(mlen), mlen, sig + i * pad8(T::signature_size), pk + i * T::public_key_size,
                                ws + i * T::workspace_size, smem);
    if (threadIdx.x == 0) valid[i] = ok;
}
// the overloads with a context string (one for the whole batch, in device memory)
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) sg_ctx_kernel(std::uint8_t* sig, const std::uint8_t* msg, std::size_t mlen,
                                                              const std::uint8_t* ctx, std::uint8_t ctxlen,
                                                              const std::uint8_t* sk, std::uint8_t* ent,
                                                              std::size_t ent_stride, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(sig + i * pad8(T::signature_size), msg + i * pad8(mlen), mlen, ctx, ctxlen, sk + i * T::secret_key_size,
                ent + i * ent_stride, ws + i * T::workspace_size, smem);
}
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) vf_ctx_kernel(bool* valid, const std::uint8_t* sig, const std::uint8_t* msg,
                                                              std::size_t mlen, const std::uint8_t* ctx, std::uint8_t ctxlen,
                                                              const std::uint8_t* pk, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    const bool ok = T().execute(msg + i * pad8(mlen), mlen, ctx, ctxlen, sig + i * pad8(T::signature_size),
                                pk + i * T::public_key_size, ws + i * T::workspace_size, smem);
    if (threadIdx.x == 0) valid[i] = ok;
}

struct CpuApi {
    openpqc_status (*keypair_derand)(std::uint8_t*, std::uint8_t*, const std::uint8_t*);
    openpqc_status (*sign_derand)(std::uint8_t*, const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,
                                  const std::uint8_t*, const std::uint8_t*);
    openpqc_status (*sign_internal)(std::uint8_t*, const std::uint8_t*, std::size_t, const std::uint8_t*,
                                    const std::uint8_t*);
    openpqc_status (*verify)(const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t, const std::uint8_t*,
                             std::size_t, const std::uint8_t*);
    openpqc_status (*verify_internal)(const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,
                                      const std::uint8_t*);
};
#define OPENPQC_CPU_API(N)                                                                                         \
    CpuApi{openpqc_mldsa##N##_keygen_from_seed, openpqc_testing_mldsa##N##_sign_derand, openpqc_testing_mldsa##N##_sign_internal,   \
           openpqc_mldsa##N##_verify, openpqc_testing_mldsa##N##_verify_internal}
template <int L> CpuApi cpu();
template <> CpuApi cpu<44>() { return OPENPQC_CPU_API(44); }
template <> CpuApi cpu<65>() { return OPENPQC_CPU_API(65); }
template <> CpuApi cpu<87>() { return OPENPQC_CPU_API(87); }

template <int L> struct dsa_of;
template <> struct dsa_of<44> { using type = ML_DSA_44; };
template <> struct dsa_of<65> { using type = ML_DSA_65; };
template <> struct dsa_of<87> { using type = ML_DSA_87; };

std::vector<std::uint8_t> download(const std::uint8_t* d, std::size_t n) {
    std::vector<std::uint8_t> h(n);
    CHECK_CUDA(cudaMemcpy(h.data(), d, n, cudaMemcpyDeviceToHost));
    return h;
}
void upload(std::uint8_t* d, const std::vector<std::uint8_t>& h) {
    CHECK_CUDA(cudaMemcpy(d, h.data(), h.size(), cudaMemcpyHostToDevice));
}
// operations i (of n) whose `len` bytes at stride `stride` differ
std::size_t mismatches(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b, std::size_t n,
                       std::size_t stride, std::size_t len) {
    std::size_t bad = 0;
    for (std::size_t i = 0; i < n; i++) bad += std::memcmp(&a[i * stride], &b[i * stride], len) != 0;
    return bad;
}
std::size_t count_true(const std::vector<std::uint8_t>& v, std::size_t n) {
    std::size_t c = 0;
    for (std::size_t i = 0; i < n; i++) c += v[i] != 0;
    return c;
}

// ---------------------------------------------------------------- 1. conformance / interop
template <int L>
bool conformance(std::size_t n) {
    using DSA = typename dsa_of<L>::type;
    using TK = KG<DSA, 128>;
    using TS = SG<DSA, 128>;
    using TV = VF<DSA, 128>;
    constexpr std::size_t PK = TK::public_key_size, SK = TK::secret_key_size, SIG = TS::signature_size;
    constexpr std::size_t SIGS = pad8(SIG), MS = pad8(MSG);
    constexpr std::size_t ENT = std::max<std::size_t>({TK::entropy_size, TS::entropy_size, 32});
    const CpuApi c = cpu<L>();
    std::printf("# ML-DSA-%d cuPQC traits: pk %zu, sk %zu, sig %zu, entropy keygen %zu / sign %zu, "
                "workspace keygen %zu / sign %zu / verify %zu, smem keygen %zu / sign %zu / verify %zu bytes\n",
                L, PK, SK, SIG, static_cast<std::size_t>(TK::entropy_size), static_cast<std::size_t>(TS::entropy_size),
                static_cast<std::size_t>(TK::workspace_size), static_cast<std::size_t>(TS::workspace_size),
                static_cast<std::size_t>(TV::workspace_size), static_cast<std::size_t>(TK::shared_memory_size),
                static_cast<std::size_t>(TS::shared_memory_size), static_cast<std::size_t>(TV::shared_memory_size));
    const std::size_t WS = std::max({TK::workspace_size, TS::workspace_size, TV::workspace_size});
    bool ok = true;

    // inputs: xi and rnd in the first 32 bytes of each entropy slot (the rest random), messages
    auto xi = bench::random_bytes(ENT * n, 300 + L), rnd = bench::random_bytes(ENT * n, 400 + L);
    const auto msg = bench::random_bytes(MS * n, 500 + L);
    DeviceBuffer d_ent(ENT * n), d_pk(PK * n), d_sk(SK * n), d_sig(SIGS * n), d_msg(MS * n), d_ws(WS * n),
            d_valid(n);

    // CPU reference: keys, external (empty context) and internal signatures
    std::vector<std::uint8_t> pk(PK * n), sk(SK * n), sig_ext(SIGS * n, 0), sig_int(SIGS * n, 0);
    for (std::size_t i = 0; i < n; i++) {
        c.keypair_derand(&pk[i * PK], &sk[i * SK], &xi[i * ENT]);
        c.sign_derand(&sig_ext[i * SIGS], &msg[i * MS], MSG, nullptr, 0, &rnd[i * ENT], &sk[i * SK]);
        c.sign_internal(&sig_int[i * SIGS], &msg[i * MS], MSG, &rnd[i * ENT], &sk[i * SK]);
    }

    // (a) cuPQC keygen with entropy = xi
    upload(d_ent.p, xi);
    kg_kernel<TK><<<n, TK::BlockDim>>>(d_pk.p, d_sk.p, d_ent.p, ENT, d_ws.p);
    CHECK_CUDA(cudaDeviceSynchronize());
    const std::size_t bpk = mismatches(pk, download(d_pk.p, PK * n), n, PK, PK);
    const std::size_t bsk = mismatches(sk, download(d_sk.p, SK * n), n, SK, SK);
    std::printf("# ML-DSA-%d cuPQC keygen (entropy = xi): pk mismatches %zu/%zu, sk mismatches %zu/%zu\n", L, bpk, n,
                bsk, n);
    const bool same_keys = bpk == 0 && bsk == 0;
    ok &= same_keys;

    // (b) cuPQC sign with entropy = rnd, on the reference keys
    upload(d_sk.p, sk);
    upload(d_msg.p, msg);
    upload(d_ent.p, rnd);
    sg_kernel<TS><<<n, TS::BlockDim>>>(d_sig.p, d_msg.p, MSG, d_sk.p, d_ent.p, ENT, d_ws.p);
    CHECK_CUDA(cudaDeviceSynchronize());
    const auto cu_sig = download(d_sig.p, SIGS * n);
    const std::size_t bext = mismatches(sig_ext, cu_sig, n, SIGS, SIG);
    const std::size_t bint = mismatches(sig_int, cu_sig, n, SIGS, SIG);
    std::printf("# ML-DSA-%d cuPQC sign (entropy = rnd): mismatches vs sign_derand with empty context (external) "
                "%zu/%zu, vs sign_internal %zu/%zu\n", L, bext, n, bint, n);
    const char* kind = bext == 0 ? "external ML-DSA.Sign with an empty context string"
                       : bint == 0 ? "ML-DSA.Sign_internal (no domain separator, no context)"
                                   : "neither (see the verification results)";
    std::printf("# ML-DSA-%d cuPQC Sign computes: %s\n", L, kind);
    ok &= bext == 0 || bint == 0;

    // (c) OpenPQC verifies cuPQC's signatures, both ways of formatting the message
    std::size_t v_ext = 0, v_int = 0;
    for (std::size_t i = 0; i < n; i++) {
        v_ext += c.verify(&cu_sig[i * SIGS], SIG, &msg[i * MS], MSG, nullptr, 0, &pk[i * PK]) == 0;
        v_int += c.verify_internal(&cu_sig[i * SIGS], SIG, &msg[i * MS], MSG, &pk[i * PK]) == 0;
    }
    std::printf("# ML-DSA-%d OpenPQC on cuPQC signatures: verify (empty context) accepts %zu/%zu, verify_internal "
                "accepts %zu/%zu\n", L, v_ext, n, v_int, n);

    // (d) cuPQC verifies OpenPQC's signatures: external, internal, tampered
    upload(d_pk.p, pk);
    const auto cu_verify = [&](const std::vector<std::uint8_t>& sigs) {
        upload(d_sig.p, sigs);
        vf_kernel<TV><<<n, TV::BlockDim>>>(reinterpret_cast<bool*>(d_valid.p), d_sig.p, d_msg.p, MSG, d_pk.p, d_ws.p);
        CHECK_CUDA(cudaDeviceSynchronize());
        return count_true(download(d_valid.p, n), n);
    };
    std::vector<std::uint8_t> sig_bad(bext == 0 ? sig_ext : sig_int);
    for (std::size_t i = 0; i < n; i++) sig_bad[i * SIGS + (7 * i) % SIG] ^= 0x04;
    const std::size_t a_ext = cu_verify(sig_ext), a_int = cu_verify(sig_int), a_bad = cu_verify(sig_bad);
    std::printf("# ML-DSA-%d cuPQC verify accepts: external signatures %zu/%zu, internal signatures %zu/%zu, "
                "tampered %zu/%zu\n", L, a_ext, n, a_int, n, a_bad, n);
    ok &= a_bad == 0 && (bext == 0 ? a_ext == n : a_int == n);

    // (e) the overloads with a context string: cuPQC sign vs sign_derand with the same context,
    //     cuPQC verify of OpenPQC's signatures under the right and a wrong context, and OpenPQC
    //     verify of cuPQC's
    static const std::uint8_t ctx_str[] = "openpqc-bench";
    const std::size_t ctxlen = sizeof ctx_str - 1;
    std::vector<std::uint8_t> sig_ctx(SIGS * n, 0);
    for (std::size_t i = 0; i < n; i++)
        c.sign_derand(&sig_ctx[i * SIGS], &msg[i * MS], MSG, ctx_str, ctxlen, &rnd[i * ENT], &sk[i * SK]);
    DeviceBuffer d_ctx(32);
    CHECK_CUDA(cudaMemcpy(d_ctx.p, ctx_str, ctxlen, cudaMemcpyHostToDevice));
    upload(d_ent.p, rnd);
    sg_ctx_kernel<TS><<<n, TS::BlockDim>>>(d_sig.p, d_msg.p, MSG, d_ctx.p, static_cast<std::uint8_t>(ctxlen), d_sk.p,
                                           d_ent.p, ENT, d_ws.p);
    CHECK_CUDA(cudaDeviceSynchronize());
    const auto cu_sig_ctx = download(d_sig.p, SIGS * n);
    const std::size_t bctx = mismatches(sig_ctx, cu_sig_ctx, n, SIGS, SIG);
    std::size_t v_ctx = 0;
    for (std::size_t i = 0; i < n; i++)
        v_ctx += c.verify(&cu_sig_ctx[i * SIGS], SIG, &msg[i * MS], MSG, ctx_str, ctxlen, &pk[i * PK]) == 0;
    const auto cu_verify_ctx = [&](const std::uint8_t* ctx, std::size_t len) {
        upload(d_sig.p, sig_ctx);
        CHECK_CUDA(cudaMemcpy(d_ctx.p, ctx, len, cudaMemcpyHostToDevice));
        vf_ctx_kernel<TV><<<n, TV::BlockDim>>>(reinterpret_cast<bool*>(d_valid.p), d_sig.p, d_msg.p, MSG, d_ctx.p,
                                               static_cast<std::uint8_t>(len), d_pk.p, d_ws.p);
        CHECK_CUDA(cudaDeviceSynchronize());
        return count_true(download(d_valid.p, n), n);
    };
    static const std::uint8_t wrong_ctx[] = "openpqc-bencH";
    const std::size_t a_ctx = cu_verify_ctx(ctx_str, ctxlen), a_wrong = cu_verify_ctx(wrong_ctx, ctxlen);
    std::printf("# ML-DSA-%d with a %zu-byte context string: cuPQC sign mismatches vs sign_derand %zu/%zu; OpenPQC "
                "verify accepts cuPQC's %zu/%zu; cuPQC verify accepts OpenPQC's %zu/%zu, under a wrong context %zu/%zu\n",
                L, ctxlen, bctx, n, v_ctx, n, a_ctx, n, a_wrong, n);
    ok &= bctx == 0 && v_ctx == n && a_ctx == n && a_wrong == 0;
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

// As in bench_mldsa_sycl: KeyGen takes xi and Sign takes rnd from buffers of their own, so that
// every call recomputes the keys and signatures the buffers hold (cuPQC computes what the OpenPQC
// CPU library does: see conformance), and every Verify checks valid signatures.
struct Device {
    std::uint8_t *pk, *sk, *sig, *msg, *xi, *rnd, *ws, *valid;
    std::size_t ent_stride;
};
struct Host {   // page-locked inputs of the end-to-end runs, one buffer each, and their outputs
    std::uint8_t *xi, *rnd, *sk, *msg, *sig, *pk, *out;
};

template <int L, unsigned BD>
void add_runners(std::vector<Runner>& rs, cudaStream_t st, std::size_t n, Device d, Host h) {
    using DSA = typename dsa_of<L>::type;
    using TK = KG<DSA, BD>;
    using TS = SG<DSA, BD>;
    using TV = VF<DSA, BD>;
    const std::string impl = "cupqc-bd" + std::to_string(BD);
    const auto cp = [=](void* dst, const void* src, std::size_t b, cudaMemcpyKind k) {
        CHECK_CUDA(cudaMemcpyAsync(dst, src, b, k, st));
    };
    constexpr std::size_t PK = TK::public_key_size, SK = TK::secret_key_size, SIGS = pad8(TS::signature_size),
                          MS = pad8(MSG);
    const std::size_t E = d.ent_stride;
    bool* valid = reinterpret_cast<bool*>(d.valid);
    rs.push_back({impl, "keygen", "kernel", [=] { kg_kernel<TK><<<n, TK::BlockDim, 0, st>>>(d.pk, d.sk, d.xi, E, d.ws); }, {}, {}});
    rs.push_back({impl, "sign", "kernel",
                  [=] { sg_kernel<TS><<<n, TS::BlockDim, 0, st>>>(d.sig, d.msg, MSG, d.sk, d.rnd, E, d.ws); }, {}, {}});
    rs.push_back({impl, "verify", "kernel",
                  [=] { vf_kernel<TV><<<n, TV::BlockDim, 0, st>>>(valid, d.sig, d.msg, MSG, d.pk, d.ws); }, {}, {}});
    rs.push_back({impl, "keygen", "e2e", [=] {
                      cp(d.xi, h.xi, E * n, cudaMemcpyHostToDevice);
                      kg_kernel<TK><<<n, TK::BlockDim, 0, st>>>(d.pk, d.sk, d.xi, E, d.ws);
                      cp(h.out, d.pk, PK * n, cudaMemcpyDeviceToHost);
                      cp(h.out + PK * n, d.sk, SK * n, cudaMemcpyDeviceToHost);
                  }, {}, {}});
    rs.push_back({impl, "sign", "e2e", [=] {
                      cp(d.sk, h.sk, SK * n, cudaMemcpyHostToDevice);
                      cp(d.msg, h.msg, MS * n, cudaMemcpyHostToDevice);
                      cp(d.rnd, h.rnd, E * n, cudaMemcpyHostToDevice);
                      sg_kernel<TS><<<n, TS::BlockDim, 0, st>>>(d.sig, d.msg, MSG, d.sk, d.rnd, E, d.ws);
                      cp(h.out, d.sig, SIGS * n, cudaMemcpyDeviceToHost);
                  }, {}, {}});
    rs.push_back({impl, "verify", "e2e", [=] {
                      cp(d.sig, h.sig, SIGS * n, cudaMemcpyHostToDevice);
                      cp(d.msg, h.msg, MS * n, cudaMemcpyHostToDevice);
                      cp(d.pk, h.pk, PK * n, cudaMemcpyHostToDevice);
                      vf_kernel<TV><<<n, TV::BlockDim, 0, st>>>(valid, d.sig, d.msg, MSG, d.pk, d.ws);
                      cp(h.out, d.valid, n, cudaMemcpyDeviceToHost);
                  }, {}, {}});
}

template <int L>
void throughput(const std::vector<std::size_t>& batches, int trials, const std::vector<std::size_t>& blockdims,
                unsigned cool_to_c, const bench::GpuMonitor& mon) {
    using DSA = typename dsa_of<L>::type;
    using TK = KG<DSA, 128>;
    using TS = SG<DSA, 128>;
    using TV = VF<DSA, 128>;
    constexpr std::size_t PK = TK::public_key_size, SK = TK::secret_key_size, SIG = TS::signature_size,
                          SIGS = pad8(SIG), MS = pad8(MSG);
    constexpr std::size_t E = std::max<std::size_t>({TK::entropy_size, TS::entropy_size, 32});
    // the workspace of every block dimension: take the largest of all descriptors measured
    std::size_t WS = 0;
    for (const std::size_t bd : blockdims) {
        if (bd == 32) WS = std::max({WS, KG<DSA, 32>::workspace_size, SG<DSA, 32>::workspace_size, VF<DSA, 32>::workspace_size});
        if (bd == 64) WS = std::max({WS, KG<DSA, 64>::workspace_size, SG<DSA, 64>::workspace_size, VF<DSA, 64>::workspace_size});
        if (bd == 128) WS = std::max({WS, TK::workspace_size, TS::workspace_size, TV::workspace_size});
        if (bd == 256) WS = std::max({WS, KG<DSA, 256>::workspace_size, SG<DSA, 256>::workspace_size, VF<DSA, 256>::workspace_size});
    }
    const CpuApi c = cpu<L>();
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    cudaStream_t st;
    CHECK_CUDA(cudaStreamCreateWithFlags(&st, cudaStreamNonBlocking));
    DeviceBuffer pk(PK * nmax), sk(SK * nmax), sig(SIGS * nmax), msg(MS * nmax), d_xi(E * nmax), d_rnd(E * nmax),
            ws(WS * nmax), valid(nmax);
    PinnedBuffer h_xi(E * nmax), h_rnd(E * nmax), h_sk(SK * nmax), h_msg(MS * nmax), h_sig(SIGS * nmax),
            h_pk(PK * nmax), h_out((PK + SK + SIGS + 8) * nmax);

    // valid keys and signatures from the CPU library, of the kind cuPQC computes (conformance)
    const auto xi = bench::random_bytes(E * nmax, 11), rnd = bench::random_bytes(E * nmax, 12),
               m = bench::random_bytes(MS * nmax, 13);
    std::memcpy(h_xi.p, xi.data(), E * nmax);
    std::memcpy(h_rnd.p, rnd.data(), E * nmax);
    std::memcpy(h_msg.p, m.data(), MS * nmax);
    std::memset(h_sig.p, 0, SIGS * nmax);
    for (std::size_t i = 0; i < nmax; i++) {
        c.keypair_derand(h_pk.p + i * PK, h_sk.p + i * SK, &xi[i * E]);
        c.sign_derand(h_sig.p + i * SIGS, &m[i * MS], MSG, nullptr, 0, &rnd[i * E], h_sk.p + i * SK);
    }
    CHECK_CUDA(cudaMemcpy(d_xi.p, h_xi.p, E * nmax, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(d_rnd.p, h_rnd.p, E * nmax, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(sk.p, h_sk.p, SK * nmax, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(msg.p, h_msg.p, MS * nmax, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(pk.p, h_pk.p, PK * nmax, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(sig.p, h_sig.p, SIGS * nmax, cudaMemcpyHostToDevice));
    const Device d{pk.p, sk.p, sig.p, msg.p, d_xi.p, d_rnd.p, ws.p, valid.p, E};
    const Host h{h_xi.p, h_rnd.p, h_sk.p, h_msg.p, h_sig.p, h_pk.p, h_out.p};

    for (const std::size_t n : batches) {
        std::vector<Runner> rs;
        for (const std::size_t bd : blockdims) {
            if (bd == 32) add_runners<L, 32>(rs, st, n, d, h);
            if (bd == 64) add_runners<L, 64>(rs, st, n, d, h);
            if (bd == 128) add_runners<L, 128>(rs, st, n, d, h);
            if (bd == 256) add_runners<L, 256>(rs, st, n, d, h);
        }
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
        // a last check that the runs measured what they should: the device still holds the CPU
        // library's keys and signatures, and Verify accepts every one of them
        vf_kernel<TV><<<n, TV::BlockDim, 0, st>>>(reinterpret_cast<bool*>(valid.p), sig.p, msg.p, MSG, pk.p, ws.p);
        sync();
        const std::size_t accepted = count_true(download(valid.p, n), n);
        const std::vector<std::uint8_t> want_sig(h_sig.p, h_sig.p + SIGS * n), want_pk(h_pk.p, h_pk.p + PK * n);
        const std::size_t bad_sig = mismatches(want_sig, download(sig.p, SIGS * n), n, SIGS, SIG);
        const std::size_t bad_pk = mismatches(want_pk, download(pk.p, PK * n), n, PK, PK);
        if (accepted != n || bad_sig || bad_pk)
            std::printf("# WARNING: ML-DSA-%d batch %zu: verify accepted %zu/%zu, signatures differ %zu, keys differ %zu\n",
                        L, n, accepted, n, bad_sig, bad_pk);
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
    const auto levels = bench::parse_list(argc > 1 ? argv[1] : "44,65,87");
    const auto batches = bench::parse_list(argc > 2 ? argv[2] : "1,8,64,512,4096,8192");
    const int trials = argc > 3 ? std::atoi(argv[3]) : 15;
    const auto blockdims = bench::parse_list(argc > 4 ? argv[4] : "32,64,128,256");
    const unsigned cool_to_c = argc > 5 ? static_cast<unsigned>(std::atoi(argv[5])) : 0;
    bench::GpuMonitor mon;
    bool ok = true;
    for (auto l : levels) {
        if (l == 44) ok &= conformance<44>(512);
        if (l == 65) ok &= conformance<65>(512);
        if (l == 87) ok &= conformance<87>(512);
    }
    std::printf("# conformance: %s\n", ok ? "cuPQC agrees with the OpenPQC CPU library" : "MISMATCH (see above)");
    std::printf("impl,level,op,mode,batch,median_s,p10_s,p90_s,ops_per_s,sm_mhz,temp_c\n");
    for (auto l : levels) {
        if (l == 44) throughput<44>(batches, trials, blockdims, cool_to_c, mon);
        if (l == 65) throughput<65>(batches, trials, blockdims, cool_to_c, mon);
        if (l == 87) throughput<87>(batches, trials, blockdims, cool_to_c, mon);
    }
    return ok ? 0 : 1;
}
