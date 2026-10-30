// bench_latency_cupqc.cu  --  latency of NVIDIA cuPQC: the steps of its example programs (optional)
//
// Built only when OPENPQC_CUPQC_DIR points to a cuPQC SDK (not distributed with OpenPQC).
// NOTE: the cuPQC SDK ships under NVIDIA's evaluation licence, which treats benchmark results
// of cuPQC as NVIDIA confidential information: keep the output of this program internal unless
// NVIDIA has approved publication.
//
// usage: bench_latency_cupqc [kem_levels=512,768,1024] [dsa_levels=44,65,87] [batches=10,1]
//                            [reps=50] [styles=example,app]
// The steps, styles and CSV of bench_latency_sycl, with cuPQC's kernels at the block size of its
// examples (one block of 128 threads per operation):
//   style example: the calls of cuPQC's examples/public_key/example_ml_kem.cu and
//                  example_ml_dsa.cu: in every step make_workspace, get_entropy (which reads
//                  /dev/urandom and copies the bytes to the device), cudaMalloc, cudaMemcpy, the
//                  kernel, cudaMemcpy back, cudaFree, destroy_workspace and release_entropy
//   style app:     device buffers, workspace and page-locked host buffers allocated once; in
//                  every step the entropy from the operating system (getrandom, as OpenPQC's
//                  randomized calls get theirs), the inputs, the kernel and the outputs are
//                  queued on one stream, then one cudaStreamSynchronize
// Step init: from the start of main() to a CUDA context (cudaFree(0)).
#include <cuda_runtime.h>
#include <sys/random.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <pk.hpp>

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

constexpr unsigned BD = 128;                  // the block size of cuPQC's examples
constexpr std::size_t MESSAGE_BYTES = 1024;   // as in example_ml_dsa.cu
__host__ __device__ constexpr std::size_t pad8(std::size_t x) { return (x + 7) / 8 * 8; }   // 8-byte strides

template <class KEM> using KG = decltype(KEM() + Function<function::Keygen>() + Block() + BlockDim<BD>());
template <class KEM> using EN = decltype(KEM() + Function<function::Encaps>() + Block() + BlockDim<BD>());
template <class KEM> using DE = decltype(KEM() + Function<function::Decaps>() + Block() + BlockDim<BD>());
template <class DSA> using SKG = decltype(DSA() + Function<function::Keygen>() + Block() + BlockDim<BD>());
template <class DSA> using SSG = decltype(DSA() + Function<function::Sign>() + Block() + BlockDim<BD>());
template <class DSA> using SVF = decltype(DSA() + Function<function::Verify>() + Block() + BlockDim<BD>());

template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) kem_keygen_kernel(std::uint8_t* pk, std::uint8_t* sk,
                                                                  std::uint8_t* ent, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(pk + i * T::public_key_size, sk + i * T::secret_key_size, ent + i * T::entropy_size,
                ws + i * T::workspace_size, smem);
}
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) kem_encaps_kernel(std::uint8_t* ct, std::uint8_t* ss,
                                                                  const std::uint8_t* pk, std::uint8_t* ent,
                                                                  std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(ct + i * T::ciphertext_size, ss + i * T::shared_secret_size, pk + i * T::public_key_size,
                ent + i * T::entropy_size, ws + i * T::workspace_size, smem);
}
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) kem_decaps_kernel(std::uint8_t* ss, const std::uint8_t* ct,
                                                                  const std::uint8_t* sk, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(ss + i * T::shared_secret_size, ct + i * T::ciphertext_size, sk + i * T::secret_key_size,
                ws + i * T::workspace_size, smem);
}
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) dsa_keygen_kernel(std::uint8_t* pk, std::uint8_t* sk,
                                                                  std::uint8_t* ent, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(pk + i * T::public_key_size, sk + i * T::secret_key_size, ent + i * T::entropy_size,
                ws + i * T::workspace_size, smem);
}
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) dsa_sign_kernel(std::uint8_t* sig, const std::uint8_t* msg,
                                                                std::size_t mlen, const std::uint8_t* sk,
                                                                std::uint8_t* ent, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    T().execute(sig + i * pad8(T::signature_size), msg + i * mlen, mlen, sk + i * T::secret_key_size,
                ent + i * T::entropy_size, ws + i * T::workspace_size, smem);
}
template <class T>
__global__ void __launch_bounds__(T::BlockDim.x) dsa_verify_kernel(bool* valid, const std::uint8_t* sig,
                                                                  const std::uint8_t* msg, std::size_t mlen,
                                                                  const std::uint8_t* pk, std::uint8_t* ws) {
    __shared__ __align__(16) std::uint8_t smem[T::shared_memory_size];
    const std::size_t i = blockIdx.x;
    const bool ok = T().execute(msg + i * mlen, mlen, sig + i * pad8(T::signature_size), pk + i * T::public_key_size,
                                ws + i * T::workspace_size, smem);
    if (threadIdx.x == 0) valid[i] = ok;
}

// "example,app" -> {"example", "app"}
std::vector<std::string> parse_words(const char* s) {
    std::vector<std::string> v;
    const std::string str(s);
    std::size_t pos = 0;
    while (pos <= str.size()) {
        const std::size_t comma = str.find(',', pos);
        v.push_back(str.substr(pos, comma - pos));
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return v;
}

// The seconds of the three steps of one run, and their sum
using Run = std::array<double, 4>;

template <class F>
double timed(F f) {
    const double t0 = bench::now();
    f();
    return bench::now() - t0;
}

const char* const IMPL = "cupqc";

// One row per step: the first run, and the statistics of the runs after it
void report(const char* scheme, int level, const std::string& style, std::size_t n, const char* const (&steps)[3],
            std::vector<Run>& runs) {
    for (auto& t : runs) t[3] = t[0] + t[1] + t[2];
    for (int s = 0; s < 4; s++) {
        std::printf("%s,%s,%d,%s,%zu,%s,%.9g", IMPL, scheme, level, style.c_str(), n, s < 3 ? steps[s] : "total",
                    runs[0][s]);
        std::vector<double> v;
        for (std::size_t r = 1; r < runs.size(); r++) v.push_back(runs[r][s]);
        if (v.empty()) {
            std::printf(",,,,0\n");
        } else {
            const auto st = bench::summarize(v);
            std::printf(",%.9g,%.9g,%.9g,%zu\n", st.median, st.p10, st.p90, v.size());
        }
    }
    std::fflush(stdout);
}

std::size_t differing(const std::uint8_t* a, const std::uint8_t* b, std::size_t n, std::size_t stride) {
    std::size_t bad = 0;
    for (std::size_t i = 0; i < n; i++) bad += std::memcmp(a + i * stride, b + i * stride, stride) != 0;
    return bad;
}

// randomness from the operating system
void fill_random(std::uint8_t* p, std::size_t bytes) {
    for (std::size_t got = 0; got < bytes;) {
        const ssize_t r = getrandom(p + got, bytes - got, 0);
        if (r <= 0) {
            std::fprintf(stderr, "getrandom failed\n");
            std::exit(1);
        }
        got += static_cast<std::size_t>(r);
    }
}

// ---------------------------------------------------------------- ML-KEM

// One run with the calls of example_ml_kem.cu. Returns the number of shared secrets that differ.
template <class KEM>
std::size_t kem_run_example(std::size_t n, Run& t) {
    using K = KG<KEM>;
    using E = EN<KEM>;
    using D = DE<KEM>;
    std::vector<std::uint8_t> pk(K::public_key_size * n), sk(K::secret_key_size * n), ct(E::ciphertext_size * n),
            ss(E::shared_secret_size * n), ss2(D::shared_secret_size * n);
    t[0] = timed([&] {
        auto* ws = make_workspace<K>(n);
        auto* ent = get_entropy<K>(n);
        std::uint8_t *d_pk = nullptr, *d_sk = nullptr;
        CHECK_CUDA(cudaMalloc(&d_pk, pk.size()));
        CHECK_CUDA(cudaMalloc(&d_sk, sk.size()));
        kem_keygen_kernel<K><<<n, K::BlockDim>>>(d_pk, d_sk, ent, ws);
        CHECK_CUDA(cudaGetLastError());
        CHECK_CUDA(cudaMemcpy(pk.data(), d_pk, pk.size(), cudaMemcpyDeviceToHost));
        CHECK_CUDA(cudaMemcpy(sk.data(), d_sk, sk.size(), cudaMemcpyDeviceToHost));
        CHECK_CUDA(cudaFree(d_pk));
        CHECK_CUDA(cudaFree(d_sk));
        destroy_workspace(ws);
        release_entropy(ent);
    });
    t[1] = timed([&] {
        auto* ws = make_workspace<E>(n);
        auto* ent = get_entropy<E>(n);
        std::uint8_t *d_ct = nullptr, *d_pk = nullptr, *d_ss = nullptr;
        CHECK_CUDA(cudaMalloc(&d_ct, ct.size()));
        CHECK_CUDA(cudaMalloc(&d_pk, pk.size()));
        CHECK_CUDA(cudaMalloc(&d_ss, ss.size()));
        CHECK_CUDA(cudaMemcpy(d_pk, pk.data(), pk.size(), cudaMemcpyHostToDevice));
        kem_encaps_kernel<E><<<n, E::BlockDim>>>(d_ct, d_ss, d_pk, ent, ws);
        CHECK_CUDA(cudaGetLastError());
        CHECK_CUDA(cudaMemcpy(ct.data(), d_ct, ct.size(), cudaMemcpyDeviceToHost));
        CHECK_CUDA(cudaMemcpy(ss.data(), d_ss, ss.size(), cudaMemcpyDeviceToHost));
        CHECK_CUDA(cudaFree(d_ct));
        CHECK_CUDA(cudaFree(d_pk));
        CHECK_CUDA(cudaFree(d_ss));
        destroy_workspace(ws);
        release_entropy(ent);
    });
    t[2] = timed([&] {
        auto* ws = make_workspace<D>(n);
        std::uint8_t *d_ss = nullptr, *d_ct = nullptr, *d_sk = nullptr;
        CHECK_CUDA(cudaMalloc(&d_ss, ss2.size()));
        CHECK_CUDA(cudaMalloc(&d_ct, ct.size()));
        CHECK_CUDA(cudaMalloc(&d_sk, sk.size()));
        CHECK_CUDA(cudaMemcpy(d_ct, ct.data(), ct.size(), cudaMemcpyHostToDevice));
        CHECK_CUDA(cudaMemcpy(d_sk, sk.data(), sk.size(), cudaMemcpyHostToDevice));
        kem_decaps_kernel<D><<<n, D::BlockDim>>>(d_ss, d_ct, d_sk, ws);
        CHECK_CUDA(cudaGetLastError());
        CHECK_CUDA(cudaMemcpy(ss2.data(), d_ss, ss2.size(), cudaMemcpyDeviceToHost));
        CHECK_CUDA(cudaFree(d_ss));
        CHECK_CUDA(cudaFree(d_ct));
        CHECK_CUDA(cudaFree(d_sk));
        destroy_workspace(ws);
    });
    return differing(ss.data(), ss2.data(), n, 32);
}

// The buffers of the app style, for up to nmax operations
template <class KEM>
struct KemApp {
    using K = KG<KEM>;
    using E = EN<KEM>;
    using D = DE<KEM>;
    static constexpr std::size_t ENT = std::max(K::entropy_size, E::entropy_size);
    static constexpr std::size_t WS = std::max({K::workspace_size, E::workspace_size, D::workspace_size});
    DeviceBuffer d_pk, d_sk, d_ct, d_ss, d_ent, d_ws;
    PinnedBuffer h_pk, h_sk, h_ct, h_ss, h_ss2, h_ent;
    explicit KemApp(std::size_t nmax)
        : d_pk(K::public_key_size * nmax), d_sk(K::secret_key_size * nmax), d_ct(E::ciphertext_size * nmax),
          d_ss(32 * nmax), d_ent(ENT * nmax), d_ws(WS * nmax), h_pk(K::public_key_size * nmax),
          h_sk(K::secret_key_size * nmax), h_ct(E::ciphertext_size * nmax), h_ss(32 * nmax), h_ss2(32 * nmax),
          h_ent(ENT * nmax) {}
};

// One run in the app style: everything of a step queued on one stream, one wait per step
template <class KEM>
std::size_t kem_run_app(std::size_t n, KemApp<KEM>& b, cudaStream_t st, Run& t) {
    using K = KG<KEM>;
    using E = EN<KEM>;
    using D = DE<KEM>;
    const auto copy = [&](void* dst, const void* src, std::size_t bytes) {
        CHECK_CUDA(cudaMemcpyAsync(dst, src, bytes, cudaMemcpyDefault, st));
    };
    const auto wait = [&] { CHECK_CUDA(cudaStreamSynchronize(st)); };
    t[0] = timed([&] {
        fill_random(b.h_ent.p, K::entropy_size * n);
        copy(b.d_ent.p, b.h_ent.p, K::entropy_size * n);
        kem_keygen_kernel<K><<<n, K::BlockDim, 0, st>>>(b.d_pk.p, b.d_sk.p, b.d_ent.p, b.d_ws.p);
        CHECK_CUDA(cudaGetLastError());
        copy(b.h_pk.p, b.d_pk.p, K::public_key_size * n);
        copy(b.h_sk.p, b.d_sk.p, K::secret_key_size * n);
        wait();
    });
    t[1] = timed([&] {
        fill_random(b.h_ent.p, E::entropy_size * n);
        copy(b.d_ent.p, b.h_ent.p, E::entropy_size * n);
        copy(b.d_pk.p, b.h_pk.p, K::public_key_size * n);
        kem_encaps_kernel<E><<<n, E::BlockDim, 0, st>>>(b.d_ct.p, b.d_ss.p, b.d_pk.p, b.d_ent.p, b.d_ws.p);
        CHECK_CUDA(cudaGetLastError());
        copy(b.h_ct.p, b.d_ct.p, E::ciphertext_size * n);
        copy(b.h_ss.p, b.d_ss.p, 32 * n);
        wait();
    });
    t[2] = timed([&] {
        copy(b.d_ct.p, b.h_ct.p, E::ciphertext_size * n);
        copy(b.d_sk.p, b.h_sk.p, K::secret_key_size * n);
        kem_decaps_kernel<D><<<n, D::BlockDim, 0, st>>>(b.d_ss.p, b.d_ct.p, b.d_sk.p, b.d_ws.p);
        CHECK_CUDA(cudaGetLastError());
        copy(b.h_ss2.p, b.d_ss.p, 32 * n);
        wait();
    });
    return differing(b.h_ss.p, b.h_ss2.p, n, 32);
}

template <class KEM>
std::size_t bench_kem(int level, const std::vector<std::size_t>& batches, int reps,
                      const std::vector<std::string>& styles) {
    static const char* const steps[3] = {"keygen", "encaps", "decaps"};
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    cudaStream_t st;
    CHECK_CUDA(cudaStreamCreateWithFlags(&st, cudaStreamNonBlocking));
    std::size_t bad = 0;
    {
        KemApp<KEM> app(nmax);
        for (const std::size_t n : batches) {
            for (const auto& style : styles) {
                std::vector<Run> runs(static_cast<std::size_t>(reps) + 1);
                std::size_t differ = 0;
                for (auto& t : runs) differ += style == "app" ? kem_run_app<KEM>(n, app, st, t) : kem_run_example<KEM>(n, t);
                report("ML-KEM", level, style, n, steps, runs);
                if (differ)
                    std::fprintf(stderr, "# WARNING ML-KEM-%d %s batch %zu: %zu shared secrets differ\n", level,
                                 style.c_str(), n, differ);
                bad += differ;
            }
        }
    }
    cudaStreamDestroy(st);
    return bad;
}

// ---------------------------------------------------------------- ML-DSA

// One run with the calls of example_ml_dsa.cu. Returns the number of signatures that do not verify.
template <class DSA>
std::size_t dsa_run_example(std::size_t n, const std::vector<std::uint8_t>& msg, Run& t) {
    using K = SKG<DSA>;
    using S = SSG<DSA>;
    using V = SVF<DSA>;
    const std::size_t sigstride = pad8(S::signature_size), mbytes = MESSAGE_BYTES * n;
    std::vector<std::uint8_t> pk(K::public_key_size * n), sk(K::secret_key_size * n), sig(sigstride * n);
    bool valid[1024] = {};   // n <= 1024 (checked in main)
    t[0] = timed([&] {
        auto* ws = make_workspace<K>(n);
        auto* ent = get_entropy<K>(n);
        std::uint8_t *d_pk = nullptr, *d_sk = nullptr;
        CHECK_CUDA(cudaMalloc(&d_pk, pk.size()));
        CHECK_CUDA(cudaMalloc(&d_sk, sk.size()));
        dsa_keygen_kernel<K><<<n, K::BlockDim>>>(d_pk, d_sk, ent, ws);
        CHECK_CUDA(cudaGetLastError());
        CHECK_CUDA(cudaMemcpy(pk.data(), d_pk, pk.size(), cudaMemcpyDeviceToHost));
        CHECK_CUDA(cudaMemcpy(sk.data(), d_sk, sk.size(), cudaMemcpyDeviceToHost));
        CHECK_CUDA(cudaFree(d_pk));
        CHECK_CUDA(cudaFree(d_sk));
        destroy_workspace(ws);
        release_entropy(ent);
    });
    t[1] = timed([&] {
        auto* ws = make_workspace<S>(n);
        auto* ent = get_entropy<S>(n);
        std::uint8_t *d_sig = nullptr, *d_sk = nullptr, *d_msg = nullptr;
        CHECK_CUDA(cudaMalloc(&d_sig, sig.size()));
        CHECK_CUDA(cudaMalloc(&d_sk, sk.size()));
        CHECK_CUDA(cudaMalloc(&d_msg, mbytes));
        CHECK_CUDA(cudaMemcpy(d_sk, sk.data(), sk.size(), cudaMemcpyHostToDevice));
        CHECK_CUDA(cudaMemcpy(d_msg, msg.data(), mbytes, cudaMemcpyHostToDevice));
        dsa_sign_kernel<S><<<n, S::BlockDim>>>(d_sig, d_msg, MESSAGE_BYTES, d_sk, ent, ws);
        CHECK_CUDA(cudaGetLastError());
        CHECK_CUDA(cudaMemcpy(sig.data(), d_sig, sig.size(), cudaMemcpyDeviceToHost));
        CHECK_CUDA(cudaFree(d_sk));
        CHECK_CUDA(cudaFree(d_sig));
        CHECK_CUDA(cudaFree(d_msg));
        destroy_workspace(ws);
        release_entropy(ent);
    });
    t[2] = timed([&] {
        auto* ws = make_workspace<V>(n);
        std::uint8_t *d_sig = nullptr, *d_msg = nullptr, *d_pk = nullptr;
        bool* d_valid = nullptr;
        CHECK_CUDA(cudaMalloc(&d_sig, sig.size()));
        CHECK_CUDA(cudaMalloc(&d_pk, pk.size()));
        CHECK_CUDA(cudaMalloc(&d_msg, mbytes));
        CHECK_CUDA(cudaMalloc(&d_valid, n));
        CHECK_CUDA(cudaMemcpy(d_pk, pk.data(), pk.size(), cudaMemcpyHostToDevice));
        CHECK_CUDA(cudaMemcpy(d_sig, sig.data(), sig.size(), cudaMemcpyHostToDevice));
        CHECK_CUDA(cudaMemcpy(d_msg, msg.data(), mbytes, cudaMemcpyHostToDevice));
        dsa_verify_kernel<V><<<n, V::BlockDim>>>(d_valid, d_sig, d_msg, MESSAGE_BYTES, d_pk, ws);
        CHECK_CUDA(cudaGetLastError());
        CHECK_CUDA(cudaMemcpy(valid, d_valid, n, cudaMemcpyDeviceToHost));
        CHECK_CUDA(cudaFree(d_pk));
        CHECK_CUDA(cudaFree(d_sig));
        CHECK_CUDA(cudaFree(d_msg));
        CHECK_CUDA(cudaFree(d_valid));
        destroy_workspace(ws);
    });
    return static_cast<std::size_t>(std::count(valid, valid + n, false));
}

// The buffers of the app style, for up to nmax operations
template <class DSA>
struct DsaApp {
    using K = SKG<DSA>;
    using S = SSG<DSA>;
    using V = SVF<DSA>;
    static constexpr std::size_t ENT = std::max(K::entropy_size, S::entropy_size);
    static constexpr std::size_t WS = std::max({K::workspace_size, S::workspace_size, V::workspace_size});
    DeviceBuffer d_pk, d_sk, d_sig, d_msg, d_valid, d_ent, d_ws;
    PinnedBuffer h_pk, h_sk, h_sig, h_msg, h_valid, h_ent;
    DsaApp(std::size_t nmax, const std::vector<std::uint8_t>& msg)
        : d_pk(K::public_key_size * nmax), d_sk(K::secret_key_size * nmax), d_sig(pad8(S::signature_size) * nmax),
          d_msg(MESSAGE_BYTES * nmax), d_valid(nmax), d_ent(ENT * nmax), d_ws(WS * nmax),
          h_pk(K::public_key_size * nmax), h_sk(K::secret_key_size * nmax), h_sig(pad8(S::signature_size) * nmax),
          h_msg(MESSAGE_BYTES * nmax), h_valid(nmax), h_ent(ENT * nmax) {
        std::memcpy(h_msg.p, msg.data(), MESSAGE_BYTES * nmax);
    }
};

// One run in the app style: everything of a step queued on one stream, one wait per step
template <class DSA>
std::size_t dsa_run_app(std::size_t n, DsaApp<DSA>& b, cudaStream_t st, Run& t) {
    using K = SKG<DSA>;
    using S = SSG<DSA>;
    using V = SVF<DSA>;
    const std::size_t sigstride = pad8(S::signature_size);
    const auto copy = [&](void* dst, const void* src, std::size_t bytes) {
        CHECK_CUDA(cudaMemcpyAsync(dst, src, bytes, cudaMemcpyDefault, st));
    };
    const auto wait = [&] { CHECK_CUDA(cudaStreamSynchronize(st)); };
    t[0] = timed([&] {
        fill_random(b.h_ent.p, K::entropy_size * n);
        copy(b.d_ent.p, b.h_ent.p, K::entropy_size * n);
        dsa_keygen_kernel<K><<<n, K::BlockDim, 0, st>>>(b.d_pk.p, b.d_sk.p, b.d_ent.p, b.d_ws.p);
        CHECK_CUDA(cudaGetLastError());
        copy(b.h_pk.p, b.d_pk.p, K::public_key_size * n);
        copy(b.h_sk.p, b.d_sk.p, K::secret_key_size * n);
        wait();
    });
    t[1] = timed([&] {
        fill_random(b.h_ent.p, S::entropy_size * n);
        copy(b.d_ent.p, b.h_ent.p, S::entropy_size * n);
        copy(b.d_sk.p, b.h_sk.p, K::secret_key_size * n);
        copy(b.d_msg.p, b.h_msg.p, MESSAGE_BYTES * n);
        dsa_sign_kernel<S><<<n, S::BlockDim, 0, st>>>(b.d_sig.p, b.d_msg.p, MESSAGE_BYTES, b.d_sk.p, b.d_ent.p,
                                                      b.d_ws.p);
        CHECK_CUDA(cudaGetLastError());
        copy(b.h_sig.p, b.d_sig.p, sigstride * n);
        wait();
    });
    t[2] = timed([&] {
        copy(b.d_pk.p, b.h_pk.p, K::public_key_size * n);
        copy(b.d_sig.p, b.h_sig.p, sigstride * n);
        copy(b.d_msg.p, b.h_msg.p, MESSAGE_BYTES * n);
        dsa_verify_kernel<V><<<n, V::BlockDim, 0, st>>>(reinterpret_cast<bool*>(b.d_valid.p), b.d_sig.p, b.d_msg.p,
                                                        MESSAGE_BYTES, b.d_pk.p, b.d_ws.p);
        CHECK_CUDA(cudaGetLastError());
        copy(b.h_valid.p, b.d_valid.p, n);
        wait();
    });
    const bool* valid = reinterpret_cast<const bool*>(b.h_valid.p);
    return static_cast<std::size_t>(std::count(valid, valid + n, false));
}

template <class DSA>
std::size_t bench_dsa(int level, const std::vector<std::size_t>& batches, int reps,
                      const std::vector<std::string>& styles) {
    static const char* const steps[3] = {"keygen", "sign", "verify"};
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    const auto msg = bench::random_bytes(MESSAGE_BYTES * nmax, 3);
    cudaStream_t st;
    CHECK_CUDA(cudaStreamCreateWithFlags(&st, cudaStreamNonBlocking));
    std::size_t bad = 0;
    {
        DsaApp<DSA> app(nmax, msg);
        for (const std::size_t n : batches) {
            for (const auto& style : styles) {
                std::vector<Run> runs(static_cast<std::size_t>(reps) + 1);
                std::size_t invalid = 0;
                for (auto& t : runs)
                    invalid += style == "app" ? dsa_run_app<DSA>(n, app, st, t) : dsa_run_example<DSA>(n, msg, t);
                report("ML-DSA", level, style, n, steps, runs);
                if (invalid)
                    std::fprintf(stderr, "# WARNING ML-DSA-%d %s batch %zu: %zu signatures do not verify\n", level,
                                 style.c_str(), n, invalid);
                bad += invalid;
            }
        }
    }
    cudaStreamDestroy(st);
    return bad;
}

} // namespace

int main(int argc, char** argv) {
    const double start = bench::now();
    const auto kem_levels = bench::parse_list(argc > 1 ? argv[1] : "512,768,1024");
    const auto dsa_levels = bench::parse_list(argc > 2 ? argv[2] : "44,65,87");
    const auto batches = bench::parse_list(argc > 3 ? argv[3] : "10,1");
    const int reps = argc > 4 ? std::atoi(argv[4]) : 50;
    const auto styles = parse_words(argc > 5 ? argv[5] : "example,app");
    if (*std::max_element(batches.begin(), batches.end()) > 1024) {
        std::fprintf(stderr, "batches of at most 1024\n");
        return 2;
    }
    CHECK_CUDA(cudaFree(nullptr));   // the CUDA context
    const double init = bench::now() - start;
    cudaDeviceProp prop;
    CHECK_CUDA(cudaGetDeviceProperties(&prop, 0));
    std::fprintf(stderr, "# cuPQC on %s\n", prop.name);
    std::printf("impl,scheme,level,style,batch,step,first_s,median_s,p10_s,p90_s,runs\n");
    const std::size_t nmax = *std::max_element(batches.begin(), batches.end());
    bool first = true;   // the init row: before the first parameter set
    const auto report_init = [&](const char* scheme, int level) {
        if (first) std::printf("%s,%s,%d,-,%zu,init,%.9g,,,,0\n", IMPL, scheme, level, nmax, init);
        first = false;
    };
    std::size_t bad = 0;
    for (const auto level : kem_levels) {
        if (level == 0) continue;
        report_init("ML-KEM", static_cast<int>(level));
        if (level == 512) bad += bench_kem<ML_KEM_512>(512, batches, reps, styles);
        else if (level == 768) bad += bench_kem<ML_KEM_768>(768, batches, reps, styles);
        else if (level == 1024) bad += bench_kem<ML_KEM_1024>(1024, batches, reps, styles);
    }
    for (const auto level : dsa_levels) {
        if (level == 0) continue;
        report_init("ML-DSA", static_cast<int>(level));
        if (level == 44) bad += bench_dsa<ML_DSA_44>(44, batches, reps, styles);
        else if (level == 65) bad += bench_dsa<ML_DSA_65>(65, batches, reps, styles);
        else if (level == 87) bad += bench_dsa<ML_DSA_87>(87, batches, reps, styles);
    }
    return bad ? 1 : 0;
}
