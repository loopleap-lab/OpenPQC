// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// openpqc/sycl.hpp  --  the GPU API (openpqc/sycl.h) in C++: one context per parameter set, host staging, results
//
//   #include <openpqc/openpqc.hpp>
//   #include <openpqc/sycl.hpp>
//   using KEM = openpqc::ML_KEM_768;
//
//   openpqc::sycl::Context<KEM> gpu{{.device = -1, .max_batch = 8192}};   // throws openpqc::error if it fails
//   std::vector<KEM::public_key> pk(n);  std::vector<KEM::secret_key> sk(n);
//   std::vector<KEM::ciphertext> ct(n);  std::vector<KEM::shared_secret> ss(n);
//   openpqc::check(gpu.keygen(pk, sk).status());   // host data: staged through page-locked memory and back
//   auto r = gpu.encaps(ct, ss, pk);                // r.ok(): the call and every operation; r[i]: operation i
//
//   // for pipelines: device memory in, an event out; buffers are overwritten with zeros when they are freed
//   openpqc::sycl::Buffer<KEM::public_key> d_pk{gpu, n};
//   openpqc::sycl::Buffer<KEM::secret_key> d_sk{gpu, n};
//   openpqc::sycl::Buffer<std::int32_t> d_status{gpu, n};
//   ::sycl::event done;
//   openpqc::check(gpu.keygen_async(d_pk, d_sk, d_status, &done));
//
// Context<Scheme> takes the schemes' types of openpqc/openpqc.hpp (openpqc::ML_KEM_768, openpqc::ML_DSA_65,
// openpqc::SLH_DSA_SHAKE_128f, ...): their alg, key, ciphertext, shared-secret and signature types. Everything
// openpqc/sycl.h says of the calls holds here (status, results, order of checks, threads, device failures).
//
//   Host calls (keygen, keygen_from_seed, encaps, decaps, sign, verify, sign_mu, verify_mu on spans of host memory): n
//   is the size of the spans, which must agree. They copy the inputs into page-locked memory of the context and on to
//   device memory, run the call, wait for it (sync), and copy the outputs back the same way; every staging buffer is
//   overwritten with zeros when it is freed, and the page-locked one keeps secrets out of the driver's staging buffers
//   for pageable memory. The result is a Results: the call's status (status()), the status of every operation
//   (operator[]), and ok() for "the call and every operation succeeded". An output of an operation whose status is not
//   status::ok is not a result (zeros, as openpqc/sycl.h says). The messages of sign and verify are spans of bytes, one
//   per operation, packed into one buffer: at a stride when they all have the same length (so the pre-hashes PH(M) of
//   SLH-DSA's pre-hash variants, opts->prehash, pass as openpqc/sycl.h asks), else with offsets.
//
//   Device calls (*_async, on Buffer<T>): queued on the context, as the C API's are; with `done`, an event that
//   completes when the call's work is done (openpqc_gpu_event: waiting for it does not report a device failure,
//   sync does). The messages are an openpqc_gpu_messages of device memory.
//
// The context is move-only: its destructor runs once, and destroy must not overlap another call
// (openpqc/sycl.h, Threads). Buffers must be freed (destroyed) before their context; a Buffer keeps a pointer to
// the context's handle, not to the Context object, so moving the Context does not invalidate it; release() frees a
// Buffer and reports whether its memory was overwritten (openpqc_gpu_free), which the destructor cannot. Constructors
// throw openpqc::error when the C API fails, if exceptions are enabled (otherwise check valid()). In this
// namespace the SYCL implementation's own names are written ::sycl:: (openpqc::sycl is this namespace).
#pragma once

#include <sycl/sycl.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#include "openpqc/common.hpp"
#include "openpqc/sycl.h"
#include "openpqc/sycl/interop.hpp"

namespace openpqc::sycl {

namespace detail {
template <class S>
concept kem = requires { typename S::ciphertext; typename S::shared_secret; };
template <class S>
concept signature_scheme = requires { typename S::signature; };
// ML-KEM and ML-DSA: the key pair of a stored seed (keygen_from_seed)
template <class S>
concept from_seed = requires { &S::keygen_from_seed; };
// ML-DSA: signing and verification of message representatives mu (external mu, FIPS 204, Algorithm 7, line 6)
template <class S>
concept external_mu = requires { typename S::message_representative; };
} // namespace detail

// n values of type T (a key, ciphertext, shared secret or signature type of a scheme, or std::int32_t for status
// entries, or std::uint8_t / std::uint64_t for messages and offsets) in device memory of a context
// (openpqc_gpu_malloc; host = true: page-locked host memory, openpqc_gpu_malloc_host), overwritten with zeros
// when freed. Move-only.
template <class T>
class Buffer {
public:
    static constexpr std::size_t value_bytes = sizeof(T);

    Buffer() noexcept = default;
    Buffer(openpqc_gpu* gpu, std::size_t n, bool host = false) : gpu_(gpu), n_(n) {
        if (n == 0) return;
        bytes_ = host ? openpqc_gpu_malloc_host(gpu, n * sizeof(T)) : openpqc_gpu_malloc(gpu, n * sizeof(T));
#if defined(__cpp_exceptions)
        if (!bytes_) throw openpqc::error(status::device_failure);
#endif
        if (!bytes_) n_ = 0;
    }
    template <class C>
        requires requires(C& c) { c.get(); }
    Buffer(C& context, std::size_t n, bool host = false) : Buffer(context.get(), n, host) {}
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
    Buffer(Buffer&& o) noexcept : gpu_(o.gpu_), bytes_(std::exchange(o.bytes_, nullptr)), n_(std::exchange(o.n_, 0)) {}
    Buffer& operator=(Buffer&& o) noexcept {
        if (this != &o) {
            reset();
            gpu_ = o.gpu_;
            bytes_ = std::exchange(o.bytes_, nullptr);
            n_ = std::exchange(o.n_, 0);
        }
        return *this;
    }
    ~Buffer() { reset(); }

    // Frees the memory (overwritten with zeros first: openpqc_gpu_free waits for the context's work). release
    // reports openpqc_gpu_free's result (status::device: the context has failed, and the memory may not have been
    // overwritten); reset and the destructor drop it.
    [[nodiscard]] status release() noexcept {
        const openpqc_status s = bytes_ ? openpqc_gpu_free(gpu_, bytes_) : OPENPQC_OK;
        bytes_ = nullptr;
        n_ = 0;
        return to_status(s);
    }
    void reset() noexcept { (void)release(); }

    [[nodiscard]] std::uint8_t* bytes() const noexcept { return static_cast<std::uint8_t*>(bytes_); }
    // Typed access for the types whose bytes are their value (status entries, messages, offsets)
    [[nodiscard]] T* data() const noexcept
        requires std::is_trivially_copyable_v<T>
    {
        return static_cast<T*>(bytes_);
    }
    [[nodiscard]] std::size_t size() const noexcept { return n_; }
    [[nodiscard]] std::size_t size_bytes() const noexcept { return n_ * sizeof(T); }
    [[nodiscard]] bool valid() const noexcept { return bytes_ != nullptr; }

    // Copies between the buffer and host memory of the same number of values, and waits
    [[nodiscard]] status copy_from(std::span<const T> host) const noexcept {
        if (host.size() != n_) return status::invalid_argument;
        return to_status(openpqc_gpu_memcpy(gpu_, bytes_, host.data(), size_bytes()));
    }
    [[nodiscard]] status copy_to(std::span<T> host) const noexcept {
        if (host.size() != n_) return status::invalid_argument;
        return to_status(openpqc_gpu_memcpy(gpu_, host.data(), bytes_, size_bytes()));
    }

private:
    openpqc_gpu* gpu_ = nullptr;
    void* bytes_ = nullptr;
    std::size_t n_ = 0;
};

// The result of a host call: the call's status and that of every operation
class Results {
public:
    Results() = default;
    Results(openpqc::status call, std::vector<std::int32_t> ops) : call_(call), ops_(std::move(ops)) {
        if (call_ != openpqc::status::ok) {
            for (std::int32_t& s : ops_) {
                if (s == OPENPQC_OK) s = OPENPQC_ERR_NOT_COMPUTED;   // nothing of a failed call is a result
            }
        }
    }

    // The call's own result (openpqc/sycl.h, Results of calls)
    [[nodiscard]] openpqc::status status() const noexcept { return call_; }
    // Operation i: status::ok if it has a result
    [[nodiscard]] openpqc::status operator[](std::size_t i) const noexcept {
        return static_cast<openpqc::status>(ops_[i]);
    }
    [[nodiscard]] std::size_t size() const noexcept { return ops_.size(); }
    // The call and every operation succeeded (for a verification: every signature is valid)
    [[nodiscard]] bool ok() const noexcept {
        if (call_ != openpqc::status::ok) return false;
        for (std::int32_t s : ops_) {
            if (s != OPENPQC_OK) return false;
        }
        return true;
    }
    [[nodiscard]] std::span<const std::int32_t> raw() const noexcept { return ops_; }

private:
    openpqc::status call_ = openpqc::status::not_computed;
    std::vector<std::int32_t> ops_;
};

template <class Scheme>
class Context {
public:
    using scheme = Scheme;
    static constexpr openpqc_alg alg = Scheme::alg;

    // On the device of cfg (openpqc_gpu_create)
    explicit Context(const openpqc_gpu_config& cfg = {-1, 0}) { init(openpqc_gpu_create(&gpu_, alg, &cfg)); }
    // On `dev` in the application's SYCL context `ctx` (openpqc_gpu_create_on): USM memory the application
    // allocated in ctx is memory of this context's
    Context(const ::sycl::context& ctx, const ::sycl::device& dev, std::size_t max_batch = 0) {
        init(openpqc_gpu_create_on(&gpu_, alg, max_batch, &ctx, &dev));
    }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&& o) noexcept : gpu_(std::exchange(o.gpu_, nullptr)), created_(o.created_) {}
    Context& operator=(Context&& o) noexcept {
        if (this != &o) {
            openpqc_gpu_destroy(gpu_);
            gpu_ = std::exchange(o.gpu_, nullptr);
            created_ = o.created_;
        }
        return *this;
    }
    ~Context() { openpqc_gpu_destroy(gpu_); }

    [[nodiscard]] openpqc_gpu* get() const noexcept { return gpu_; }
    [[nodiscard]] bool valid() const noexcept { return gpu_ != nullptr; }
    // Why the context does not exist (without exceptions): openpqc_gpu_create's result
    [[nodiscard]] status creation_status() const noexcept { return created_; }
    [[nodiscard]] const char* device_name() const noexcept { return openpqc_gpu_name(gpu_); }
    [[nodiscard]] std::size_t max_batch() const noexcept { return openpqc_gpu_max_batch(gpu_); }
    [[nodiscard]] status sync() noexcept { return to_status(openpqc_gpu_sync(gpu_)); }

    // ------------------------------------------------------------ device calls (openpqc/sycl.h)

    template <class PK, class SK>
    [[nodiscard]] status keygen_async(Buffer<PK>& pk, Buffer<SK>& sk, Buffer<std::int32_t>& st,
                                      ::sycl::event* done = nullptr) {
        if (pk.size() != sk.size() || st.size() != pk.size()) return status::invalid_argument;
        openpqc_status s;
        if constexpr (detail::kem<Scheme>) s = openpqc_gpu_kem_keygen(gpu_, pk.bytes(), sk.bytes(), st.data(), pk.size());
        else s = openpqc_gpu_sig_keygen(gpu_, pk.bytes(), sk.bytes(), st.data(), pk.size());
        return queued(s, done);
    }
    // seed: the stored seeds (Scheme::seed: ML-KEM d || z, ML-DSA xi), one per key pair
    template <class PK, class SK, class SEED>
        requires detail::from_seed<Scheme>
    [[nodiscard]] status keygen_from_seed_async(Buffer<PK>& pk, Buffer<SK>& sk, const Buffer<SEED>& seed,
                                                Buffer<std::int32_t>& st, ::sycl::event* done = nullptr) {
        static_assert(sizeof(SEED) == Scheme::seed_bytes, "seed: Scheme::seed");
        if (pk.size() != sk.size() || seed.size() != pk.size() || st.size() != pk.size())
            return status::invalid_argument;
        openpqc_status s;
        if constexpr (detail::kem<Scheme>)
            s = openpqc_gpu_kem_keygen_from_seed(gpu_, pk.bytes(), sk.bytes(), seed.bytes(), st.data(), pk.size());
        else s = openpqc_gpu_sig_keygen_from_seed(gpu_, pk.bytes(), sk.bytes(), seed.bytes(), st.data(), pk.size());
        return queued(s, done);
    }
    template <class CT, class SS, class PK>
        requires detail::kem<Scheme>
    [[nodiscard]] status encaps_async(Buffer<CT>& ct, Buffer<SS>& ss, const Buffer<PK>& pk, Buffer<std::int32_t>& st,
                                      ::sycl::event* done = nullptr) {
        if (ct.size() != pk.size() || ss.size() != pk.size() || st.size() != pk.size()) return status::invalid_argument;
        return queued(openpqc_gpu_kem_encaps(gpu_, ct.bytes(), ss.bytes(), pk.bytes(), st.data(), pk.size()), done);
    }
    template <class SS, class CT, class SK>
        requires detail::kem<Scheme>
    [[nodiscard]] status decaps_async(Buffer<SS>& ss, const Buffer<CT>& ct, const Buffer<SK>& sk,
                                      Buffer<std::int32_t>& st, ::sycl::event* done = nullptr) {
        if (ss.size() != ct.size() || sk.size() != ct.size() || st.size() != ct.size()) return status::invalid_argument;
        return queued(openpqc_gpu_kem_decaps(gpu_, ss.bytes(), ct.bytes(), sk.bytes(), st.data(), ct.size()), done);
    }
    // sk: one key per signature, or one key for all with OPENPQC_GPU_ONE_KEY in opts->flags
    template <class SIG, class SK>
        requires detail::signature_scheme<Scheme>
    [[nodiscard]] status sign_async(Buffer<SIG>& sig, const openpqc_gpu_messages& msgs, const openpqc_sign_opts* opts,
                                    const Buffer<SK>& sk, Buffer<std::int32_t>& st, ::sycl::event* done = nullptr) {
        if (st.size() != sig.size()) return status::invalid_argument;
        return queued(openpqc_gpu_sig_sign(gpu_, sig.bytes(), msgs, opts, sk.bytes(), st.data(), sig.size()), done);
    }
    template <class SIG, class PK>
        requires detail::signature_scheme<Scheme>
    [[nodiscard]] status verify_async(const Buffer<SIG>& sig, const openpqc_gpu_messages& msgs,
                                      const openpqc_sign_opts* opts, const Buffer<PK>& pk, Buffer<std::int32_t>& st,
                                      ::sycl::event* done = nullptr) {
        if (st.size() != sig.size()) return status::invalid_argument;
        return queued(openpqc_gpu_sig_verify(gpu_, sig.bytes(), msgs, opts, pk.bytes(), st.data(), sig.size()), done);
    }
    // External mu: mu[i] is the message representative of signature i (Scheme::message_representative); opts:
    // flags only (OPENPQC_SIGN_DETERMINISTIC, OPENPQC_GPU_ONE_KEY), as mu holds the context string
    template <class SIG, class MU, class SK>
        requires detail::external_mu<Scheme>
    [[nodiscard]] status sign_mu_async(Buffer<SIG>& sig, const Buffer<MU>& mu, const openpqc_sign_opts* opts,
                                       const Buffer<SK>& sk, Buffer<std::int32_t>& st, ::sycl::event* done = nullptr) {
        static_assert(sizeof(MU) == Scheme::mu_bytes, "mu: Scheme::message_representative");
        if (mu.size() != sig.size() || st.size() != sig.size()) return status::invalid_argument;
        return queued(openpqc_gpu_sig_sign_mu(gpu_, sig.bytes(), mu.bytes(), opts, sk.bytes(), st.data(), sig.size()),
                      done);
    }
    template <class SIG, class MU, class PK>
        requires detail::external_mu<Scheme>
    [[nodiscard]] status verify_mu_async(const Buffer<SIG>& sig, const Buffer<MU>& mu, const openpqc_sign_opts* opts,
                                         const Buffer<PK>& pk, Buffer<std::int32_t>& st,
                                         ::sycl::event* done = nullptr) {
        static_assert(sizeof(MU) == Scheme::mu_bytes, "mu: Scheme::message_representative");
        if (mu.size() != sig.size() || st.size() != sig.size()) return status::invalid_argument;
        return queued(openpqc_gpu_sig_verify_mu(gpu_, sig.bytes(), mu.bytes(), opts, pk.bytes(), st.data(), sig.size()),
                      done);
    }

    // ------------------------------------------------------------ host calls (staged, waited for)

    template <class PK, class SK>
    [[nodiscard]] Results keygen(std::span<PK> pk, std::span<SK> sk) {
        const std::size_t n = pk.size();
        if (sk.size() != n) return {status::invalid_argument, std::vector<std::int32_t>(n, OPENPQC_ERR_NOT_COMPUTED)};
        Staged d_pk(*this, n * sizeof(PK)), d_sk(*this, n * sizeof(SK));
        Buffer<std::int32_t> st(gpu_, n);
        openpqc_status s = staging_ok({&d_pk, &d_sk}, st, n);
        if (s == OPENPQC_OK) {
            if constexpr (detail::kem<Scheme>) s = openpqc_gpu_kem_keygen(gpu_, d_pk.dev(), d_sk.dev(), st.data(), n);
            else s = openpqc_gpu_sig_keygen(gpu_, d_pk.dev(), d_sk.dev(), st.data(), n);
        }
        s = finish(s);
        d_pk.download(pk.data(), s);
        d_sk.download(sk.data(), s);
        return results(s, st, n);
    }
    // The key pairs of stored seeds (Scheme::seed: ML-KEM d || z, ML-DSA xi), one per key pair
    template <class PK, class SK, class SEED>
        requires detail::from_seed<Scheme>
    [[nodiscard]] Results keygen_from_seed(std::span<PK> pk, std::span<SK> sk, std::span<const SEED> seed) {
        static_assert(sizeof(SEED) == Scheme::seed_bytes, "seed: Scheme::seed");
        const std::size_t n = pk.size();
        if (sk.size() != n || seed.size() != n)
            return {status::invalid_argument, std::vector<std::int32_t>(n, OPENPQC_ERR_NOT_COMPUTED)};
        Staged d_pk(*this, n * sizeof(PK)), d_sk(*this, n * sizeof(SK)), d_seed(*this, n * sizeof(SEED));
        Buffer<std::int32_t> st(gpu_, n);
        openpqc_status s = staging_ok({&d_pk, &d_sk, &d_seed}, st, n);
        if (s == OPENPQC_OK) s = d_seed.upload(seed.data());
        if (s == OPENPQC_OK) {
            if constexpr (detail::kem<Scheme>)
                s = openpqc_gpu_kem_keygen_from_seed(gpu_, d_pk.dev(), d_sk.dev(), d_seed.dev(), st.data(), n);
            else s = openpqc_gpu_sig_keygen_from_seed(gpu_, d_pk.dev(), d_sk.dev(), d_seed.dev(), st.data(), n);
        }
        s = finish(s);
        d_pk.download(pk.data(), s);
        d_sk.download(sk.data(), s);
        return results(s, st, n);
    }
    template <class CT, class SS, class PK>
        requires detail::kem<Scheme>
    [[nodiscard]] Results encaps(std::span<CT> ct, std::span<SS> ss, std::span<const PK> pk) {
        const std::size_t n = pk.size();
        if (ct.size() != n || ss.size() != n)
            return {status::invalid_argument, std::vector<std::int32_t>(n, OPENPQC_ERR_NOT_COMPUTED)};
        Staged d_ct(*this, n * sizeof(CT)), d_ss(*this, n * sizeof(SS)), d_pk(*this, n * sizeof(PK));
        Buffer<std::int32_t> st(gpu_, n);
        openpqc_status s = staging_ok({&d_ct, &d_ss, &d_pk}, st, n);
        if (s == OPENPQC_OK) s = d_pk.upload(pk.data());
        if (s == OPENPQC_OK) s = openpqc_gpu_kem_encaps(gpu_, d_ct.dev(), d_ss.dev(), d_pk.dev(), st.data(), n);
        s = finish(s);
        d_ct.download(ct.data(), s);
        d_ss.download(ss.data(), s);
        return results(s, st, n);
    }
    template <class SS, class CT, class SK>
        requires detail::kem<Scheme>
    [[nodiscard]] Results decaps(std::span<SS> ss, std::span<const CT> ct, std::span<const SK> sk) {
        const std::size_t n = ct.size();
        if (ss.size() != n || sk.size() != n)
            return {status::invalid_argument, std::vector<std::int32_t>(n, OPENPQC_ERR_NOT_COMPUTED)};
        Staged d_ss(*this, n * sizeof(SS)), d_ct(*this, n * sizeof(CT)), d_sk(*this, n * sizeof(SK));
        Buffer<std::int32_t> st(gpu_, n);
        openpqc_status s = staging_ok({&d_ss, &d_ct, &d_sk}, st, n);
        if (s == OPENPQC_OK) s = d_ct.upload(ct.data());
        if (s == OPENPQC_OK) s = d_sk.upload(sk.data());
        if (s == OPENPQC_OK) s = openpqc_gpu_kem_decaps(gpu_, d_ss.dev(), d_ct.dev(), d_sk.dev(), st.data(), n);
        s = finish(s);
        d_ss.download(ss.data(), s);
        return results(s, st, n);
    }
    // msgs[i] is the message of signature i; sk: one key per signature, or a single key for all with
    // OPENPQC_GPU_ONE_KEY in opts->flags
    template <class SIG, class SK>
        requires detail::signature_scheme<Scheme>
    [[nodiscard]] Results sign(std::span<SIG> sig, std::span<const std::span<const std::uint8_t>> msgs,
                               const openpqc_sign_opts* opts, std::span<const SK> sk) {
        const std::size_t n = sig.size();
        const bool one_key = opts && (opts->flags & OPENPQC_GPU_ONE_KEY);
        if (msgs.size() != n || sk.size() != (one_key ? 1 : n))
            return {status::invalid_argument, std::vector<std::int32_t>(n, OPENPQC_ERR_NOT_COMPUTED)};
        Staged d_sig(*this, n * sizeof(SIG)), d_sk(*this, sk.size() * sizeof(SK));
        Packed m(*this, msgs);
        Buffer<std::int32_t> st(gpu_, n);
        openpqc_status s = staging_ok({&d_sig, &d_sk, &m.data, &m.offsets}, st, n);
        if (s == OPENPQC_OK) s = d_sk.upload(sk.data());
        if (s == OPENPQC_OK) s = m.upload();
        if (s == OPENPQC_OK) s = openpqc_gpu_sig_sign(gpu_, d_sig.dev(), m.messages(), opts, d_sk.dev(), st.data(), n);
        s = finish(s);
        d_sig.download(sig.data(), s);
        return results(s, st, n);
    }
    template <class SIG, class PK>
        requires detail::signature_scheme<Scheme>
    [[nodiscard]] Results verify(std::span<const SIG> sig, std::span<const std::span<const std::uint8_t>> msgs,
                                 const openpqc_sign_opts* opts, std::span<const PK> pk) {
        const std::size_t n = sig.size();
        const bool one_key = opts && (opts->flags & OPENPQC_GPU_ONE_KEY);
        if (msgs.size() != n || pk.size() != (one_key ? 1 : n))
            return {status::invalid_argument, std::vector<std::int32_t>(n, OPENPQC_ERR_NOT_COMPUTED)};
        Staged d_sig(*this, n * sizeof(SIG)), d_pk(*this, pk.size() * sizeof(PK));
        Packed m(*this, msgs);
        Buffer<std::int32_t> st(gpu_, n);
        openpqc_status s = staging_ok({&d_sig, &d_pk, &m.data, &m.offsets}, st, n);
        if (s == OPENPQC_OK) s = d_sig.upload(sig.data());
        if (s == OPENPQC_OK) s = d_pk.upload(pk.data());
        if (s == OPENPQC_OK) s = m.upload();
        if (s == OPENPQC_OK) s = openpqc_gpu_sig_verify(gpu_, d_sig.dev(), m.messages(), opts, d_pk.dev(), st.data(), n);
        s = finish(s);
        return results(s, st, n);
    }
    // External mu (ML-DSA): mu[i] is the message representative of signature i; opts: flags only
    // (OPENPQC_SIGN_DETERMINISTIC, OPENPQC_GPU_ONE_KEY: then sk, or pk, is a single key)
    template <class SIG, class MU, class SK>
        requires detail::external_mu<Scheme>
    [[nodiscard]] Results sign_mu(std::span<SIG> sig, std::span<const MU> mu, const openpqc_sign_opts* opts,
                                  std::span<const SK> sk) {
        static_assert(sizeof(MU) == Scheme::mu_bytes, "mu: Scheme::message_representative");
        const std::size_t n = sig.size();
        const bool one_key = opts && (opts->flags & OPENPQC_GPU_ONE_KEY);
        if (mu.size() != n || sk.size() != (one_key ? 1 : n))
            return {status::invalid_argument, std::vector<std::int32_t>(n, OPENPQC_ERR_NOT_COMPUTED)};
        Staged d_sig(*this, n * sizeof(SIG)), d_mu(*this, n * sizeof(MU)), d_sk(*this, sk.size() * sizeof(SK));
        Buffer<std::int32_t> st(gpu_, n);
        openpqc_status s = staging_ok({&d_sig, &d_mu, &d_sk}, st, n);
        if (s == OPENPQC_OK) s = d_mu.upload(mu.data());
        if (s == OPENPQC_OK) s = d_sk.upload(sk.data());
        if (s == OPENPQC_OK) s = openpqc_gpu_sig_sign_mu(gpu_, d_sig.dev(), d_mu.dev(), opts, d_sk.dev(), st.data(), n);
        s = finish(s);
        d_sig.download(sig.data(), s);
        return results(s, st, n);
    }
    template <class SIG, class MU, class PK>
        requires detail::external_mu<Scheme>
    [[nodiscard]] Results verify_mu(std::span<const SIG> sig, std::span<const MU> mu, const openpqc_sign_opts* opts,
                                    std::span<const PK> pk) {
        static_assert(sizeof(MU) == Scheme::mu_bytes, "mu: Scheme::message_representative");
        const std::size_t n = sig.size();
        const bool one_key = opts && (opts->flags & OPENPQC_GPU_ONE_KEY);
        if (mu.size() != n || pk.size() != (one_key ? 1 : n))
            return {status::invalid_argument, std::vector<std::int32_t>(n, OPENPQC_ERR_NOT_COMPUTED)};
        Staged d_sig(*this, n * sizeof(SIG)), d_mu(*this, n * sizeof(MU)), d_pk(*this, pk.size() * sizeof(PK));
        Buffer<std::int32_t> st(gpu_, n);
        openpqc_status s = staging_ok({&d_sig, &d_mu, &d_pk}, st, n);
        if (s == OPENPQC_OK) s = d_sig.upload(sig.data());
        if (s == OPENPQC_OK) s = d_mu.upload(mu.data());
        if (s == OPENPQC_OK) s = d_pk.upload(pk.data());
        if (s == OPENPQC_OK)
            s = openpqc_gpu_sig_verify_mu(gpu_, d_sig.dev(), d_mu.dev(), opts, d_pk.dev(), st.data(), n);
        s = finish(s);
        return results(s, st, n);
    }

    // The same for containers (std::vector<KEM::public_key> and the like)
    template <class PKs, class SKs>
    [[nodiscard]] Results keygen(PKs& pk, SKs& sk) {
        return keygen(std::span(pk), std::span(sk));
    }
    template <class PKs, class SKs, class SEEDs>
        requires detail::from_seed<Scheme>
    [[nodiscard]] Results keygen_from_seed(PKs& pk, SKs& sk, const SEEDs& seed) {
        return keygen_from_seed(std::span(pk), std::span(sk), std::span(seed));
    }
    template <class CTs, class SSs, class PKs>
        requires detail::kem<Scheme>
    [[nodiscard]] Results encaps(CTs& ct, SSs& ss, const PKs& pk) {
        return encaps(std::span(ct), std::span(ss), std::span(pk));
    }
    template <class SSs, class CTs, class SKs>
        requires detail::kem<Scheme>
    [[nodiscard]] Results decaps(SSs& ss, const CTs& ct, const SKs& sk) {
        return decaps(std::span(ss), std::span(ct), std::span(sk));
    }

private:
    // A host call's buffer: device memory, and the page-locked host memory it is staged through
    class Staged {
    public:
        Staged(Context& c, std::size_t bytes) : gpu_(c.gpu_), bytes_(bytes) {
            if (bytes == 0) return;
            dev_ = static_cast<std::uint8_t*>(openpqc_gpu_malloc(gpu_, bytes));
            host_ = static_cast<std::uint8_t*>(openpqc_gpu_malloc_host(gpu_, bytes));
        }
        Staged(const Staged&) = delete;
        Staged& operator=(const Staged&) = delete;
        // a wipe that fails means the context has failed, which the call's result reports (finish: sync)
        ~Staged() {
            if (host_) (void)openpqc_gpu_free(gpu_, host_);
            if (dev_) (void)openpqc_gpu_free(gpu_, dev_);
        }
        [[nodiscard]] bool ok() const noexcept { return bytes_ == 0 || (dev_ && host_); }
        [[nodiscard]] std::uint8_t* dev() const noexcept { return dev_; }
        openpqc_status upload(const void* from) {
            if (bytes_ == 0) return OPENPQC_OK;
            std::memcpy(host_, from, bytes_);
            return openpqc_gpu_memcpy(gpu_, dev_, host_, bytes_);
        }
        // the outputs reach the caller only with a successful call (the device has zeroed them otherwise)
        void download(void* to, openpqc_status call) {
            if (bytes_ == 0) return;
            if (call == OPENPQC_OK && openpqc_gpu_memcpy(gpu_, host_, dev_, bytes_) == OPENPQC_OK)
                std::memcpy(to, host_, bytes_);
            else std::memset(to, 0, bytes_);
        }

    private:
        openpqc_gpu* gpu_;
        std::size_t bytes_;
        std::uint8_t* dev_ = nullptr;
        std::uint8_t* host_ = nullptr;
    };

    // The messages of a host call, packed back to back: at a stride when they all have the same length (which
    // SLH-DSA's pre-hash variants require of PH(M), openpqc/sycl.h, Messages), else with offsets
    struct Packed {
        bool strided;
        std::size_t stride;
        Staged data, offsets;
        std::vector<std::uint8_t> bytes;
        std::vector<std::uint64_t> offs;
        Packed(Context& c, std::span<const std::span<const std::uint8_t>> msgs)
            : strided(same_length(msgs)), stride(strided && !msgs.empty() ? msgs[0].size() : 0),
              data(c, std::max<std::size_t>(1, total(msgs))),
              offsets(c, strided ? 0 : (msgs.size() + 1) * sizeof(std::uint64_t)) {
            bytes.reserve(total(msgs));
            offs.reserve(msgs.size() + 1);
            offs.push_back(0);
            for (const auto& m : msgs) {
                bytes.insert(bytes.end(), m.begin(), m.end());
                offs.push_back(bytes.size());
            }
            bytes.resize(std::max<std::size_t>(1, bytes.size()));   // data is never NULL, even for empty messages
        }
        static std::size_t total(std::span<const std::span<const std::uint8_t>> msgs) {
            std::size_t t = 0;
            for (const auto& m : msgs) t += m.size();
            return t;
        }
        static bool same_length(std::span<const std::span<const std::uint8_t>> msgs) {
            for (const auto& m : msgs) {
                if (m.size() != msgs[0].size()) return false;
            }
            return true;
        }
        openpqc_status upload() {
            const openpqc_status s = data.upload(bytes.data());
            return s == OPENPQC_OK && !strided ? offsets.upload(offs.data()) : s;
        }
        [[nodiscard]] openpqc_gpu_messages messages() const noexcept {
            if (strided) return {data.dev(), nullptr, stride, offs.back()};
            return {data.dev(), reinterpret_cast<const std::uint64_t*>(offsets.dev()), 0, offs.back()};
        }
    };

    void init(openpqc_status s) {
        created_ = to_status(s);
#if defined(__cpp_exceptions)
        if (s != OPENPQC_OK) throw openpqc::error(created_);
#endif
    }
    // A host call whose staging memory could not be allocated fails as the device would (nothing is computed)
    openpqc_status staging_ok(std::initializer_list<const Staged*> staged, const Buffer<std::int32_t>& st,
                              std::size_t n) const {
        if (!gpu_) return OPENPQC_ERR_INVALID_ARGUMENT;
        if (n > 0 && !st.valid()) return OPENPQC_ERR_DEVICE;
        for (const Staged* p : staged) {
            if (!p->ok()) return OPENPQC_ERR_DEVICE;
        }
        return OPENPQC_OK;
    }
    // A host call ends when its work is done: its result, or the sync's
    openpqc_status finish(openpqc_status call) {
        const openpqc_status synced = gpu_ ? openpqc_gpu_sync(gpu_) : OPENPQC_ERR_INVALID_ARGUMENT;
        return call != OPENPQC_OK ? call : synced;
    }
    Results results(openpqc_status call, const Buffer<std::int32_t>& st, std::size_t n) {
        std::vector<std::int32_t> ops(n, OPENPQC_ERR_NOT_COMPUTED);
        if (n > 0 && st.valid() && openpqc_gpu_memcpy(gpu_, ops.data(), st.data(), n * sizeof(std::int32_t)) != OPENPQC_OK)
            std::fill(ops.begin(), ops.end(), OPENPQC_ERR_NOT_COMPUTED);
        return {to_status(call), std::move(ops)};
    }
    status queued(openpqc_status s, ::sycl::event* done) {
        if (s == OPENPQC_OK && done) s = openpqc_gpu_event(gpu_, done);
        return to_status(s);
    }

    openpqc_gpu* gpu_ = nullptr;
    status created_ = status::not_computed;
};

} // namespace openpqc::sycl
