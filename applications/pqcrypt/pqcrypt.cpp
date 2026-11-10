/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * pqcrypt.cpp  --  post-quantum file encryption (ML-KEM-768) and file signatures (ML-DSA-65)
 *
 * A small command-line tool for encrypting files to a recipient's public key and for signing
 * them, built from OpenPQC's ML-KEM (FIPS 203) and ML-DSA (FIPS 204):
 *
 *   pqcrypt keygen PREFIX                       PREFIX.kem.pk, PREFIX.kem.sk (ML-KEM-768) and
 *                                               PREFIX.sig.pk, PREFIX.sig.sk (ML-DSA-65)
 *   pqcrypt encrypt RECIPIENT.kem.pk IN OUT     encrypt IN for the holder of RECIPIENT.kem.sk
 *   pqcrypt decrypt RECIPIENT.kem.sk IN OUT
 *   pqcrypt sign SIGNER.sig.sk FILE SIGFILE
 *   pqcrypt verify SIGNER.sig.pk FILE SIGFILE
 *   pqcrypt selftest                            round trips and tampering cases, in memory
 *
 * File header. Every file pqcrypt writes starts with 8 bytes: the magic "PQCR", the format
 * version (1), the kind of file, and the parameter set as a 16-bit big-endian number:
 *
 *   kind  file                  set   after the header
 *   1     KEM public key        768   the encapsulation key ek (1184 bytes)
 *   2     KEM secret key        768   the seed d || z (64 bytes), SHA3-256(ek) (32 bytes)
 *   3     signature public key   65   pk (1952 bytes)
 *   4     signature secret key   65   the seed xi (32 bytes), SHA3-256(pk) (32 bytes)
 *   5     encrypted file        768   the ML-KEM ciphertext c (1088 bytes), then the chunks
 *   6     signature              65   sigma (3309 bytes)
 *
 * A file of another kind, version or parameter set, or of the wrong length, is rejected before
 * its contents are used, so that an encryption key passed where a verification key belongs, say,
 * gives an error message and not a meaningless result.
 *
 * Secret keys are stored as seeds: 64 bytes instead of the 2400-byte ML-KEM decapsulation key,
 * 32 instead of the 4032-byte ML-DSA private key. Each use expands the seed with keygen_from_seed
 * (ML-KEM.KeyGen_internal, ML-DSA.KeyGen_internal), which FIPS 203 (Section 3.3) and FIPS 204
 * (Section 3.6.3) allow for a seed stored in place of the private key. keygen draws the seeds
 * from the operating system (opqc_randombytes) and expands them in the same way, which is
 * exactly ML-KEM.KeyGen and ML-DSA.KeyGen. The hash of the public key next to
 * the seed turns a damaged seed into an error instead of a key that silently fails to decrypt.
 * keygen creates the secret key files with mode 0600 and never overwrites an existing file.
 *
 * Encryption is KEM-DEM. encrypt runs ML-KEM-768 Encaps against ek, giving c and the shared
 * secret K, and derives a file key
 *
 *   key = demo_kdf("pqcrypt v1 file key", K, header || c || ek).
 *
 * FIPS 203 computes K from m and H(ek) only (Kyber also hashed c into K; ML-KEM does not), so the
 * KDF takes c and ek explicitly: the key then belongs to this ciphertext and this recipient,
 * whatever binding properties one assumes of the KEM. The data is not read into memory but
 * processed in 64 KiB chunks, so that files of any size need a constant 200 KiB or so. Chunk i
 * is sealed with demo_seal under the nonce i (8 bytes, little-endian) || 0^7 || f, where f = 1
 * marks the last chunk: the STREAM construction (Hoang, Reyhanitabar, Rogaway and Vizar, 2015),
 * which age also uses. Chunks then cannot be reordered, dropped or appended without detection,
 * and a file cut at a chunk boundary fails because its new last chunk was not sealed as the
 * last. Each file has a fresh K, hence a fresh key, so a (key, nonce) pair never repeats. All
 * chunks but the last hold 65536 bytes; the last holds 0 to 65536 (an empty input is one empty
 * chunk). A wrong secret key is not detected by ML-KEM itself: Decaps then returns a pseudorandom
 * K (implicit rejection, FIPS 203 Algorithm 18), and the first chunk fails its tag. The file does
 * not name its recipient.
 *
 * Outputs appear only when complete. decrypt writes to a temporary file OUT.pqcrypt-XXXXXX next
 * to OUT and renames it to OUT only after the last chunk has been authenticated; on any failure
 * it removes the temporary file and leaves OUT as it was, so OUT never holds partial or
 * unauthenticated plaintext. encrypt and sign write their outputs in the same way. (A process
 * killed in the middle can leave the temporary file behind, never a partial OUT.) The new OUT
 * keeps the permission bits of the file it replaces, as cp onto an existing file does, and a new
 * one gets 0666 less the umask. It is a new file all the same: a symbolic link named OUT is
 * replaced rather than followed, and the owner is the user who runs pqcrypt.
 *
 * Files are read and written through unbuffered streams: a buffered stdio stream copies the data
 * into a buffer of its own, which fclose frees without zeroizing, and a seed or a piece of
 * plaintext would stay behind in freed memory. pqcrypt moves data in 64 KiB pieces, so the
 * buffer would save hardly any system calls.
 *
 * Signatures cover the file without holding it in memory. sign computes the message
 * representative mu of ML-DSA (FIPS 204, Algorithm 7, line 6) while reading the file:
 *
 *   tr = SHAKE256(pk, 64),  mu = SHAKE256(tr || M', 64),  M' = 0x00 || len(ctx) || ctx || file
 *
 * with M' formatted as pure ML-DSA does (Algorithm 2, line 10) and the context string
 * ctx = "pqcrypt file signature v1", then signs mu with sign_mu (hedged: fresh randomness each
 * time). verify computes mu the same way and calls verify_mu. The result is an ordinary
 * ML-DSA-65 signature of the file under ctx, which openpqc_mldsa65_verify accepts on the whole
 * file; selftest checks this and that the streamed mu equals openpqc_mldsa65_external_mu.
 *
 * All symmetric cryptography is demo_sym.h (a SHAKE256 KDF and an encrypt-then-MAC construction
 * from SHAKE256): a demo construction, not a standardized AEAD. pqcrypt is a demonstration, not
 * a reviewed tool: a real one would use AES-256-GCM or ChaCha20-Poly1305 with HKDF, and a hybrid
 * KEM (ML-KEM-768 with X25519, as X-Wing or TLS 1.3's X25519MLKEM768) so that the files stay
 * protected if either algorithm is broken. POSIX only (mkstemp, fchmod, fsync, rename).
 *
 * Each command prints a line or two (sizes, time); errors go to stderr. selftest prints one line
 * per check. Exit code: 0 if the command succeeded (verify: the signature is valid; selftest:
 * every check gave the expected result, the expected rejections included), 1 if it failed,
 * 2 for a usage error.
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "Core/openpqc_core.h"
#include "Core/xof.hpp"
#include "Core/zeroize.hpp"
#include "demo_sym.h"
#include "openpqc/openpqc.hpp"

namespace {

using KEM = openpqc::ML_KEM_768;
using DSA = openpqc::ML_DSA_65;
using Bytes = std::vector<std::uint8_t>;
using ByteSpan = std::span<const std::uint8_t>;
using Clock = std::chrono::steady_clock;

constexpr std::size_t chunk_bytes = 64 * 1024;  // plaintext per chunk
constexpr std::size_t sealed_chunk_bytes = chunk_bytes + DEMO_TAG_BYTES;
constexpr std::string_view signature_context = "pqcrypt file signature v1";
constexpr const char* file_key_label = "pqcrypt v1 file key";

ByteSpan text_bytes(std::string_view s) { return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()}; }

double ms_since(Clock::time_point t0) { return std::chrono::duration<double, std::milli>(Clock::now() - t0).count(); }

unsigned long long ull(std::uint64_t x) { return static_cast<unsigned long long>(x); }

// "1 chunk", "4 chunks"
std::string count(std::uint64_t n, const char* noun) {
    return std::to_string(n) + " " + noun + (n == 1 ? "" : "s");
}

// --- results -------------------------------------------------------------------------------------

// The result of an operation: success, or a description of what failed
class [[nodiscard]] Status {
public:
    Status() = default;
    static Status failure(std::string what) {
        Status s;
        s.error_ = std::move(what);
        return s;
    }
    explicit operator bool() const { return error_.empty(); }
    const std::string& error() const { return error_; }

private:
    std::string error_;
};

Status fail(std::string what) { return Status::failure(std::move(what)); }

// `what`: the text of errno (call right after the failing system call)
std::string sys_error(const std::string& what) { return what + ": " + std::strerror(errno); }

// A byte vector that is zeroized when destroyed (key files that hold a seed, plaintext)
struct SecretBytes {
    Bytes v;
    ~SecretBytes() { opqc_zeroize(v.data(), v.size()); }
};

Bytes concat(std::initializer_list<ByteSpan> parts) {
    std::size_t n = 0;
    for (auto p : parts) n += p.size();
    Bytes out;
    out.reserve(n);  // one allocation: no copy of a secret is left in a freed buffer
    for (auto p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// --- keys ----------------------------------------------------------------------------------------

// The seeds and private keys are openpqc::secret<N>: not copyable, zeroized when destroyed
using KemSeed = KEM::seed;                  // d || z
using SigSeed = DSA::seed;                  // xi
using Hash = std::array<std::uint8_t, 32>;  // SHA3-256

Hash sha3_256(ByteSpan data) {
    Hash h;
    opqc_sha3_256(h.data(), data.data(), data.size());
    return h;
}

// An expanded key pair; the secret key is an openpqc::secret, so it exists once and is zeroized
struct KemKeys {
    KEM::public_key pk{};
    KEM::secret_key sk;
};

struct SigKeys {
    DSA::public_key pk{};
    DSA::secret_key sk;
};

// ML-KEM.KeyGen_internal(d, z) and ML-DSA.KeyGen_internal(xi): the key pair of a stored seed
Status expand(const KemSeed& seed, KemKeys& keys) {
    if (const openpqc::status s = KEM::keygen_from_seed(keys.pk, keys.sk, seed); s != openpqc::status::ok) {
        return fail(std::string("ML-KEM-768 KeyGen_internal failed (") + openpqc::to_string(s) + ")");
    }
    return {};
}

Status expand(const SigSeed& seed, SigKeys& keys) {
    if (const openpqc::status s = DSA::keygen_from_seed(keys.pk, keys.sk, seed); s != openpqc::status::ok) {
        return fail(std::string("ML-DSA-65 KeyGen_internal failed (") + openpqc::to_string(s) + ")");
    }
    return {};
}

// Both key pairs of one user, with their seeds
struct Party {
    KemSeed kem_seed;
    SigSeed sig_seed;
    KemKeys kem;
    SigKeys sig;
};

// ML-KEM.KeyGen and ML-DSA.KeyGen: fresh seeds from the operating system, then expanded
Status new_party(Party& p) {
    if (opqc_randombytes(p.kem_seed.data(), p.kem_seed.size()) != 0 ||
        opqc_randombytes(p.sig_seed.data(), p.sig_seed.size()) != 0) {
        return fail("no randomness from the operating system");
    }
    if (auto s = expand(p.kem_seed, p.kem); !s) return s;
    return expand(p.sig_seed, p.sig);
}

// --- file format ---------------------------------------------------------------------------------

constexpr std::array<std::uint8_t, 4> magic = {'P', 'Q', 'C', 'R'};
constexpr std::uint8_t format_version = 1;
constexpr std::size_t header_bytes = 8;
using Header = std::array<std::uint8_t, header_bytes>;

enum class Kind : std::uint8_t { kem_public = 1, kem_secret, sig_public, sig_secret, encrypted, signature };
constexpr std::uint8_t kind_count = 6;

struct KindInfo {
    unsigned parameter_set;  // 768: ML-KEM-768, 65: ML-DSA-65
    std::size_t body_bytes;  // after the header; 0 for any length
    const char* name;
};

KindInfo info(Kind k) {
    switch (k) {
        case Kind::kem_public: return {768, KEM::public_key_bytes, "an ML-KEM-768 public key"};
        case Kind::kem_secret: return {768, KEM::seed_bytes + Hash().size(), "an ML-KEM-768 secret key"};
        case Kind::sig_public: return {65, DSA::public_key_bytes, "an ML-DSA-65 public key"};
        case Kind::sig_secret: return {65, DSA::seed_bytes + Hash().size(), "an ML-DSA-65 secret key"};
        case Kind::encrypted: return {768, 0, "a pqcrypt encrypted file"};
        case Kind::signature: return {65, DSA::signature_bytes, "an ML-DSA-65 signature"};
    }
    return {0, 0, "an unknown kind of file"};
}

Header make_header(Kind k) {
    const unsigned set = info(k).parameter_set;
    return {magic[0], magic[1], magic[2], magic[3], format_version, static_cast<std::uint8_t>(k),
            static_cast<std::uint8_t>(set >> 8), static_cast<std::uint8_t>(set & 0xff)};
}

// Checks that `file` starts with the header of `expected` (magic, version, kind, parameter set)
Status check_kind(ByteSpan file, Kind expected, std::string_view name) {
    const std::string n(name);
    if (file.size() < header_bytes || !std::equal(magic.begin(), magic.end(), file.begin())) {
        return fail(n + ": not a pqcrypt file");
    }
    if (file[4] != format_version) {
        return fail(n + ": pqcrypt format version " + std::to_string(file[4]) + "; this program reads version " +
                    std::to_string(format_version));
    }
    if (file[5] < 1 || file[5] > kind_count) {
        return fail(n + ": unknown kind of pqcrypt file (" + std::to_string(file[5]) + ")");
    }
    const Kind kind = static_cast<Kind>(file[5]);
    const KindInfo want = info(expected);
    if (kind != expected) return fail(n + " is " + info(kind).name + ", not " + want.name);
    const unsigned set = static_cast<unsigned>(file[6]) << 8 | static_cast<unsigned>(file[7]);
    if (set != want.parameter_set) {
        return fail(n + ": parameter set " + std::to_string(set) + ", expected " + std::to_string(want.parameter_set));
    }
    return {};
}

// check_kind, and for the kinds of fixed size the length of the file (for an encrypted file,
// `file` is the header only)
Status check_header(ByteSpan file, Kind expected, std::string_view name) {
    if (auto s = check_kind(file, expected, name); !s) return s;
    const KindInfo want = info(expected);
    const std::string n(name);
    if (want.body_bytes != 0 && file.size() != header_bytes + want.body_bytes) {
        return fail(n + ": " + std::to_string(file.size()) + " bytes, but " + want.name + " file has " +
                    std::to_string(header_bytes + want.body_bytes));
    }
    return {};
}

Bytes kem_public_file(const KEM::public_key& pk) { return concat({make_header(Kind::kem_public), pk}); }
Bytes sig_public_file(const DSA::public_key& pk) { return concat({make_header(Kind::sig_public), pk}); }
Bytes signature_file(const DSA::signature& sig) { return concat({make_header(Kind::signature), sig}); }
Bytes kem_secret_file(const KemSeed& seed, const KEM::public_key& pk) {
    return concat({make_header(Kind::kem_secret), seed, sha3_256(pk)});
}
Bytes sig_secret_file(const SigSeed& seed, const DSA::public_key& pk) {
    return concat({make_header(Kind::sig_secret), seed, sha3_256(pk)});
}

Status check_pk_hash(ByteSpan pk, ByteSpan stored, std::string_view name) {
    if (!std::ranges::equal(sha3_256(pk), stored)) {
        return fail(std::string(name) + ": damaged: the seed does not give the public key whose hash is stored");
    }
    return {};
}

Status parse_kem_public(ByteSpan file, std::string_view name, KEM::public_key& pk) {
    if (auto s = check_header(file, Kind::kem_public, name); !s) return s;
    std::ranges::copy(file.subspan(header_bytes), pk.begin());
    return {};
}

Status parse_sig_public(ByteSpan file, std::string_view name, DSA::public_key& pk) {
    if (auto s = check_header(file, Kind::sig_public, name); !s) return s;
    std::ranges::copy(file.subspan(header_bytes), pk.begin());
    return {};
}

Status parse_signature(ByteSpan file, std::string_view name, DSA::signature& sig) {
    if (auto s = check_header(file, Kind::signature, name); !s) return s;
    std::ranges::copy(file.subspan(header_bytes), sig.begin());
    return {};
}

Status parse_kem_secret(ByteSpan file, std::string_view name, KemKeys& keys) {
    if (auto s = check_header(file, Kind::kem_secret, name); !s) return s;
    const ByteSpan body = file.subspan(header_bytes);
    KemSeed seed;
    std::ranges::copy(body.first(seed.size()), seed.begin());
    if (auto s = expand(seed, keys); !s) return s;
    return check_pk_hash(keys.pk, body.subspan(seed.size()), name);
}

Status parse_sig_secret(ByteSpan file, std::string_view name, SigKeys& keys) {
    if (auto s = check_header(file, Kind::sig_secret, name); !s) return s;
    const ByteSpan body = file.subspan(header_bytes);
    SigSeed seed;
    std::ranges::copy(body.first(seed.size()), seed.begin());
    if (auto s = expand(seed, keys); !s) return s;
    return check_pk_hash(keys.pk, body.subspan(seed.size()), name);
}

// --- input and output ----------------------------------------------------------------------------

// fopen with an unbuffered stream, so that fread and fwrite move the data between the file and
// the caller's buffer directly (see the header comment); setvbuf must come before any other use
std::FILE* open_unbuffered(const char* path, const char* mode) {
    std::FILE* f = std::fopen(path, mode);
    if (f != nullptr && std::setvbuf(f, nullptr, _IONBF, 0) != 0) {
        std::fclose(f);
        errno = EINVAL;
        return nullptr;
    }
    return f;
}

// A source of bytes: a file, or memory in the self-test
class Input {
public:
    virtual ~Input() = default;
    // Reads buf.size() bytes, or fewer at the end of the input; `got` is the number read
    virtual Status read(std::span<std::uint8_t> buf, std::size_t& got) = 0;
};

class FileInput final : public Input {
public:
    explicit FileInput(std::string path) : path_(std::move(path)) {}
    FileInput(const FileInput&) = delete;
    FileInput& operator=(const FileInput&) = delete;
    ~FileInput() override {
        if (f_ != nullptr) std::fclose(f_);
    }
    Status open() {
        f_ = open_unbuffered(path_.c_str(), "rb");
        if (f_ == nullptr) return fail(sys_error("cannot open " + path_));
        return {};
    }
    Status read(std::span<std::uint8_t> buf, std::size_t& got) override {
        got = buf.empty() ? 0 : std::fread(buf.data(), 1, buf.size(), f_);
        if (std::ferror(f_) != 0) return fail(sys_error("cannot read " + path_));
        return {};
    }

private:
    std::string path_;
    std::FILE* f_ = nullptr;
};

class MemoryInput final : public Input {
public:
    explicit MemoryInput(ByteSpan data) : data_(data) {}
    Status read(std::span<std::uint8_t> buf, std::size_t& got) override {
        got = std::min(buf.size(), data_.size() - pos_);
        if (got > 0) std::memcpy(buf.data(), data_.data() + pos_, got);
        pos_ += got;
        return {};
    }

private:
    ByteSpan data_;
    std::size_t pos_ = 0;
};

class Output {
public:
    virtual ~Output() = default;
    virtual Status write(ByteSpan data) = 0;
};

class MemoryOutput final : public Output {
public:
    Status write(ByteSpan data) override {
        bytes.insert(bytes.end(), data.begin(), data.end());
        return {};
    }
    Bytes bytes;
};

// An output file that appears under its name only when complete: the data goes to a temporary
// file in the same directory, which commit() renames to `path` (replacing a file of that name,
// whose permission bits it takes). If commit() is not reached, the destructor removes the
// temporary file.
class AtomicFile final : public Output {
public:
    explicit AtomicFile(std::string path) : path_(std::move(path)), tmp_(path_ + ".pqcrypt-XXXXXX") {}
    AtomicFile(const AtomicFile&) = delete;
    AtomicFile& operator=(const AtomicFile&) = delete;
    ~AtomicFile() override {
        if (f_ != nullptr) std::fclose(f_);
        if (created_ && !committed_) ::unlink(tmp_.c_str());
    }

    Status open() {
        // The permission bits of the regular file being replaced, as cp or a shell redirection
        // onto an existing file keep them (only those: a set-user-ID bit, say, should not pass
        // to decrypted data); for a new file 0666 less the umask, as cp and the shell give.
        mode_t mode = 0;
        struct stat st {};
        if (::stat(path_.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            mode = static_cast<mode_t>(st.st_mode & 0777);
        } else {
            const mode_t mask = ::umask(0);
            ::umask(mask);
            mode = static_cast<mode_t>(0666 & ~mask);
        }
        const int fd = ::mkstemp(tmp_.data());  // created with mode 0600
        if (fd < 0) return fail(sys_error("cannot create a temporary file for " + path_));
        created_ = true;
        if (::fchmod(fd, mode) != 0 || (f_ = ::fdopen(fd, "wb")) == nullptr) {
            const std::string e = sys_error("cannot set up " + tmp_);
            ::close(fd);
            return fail(e);
        }
        if (std::setvbuf(f_, nullptr, _IONBF, 0) != 0) return fail("cannot set up " + tmp_ + ": setvbuf failed");
        return {};
    }
    Status write(ByteSpan data) override {
        if (!data.empty() && std::fwrite(data.data(), 1, data.size(), f_) != data.size()) {
            return fail(sys_error("cannot write " + tmp_));
        }
        return {};
    }
    Status commit() {
        bool ok = std::fflush(f_) == 0 && ::fsync(::fileno(f_)) == 0;
        std::string e = ok ? "" : sys_error("cannot write " + tmp_);
        if (std::fclose(f_) != 0 && ok) {
            ok = false;
            e = sys_error("cannot write " + tmp_);
        }
        f_ = nullptr;
        if (!ok) return fail(e);
        if (std::rename(tmp_.c_str(), path_.c_str()) != 0) {
            return fail(sys_error("cannot rename " + tmp_ + " to " + path_));
        }
        committed_ = true;
        return {};
    }

private:
    std::string path_, tmp_;
    std::FILE* f_ = nullptr;
    bool created_ = false, committed_ = false;
};

// Creates `path`, which must not exist yet, with permissions `mode` (less the umask) and the
// contents `data`; `got_mode` is the mode the file has. O_EXCL makes the no-overwrite rule exact,
// and a secret key file is never readable by others, not even while it is being written.
Status write_new_file(const std::string& path, ByteSpan data, mode_t mode, unsigned& got_mode) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) return fail(sys_error("cannot create " + path));
    bool ok = true;
    for (std::size_t done = 0; ok && done < data.size();) {
        const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n < 0 && errno == EINTR) continue;
        ok = n > 0;
        if (ok) done += static_cast<std::size_t>(n);
    }
    struct stat st {};
    ok = ok && ::fsync(fd) == 0 && ::fstat(fd, &st) == 0;
    std::string e = ok ? "" : sys_error("cannot write " + path);
    if (::close(fd) != 0 && ok) {
        ok = false;
        e = sys_error("cannot write " + path);
    }
    if (!ok) {
        ::unlink(path.c_str());
        return fail(e);
    }
    got_mode = static_cast<unsigned>(st.st_mode & 07777);
    return {};
}

// The contents of a key or signature file, all of which are smaller than 4 KiB; zeroized when
// destroyed, as they may be a seed. read_small_file reads them unbuffered, so that this is the
// only copy.
struct SmallFile {
    std::array<std::uint8_t, 4096> data{};
    std::size_t size = 0;
    ByteSpan bytes() const { return {data.data(), size}; }
    ~SmallFile() { opqc_zeroize(data.data(), data.size()); }
};

// Reads a file that should be of kind `kind`; a longer file is rejected after its header has been
// checked, so that the message names the kind of a pqcrypt file given in the wrong place
Status read_small_file(const std::string& path, Kind kind, SmallFile& out) {
    std::FILE* f = open_unbuffered(path.c_str(), "rb");
    if (f == nullptr) return fail(sys_error("cannot open " + path));
    out.size = std::fread(out.data.data(), 1, out.data.size(), f);
    const std::string error = std::ferror(f) != 0 ? sys_error("cannot read " + path) : "";
    std::fclose(f);
    if (!error.empty()) return fail(error);
    if (out.size == out.data.size()) {
        if (auto s = check_kind(out.bytes(), kind, path); !s) return s;
        return fail(path + ": too large for " + info(kind).name + " file");
    }
    return {};
}

// Reads an input in pieces of `size` bytes, one piece ahead, so that it knows which piece is the
// last: the first one shorter than `size`, or a full one at the end of the input. An empty input
// is a single empty last piece.
class Chunker {
public:
    Chunker(Input& in, std::size_t size) : in_(in), cur_(size), next_(size) {}
    Chunker(const Chunker&) = delete;
    Chunker& operator=(const Chunker&) = delete;
    ~Chunker() {  // the pieces may be plaintext
        opqc_zeroize(cur_.data(), cur_.size());
        opqc_zeroize(next_.data(), next_.size());
    }

    // The next piece; not to be called again after the last
    Status next(ByteSpan& piece, bool& last) {
        if (!started_) {
            started_ = true;
            if (auto s = in_.read(cur_, cur_len_); !s) return s;
        } else {
            std::swap(cur_, next_);
            cur_len_ = next_len_;
        }
        last = cur_len_ < cur_.size();
        if (!last) {
            if (auto s = in_.read(next_, next_len_); !s) return s;
            last = next_len_ == 0;
        }
        piece = ByteSpan(cur_.data(), cur_len_);
        return {};
    }

private:
    Input& in_;
    Bytes cur_, next_;
    std::size_t cur_len_ = 0, next_len_ = 0;
    bool started_ = false;
};

// --- encryption ----------------------------------------------------------------------------------

using FileKey = std::array<std::uint8_t, DEMO_KEY_BYTES>;
using Nonce = std::array<std::uint8_t, DEMO_NONCE_BYTES>;

struct StreamStats {
    std::uint64_t bytes = 0;  // plaintext
    std::uint64_t chunks = 0;
};

std::uint64_t encrypted_size(const StreamStats& st) {
    return header_bytes + KEM::ciphertext_bytes + st.bytes + DEMO_TAG_BYTES * st.chunks;
}

// key = demo_kdf("pqcrypt v1 file key", K, header || c || ek); all three have fixed lengths
void derive_file_key(FileKey& key, const KEM::shared_secret& K, const Header& header, const KEM::ciphertext& c,
                     const KEM::public_key& ek) {
    std::array<std::uint8_t, header_bytes + KEM::ciphertext_bytes + KEM::public_key_bytes> kdf_info;
    auto it = std::ranges::copy(header, kdf_info.begin()).out;
    it = std::ranges::copy(c, it).out;
    std::ranges::copy(ek, it);
    demo_kdf(key.data(), key.size(), file_key_label, K.data(), K.size(), kdf_info.data(), kdf_info.size());
}

// STREAM: the chunk index, then the last-chunk flag in the final byte
Nonce chunk_nonce(std::uint64_t index, bool last) {
    Nonce n{};
    for (unsigned i = 0; i < 8; i++) n[i] = static_cast<std::uint8_t>(index >> (8 * i));
    n[DEMO_NONCE_BYTES - 1] = static_cast<std::uint8_t>(last ? 1 : 0);
    return n;
}

Status encrypt_stream(const KEM::public_key& ek, Input& in, Output& out, StreamStats& st) {
    KEM::ciphertext c;
    KEM::shared_secret K;  // an openpqc::secret, zeroized when destroyed
    FileKey key;
    openpqc::ZeroizeOnExit wipe{key};
    if (const openpqc::status s = KEM::encaps(c, K, ek); s != openpqc::status::ok) {
        return fail(s == openpqc::status::invalid_public_key
                        ? "the recipient key fails the ML-KEM-768 encapsulation key check (FIPS 203, Section 7.2)"
                        : std::string("ML-KEM-768 Encaps failed (") + openpqc::to_string(s) + ")");
    }
    const Header header = make_header(Kind::encrypted);
    derive_file_key(key, K, header, c, ek);
    if (auto s = out.write(header); !s) return s;
    if (auto s = out.write(c); !s) return s;

    Chunker chunks(in, chunk_bytes);
    Bytes sealed(sealed_chunk_bytes);
    for (std::uint64_t i = 0;; i++) {
        ByteSpan piece;
        bool last = false;
        if (auto s = chunks.next(piece, last); !s) return s;
        const Nonce nonce = chunk_nonce(i, last);
        demo_seal(sealed.data(), key.data(), nonce.data(), nullptr, 0, piece.data(), piece.size());
        if (auto s = out.write(ByteSpan(sealed).first(piece.size() + DEMO_TAG_BYTES)); !s) return s;
        st.bytes += piece.size();
        st.chunks++;
        if (last) return {};
    }
}

// Writes the plaintext of each chunk once its tag has been checked; the caller releases the
// output only if the whole stream decrypts (see AtomicFile)
Status decrypt_stream(const KemKeys& keys, Input& in, std::string_view name, Output& out, StreamStats& st) {
    const std::string n(name);
    Header header;
    std::size_t got = 0;
    if (auto s = in.read(header, got); !s) return s;
    if (auto s = check_header(ByteSpan(header).first(got), Kind::encrypted, name); !s) return s;
    KEM::ciphertext c;
    if (auto s = in.read(c, got); !s) return s;
    if (got != c.size()) return fail(n + ": truncated: no complete ML-KEM ciphertext");

    KEM::shared_secret K;
    FileKey key;
    openpqc::ZeroizeOnExit wipe{key};
    // a wrong key or a modified c gives no error here, but a pseudorandom K (implicit rejection)
    if (const openpqc::status s = KEM::decaps(K, c, keys.sk); s != openpqc::status::ok) {
        return fail(std::string("ML-KEM-768 Decaps failed (") + openpqc::to_string(s) + ")");
    }
    derive_file_key(key, K, header, c, keys.pk);

    Chunker chunks(in, sealed_chunk_bytes);
    SecretBytes plain{Bytes(chunk_bytes)};
    for (std::uint64_t i = 0;; i++) {
        ByteSpan piece;
        bool last = false;
        if (auto s = chunks.next(piece, last); !s) return s;
        if (piece.size() < DEMO_TAG_BYTES) {
            return fail(n + ": truncated: chunk " + std::to_string(i) + " is shorter than a tag");
        }
        const Nonce nonce = chunk_nonce(i, last);
        if (demo_open(plain.v.data(), key.data(), nonce.data(), nullptr, 0, piece.data(), piece.size()) != 0) {
            return fail(n + ": chunk " + std::to_string(i) + " failed authentication");
        }
        if (auto s = out.write(ByteSpan(plain.v).first(piece.size() - DEMO_TAG_BYTES)); !s) return s;
        st.bytes += piece.size() - DEMO_TAG_BYTES;
        st.chunks++;
        if (last) return {};
    }
}

// --- signatures ----------------------------------------------------------------------------------

// The message representative of FIPS 204, Algorithm 7, line 6, for the message read from `in`:
//   mu = SHAKE256(tr || M', 64),  tr = SHAKE256(pk, 64),  M' = 0x00 || len(ctx) || ctx || message
// absorbed in pieces as it is read, so only one buffer of the message is in memory
Status streamed_mu(DSA::message_representative& mu, const DSA::public_key& pk, ByteSpan ctx, Input& in,
                   std::uint64_t& bytes, std::uint64_t& reads) {
    if (ctx.size() > 255) return fail("context string longer than 255 bytes");
    std::array<std::uint8_t, 64> tr;
    openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, tr, {pk});
    auto h = openpqc::Xof::shake256();
    const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};  // pure ML-DSA
    h.absorb(tr);
    h.absorb(domain);
    h.absorb(ctx);
    Bytes buf(chunk_bytes);
    bytes = reads = 0;
    for (;;) {
        std::size_t got = 0;
        if (auto s = in.read(buf, got); !s) return s;
        h.absorb(ByteSpan(buf).first(got));
        bytes += got;
        reads++;
        if (got < buf.size()) break;
    }
    h.squeeze(mu);
    return {};
}

Status sign_stream(const SigKeys& keys, Input& in, DSA::signature& sig, std::uint64_t& bytes) {
    DSA::message_representative mu;
    std::uint64_t reads = 0;
    if (auto s = streamed_mu(mu, keys.pk, text_bytes(signature_context), in, bytes, reads); !s) return s;
    if (const openpqc::status s = DSA::sign_mu(sig, mu, keys.sk); s != openpqc::status::ok) {
        return fail(std::string("ML-DSA-65 Sign (from mu) failed (") + openpqc::to_string(s) + ")");
    }
    return {};
}

// `valid` is the result of the verification; the Status reports read errors
Status verify_stream(const DSA::public_key& pk, Input& in, ByteSpan sig, std::uint64_t& bytes, bool& valid) {
    DSA::message_representative mu;
    std::uint64_t reads = 0;
    if (auto s = streamed_mu(mu, pk, text_bytes(signature_context), in, bytes, reads); !s) return s;
    const openpqc::status s = DSA::verify_mu(sig, mu, pk);
    if (s != openpqc::status::ok && s != openpqc::status::invalid_signature) {
        return fail(std::string("ML-DSA-65 Verify (from mu) failed (") + openpqc::to_string(s) + ")");
    }
    valid = s == openpqc::status::ok;
    return {};
}

// --- commands ------------------------------------------------------------------------------------

Status load_kem_public(const std::string& path, KEM::public_key& pk) {
    SmallFile f;
    if (auto s = read_small_file(path, Kind::kem_public, f); !s) return s;
    return parse_kem_public(f.bytes(), path, pk);
}

Status load_kem_secret(const std::string& path, KemKeys& keys) {
    SmallFile f;
    if (auto s = read_small_file(path, Kind::kem_secret, f); !s) return s;
    return parse_kem_secret(f.bytes(), path, keys);
}

Status load_sig_public(const std::string& path, DSA::public_key& pk) {
    SmallFile f;
    if (auto s = read_small_file(path, Kind::sig_public, f); !s) return s;
    return parse_sig_public(f.bytes(), path, pk);
}

Status load_sig_secret(const std::string& path, SigKeys& keys) {
    SmallFile f;
    if (auto s = read_small_file(path, Kind::sig_secret, f); !s) return s;
    return parse_sig_secret(f.bytes(), path, keys);
}

Status load_signature(const std::string& path, DSA::signature& sig) {
    SmallFile f;
    if (auto s = read_small_file(path, Kind::signature, f); !s) return s;
    return parse_signature(f.bytes(), path, sig);
}

Status cmd_keygen(const std::string& prefix) {
    Party p;
    if (auto s = new_party(p); !s) return s;
    const SecretBytes kem_sk{kem_secret_file(p.kem_seed, p.kem.pk)};
    const SecretBytes sig_sk{sig_secret_file(p.sig_seed, p.sig.pk)};
    const Bytes kem_pk = kem_public_file(p.kem.pk);
    const Bytes sig_pk = sig_public_file(p.sig.pk);
    struct Out {
        std::string path;
        const Bytes& data;
        mode_t mode;
        const char* what;
    };
    const Out outs[] = {
        {prefix + ".kem.pk", kem_pk, 0666, "ML-KEM-768 encapsulation key"},
        {prefix + ".kem.sk", kem_sk.v, 0600, "ML-KEM-768 seed d || z, SHA3-256(ek)"},
        {prefix + ".sig.pk", sig_pk, 0666, "ML-DSA-65 public key"},
        {prefix + ".sig.sk", sig_sk.v, 0600, "ML-DSA-65 seed xi, SHA3-256(pk)"},
    };
    // refused before anything is created, so that a refused keygen leaves no partial set behind;
    // O_EXCL in write_new_file still guards each file
    for (const Out& o : outs) {
        struct stat st {};
        if (::lstat(o.path.c_str(), &st) == 0) return fail(o.path + " exists; keygen does not overwrite key files");
    }
    unsigned modes[std::size(outs)] = {};
    for (std::size_t i = 0; i < std::size(outs); i++) {
        if (auto s = write_new_file(outs[i].path, outs[i].data, outs[i].mode, modes[i]); !s) {
            for (std::size_t j = 0; j < i; j++) ::unlink(outs[j].path.c_str());
            return s;
        }
    }
    std::printf("pqcrypt keygen: ML-KEM-768 and ML-DSA-65 key pairs from fresh seeds\n");
    for (std::size_t i = 0; i < std::size(outs); i++) {
        std::printf("  %-20s %5zu bytes  mode %04o  %s\n", outs[i].path.c_str(), outs[i].data.size(), modes[i],
                    outs[i].what);
    }
    return {};
}

Status cmd_encrypt(const std::string& pk_path, const std::string& in_path, const std::string& out_path) {
    const auto t0 = Clock::now();
    KEM::public_key ek;
    if (auto s = load_kem_public(pk_path, ek); !s) return s;
    FileInput in(in_path);
    if (auto s = in.open(); !s) return s;
    AtomicFile out(out_path);
    if (auto s = out.open(); !s) return s;
    StreamStats st;
    if (auto s = encrypt_stream(ek, in, out, st); !s) return s;
    if (auto s = out.commit(); !s) return s;
    std::printf("pqcrypt encrypt: %s (%llu bytes) for the holder of %s -> %s (%llu bytes), %.1f ms\n",
                in_path.c_str(), ull(st.bytes), pk_path.c_str(), out_path.c_str(), ull(encrypted_size(st)),
                ms_since(t0));
    std::printf("  %zu-byte ML-KEM-768 ciphertext, %s of up to %zu bytes with %d-byte tags "
                "(demo_sym, not a standardized AEAD)\n",
                KEM::ciphertext_bytes, count(st.chunks, "chunk").c_str(), chunk_bytes, DEMO_TAG_BYTES);
    return {};
}

Status cmd_decrypt(const std::string& sk_path, const std::string& in_path, const std::string& out_path) {
    const auto t0 = Clock::now();
    KemKeys keys;
    if (auto s = load_kem_secret(sk_path, keys); !s) return s;
    FileInput in(in_path);
    if (auto s = in.open(); !s) return s;
    AtomicFile out(out_path);
    if (auto s = out.open(); !s) return s;
    StreamStats st;
    if (auto s = decrypt_stream(keys, in, in_path, out, st); !s) {
        std::string e = s.error();
        if (e.ends_with("failed authentication")) e += " (wrong key, or the file was modified or truncated)";
        return fail(e + "; " + out_path + " not written");
    }
    if (auto s = out.commit(); !s) return s;
    std::printf("pqcrypt decrypt: %s -> %s (%llu bytes, %s authenticated), %.1f ms\n", in_path.c_str(),
                out_path.c_str(), ull(st.bytes), count(st.chunks, "chunk").c_str(), ms_since(t0));
    return {};
}

Status cmd_sign(const std::string& sk_path, const std::string& file, const std::string& sig_path) {
    const auto t0 = Clock::now();
    SigKeys keys;
    if (auto s = load_sig_secret(sk_path, keys); !s) return s;
    FileInput in(file);
    if (auto s = in.open(); !s) return s;
    DSA::signature sig;
    std::uint64_t bytes = 0;
    if (auto s = sign_stream(keys, in, sig, bytes); !s) return s;
    const Bytes out_bytes = signature_file(sig);
    AtomicFile out(sig_path);
    if (auto s = out.open(); !s) return s;
    if (auto s = out.write(out_bytes); !s) return s;
    if (auto s = out.commit(); !s) return s;
    std::printf("pqcrypt sign: %s (%llu bytes, mu computed while reading) -> %s (%zu bytes), %.1f ms\n",
                file.c_str(), ull(bytes), sig_path.c_str(), out_bytes.size(), ms_since(t0));
    std::printf("  ML-DSA-65, hedged, context \"%.*s\"\n", static_cast<int>(signature_context.size()),
                signature_context.data());
    return {};
}

Status cmd_verify(const std::string& pk_path, const std::string& file, const std::string& sig_path) {
    const auto t0 = Clock::now();
    DSA::public_key pk;
    if (auto s = load_sig_public(pk_path, pk); !s) return s;
    DSA::signature sig;
    if (auto s = load_signature(sig_path, sig); !s) return s;
    FileInput in(file);
    if (auto s = in.open(); !s) return s;
    std::uint64_t bytes = 0;
    bool valid = false;
    if (auto s = verify_stream(pk, in, sig, bytes, valid); !s) return s;
    if (!valid) return fail(file + ": INVALID signature " + sig_path + " for " + pk_path);
    std::printf("pqcrypt verify: %s (%llu bytes): valid ML-DSA-65 signature by the holder of %s, %.1f ms\n",
                file.c_str(), ull(bytes), pk_path.c_str(), ms_since(t0));
    return {};
}

// --- selftest ------------------------------------------------------------------------------------

class Checks {
public:
    void operator()(bool ok, const std::string& what) {
        total_++;
        if (!ok) failed_++;
        std::printf("  %-7s %s\n", ok ? "ok" : "FAILED", what.c_str());
        if (!ok) std::fprintf(stderr, "pqcrypt selftest: FAILED: %s\n", what.c_str());
    }
    // A check that `s` is the failure it should be
    void rejected(const Status& s, const std::string& what) {
        (*this)(!s, what + (s ? ": accepted" : ": rejected (" + s.error() + ")"));
    }
    int total() const { return total_; }
    int failed() const { return failed_; }

private:
    int total_ = 0, failed_ = 0;
};

Status encrypt_bytes(const KEM::public_key& ek, ByteSpan pt, Bytes& enc, StreamStats& st) {
    MemoryInput in(pt);
    MemoryOutput out;
    Status s = encrypt_stream(ek, in, out, st);
    enc = std::move(out.bytes);
    return s;
}

Status decrypt_bytes(const KemKeys& keys, ByteSpan enc, SecretBytes& pt) {
    MemoryInput in(enc);
    MemoryOutput out;
    StreamStats st;
    Status s = decrypt_stream(keys, in, "test.enc", out, st);
    pt.v = std::move(out.bytes);
    return s;
}

Bytes flip(Bytes b, std::size_t at) {
    b[at] ^= 0x01;
    return b;
}

Bytes test_message(std::size_t n) {
    Bytes m(n);
    for (std::size_t i = 0; i < n; i++) m[i] = static_cast<std::uint8_t>(i * 131u + (i >> 9));
    return m;
}

void selftest_key_files(Checks& check, const Party& bob) {
    std::printf("key files\n");
    {
        const SecretBytes file{kem_secret_file(bob.kem_seed, bob.kem.pk)};
        KemKeys k;
        const Status s = parse_kem_secret(file.v, "bob.kem.sk", k);
        check(s && k.pk == bob.kem.pk && k.sk == bob.kem.sk,
              "ML-KEM-768 secret key file (" + std::to_string(file.v.size()) +
                  " bytes: seed d || z) expands to the same key pair" + (s ? "" : ": " + s.error()));
        const SecretBytes damaged{flip(file.v, header_bytes + 5)};
        KemKeys k2;
        check.rejected(parse_kem_secret(damaged.v, "bob.kem.sk", k2), "damaged ML-KEM seed");
    }
    {
        const SecretBytes file{sig_secret_file(bob.sig_seed, bob.sig.pk)};
        SigKeys k;
        const Status s = parse_sig_secret(file.v, "bob.sig.sk", k);
        check(s && k.pk == bob.sig.pk && k.sk == bob.sig.sk,
              "ML-DSA-65 secret key file (" + std::to_string(file.v.size()) +
                  " bytes: seed xi) expands to the same key pair" + (s ? "" : ": " + s.error()));
        KemKeys k2;
        check.rejected(parse_kem_secret(file.v, "bob.sig.sk", k2), "ML-DSA secret key used as an ML-KEM one");
    }
    const Bytes kem_pk = kem_public_file(bob.kem.pk);
    KEM::public_key ek{};
    const Status s = parse_kem_public(kem_pk, "bob.kem.pk", ek);
    check(s && ek == bob.kem.pk, "ML-KEM-768 public key file (" + std::to_string(kem_pk.size()) + " bytes) round trip");
    DSA::public_key pk;
    check.rejected(parse_sig_public(kem_pk, "bob.kem.pk", pk), "ML-KEM public key used as an ML-DSA one");
    Bytes v2 = kem_pk;
    v2[4] = 2;
    check.rejected(parse_kem_public(v2, "bob.kem.pk", ek), "format version 2");
    check.rejected(parse_kem_public(ByteSpan(kem_pk).first(kem_pk.size() - 1), "bob.kem.pk", ek),
                   "public key file one byte short");
}

void selftest_encryption(Checks& check, const Party& alice, const Party& bob) {
    std::printf("encryption (ML-KEM-768 + demo_sym, %zu-byte chunks)\n", chunk_bytes);
    for (const std::size_t n : {std::size_t{0}, std::size_t{1}, chunk_bytes - 1, chunk_bytes, chunk_bytes + 1,
                                std::size_t{200000}}) {
        const Bytes m = test_message(n);
        Bytes enc;
        StreamStats st;
        SecretBytes back;
        Status s = encrypt_bytes(bob.kem.pk, m, enc, st);
        if (s) s = decrypt_bytes(bob.kem, enc, back);
        check(s && back.v == m && enc.size() == encrypted_size(st),
              "round trip, " + count(n, "byte") + ": " + count(st.chunks, "chunk") + ", " +
                  std::to_string(enc.size()) + " bytes encrypted" + (s ? "" : ": " + s.error()));
    }

    const Bytes m = test_message(200000);  // chunks 0, 1, 2 full, chunk 3 with 3392 bytes
    Bytes enc, enc2;
    StreamStats st;
    if (const Status s = encrypt_bytes(bob.kem.pk, m, enc, st); !s) return check(false, "encryption: " + s.error());
    if (const Status s = encrypt_bytes(bob.kem.pk, m, enc2, st); !s) return check(false, "encryption: " + s.error());
    check(enc != enc2, "two encryptions of the same file differ (fresh Encaps, fresh key)");

    const std::size_t c_at = header_bytes, chunk0_at = header_bytes + KEM::ciphertext_bytes;
    auto chunk_at = [&](std::size_t i) { return chunk0_at + i * sealed_chunk_bytes; };
    SecretBytes out;
    std::printf("  tampering with a 200000-byte file (4 chunks, %zu bytes encrypted):\n", enc.size());
    check.rejected(decrypt_bytes(alice.kem, enc, out), "wrong secret key (alice's)");
    check.rejected(decrypt_bytes(bob.kem, flip(enc, c_at + 100), out), "ML-KEM ciphertext modified");
    check.rejected(decrypt_bytes(bob.kem, flip(enc, 4), out), "header modified (version)");
    check.rejected(decrypt_bytes(bob.kem, flip(enc, chunk_at(1) + 1000), out), "chunk 1 ciphertext modified");
    check.rejected(decrypt_bytes(bob.kem, flip(enc, enc.size() - 1), out), "tag of the last chunk modified");
    Bytes swapped = enc;
    std::swap_ranges(swapped.begin() + static_cast<std::ptrdiff_t>(chunk_at(1)),
                     swapped.begin() + static_cast<std::ptrdiff_t>(chunk_at(2)),
                     swapped.begin() + static_cast<std::ptrdiff_t>(chunk_at(2)));
    check.rejected(decrypt_bytes(bob.kem, swapped, out), "chunks 1 and 2 swapped");
    const ByteSpan e(enc);
    check.rejected(decrypt_bytes(bob.kem, e.first(chunk_at(3)), out), "last chunk removed (cut at a chunk boundary)");
    check.rejected(decrypt_bytes(bob.kem, e.first(enc.size() - 1), out), "cut inside the last chunk");
    check.rejected(decrypt_bytes(bob.kem, e.first(chunk0_at), out), "all chunks removed");
    check.rejected(decrypt_bytes(bob.kem, e.first(chunk0_at - 1), out), "cut inside the ML-KEM ciphertext");
    check.rejected(decrypt_bytes(bob.kem, concat({enc, std::array<std::uint8_t, 1>{0}}), out), "one byte appended");
    check.rejected(decrypt_bytes(bob.kem, concat({e.first(chunk_at(1)), ByteSpan(enc2).subspan(chunk_at(1))}), out),
                   "chunks 1-3 taken from another encryption of the same file");
}

void selftest_signatures(Checks& check, const Party& alice, const Party& bob) {
    const ByteSpan ctx = text_bytes(signature_context);
    std::printf("signatures (ML-DSA-65, context \"%.*s\", mu streamed)\n", static_cast<int>(ctx.size()),
                signature_context.data());
    for (const std::size_t n : {std::size_t{0}, std::size_t{100}, std::size_t{200000}}) {
        const Bytes m = test_message(n);
        DSA::message_representative mu{}, ref{};
        std::uint64_t bytes = 0, reads = 0;
        MemoryInput in(m);
        const Status s = streamed_mu(mu, alice.sig.pk, ctx, in, bytes, reads);
        const openpqc::status rs = DSA::external_mu(ref, m, alice.sig.pk, ctx);
        check(s && rs == openpqc::status::ok && mu == ref, "streamed mu = openpqc_mldsa65_external_mu, " + std::to_string(n) +
                                             "-byte message (" + count(reads, "read") + ")");
    }

    const Bytes m = test_message(200000);
    DSA::signature sig{};
    std::uint64_t bytes = 0;
    {
        MemoryInput in(m);
        if (const Status s = sign_stream(alice.sig, in, sig, bytes); !s) return check(false, "signing: " + s.error());
    }
    check(DSA::verify(sig, m, alice.sig.pk, ctx) == openpqc::status::ok,
          "the signature verifies with openpqc_mldsa65_verify");
    auto verify = [&](ByteSpan message, ByteSpan signature, const DSA::public_key& pk) {
        MemoryInput in(message);
        bool valid = false;
        std::uint64_t n = 0;
        const Status s = verify_stream(pk, in, signature, n, valid);
        return s && valid;
    };
    check(verify(m, sig, alice.sig.pk), "verify_mu with the streamed mu accepts it");

    const Bytes sig_file = signature_file(sig);
    DSA::signature parsed{};
    const Status s = parse_signature(sig_file, "file.sig", parsed);
    check(s && parsed == sig, "signature file (" + std::to_string(sig_file.size()) + " bytes) round trip");

    check(!verify(flip(m, 150000), sig, alice.sig.pk), "message modified: rejected");
    check(!verify(ByteSpan(m).first(m.size() - 1), sig, alice.sig.pk), "message one byte short: rejected");
    const Bytes bad_sig = flip(Bytes(sig.begin(), sig.end()), 1000);
    check(!verify(m, bad_sig, alice.sig.pk), "signature modified: rejected");
    check(!verify(m, sig, bob.sig.pk), "bob's public key: rejected");
    check(DSA::verify(sig, m, alice.sig.pk, text_bytes("pqcrypt file signature v2")) ==
              openpqc::status::invalid_signature,
          "another context string: rejected");
}

Status cmd_selftest() {
    const auto t0 = Clock::now();
    std::printf("pqcrypt selftest: in-memory round trips and tampering cases\n");
    std::printf("  symmetric layer: demo_sym.h (SHAKE256 KDF, encrypt-then-MAC), a demo construction, "
                "not a standardized AEAD\n");
    Party alice, bob;
    if (auto s = new_party(alice); !s) return s;
    if (auto s = new_party(bob); !s) return s;
    Checks check;
    selftest_key_files(check, bob);
    selftest_encryption(check, alice, bob);
    selftest_signatures(check, alice, bob);
    if (check.failed() != 0) {
        return fail(std::to_string(check.failed()) + " of " + std::to_string(check.total()) + " checks failed");
    }
    std::printf("pqcrypt selftest: all %d checks passed, %.0f ms\n", check.total(), ms_since(t0));
    return {};
}

constexpr const char* usage_text =
    "usage: pqcrypt keygen PREFIX                     PREFIX.kem.pk/.kem.sk (ML-KEM-768), .sig.pk/.sig.sk (ML-DSA-65)\n"
    "       pqcrypt encrypt RECIPIENT.kem.pk IN OUT\n"
    "       pqcrypt decrypt RECIPIENT.kem.sk IN OUT\n"
    "       pqcrypt sign SIGNER.sig.sk FILE SIGFILE\n"
    "       pqcrypt verify SIGNER.sig.pk FILE SIGFILE   exit 0 only for a valid signature\n"
    "       pqcrypt selftest\n";

int finish(const std::string& command, const Status& s) {
    if (s) return 0;
    std::fprintf(stderr, "pqcrypt %s: %s\n", command.c_str(), s.error().c_str());
    return 1;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const std::vector<std::string> a(argv + 1, argv + argc);
        const std::string cmd = a.empty() ? "" : a[0];
        if (cmd == "keygen" && a.size() == 2) return finish(cmd, cmd_keygen(a[1]));
        if (cmd == "encrypt" && a.size() == 4) return finish(cmd, cmd_encrypt(a[1], a[2], a[3]));
        if (cmd == "decrypt" && a.size() == 4) return finish(cmd, cmd_decrypt(a[1], a[2], a[3]));
        if (cmd == "sign" && a.size() == 4) return finish(cmd, cmd_sign(a[1], a[2], a[3]));
        if (cmd == "verify" && a.size() == 4) return finish(cmd, cmd_verify(a[1], a[2], a[3]));
        if (cmd == "selftest" && a.size() == 1) return finish(cmd, cmd_selftest());
        std::fputs(usage_text, stderr);
        return 2;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "pqcrypt: %s\n", e.what());
        return 1;
    }
}
