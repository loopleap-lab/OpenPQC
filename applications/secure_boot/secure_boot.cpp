/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * secure_boot.cpp  --  a firmware update and secure boot chain: an SLH-DSA root key, ML-DSA release keys
 *
 * A device vendor and one of its devices, two parts of one process that pass each other nothing
 * but byte strings, run the update chain of a secure boot design:
 *
 *   vendor ROOT key      SLH-DSA-SHA2-128s. Its security rests on a hash function alone (SHA-256
 *                        for this set), which suits the one key a device must keep trusting for
 *                        the 10 to 20 years it is in the field; its 32-byte public key is what the
 *                        device keeps in ROM or fuses; its signing is slow (about a second on one
 *                        core), which does not matter for a key that signs a few times a year. It
 *                        signs key certificates for release keys (SLH-DSA, context string
 *                        "openpqc-demo key certificate") and recovery images directly (HashSLH-DSA
 *                        with SHA2-256 as the pre-hash, context "openpqc-demo recovery image").
 *   RELEASE signing key  ML-DSA-65, whose signing is fast, for frequent releases. It signs firmware
 *                        manifests (context "openpqc-demo firmware manifest").
 *   DEVICE               its boot loader holds the root public key and two persistent anti-rollback
 *                        counters, the minimum key version and the minimum security version (SVN);
 *                        nothing else. The pair (key version, SVN), compared in that order, is only
 *                        ever raised.
 *
 * The context strings keep the root's two kinds of signature apart (and HashSLH-DSA's M' differs
 * from SLH-DSA's in its first byte), so neither can be passed off as the other.
 *
 * Formats (big-endian integers; [n] is a length prefix of n bytes):
 *   key certificate   = tbs [2] || signature algorithm (2) || signature [2]
 *     tbs             = format (1) || key id (4) || key version (4) || key algorithm (2) ||
 *                       public key [2] || model count (1) || models ([1] each) ||
 *                       image type count (1) || image types (1 each)
 *   signed manifest   = manifest [2] || signature algorithm (2) || signature [2]
 *     manifest        = format (1) || model [1] || image type (1) || security version (4) ||
 *                       firmware version [1] || image size (4) || SHA3-256 of the image (32)
 *   update package    = key certificate [2] || signed manifest [2] || image [4]
 *   recovery package  = recovery image [4] || HashSLH-DSA signature [2]
 *     recovery image  = format (1) || model [1] || recovery version [1] || payload [4]
 * The algorithm numbers are the last arcs of the algorithms' OIDs under NIST's sigAlgs arc,
 * 2.16.840.1.101.3.4.3 (18: ML-DSA-65, 20: SLH-DSA-SHA2-128s).
 *
 * The boot loader checks an update package in this order, and parses a structure only after the
 * signature over it has been verified:
 *   1. the key certificate: SLH-DSA Verify under the root key in ROM
 *   2. the key version: not below the device's minimum key version
 *   3. the manifest: ML-DSA-65 Verify under the release key that the certificate certifies
 *   4. the image: its size and its SHA3-256 against the manifest's
 *   5. the model and the image type: both covered by the key certificate, and those of this
 *      device and of the slot the boot loader updates (main firmware)
 *   6. the security version: if the key version equals the device's minimum key version, not below
 *      the device's minimum SVN (a higher key version starts a new SVN sequence)
 * It then installs the image and raises the stored pair: a higher key version becomes the minimum
 * key version, with the update's SVN as the new minimum SVN; otherwise the minimum SVN rises to the
 * update's. This is how a device learns that an older release key is retired. Starting a new SVN
 * sequence matters: with one SVN shared by all key versions, an image signed with a stolen key
 * and SVN 2^32-1 would make a device refuse every later release, the rotation release included.
 * A recovery package is checked with HashSLH-DSA Verify under the root key, then the model in the
 * image's header. Recovery images carry a version but are not rollback-protected here: every
 * recovery image the root has signed for the model verifies. A real design gives them a security
 * version checked against a counter of their own.
 *
 * The program runs eight scenarios and checks that each ends as it should:
 *   1. an honest update installs (and its verification is timed)
 *   2. a modified image is rejected (check 4)
 *   3. a manifest signed by a key the root did not certify is rejected (check 3)
 *   4. forged key certificates are rejected (check 1): the genuine certificate with an attacker's
 *      public key in it, and one signed by an attacker's own SLH-DSA key
 *   5. a rollback to an older, validly signed image is rejected (check 6)
 *   6. images for another model and of another type are rejected (check 5), and so is an image
 *      for a model that the release key is not certified for
 *   7. key rotation: release key 1 is compromised, the root certifies key 2 with key version 2,
 *      the device installs the next release (signed by key 2) and from then on rejects images
 *      signed by key 1 (check 2). A device that has not installed that release yet still accepts
 *      them, which is the window that rotation leaves; after installing the attacker's image with
 *      SVN 2^32-1 it still installs the release signed by key 2, and then rejects key 1 too
 *   8. a recovery image signed by the root with HashSLH-DSA (8 MiB, PH = SHA2-256) verifies, and a
 *      modified one is rejected, as is a key certificate's signature presented as a recovery one
 *
 * This is a demonstration, not a product. The formats are this program's own; real systems use a
 * standard manifest (the IETF SUIT model, RFC 9019 and RFC 9124), keep the root's private key
 * offline in an HSM, keep the counters in replay-protected storage (one-time fuses cannot lower
 * the minimum SVN when a new key version starts a new sequence; a fuse design keeps one SVN
 * counter per key version), and verify the image where it will run from, so that it cannot change
 * between check and use.
 *
 * usage: secure_boot [runs]
 *   runs        number of timed repetitions of an ML-DSA-65 manifest signature, an update
 *               verification and a recovery verification (together about 50 ms on one core),
 *               whose times are averaged, 1 to 10000 (default 10)
 *   --help, -h  print the usage and exit
 *
 * Prints the vendor's keys with their KeyGen and Sign times, why each scheme is used where it is,
 * the sizes (the root key in ROM, key certificate, manifest, signatures), then one line per check
 * with ok or FAILED, each followed by the boot loader's verdict, and the boot loader's
 * verification times. Failed checks are also reported on stderr. Exits with 0 if every scenario
 * ended as expected, the expected rejections included, and 1 otherwise (also if a library call
 * fails).
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "Core/openpqc_core.h"
#include "ML/DSA/mldsa.hpp"
#include "SLH/DSA/slhdsa.hpp"

namespace {

using RootDSA = openpqc::slhdsa::SLHDSA_SHA2_128s; // the vendor root key; its public key is in ROM
using ReleaseDSA = openpqc::mldsa::MLDSA65;        // release signing keys, certified by the root

using Bytes = std::vector<std::uint8_t>;
using View = std::span<const std::uint8_t>;
using Hash = std::array<std::uint8_t, 32>;
using Clock = std::chrono::steady_clock;

// The last arcs of the OIDs id-ml-dsa-65 and id-slh-dsa-sha2-128s (2.16.840.1.101.3.4.3.x)
constexpr std::uint16_t kAlgMLDSA65 = 18;
constexpr std::uint16_t kAlgSLHDSA_SHA2_128s = 20;

constexpr std::uint8_t kFormat = 1;
constexpr std::uint8_t kMainFirmware = 1;
constexpr std::uint8_t kRadioFirmware = 2;

constexpr std::string_view kCertificateContext = "openpqc-demo key certificate";
constexpr std::string_view kManifestContext = "openpqc-demo firmware manifest";
constexpr std::string_view kRecoveryContext = "openpqc-demo recovery image";
// FIPS 205, Section 10.2.2 limits SHA-256 (and SHAKE128) as the pre-hash to the sets of category 1,
// such as this one; boot ROMs often have a SHA-256 engine to stream the image through
constexpr openpqc::PreHash kRecoveryPreHash = openpqc::PreHash::SHA2_256;

constexpr std::size_t kImageBytes = std::size_t{1} << 20;    // a main firmware image
constexpr std::size_t kRecoveryBytes = std::size_t{8} << 20; // the recovery image

constexpr std::string_view kDeviceModel = "GW-100";
const std::vector<std::string_view> kCertifiedModels = {"GW-100", "GW-200"};
const std::vector<std::uint8_t> kCertifiedTypes = {kMainFirmware, kRadioFirmware};

View view(std::string_view s) { return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()}; }
std::string_view text(View v) { return {reinterpret_cast<const char*>(v.data()), v.size()}; }

double ms(Clock::duration d) { return std::chrono::duration<double, std::milli>(d).count(); }

// Errors are exceptions, so that the destructors that zeroize the secret keys run on every path;
// main() prints the message and exits with 1
[[noreturn]] void fail(const std::string& what) { throw std::runtime_error(what); }

void require(int rc, const std::string& what) {
    if (rc != 0) fail(what + " failed (" + std::to_string(rc) + ")");
}

// Secret bytes (private keys), zeroized when their lifetime ends. Not copyable, so that no copy
// is left behind.
template <std::size_t N>
struct Secret {
    std::array<std::uint8_t, N> bytes{};

    Secret() = default;
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    ~Secret() { opqc_zeroize(bytes.data(), N); }
};

// --- Encoding: big-endian integers and length-prefixed byte strings ---------------------------

class Writer {
public:
    Writer& u8(std::uint8_t v) { return be(v, 1); }
    Writer& u16(std::uint16_t v) { return be(v, 2); }
    Writer& u32(std::uint32_t v) { return be(v, 4); }
    Writer& raw(View v) {
        out.insert(out.end(), v.begin(), v.end());
        return *this;
    }
    // v preceded by its length in len_bytes bytes
    Writer& vec(View v, unsigned len_bytes) { return be(v.size(), len_bytes).raw(v); }

    Bytes out;

private:
    Writer& be(std::uint64_t v, unsigned n) {
        if (n < 8 && (v >> (8 * n)) != 0) fail("a field does not fit its length prefix");
        for (unsigned i = n; i-- > 0;) out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
        return *this;
    }
};

// Reads what Writer writes. Reading past the end makes every later read return zeros or empty
// views and done() false, so a parser checks done() once at the end instead of after each field.
class Reader {
public:
    explicit Reader(View in) : in_(in) {}

    std::uint8_t u8() { return static_cast<std::uint8_t>(be(1)); }
    std::uint16_t u16() { return static_cast<std::uint16_t>(be(2)); }
    std::uint32_t u32() { return static_cast<std::uint32_t>(be(4)); }
    View raw(std::size_t n) { return take(n) ? in_.subspan(pos_ - n, n) : View{}; }
    View vec(unsigned len_bytes) { return raw(static_cast<std::size_t>(be(len_bytes))); }
    // everything was read, and nothing more than there was
    bool done() const { return ok_ && pos_ == in_.size(); }

private:
    std::uint64_t be(unsigned n) {
        if (!take(n)) return 0;
        std::uint64_t v = 0;
        for (std::size_t i = pos_ - n; i < pos_; i++) v = (v << 8) | in_[i];
        return v;
    }
    bool take(std::size_t n) {
        if (!ok_ || n > in_.size() - pos_) {
            ok_ = false;
            return false;
        }
        pos_ += n;
        return true;
    }

    View in_;
    std::size_t pos_ = 0;
    bool ok_ = true;
};

// --- Formats ----------------------------------------------------------------------------------

// A signed structure: body [2] || signature algorithm (2) || signature [2]
struct Signed {
    View body;
    std::uint16_t algorithm = 0;
    View signature;
};

Bytes encode_signed(View body, std::uint16_t algorithm, View signature) {
    Writer w;
    w.vec(body, 2).u16(algorithm).vec(signature, 2);
    return w.out;
}

bool parse_signed(View in, Signed& s) {
    Reader r(in);
    s.body = r.vec(2);
    s.algorithm = r.u16();
    s.signature = r.vec(2);
    return r.done();
}

// The signed part of a key certificate: which release key, and what it may sign for
struct KeyCertificate {
    std::uint32_t key_id = 0;
    std::uint32_t key_version = 0;
    std::uint16_t key_algorithm = 0;
    View public_key;
    std::vector<std::string_view> models;
    std::vector<std::uint8_t> image_types;
};

Bytes encode_certificate_tbs(const KeyCertificate& c) {
    Writer w;
    w.u8(kFormat).u32(c.key_id).u32(c.key_version).u16(c.key_algorithm).vec(c.public_key, 2);
    w.u8(static_cast<std::uint8_t>(c.models.size()));
    for (std::string_view m : c.models) w.vec(view(m), 1);
    w.u8(static_cast<std::uint8_t>(c.image_types.size()));
    for (std::uint8_t t : c.image_types) w.u8(t);
    return w.out;
}

bool parse_certificate_tbs(View tbs, KeyCertificate& c) {
    Reader r(tbs);
    const std::uint8_t format = r.u8();
    c.key_id = r.u32();
    c.key_version = r.u32();
    c.key_algorithm = r.u16();
    c.public_key = r.vec(2);
    for (unsigned i = r.u8(); i > 0; i--) c.models.push_back(text(r.vec(1)));
    for (unsigned i = r.u8(); i > 0; i--) c.image_types.push_back(r.u8());
    return r.done() && format == kFormat;
}

struct Manifest {
    std::string_view model;
    std::uint8_t image_type = 0;
    std::uint32_t svn = 0; // security version: raised only by releases that fix vulnerabilities
    std::string_view version;
    std::uint32_t image_size = 0;
    Hash image_hash{};
};

Bytes encode_manifest(const Manifest& m) {
    Writer w;
    w.u8(kFormat).vec(view(m.model), 1).u8(m.image_type).u32(m.svn).vec(view(m.version), 1);
    w.u32(m.image_size).raw(m.image_hash);
    return w.out;
}

bool parse_manifest(View in, Manifest& m) {
    Reader r(in);
    const std::uint8_t format = r.u8();
    m.model = text(r.vec(1));
    m.image_type = r.u8();
    m.svn = r.u32();
    m.version = text(r.vec(1));
    m.image_size = r.u32();
    const View hash = r.raw(m.image_hash.size());
    if (!r.done() || format != kFormat) return false;
    std::ranges::copy(hash, m.image_hash.begin());
    return true;
}

struct Package {
    View certificate, manifest, image;
};

Bytes encode_package(View certificate, View signed_manifest, View image) {
    Writer w;
    w.vec(certificate, 2).vec(signed_manifest, 2).vec(image, 4);
    return w.out;
}

bool parse_package(View in, Package& p) {
    Reader r(in);
    p.certificate = r.vec(2);
    p.manifest = r.vec(2);
    p.image = r.vec(4);
    return r.done();
}

// The parts of a package this program built itself
Package parts(View package) {
    Package p;
    if (!parse_package(package, p)) fail("cannot parse a package of the vendor's");
    return p;
}

const char* type_name(std::uint8_t type) {
    switch (type) {
        case kMainFirmware: return "main firmware";
        case kRadioFirmware: return "radio firmware";
        default: return "an unknown image type";
    }
}

Hash sha3_256(View data) {
    Hash h;
    opqc_sha3_256(h.data(), data.data(), data.size());
    return h;
}

// An image of size bytes whose content is SHAKE256 of its label: different for every release
Bytes make_image(std::string_view label, std::size_t size) {
    Bytes image(size);
    opqc_shake256(image.data(), image.size(), view(label).data(), label.size());
    return image;
}

// A recovery image of kRecoveryBytes bytes: its header, then the payload
Bytes make_recovery_image(std::string_view model, std::string_view version) {
    Writer header;
    header.u8(kFormat).vec(view(model), 1).vec(view(version), 1);
    const std::size_t payload = kRecoveryBytes - header.out.size() - 4;
    header.vec(make_image("recovery " + std::string(version), payload), 4);
    return std::move(header.out);
}

// --- The vendor -------------------------------------------------------------------------------

// An ML-DSA-65 key that signs manifests: a release key of the vendor's, or an attacker's
struct ReleaseKey {
    std::string role; // names the key in error messages
    std::uint32_t key_id;
    std::uint32_t key_version;
    ReleaseDSA::public_key pk{};
    Secret<ReleaseDSA::secret_key_bytes> sk;
    Bytes certificate; // issued by the root (or, in the attacks, made up)

    ReleaseKey(std::string name, std::uint32_t id, std::uint32_t version)
        : role(std::move(name)), key_id(id), key_version(version) {
        require(ReleaseDSA::keypair(pk, sk.bytes), "ML-DSA-65 KeyGen (" + role + ")");
    }

    Bytes sign_manifest(const Manifest& m) const {
        const Bytes body = encode_manifest(m);
        ReleaseDSA::signature sig;
        require(ReleaseDSA::sign(sig, body, sk.bytes, view(kManifestContext)),
                "ML-DSA-65 Sign (a manifest, " + role + ")");
        return encode_signed(body, kAlgMLDSA65, sig);
    }

    // A release: the manifest of image, signed with this key, and the package with its certificate
    Bytes release(std::string_view model, std::uint8_t type, std::uint32_t svn, std::string_view version,
                  View image) const {
        const Manifest m{model, type, svn, version, static_cast<std::uint32_t>(image.size()), sha3_256(image)};
        return encode_package(certificate, sign_manifest(m), image);
    }
};

// An SLH-DSA-SHA2-128s key that certifies release keys and signs recovery images: the vendor's
// root, or in scenario 4 an attacker's
struct RootKey {
    std::string role; // names the key in error messages
    RootDSA::public_key pk{};
    Secret<RootDSA::secret_key_bytes> sk;

    explicit RootKey(std::string name) : role(std::move(name)) {
        require(RootDSA::keypair(pk, sk.bytes), "SLH-DSA-SHA2-128s KeyGen (" + role + ")");
    }

    Bytes certify(const ReleaseKey& key, const std::vector<std::string_view>& models,
                  const std::vector<std::uint8_t>& types) const {
        const KeyCertificate c{key.key_id, key.key_version, kAlgMLDSA65, key.pk, models, types};
        const Bytes tbs = encode_certificate_tbs(c);
        const auto sig = std::make_unique<RootDSA::signature>();
        require(RootDSA::sign(*sig, tbs, sk.bytes, view(kCertificateContext)),
                "SLH-DSA-SHA2-128s Sign (a key certificate, " + role + ")");
        return encode_signed(tbs, kAlgSLHDSA_SHA2_128s, *sig);
    }

    // HashSLH-DSA signs M' = 1 || |ctx| || ctx || OID(SHA-256) || SHA-256(image) (FIPS 205,
    // Algorithm 23), so a signer holding the root key needs only the 32-byte digest, not the 8 MiB
    // image (prehash_sign computes the digest here from the image)
    Bytes sign_recovery(View image) const {
        const auto sig = std::make_unique<RootDSA::signature>();
        require(RootDSA::prehash_sign(*sig, image, kRecoveryPreHash, sk.bytes, view(kRecoveryContext)),
                "SLH-DSA-SHA2-128s HashSLH-DSA Sign (a recovery image, " + role + ")");
        Writer w;
        w.vec(image, 4).vec(*sig, 2);
        return w.out;
    }
};

// --- The device and its boot loader -----------------------------------------------------------

struct Device {
    std::string model;
    RootDSA::public_key rom_root_key{}; // written at manufacture, never changed
    // The anti-rollback counters. The pair (min_key_version, min_svn), compared in that order, is
    // only ever raised; min_svn alone falls when a higher key version starts a new SVN sequence.
    std::uint32_t min_svn = 0;
    std::uint32_t min_key_version = 0;
    std::string installed_version;
    std::uint32_t installed_svn = 0;
};

bool same_state(const Device& a, const Device& b) {
    return a.min_svn == b.min_svn && a.min_key_version == b.min_key_version &&
           a.installed_version == b.installed_version && a.installed_svn == b.installed_svn;
}

// The check that rejected an update (scope: the model or type is not covered by the certificate)
enum class Check { none, format, certificate, key_version, manifest, image, scope, model, image_type, svn, recovery };

int check_number(Check c) {
    switch (c) {
        case Check::certificate: return 1;
        case Check::key_version: return 2;
        case Check::manifest: return 3;
        case Check::image: return 4;
        case Check::scope: case Check::model: case Check::image_type: return 5;
        case Check::svn: return 6;
        default: return 0;
    }
}

struct Verdict {
    Check failed = Check::none;
    std::string reason; // why the boot loader rejected it, or what it accepted
    std::uint32_t key_version = 0, svn = 0;
    std::string version;

    bool accepted() const { return failed == Check::none; }
};

Verdict reject(Check c, const std::string& why) {
    Verdict v;
    v.failed = c;
    const int n = check_number(c);
    v.reason = (n != 0 ? "rejected at check " + std::to_string(n) + ": " : std::string("rejected: ")) + why;
    return v;
}

// Time spent in the three cryptographic steps of verify_update
struct Times {
    Clock::duration certificate{}, manifest{}, image{};
};

template <class F>
auto timed(Clock::duration* sum, F&& f) {
    const auto t0 = Clock::now();
    auto result = f();
    if (sum != nullptr) *sum += Clock::now() - t0;
    return result;
}

std::string str(std::uint32_t v) { return std::to_string(v); }

// Checks 1 to 6 of the update package; changes nothing
Verdict verify_update(const Device& dev, View package, Times* times = nullptr) {
    Package p;
    Signed signed_cert, signed_manifest;
    if (!parse_package(package, p) || !parse_signed(p.certificate, signed_cert) ||
        !parse_signed(p.manifest, signed_manifest))
        return reject(Check::format, "the package is malformed");

    // 1. The key certificate, under the only key the device trusts
    if (signed_cert.algorithm != kAlgSLHDSA_SHA2_128s)
        return reject(Check::certificate, "the key certificate is not signed with SLH-DSA-SHA2-128s");
    const int cert_rc = timed(times ? &times->certificate : nullptr, [&] {
        return RootDSA::verify(signed_cert.signature, signed_cert.body, dev.rom_root_key, view(kCertificateContext));
    });
    if (cert_rc != 0)
        return reject(Check::certificate, "the key certificate does not verify under the root key in ROM");
    KeyCertificate cert;
    if (!parse_certificate_tbs(signed_cert.body, cert) || cert.key_algorithm != kAlgMLDSA65 ||
        cert.public_key.size() != ReleaseDSA::public_key_bytes)
        return reject(Check::format, "the key certificate is signed but malformed");

    // 2. A retired release key is rejected however valid its signatures are
    if (cert.key_version < dev.min_key_version)
        return reject(Check::key_version, "release key " + str(cert.key_id) + " has key version " +
                                                  str(cert.key_version) + ", below the device's minimum " +
                                                  str(dev.min_key_version));

    // 3. The manifest, under the key the root certified
    ReleaseDSA::public_key release_pk;
    std::ranges::copy(cert.public_key, release_pk.begin());
    const int manifest_rc = timed(times ? &times->manifest : nullptr, [&] {
        return signed_manifest.algorithm == kAlgMLDSA65
                       ? ReleaseDSA::verify(signed_manifest.signature, signed_manifest.body, release_pk,
                                            view(kManifestContext))
                       : OPENPQC_MLDSA_ERR_INVALID_SIGNATURE;
    });
    if (manifest_rc != 0)
        return reject(Check::manifest, "the manifest does not verify under certified release key " + str(cert.key_id));
    Manifest m;
    if (!parse_manifest(signed_manifest.body, m)) return reject(Check::format, "the manifest is signed but malformed");

    // 4. The image the manifest describes
    if (m.image_size != p.image.size())
        return reject(Check::image, "the image has " + std::to_string(p.image.size()) + " bytes, the manifest " +
                                            str(m.image_size));
    const Hash hash = timed(times ? &times->image : nullptr, [&] { return sha3_256(p.image); });
    if (hash != m.image_hash) return reject(Check::image, "the image's SHA3-256 differs from the manifest's");

    // 5. What the key may sign for, then what this device and its slot take
    const std::string model(m.model);
    if (std::ranges::find(cert.models, m.model) == cert.models.end())
        return reject(Check::scope, "release key " + str(cert.key_id) + " is not certified for model " + model);
    if (std::ranges::find(cert.image_types, m.image_type) == cert.image_types.end())
        return reject(Check::scope, "release key " + str(cert.key_id) + " is not certified for " +
                                            type_name(m.image_type));
    if (model != dev.model) return reject(Check::model, "the image is for model " + model + ", this is a " + dev.model);
    if (m.image_type != kMainFirmware)
        return reject(Check::image_type, std::string("the image is ") + type_name(m.image_type) +
                                                 ", this slot takes main firmware");

    // 6. Anti-rollback, within the key version (check 2 leaves only key versions at or above the
    // minimum). A higher key version starts a new SVN sequence, so the SVNs that a retired key
    // signed, up to 2^32-1 with a stolen one, cannot shut out the releases of its successor.
    if (cert.key_version == dev.min_key_version && m.svn < dev.min_svn)
        return reject(Check::svn, "SVN " + str(m.svn) + " is below the device's minimum " + str(dev.min_svn) +
                                          " for key version " + str(cert.key_version));

    Verdict v;
    v.key_version = cert.key_version;
    v.svn = m.svn;
    v.version = std::string(m.version);
    v.reason = "accepted firmware " + v.version + " (SVN " + str(m.svn) + "), release key " + str(cert.key_id) +
               " (key version " + str(cert.key_version) + ")";
    return v;
}

// Checks the package and, if it passes, installs the image and raises the stored pair
// (minimum key version, minimum SVN) to the update's
Verdict install_update(Device& dev, View package) {
    Verdict v = verify_update(dev, package);
    if (v.accepted()) {
        dev.installed_version = v.version;
        dev.installed_svn = v.svn;
        if (v.key_version > dev.min_key_version) {
            dev.min_key_version = v.key_version;
            dev.min_svn = v.svn;
        } else {
            dev.min_svn = std::max(dev.min_svn, v.svn);
        }
    }
    return v;
}

Verdict verify_recovery(const Device& dev, View package) {
    Reader r(package);
    const View image = r.vec(4);
    const View sig = r.vec(2);
    if (!r.done()) return reject(Check::format, "the recovery package is malformed");
    if (RootDSA::prehash_verify(sig, image, kRecoveryPreHash, dev.rom_root_key, view(kRecoveryContext)) != 0)
        return reject(Check::recovery, "the HashSLH-DSA signature does not verify under the root key in ROM");
    Reader header(image);
    const std::uint8_t format = header.u8();
    const std::string model(text(header.vec(1)));
    const std::string version(text(header.vec(1)));
    header.vec(4);
    if (!header.done() || format != kFormat) return reject(Check::format, "the recovery image is signed but malformed");
    if (model != dev.model) return reject(Check::recovery, "the recovery image is for model " + model);
    Verdict v;
    v.version = version;
    v.reason = "accepted recovery image " + version + " for " + model;
    return v;
}

// --- Scenarios --------------------------------------------------------------------------------

int g_failures = 0;

// Prints one checked result and, if given, the boot loader's verdict on the next line
bool check(bool ok, const std::string& what, const std::string& detail = {}) {
    std::printf("  %-74s %s\n", what.c_str(), ok ? "ok" : "FAILED");
    if (!detail.empty()) std::printf("      %s\n", detail.c_str());
    if (!ok) {
        g_failures++;
        std::fprintf(stderr, "secure_boot: FAILED: %s%s%s\n", what.c_str(), detail.empty() ? "" : ": ",
                     detail.c_str());
    }
    return ok;
}

// Offers a package that must be rejected at the given check and leave the device as it was
void expect_rejection(Device& dev, View package, Check expected, const std::string& what) {
    const Device before = dev;
    const Verdict v = install_update(dev, package);
    check(v.failed == expected && same_state(before, dev), what, "boot loader: " + v.reason);
}

std::string state(const Device& d) {
    return "firmware " + d.installed_version + " (SVN " + str(d.installed_svn) + "), minimum SVN " + str(d.min_svn) +
           ", minimum key version " + str(d.min_key_version);
}

struct Vendor {
    std::unique_ptr<RootKey> root;
    std::unique_ptr<ReleaseKey> key1;
    Bytes package_120; // the release the device left the factory with
    Bytes package_130; // the honest update of scenario 1
};

void honest_update(const Vendor& v, Device& dev, int runs) {
    std::printf("\n1. an honest update\n");
    const Verdict verdict = install_update(dev, v.package_130);
    check(verdict.accepted() && dev.installed_version == "1.3.0",
          "firmware 1.3.0 (SVN 3), signed by release key 1, installs", "boot loader: " + verdict.reason);
    check(dev.min_svn == 3 && dev.min_key_version == 1, "the device raised its minimum SVN from 2 to 3",
          "device: " + state(dev));

    Times t;
    const auto t0 = Clock::now();
    for (int i = 0; i < runs; i++)
        if (!verify_update(dev, v.package_130, &t).accepted()) fail("a timed verification was rejected");
    const double total = ms(Clock::now() - t0) / runs;
    std::printf("  boot loader verification time, mean of %d: %.2f ms\n"
                "    SLH-DSA Verify %.2f ms, ML-DSA-65 Verify %.2f ms, SHA3-256 of the 1 MiB image %.2f ms\n",
                runs, total, ms(t.certificate) / runs, ms(t.manifest) / runs, ms(t.image) / runs);
}

void modified_image(const Vendor& v, Device& dev) {
    std::printf("\n2. a modified image\n");
    const Package p = parts(v.package_130);
    Bytes image(p.image.begin(), p.image.end());
    image[image.size() / 2] ^= 0x01;
    expect_rejection(dev, encode_package(p.certificate, p.manifest, image), Check::image,
                     "1.3.0 with one bit of its image flipped (signatures intact): rejected");
}

void uncertified_key(const Vendor& v, Device& dev) {
    std::printf("\n3. a manifest signed by a key the root did not certify\n");
    // The attacker's own ML-DSA-65 key, sent with the genuine certificate of release key 1
    ReleaseKey attacker("the attacker's ML-DSA-65 key", 1, 1);
    attacker.certificate = v.key1->certificate;
    const Bytes image = make_image("GW-100 main firmware 1.3.0, with a backdoor", kImageBytes);
    expect_rejection(dev, attacker.release(kDeviceModel, kMainFirmware, 9, "1.3.0", image), Check::manifest,
                     "an attacker's manifest (SVN 9) with key 1's genuine certificate: rejected");
}

void forged_certificates(const Vendor& v, Device& dev) {
    std::printf("\n4. forged key certificates\n");
    ReleaseKey attacker("the attacker's ML-DSA-65 key", 1, 1);
    const Bytes image = make_image("GW-100 main firmware 1.3.0, with a backdoor", kImageBytes);

    // The genuine certificate with the attacker's public key put in place of key 1's; the root's
    // signature is kept, but it was made over the original tbs
    Signed genuine;
    KeyCertificate cert;
    if (!parse_signed(v.key1->certificate, genuine) || !parse_certificate_tbs(genuine.body, cert))
        fail("cannot parse key 1's certificate");
    cert.public_key = attacker.pk;
    attacker.certificate = encode_signed(encode_certificate_tbs(cert), genuine.algorithm, genuine.signature);
    expect_rejection(dev, attacker.release(kDeviceModel, kMainFirmware, 9, "1.3.0", image), Check::certificate,
                     "key 1's certificate, its public key replaced by the attacker's: rejected");

    // A certificate signed by the attacker's own SLH-DSA-SHA2-128s key, in the format of the root's
    const RootKey rogue("the attacker's SLH-DSA-SHA2-128s key");
    attacker.certificate = rogue.certify(attacker, kCertifiedModels, kCertifiedTypes);
    expect_rejection(dev, attacker.release(kDeviceModel, kMainFirmware, 9, "1.3.0", image), Check::certificate,
                     "a certificate signed by an attacker's SLH-DSA-SHA2-128s key: rejected");
}

void rollback(const Vendor& v, Device& dev) {
    std::printf("\n5. a rollback to an older, validly signed release\n");
    expect_rejection(dev, v.package_120, Check::svn,
                     "1.2.0 (SVN 2), validly signed by key 1, on a device at SVN 3: rejected");
}

void wrong_model_or_type(const Vendor& v, Device& dev) {
    std::printf("\n6. images for another model or of another type\n");
    const ReleaseKey& key1 = *v.key1;
    expect_rejection(dev,
                     key1.release("GW-200", kMainFirmware, 3, "1.3.0",
                                  make_image("GW-200 main firmware 1.3.0", kImageBytes)),
                     Check::model, "GW-200 firmware 1.3.0, validly signed by key 1, on this GW-100: rejected");
    expect_rejection(dev,
                     key1.release(kDeviceModel, kRadioFirmware, 3, "2.1.0",
                                  make_image("GW-100 radio firmware 2.1.0", kImageBytes)),
                     Check::image_type, "GW-100 radio firmware 2.1.0, validly signed, as main firmware: rejected");

    // A device of another product line that trusts the same root: key 1 may not sign for it
    Device gw300{"GW-300", dev.rom_root_key, 1, 1, "1.0.0", 1};
    expect_rejection(gw300,
                     key1.release("GW-300", kMainFirmware, 2, "1.1.0",
                                  make_image("GW-300 main firmware 1.1.0", kImageBytes)),
                     Check::scope, "on a GW-300 (same root key): a GW-300 image signed by key 1: rejected");
}

void key_rotation(const Vendor& v, Device& dev) {
    std::printf("\n7. key rotation: release key 1 is compromised\n");
    ReleaseKey key2("release key 2", 2, 2);
    const auto t0 = Clock::now();
    key2.certificate = v.root->certify(key2, kCertifiedModels, kCertifiedTypes);
    std::printf("  the root certifies release key 2 with key version 2 (SLH-DSA Sign %.0f ms)\n",
                ms(Clock::now() - t0));

    Device late = dev; // a device that has not installed release 1.4.0 yet
    const Bytes package_140 = key2.release(kDeviceModel, kMainFirmware, 4, "1.4.0",
                                           make_image("GW-100 main firmware 1.4.0", kImageBytes));
    const Verdict verdict = install_update(dev, package_140);
    check(verdict.accepted() && dev.min_key_version == 2 && dev.min_svn == 4,
          "1.4.0 (SVN 4), signed by key 2, installs; minimum key version 1 -> 2",
          "boot loader: " + verdict.reason);

    // The attacker signs with key 1's stolen private key (key 1's certificate is genuine), with
    // the highest SVN there is, to shut out every later release if the SVN alone were compared
    constexpr std::uint32_t kMaxSvn = 0xFFFFFFFF;
    const Bytes evil = v.key1->release(kDeviceModel, kMainFirmware, kMaxSvn, "1.4.1",
                                       make_image("GW-100 main firmware 1.4.1, with a backdoor", kImageBytes));
    expect_rejection(dev, evil, Check::key_version,
                     "an attacker's image (SVN 2^32-1) signed with the stolen key 1: rejected");

    // The window that rotation leaves: a device learns of key 2 only from an update signed by it.
    // The attacker's firmware runs on such a device; what the boot loader must still do is take
    // the vendor's next release, which a higher key version allows whatever SVN key 1 signed.
    const Verdict window = install_update(late, evil);
    check(window.accepted() && late.min_svn == kMaxSvn,
          "on a device without 1.4.0 yet, the same image: installed (the window)", "boot loader: " + window.reason);
    const Verdict closed = install_update(late, package_140);
    check(closed.accepted() && late.min_key_version == 2 && late.min_svn == 4,
          "that device then installs 1.4.0 (key version 2 starts a new SVN sequence)",
          "boot loader: " + closed.reason);
    expect_rejection(late, evil, Check::key_version, "and from then on rejects the image signed with key 1");
}

void recovery(const Vendor& v, const Device& dev, int runs) {
    std::printf("\n8. a recovery image signed by the root with HashSLH-DSA (PH = SHA2-256)\n");
    const Bytes image = make_recovery_image(kDeviceModel, "R1");
    auto t0 = Clock::now();
    const Bytes package = v.root->sign_recovery(image);
    std::printf("  the root signs the %zu-byte image (SLH-DSA-SHA2-128s HashSLH-DSA Sign %.0f ms)\n", image.size(),
                ms(Clock::now() - t0));

    const Verdict verdict = verify_recovery(dev, package);
    check(verdict.accepted(), "the recovery image verifies under the root key in ROM",
          "boot loader: " + verdict.reason);
    t0 = Clock::now();
    for (int i = 0; i < runs; i++)
        if (!verify_recovery(dev, package).accepted()) fail("a timed recovery verification was rejected");
    std::printf("  verification time, mean of %d: %.2f ms (SHA-256 of 8 MiB, then SLH-DSA Verify)\n", runs,
                ms(Clock::now() - t0) / runs);
    std::printf("  (recovery images are not rollback-protected here; a real design gives them a counter)\n");

    // One bit of the payload flipped: SHA-256 gives another PH(M), and the signature fails
    Bytes modified = package;
    modified[4 + image.size() / 2] ^= 0x01;
    const Verdict bad = verify_recovery(dev, modified);
    check(bad.failed == Check::recovery, "the recovery image with one bit flipped: rejected",
          "boot loader: " + bad.reason);

    // Key 1's certificate (tbs and the root's SLH-DSA signature) as a recovery package: the root
    // signed it, but as pure SLH-DSA under another context string
    Signed cert;
    if (!parse_signed(v.key1->certificate, cert)) fail("cannot parse key 1's certificate");
    Writer w;
    w.vec(cert.body, 4).vec(cert.signature, 2);
    const Verdict cross = verify_recovery(dev, w.out);
    check(cross.failed == Check::recovery, "key 1's certificate and root signature as a recovery package: rejected",
          "boot loader: " + cross.reason);
}

void usage(std::FILE* f) {
    std::fprintf(f, "usage: secure_boot [runs]\n"
                    "  runs  number of timed repetitions of an ML-DSA-65 manifest signature, an update\n"
                    "        verification and a recovery verification (together about 50 ms on one core),\n"
                    "        whose times are averaged, 1 to 10000 (default 10)\n");
}

void run(int runs) {
    std::printf("secure_boot: firmware updates with an SLH-DSA-SHA2-128s root key and ML-DSA-65 release keys\n"
                "Demonstration only: the certificate, manifest and package formats are this program's own.\n");

    Vendor v;
    auto t0 = Clock::now();
    v.root = std::make_unique<RootKey>("the vendor's root key");
    const double root_keygen = ms(Clock::now() - t0);
    t0 = Clock::now();
    v.key1 = std::make_unique<ReleaseKey>("release key 1", 1, 1);
    const double key1_keygen = ms(Clock::now() - t0);
    t0 = Clock::now();
    v.key1->certificate = v.root->certify(*v.key1, kCertifiedModels, kCertifiedTypes);
    const double certify = ms(Clock::now() - t0);

    v.package_130 = v.key1->release(kDeviceModel, kMainFirmware, 3, "1.3.0",
                                    make_image("GW-100 main firmware 1.3.0", kImageBytes));
    v.package_120 = v.key1->release(kDeviceModel, kMainFirmware, 2, "1.2.0",
                                    make_image("GW-100 main firmware 1.2.0", kImageBytes));

    const Package p = parts(v.package_130);
    Signed manifest;
    Manifest fields;
    if (!parse_signed(p.manifest, manifest) || !parse_manifest(manifest.body, fields))
        fail("cannot parse the manifest of 1.3.0");
    // ML-DSA signing repeats a loop a random number of times (rejection sampling): a mean
    t0 = Clock::now();
    for (int i = 0; i < runs; i++) v.key1->sign_manifest(fields);
    const double manifest_sign = ms(Clock::now() - t0) / runs;

    std::printf("\nVendor keys (times on one CPU core)\n");
    std::printf("  root key       SLH-DSA-SHA2-128s: KeyGen %.0f ms, Sign %.0f ms (key 1's certificate)\n",
                root_keygen, certify);
    std::printf("  release key 1  ML-DSA-65: KeyGen %.2f ms, Sign %.2f ms (a manifest, mean of %d); key version 1,\n"
                "                 certified for GW-100 and GW-200, main and radio firmware\n",
                key1_keygen, manifest_sign, runs);
    std::printf("Why these schemes\n"
                "  root key: SLH-DSA rests on SHA-256 alone, for a key that devices trust for 10-20 years; its\n"
                "    32-byte public key fits in ROM or fuses; its slow signing is spent a few times a year\n"
                "  release keys: ML-DSA-65 signs each release fast; a compromised key is replaced by the root\n"
                "    and retired through the devices' minimum key version (scenario 7)\n");
    std::printf("Sizes in bytes\n");
    std::printf("  root public key (device ROM) %9zu  (the device's two counters are in replay-protected storage)\n",
                RootDSA::public_key_bytes);
    std::printf("  key certificate             %10zu  (ML-DSA-65 public key %zu, SLH-DSA signature %zu)\n",
                p.certificate.size(), ReleaseDSA::public_key_bytes, RootDSA::signature_bytes);
    std::printf("  signed manifest             %10zu  (manifest %zu, ML-DSA-65 signature %zu)\n", p.manifest.size(),
                manifest.body.size(), ReleaseDSA::signature_bytes);
    std::printf("  update package              %10zu  (certificate, manifest, %zu-byte image)\n",
                v.package_130.size(), kImageBytes);
    std::printf("  recovery signature          %10zu  (HashSLH-DSA over an 8 MiB image)\n", RootDSA::signature_bytes);

    Device dev{std::string(kDeviceModel), v.root->pk, 2, 1, "1.2.0", 2};
    std::printf("\nDevice %s: %s\n", dev.model.c_str(), state(dev).c_str());
    std::printf("Boot loader checks: 1 key certificate (SLH-DSA, root key in ROM), 2 key version, 3 manifest\n"
                "(ML-DSA-65, certified key), 4 image hash (SHA3-256), 5 model and image type, 6 SVN (within\n"
                "the key version: a higher key version starts a new SVN sequence)\n");

    honest_update(v, dev, runs);
    modified_image(v, dev);
    uncertified_key(v, dev);
    forged_certificates(v, dev);
    rollback(v, dev);
    wrong_model_or_type(v, dev);
    key_rotation(v, dev);
    recovery(v, dev, runs);
}

} // namespace

int main(int argc, char** argv) {
    int runs = 10;
    if (argc == 2 && (std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h")) {
        usage(stdout);
        return 0;
    }
    if (argc > 2) {
        usage(stderr);
        return 1;
    }
    if (argc == 2) {
        char* end = nullptr;
        const long v = std::strtol(argv[1], &end, 10);
        if (*argv[1] == '\0' || *end != '\0' || v < 1 || v > 10000) {
            std::fprintf(stderr, "secure_boot: runs must be an integer from 1 to 10000\n");
            return 1;
        }
        runs = static_cast<int>(v);
    }

    try {
        run(runs);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "secure_boot: %s\n", e.what());
        return 1;
    }
    if (g_failures != 0) {
        std::fprintf(stderr, "secure_boot: %d checks FAILED\n", g_failures);
        return 1;
    }
    std::printf("\nall scenarios ended as expected\n");
    return 0;
}
