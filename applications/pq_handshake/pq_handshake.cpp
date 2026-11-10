/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * pq_handshake.cpp  --  a TLS 1.3-like authenticated key exchange from ML-KEM-768 and ML-DSA
 *
 * A client and a server, two objects in one process that exchange nothing but byte strings
 * (the wire), run a handshake shaped like TLS 1.3 (RFC 8446) with post-quantum algorithms only:
 *
 *   client -> server  ClientHello          client random, server name, ML-KEM-768 encapsulation key
 *   server -> client  ServerHello          server random, ML-KEM ciphertext (Encaps against that key)
 *   server -> client  {Certificate}        server name, validity, ML-DSA-65 public key; signed by
 *                                          a root CA with ML-DSA-87
 *   server -> client  {CertificateVerify}  ML-DSA-65 signature over the transcript hash
 *   server -> client  {Finished}           MAC over the transcript hash
 *   client -> server  {Finished}           MAC over the transcript hash
 *   both directions   [application data]
 *
 * {} marks records protected with the handshake traffic keys, [] with the application traffic
 * keys. Both sides obtain the ML-KEM shared secret K. The transcript hash is SHA3-256 over all
 * handshake messages so far, each preceded by its length. The key schedule has the shape of
 * TLS 1.3's (RFC 8446, Section 7.1) but is simplified (see KeySchedule): demo_kdf in place of
 * HKDF, and no early secret, no "derived" steps and no Extract/Expand split. A handshake secret
 * comes from K, and from it and the transcript hash one traffic secret per direction, each giving
 * a record key, an IV and a Finished key; a master secret from the handshake secret gives the
 * application traffic secrets the same way. Records are protected with demo_seal; the nonce is
 * the IV XOR the record sequence number of that direction, which is not sent, so a record is
 * accepted only once and only in order. The client trusts nothing but the root CA's public key.
 *
 * The program runs six scenarios and checks that each ends as it should:
 *   1. an honest handshake: both sides derive the same application keys, records flow both ways
 *   2. a man in the middle replaces the client's key share with its own: it then shares a K with
 *      each side and can read and re-encrypt the server's flight, but the client rejects the
 *      server's CertificateVerify, whose signature covers the server's transcript, not the client's
 *   3. the server's ML-KEM ciphertext is modified: Decaps gives no error (implicit rejection)
 *      but a different K. Certificate, CertificateVerify and Finished travel under keys derived
 *      from K, so the client already rejects the first of these records, and the handshake fails
 *   4. a certificate signed by an untrusted CA is rejected (and an expired one, and one issued
 *      for another server name)
 *   5. a modified application record fails demo_open
 *   6. a replayed and a reordered application record are rejected
 *
 * This is a demonstration, not TLS, and not for production. Deployments use hybrid key exchange
 * (X25519MLKEM768 in TLS 1.3), so that the connection stays secure if either algorithm is broken,
 * and standardized AEADs and KDFs (AES-GCM or ChaCha20-Poly1305, HKDF). OpenPQC provides neither
 * X25519 nor an AEAD: all symmetric cryptography here is demo_sym.h's SHAKE256 KDF and
 * encrypt-then-MAC construction, a demo construction, not a standardized AEAD. There is no
 * negotiation, resumption, client authentication, key update, or alert sent on the wire.
 *
 * usage: pq_handshake [handshakes]
 *   handshakes  number of honest handshakes whose time is averaged, 1 to 100000 (default 20)
 *   --help, -h  print the usage and exit
 *
 * Prints the setup of the PKI, the size of each handshake message on the wire with the total,
 * the mean time of a handshake, and one line per check with ok or FAILED (failed checks are
 * also reported on stderr). Exits with 0 if every scenario ended as expected, the expected
 * rejections included, and 1 otherwise.
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "Core/openpqc_core.h"
#include "demo_sym.h"
#include "openpqc/openpqc.hpp"

namespace {

using KEM = openpqc::ML_KEM_768;
using CaDSA = openpqc::ML_DSA_87;     // the root CA's signatures on certificates
using ServerDSA = openpqc::ML_DSA_65; // the server's key, in its certificate

using Bytes = std::vector<std::uint8_t>;
using View = std::span<const std::uint8_t>;
using Hash = std::array<std::uint8_t, 32>;

// Code points of the TLS registries for the ML-KEM-768 group and the ML-DSA signature schemes
constexpr std::uint16_t kGroupMLKEM768 = 0x0201;
constexpr std::uint16_t kSigMLDSA65 = 0x0905;
constexpr std::uint16_t kSigMLDSA87 = 0x0906;

// Record content types and handshake message types, with TLS 1.3's values
constexpr std::uint8_t kContentHandshake = 22;
constexpr std::uint8_t kContentApplicationData = 23;
constexpr std::uint8_t kClientHello = 1;
constexpr std::uint8_t kServerHello = 2;
constexpr std::uint8_t kCertificate = 11;
constexpr std::uint8_t kCertificateVerify = 15;
constexpr std::uint8_t kFinished = 20;

// ML-DSA signs the context string with the message (FIPS 204, Algorithm 2, line 10), so a
// signature made for one purpose does not verify for the other. TLS 1.3 gets the same
// separation by signing 64 spaces || "TLS 1.3, server CertificateVerify" || 0 || transcript hash.
constexpr std::string_view kCertificateContext = "openpqc-demo certificate";
constexpr std::string_view kCertificateVerifyContext = "openpqc-demo server CertificateVerify";

constexpr std::string_view kRootName = "OpenPQC Demo Root CA";
constexpr std::string_view kServerName = "server.example";
// The demo's clock is fixed, so that the run does not depend on the date. Validity dates are
// plain integers YYYYMMDD, which compare like the dates.
constexpr std::uint32_t kToday = 20261021;
constexpr std::uint32_t kValidFrom = 20260101;
constexpr std::uint32_t kValidUntil = 20271231;

View view(std::string_view s) { return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()}; }
std::string_view text(View v) { return {reinterpret_cast<const char*>(v.data()), v.size()}; }

[[noreturn]] void fatal(const std::string& what) {
    std::fprintf(stderr, "pq_handshake: %s\n", what.c_str());
    std::exit(1);
}

void require(openpqc::status s, const char* what) {
    if (s != openpqc::status::ok) fatal(std::string(what) + " failed (" + openpqc::to_string(s) + ")");
}

// Secret bytes (traffic secrets, keys, IVs): openpqc::secret<N>, zeroized when their lifetime ends,
// not copyable, so that no copy is left behind, and compared in constant time (==). The private
// keys and shared secrets of the schemes (KEM::secret_key, KEM::shared_secret, ...) are of this
// type too.
template <std::size_t N>
using Secret = openpqc::secret<N>;

// --- Encoding: big-endian integers and length-prefixed byte strings, as in TLS ----------------

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
        if (n < 8 && (v >> (8 * n)) != 0) fatal("a field does not fit its length prefix");
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

// A handshake message: type (1 byte) || length (3 bytes) || body
Bytes handshake_message(std::uint8_t type, View body) {
    Writer w;
    w.u8(type).vec(body, 3);
    return w.out;
}

bool split_handshake(View msg, std::uint8_t& type, View& body) {
    Reader r(msg);
    type = r.u8();
    body = r.vec(3);
    return r.done();
}

const char* message_name(std::uint8_t type) {
    switch (type) {
    case kClientHello: return "ClientHello";
    case kServerHello: return "ServerHello";
    case kCertificate: return "Certificate";
    case kCertificateVerify: return "CertificateVerify";
    case kFinished: return "Finished";
    default: return "an unknown message";
    }
}

// A record: content type (1 byte) || length (2 bytes) || payload. ClientHello and ServerHello
// travel in plaintext records of type handshake; every later record is protected (Traffic::seal).
Bytes plaintext_record(View msg) {
    Writer w;
    w.u8(kContentHandshake).vec(msg, 2);
    return w.out;
}

bool split_plaintext_record(View record, View& msg) {
    Reader r(record);
    const std::uint8_t type = r.u8();
    msg = r.vec(2);
    return r.done() && type == kContentHandshake;
}

struct ClientHello {
    View random;
    std::string_view server_name;
    std::uint16_t group = 0;
    View key_share; // the ML-KEM encapsulation key
};

Bytes encode_client_hello(View random, std::string_view server_name, View key_share) {
    Writer w;
    w.raw(random).vec(view(server_name), 1).u16(kGroupMLKEM768).vec(key_share, 2);
    return handshake_message(kClientHello, w.out);
}

bool decode_client_hello(View msg, ClientHello& ch) {
    std::uint8_t type = 0;
    View body;
    if (!split_handshake(msg, type, body) || type != kClientHello) return false;
    Reader r(body);
    ch.random = r.raw(32);
    ch.server_name = text(r.vec(1));
    ch.group = r.u16();
    ch.key_share = r.vec(2);
    return r.done();
}

struct ServerHello {
    View random;
    std::uint16_t group = 0;
    View ciphertext;
};

Bytes encode_server_hello(View random, View ciphertext) {
    Writer w;
    w.raw(random).u16(kGroupMLKEM768).vec(ciphertext, 2);
    return handshake_message(kServerHello, w.out);
}

bool decode_server_hello(View msg, ServerHello& sh) {
    std::uint8_t type = 0;
    View body;
    if (!split_handshake(msg, type, body) || type != kServerHello) return false;
    Reader r(body);
    sh.random = r.raw(32);
    sh.group = r.u16();
    sh.ciphertext = r.vec(2);
    return r.done();
}

// --- Certificates ------------------------------------------------------------------------------
//
//   tbs  = version (1) || serial (4) || issuer name || subject name || not_before (4) ||
//          not_after (4) || key algorithm (2) || public key        (names: 1-byte length prefix,
//                                                                   public key: 2-byte prefix)
//   cert = tbs (2-byte length prefix) || signature algorithm (2) || signature (2-byte prefix)
//
// The signature is ML-DSA-87 over tbs with the context string kCertificateContext.

struct Certificate {
    View tbs;
    std::uint8_t version = 0;
    std::uint32_t serial = 0;
    std::string_view issuer, subject;
    std::uint32_t not_before = 0, not_after = 0;
    std::uint16_t key_algorithm = 0;
    View public_key;
    std::uint16_t signature_algorithm = 0;
    View signature;
};

bool parse_certificate(View encoding, Certificate& c) {
    Reader outer(encoding);
    c.tbs = outer.vec(2);
    c.signature_algorithm = outer.u16();
    c.signature = outer.vec(2);
    Reader r(c.tbs);
    c.version = r.u8();
    c.serial = r.u32();
    c.issuer = text(r.vec(1));
    c.subject = text(r.vec(1));
    c.not_before = r.u32();
    c.not_after = r.u32();
    c.key_algorithm = r.u16();
    c.public_key = r.vec(2);
    return outer.done() && r.done() && c.version == 1;
}

struct CertificateAuthority {
    std::string name;
    CaDSA::public_key pk{};
    CaDSA::secret_key sk;
    std::uint32_t next_serial = 1;

    explicit CertificateAuthority(std::string_view n) : name(n) {
        require(CaDSA::keygen(pk, sk), "ML-DSA-87 KeyGen (CA)");
    }

    Bytes issue(std::string_view subject, std::uint32_t not_before, std::uint32_t not_after,
                const ServerDSA::public_key& key) {
        Writer tbs;
        tbs.u8(1).u32(next_serial++).vec(view(name), 1).vec(view(subject), 1);
        tbs.u32(not_before).u32(not_after).u16(kSigMLDSA65).vec(key, 2);
        CaDSA::signature sig;
        require(CaDSA::sign(sig, tbs.out, sk, view(kCertificateContext)), "ML-DSA-87 Sign (certificate)");
        Writer cert;
        cert.vec(tbs.out, 2).u16(kSigMLDSA87).vec(sig, 2);
        return cert.out;
    }
};

// What the client trusts: a root CA's name and public key, installed out of band
struct TrustAnchor {
    std::string name;
    CaDSA::public_key pk;
};

// The server's long-term key pair and its certificate
struct ServerIdentity {
    ServerDSA::public_key pk{};
    ServerDSA::secret_key sk;
    Bytes certificate;

    ServerIdentity() { require(ServerDSA::keygen(pk, sk), "ML-DSA-65 KeyGen (server)"); }
};

// --- Transcript hash, key schedule, record layer -----------------------------------------------

// SHA3-256 over len(m1) || m1 || len(m2) || m2 || ..., lengths as 4 bytes, big-endian. The
// sponge absorbs each message once; hash() finalizes a copy, so the transcript can grow after.
class Transcript {
public:
    Transcript() { opqc_sponge_init(&sponge_, OPQC_SHA3_256_RATE); }

    void add(View msg) {
        const std::uint64_t n = msg.size();
        const std::uint8_t len[4] = {static_cast<std::uint8_t>(n >> 24), static_cast<std::uint8_t>(n >> 16),
                                     static_cast<std::uint8_t>(n >> 8), static_cast<std::uint8_t>(n)};
        opqc_sponge_absorb(&sponge_, len, sizeof len);
        opqc_sponge_absorb(&sponge_, msg.data(), msg.size());
    }

    Hash hash() const {
        opqc_sponge s = sponge_;
        Hash h;
        opqc_sponge_finalize(&s, OPQC_SHA3_SUFFIX);
        opqc_sponge_squeeze(&s, h.data(), h.size());
        return h;
    }

private:
    opqc_sponge sponge_;
};

// demo_kdf with the label prefixed, as TLS 1.3 prefixes its labels with "tls13 "
template <std::size_t N>
void kdf(Secret<N>& out, std::string_view label, View ikm, View info) {
    const std::string full = "openpqc-demo " + std::string(label);
    demo_kdf(out.data(), N, full.c_str(), ikm.data(), ikm.size(), info.data(), info.size());
}

// The value of a Finished message (RFC 8446, Section 4.4.4, with demo_kdf in place of HMAC)
Hash finished_mac(const Secret<32>& finished_key, const Hash& transcript_hash) {
    Hash mac;
    demo_kdf(mac.data(), mac.size(), "openpqc-demo finished mac", finished_key.data(), 32, transcript_hash.data(),
             transcript_hash.size());
    return mac;
}

// TLS alert names for the reasons a handshake or a record is rejected (RFC 8446, Section 6.2)
enum class Alert {
    none,
    unexpected_message,
    bad_record_mac,
    decode_error,
    illegal_parameter,
    bad_certificate,
    certificate_expired,
    unknown_ca,
    decrypt_error,
    internal_error,
};

const char* alert_name(Alert a) {
    switch (a) {
    case Alert::none: return "none";
    case Alert::unexpected_message: return "unexpected_message";
    case Alert::bad_record_mac: return "bad_record_mac";
    case Alert::decode_error: return "decode_error";
    case Alert::illegal_parameter: return "illegal_parameter";
    case Alert::bad_certificate: return "bad_certificate";
    case Alert::certificate_expired: return "certificate_expired";
    case Alert::unknown_ca: return "unknown_ca";
    case Alert::decrypt_error: return "decrypt_error";
    case Alert::internal_error: return "internal_error";
    }
    return "?";
}

// One direction of the record layer: a traffic secret, the record key, IV and Finished key
// derived from it, and the sequence number of the next record
struct Traffic {
    Secret<32> secret, key, finished_key;
    Secret<DEMO_NONCE_BYTES> iv;
    std::uint64_t seq = 0;

    void derive(std::string_view label, const Secret<32>& base, const Hash& transcript_hash) {
        kdf(secret, label, base.span(), transcript_hash);
        kdf(key, "key", secret.span(), {});
        kdf(iv, "iv", secret.span(), {});
        kdf(finished_key, "finished", secret.span(), {});
        seq = 0;
    }

    // The per-record nonce of RFC 8446, Section 5.3: the IV XOR the 64-bit sequence number.
    // The receiver counts the records itself, so a replayed, reordered or dropped record is
    // opened with the wrong nonce and fails authentication.
    std::array<std::uint8_t, DEMO_NONCE_BYTES> nonce() const {
        std::array<std::uint8_t, DEMO_NONCE_BYTES> n;
        std::copy(iv.begin(), iv.end(), n.begin());
        for (unsigned i = 0; i < 8; i++) n[DEMO_NONCE_BYTES - 1 - i] ^= static_cast<std::uint8_t>(seq >> (8 * i));
        return n;
    }

    // record = 23 || length || demo_seal(content || content_type), the record header as
    // associated data (TLS 1.3's TLSInnerPlaintext, without padding)
    Bytes seal(std::uint8_t content_type, View content) {
        if (seq == UINT64_MAX) fatal("record sequence number exhausted");
        Bytes inner(content.begin(), content.end());
        inner.push_back(content_type);
        const std::size_t len = inner.size() + DEMO_TAG_BYTES;
        if (len > 0xFFFF) fatal("record too long");
        Bytes record(3 + len);
        record[0] = kContentApplicationData;
        record[1] = static_cast<std::uint8_t>(len >> 8);
        record[2] = static_cast<std::uint8_t>(len);
        const auto n = nonce();
        demo_seal(record.data() + 3, key.data(), n.data(), record.data(), 3, inner.data(), inner.size());
        opqc_zeroize(inner.data(), inner.size());
        seq++;
        return record;
    }

    Alert open(View record, std::uint8_t& content_type, Bytes& content) {
        if (record.size() < 3 + DEMO_TAG_BYTES + 1 || record[0] != kContentApplicationData ||
            ((std::size_t{record[1]} << 8) | record[2]) != record.size() - 3) {
            return Alert::decode_error;
        }
        Bytes inner(record.size() - 3 - DEMO_TAG_BYTES);
        const auto n = nonce();
        if (demo_open(inner.data(), key.data(), n.data(), record.data(), 3, record.data() + 3, record.size() - 3) != 0)
            return Alert::bad_record_mac;
        seq++;
        content_type = inner.back();
        inner.pop_back();
        content = std::move(inner);
        return Alert::none;
    }
};

// The key schedule of RFC 8446, Section 7.1, simplified. demo_kdf, one SHAKE256 call over a
// secret and its context, takes the place of both HKDF-Extract and HKDF-Expand-Label; there is
// no early secret (without a PSK it is a constant) and no Derive-Secret(., "derived", "") step:
//   handshake secret = KDF("handshake secret", K)
//   c/s hs traffic   = KDF("c hs traffic" / "s hs traffic", handshake secret, TH(ClientHello..ServerHello))
//   master secret    = KDF("master secret", handshake secret)
//   c/s ap traffic   = KDF("c ap traffic" / "s ap traffic", master secret, TH(ClientHello..server Finished))
// The client writes with the c keys and reads with the s keys; the server the other way round.
struct KeySchedule {
    Secret<32> handshake_secret;
    Traffic hs_client, hs_server, ap_client, ap_server;

    void handshake(const Secret<32>& k, const Hash& transcript_hash) {
        kdf(handshake_secret, "handshake secret", k.span(), {});
        hs_client.derive("c hs traffic", handshake_secret, transcript_hash);
        hs_server.derive("s hs traffic", handshake_secret, transcript_hash);
    }

    void application(const Hash& transcript_hash) {
        Secret<32> master;
        kdf(master, "master secret", handshake_secret.span(), {});
        ap_client.derive("c ap traffic", master, transcript_hash);
        ap_server.derive("s ap traffic", master, transcript_hash);
    }
};

bool same_keys(const Traffic& a, const Traffic& b) {
    return a.secret == b.secret && a.key == b.key && a.iv == b.iv;
}

// --- Client and server -------------------------------------------------------------------------

// A record leaving an endpoint, with the name it gets in the printout
struct Outgoing {
    const char* label;
    Bytes record;
};

// What client and server share: the transcript, K, the keys, application data and failure.
// A failure is final: the connection is closed and every later record is rejected.
class Endpoint {
public:
    bool connected() const { return connected_; }
    bool failed() const { return alert_ != Alert::none; }
    Alert alert() const { return alert_; }
    std::string failure() const { return std::string(alert_name(alert_)) + ": " + reason_; }

    // For the demo's checks only: a real endpoint never shows its secrets
    const KEM::shared_secret& shared_secret() const { return k_; }
    const KeySchedule& keys() const { return keys_; }

    Bytes send(std::string_view data) {
        if (!connected_) fatal("application data before the handshake completed");
        return ap_write().seal(kContentApplicationData, view(data));
    }

    std::vector<std::string> received; // application data, in the order it was accepted

protected:
    explicit Endpoint(bool is_client) : is_client_(is_client) {}

    Traffic& hs_write() { return is_client_ ? keys_.hs_client : keys_.hs_server; }
    Traffic& hs_read() { return is_client_ ? keys_.hs_server : keys_.hs_client; }
    Traffic& ap_write() { return is_client_ ? keys_.ap_client : keys_.ap_server; }
    Traffic& ap_read() { return is_client_ ? keys_.ap_server : keys_.ap_client; }

    bool fail(Alert a, std::string why) {
        alert_ = a;
        reason_ = std::move(why);
        connected_ = false;
        return false;
    }

    // Opens a protected record that must hold one handshake message of type expected; msg gets
    // the message (for the transcript), body points into it
    bool open_handshake(View record, std::uint8_t expected, Bytes& msg, View& body) {
        std::uint8_t content_type = 0;
        if (const Alert a = hs_read().open(record, content_type, msg); a != Alert::none) {
            return fail(a, std::string("the record that should hold ") + message_name(expected) +
                                   (a == Alert::decode_error ? " is malformed" : " fails demo_open"));
        }
        std::uint8_t type = 0;
        if (content_type != kContentHandshake || !split_handshake(msg, type, body))
            return fail(Alert::decode_error, std::string("malformed ") + message_name(expected));
        if (type != expected) {
            return fail(Alert::unexpected_message,
                        std::string(message_name(type)) + " where " + message_name(expected) + " belongs");
        }
        return true;
    }

    bool receive_application(View record) {
        std::uint8_t content_type = 0;
        Bytes content;
        const std::uint64_t seq = ap_read().seq;
        if (const Alert a = ap_read().open(record, content_type, content); a == Alert::decode_error) {
            return fail(a, "a malformed application record");
        } else if (a != Alert::none) {
            return fail(a, "an application record fails demo_open as record " + std::to_string(seq) +
                                   ", the next in sequence");
        }
        if (content_type != kContentApplicationData)
            return fail(Alert::unexpected_message, "a record that is not application data");
        received.emplace_back(text(content));
        return true;
    }

    Transcript transcript_;
    KEM::shared_secret k_; // the ML-KEM shared secret K
    KeySchedule keys_;
    bool connected_ = false;

private:
    bool is_client_;
    Alert alert_ = Alert::none;
    std::string reason_;
};

class Client : public Endpoint {
public:
    enum class State { start, wait_server_hello, wait_certificate, wait_certificate_verify, wait_finished, connected };

    Client(const TrustAnchor& root, std::string_view server_name, std::uint32_t today)
        : Endpoint(true), root_(root), server_name_(server_name), today_(today) {}

    State state() const { return state_; }
    openpqc::status decaps_result() const { return decaps_status_; }

    // ClientHello with a fresh ML-KEM-768 key pair: the key share is ephemeral, used for this
    // handshake only, so that recording the traffic and later stealing the server's long-term
    // ML-DSA key reveals nothing (forward secrecy)
    bool start(std::vector<Outgoing>& out) {
        std::array<std::uint8_t, 32> random{};
        if (opqc_randombytes(random.data(), random.size()) != 0)
            return fail(Alert::internal_error, "no randomness for the client random");
        if (const openpqc::status s = KEM::keygen(ek_, dk_); s != openpqc::status::ok)
            return fail(Alert::internal_error, std::string("ML-KEM-768 KeyGen failed (") + openpqc::to_string(s) + ")");
        const Bytes hello = encode_client_hello(random, server_name_, ek_);
        transcript_.add(hello);
        out.push_back({"ClientHello", plaintext_record(hello)});
        state_ = State::wait_server_hello;
        return true;
    }

    bool receive(View record, std::vector<Outgoing>& out) {
        if (failed()) return false;
        switch (state_) {
        case State::wait_server_hello: return on_server_hello(record);
        case State::wait_certificate: return on_certificate(record);
        case State::wait_certificate_verify: return on_certificate_verify(record);
        case State::wait_finished: return on_finished(record, out);
        case State::connected: return receive_application(record);
        case State::start: break;
        }
        return fail(Alert::unexpected_message, "a record before ClientHello was sent");
    }

private:
    bool on_server_hello(View record) {
        View msg;
        ServerHello hello;
        if (!split_plaintext_record(record, msg) || !decode_server_hello(msg, hello))
            return fail(Alert::decode_error, "malformed ServerHello");
        if (hello.group != kGroupMLKEM768 || hello.ciphertext.size() != KEM::ciphertext_bytes)
            return fail(Alert::illegal_parameter, "ServerHello without an ML-KEM-768 ciphertext");
        // A modified ciphertext is not an error here: Decaps returns a pseudorandom K instead
        // (implicit rejection, FIPS 203, Algorithm 18), and the keys from it fail later
        decaps_status_ = KEM::decaps(k_, hello.ciphertext.first<KEM::ciphertext_bytes>(), dk_);
        dk_.wipe(); // the key share is used once
        if (decaps_status_ != openpqc::status::ok)
            return fail(Alert::internal_error,
                        std::string("ML-KEM-768 Decaps failed (") + openpqc::to_string(decaps_status_) + ")");
        transcript_.add(msg);
        keys_.handshake(k_, transcript_.hash());
        state_ = State::wait_certificate;
        return true;
    }

    // The certificate is accepted only if its signature verifies under the root key. The issuer
    // name selects the trust anchor but proves nothing: anyone can write any name.
    bool on_certificate(View record) {
        Bytes msg;
        View body;
        if (!open_handshake(record, kCertificate, msg, body)) return false;
        Reader r(body);
        const View encoding = r.vec(3);
        Certificate cert;
        if (!r.done() || !parse_certificate(encoding, cert)) return fail(Alert::bad_certificate, "malformed certificate");
        if (cert.issuer != root_.name)
            return fail(Alert::unknown_ca, "issuer '" + std::string(cert.issuer) + "' is not a trusted root");
        if (cert.signature_algorithm != kSigMLDSA87 ||
            CaDSA::verify(cert.signature, cert.tbs, root_.pk, view(kCertificateContext)) != openpqc::status::ok) {
            return fail(Alert::bad_certificate, "the issuer's signature does not verify under the trusted root key");
        }
        if (cert.subject != server_name_) {
            return fail(Alert::bad_certificate,
                        "issued to " + std::string(cert.subject) + ", not to " + std::string(server_name_));
        }
        if (today_ < cert.not_before || today_ > cert.not_after) {
            return fail(Alert::certificate_expired, "valid " + std::to_string(cert.not_before) + ".." +
                                                            std::to_string(cert.not_after) + ", today is " +
                                                            std::to_string(today_));
        }
        if (cert.key_algorithm != kSigMLDSA65 || cert.public_key.size() != ServerDSA::public_key_bytes)
            return fail(Alert::bad_certificate, "the certificate's key is not an ML-DSA-65 key");
        std::copy(cert.public_key.begin(), cert.public_key.end(), server_pk_.begin());
        transcript_.add(msg);
        state_ = State::wait_certificate_verify;
        return true;
    }

    // The signature covers the transcript hash, which contains both randoms and both key
    // shares as this client saw them: only the holder of the certificate's key can make it, and
    // only for this handshake
    bool on_certificate_verify(View record) {
        Bytes msg;
        View body;
        if (!open_handshake(record, kCertificateVerify, msg, body)) return false;
        Reader r(body);
        const std::uint16_t algorithm = r.u16();
        const View sig = r.vec(2);
        if (!r.done()) return fail(Alert::decode_error, "malformed CertificateVerify");
        if (algorithm != kSigMLDSA65) return fail(Alert::illegal_parameter, "CertificateVerify is not ML-DSA-65");
        const Hash th = transcript_.hash(); // ClientHello..Certificate
        if (ServerDSA::verify(sig, th, server_pk_, view(kCertificateVerifyContext)) != openpqc::status::ok) {
            return fail(Alert::decrypt_error, "the signature does not verify over the client's transcript hash");
        }
        transcript_.add(msg);
        state_ = State::wait_finished;
        return true;
    }

    bool on_finished(View record, std::vector<Outgoing>& out) {
        Bytes msg;
        View body;
        if (!open_handshake(record, kFinished, msg, body)) return false;
        const Hash expected = finished_mac(keys_.hs_server.finished_key, transcript_.hash());
        if (body.size() != expected.size() || opqc_ct_memcmp(body.data(), expected.data(), expected.size()) != 0)
            return fail(Alert::decrypt_error, "the server's Finished does not match the client's transcript");
        transcript_.add(msg);
        const Hash th = transcript_.hash(); // ClientHello..server Finished
        keys_.application(th);
        const Hash mac = finished_mac(keys_.hs_client.finished_key, th);
        const Bytes fin = handshake_message(kFinished, mac);
        transcript_.add(fin);
        out.push_back({"{Finished}", hs_write().seal(kContentHandshake, fin)});
        state_ = State::connected;
        connected_ = true;
        return true;
    }

    const TrustAnchor& root_;
    std::string_view server_name_;
    std::uint32_t today_;
    State state_ = State::start;
    KEM::public_key ek_{};
    KEM::secret_key dk_;
    ServerDSA::public_key server_pk_{};
    openpqc::status decaps_status_ = openpqc::status::not_computed;
};

class Server : public Endpoint {
public:
    enum class State { wait_client_hello, wait_finished, connected };

    explicit Server(const ServerIdentity& identity) : Endpoint(false), id_(identity) {}

    State state() const { return state_; }

    bool receive(View record, std::vector<Outgoing>& out) {
        if (failed()) return false;
        switch (state_) {
        case State::wait_client_hello: return on_client_hello(record, out);
        case State::wait_finished: return on_finished(record);
        case State::connected: return receive_application(record);
        }
        return false;
    }

private:
    // Answers ClientHello with the whole server flight: ServerHello, {Certificate},
    // {CertificateVerify}, {Finished}
    bool on_client_hello(View record, std::vector<Outgoing>& out) {
        View msg;
        ClientHello hello;
        if (!split_plaintext_record(record, msg) || !decode_client_hello(msg, hello))
            return fail(Alert::decode_error, "malformed ClientHello");
        if (hello.group != kGroupMLKEM768 || hello.key_share.size() != KEM::public_key_bytes)
            return fail(Alert::illegal_parameter, "ClientHello without an ML-KEM-768 key share");
        transcript_.add(msg);

        std::array<std::uint8_t, 32> random{};
        if (opqc_randombytes(random.data(), random.size()) != 0)
            return fail(Alert::internal_error, "no randomness for the server random");
        // Encaps checks the key share first (FIPS 203, Section 7.2)
        KEM::ciphertext ct;
        const openpqc::status es = KEM::encaps(ct, k_, hello.key_share.first<KEM::public_key_bytes>());
        if (es == openpqc::status::invalid_public_key)
            return fail(Alert::illegal_parameter, "the client's key share fails the check of FIPS 203, Section 7.2");
        if (es != openpqc::status::ok)
            return fail(Alert::internal_error,
                        std::string("ML-KEM-768 Encaps failed (") + openpqc::to_string(es) + ")");
        const Bytes server_hello = encode_server_hello(random, ct);
        transcript_.add(server_hello);
        out.push_back({"ServerHello", plaintext_record(server_hello)});
        keys_.handshake(k_, transcript_.hash());

        Writer certificate;
        certificate.vec(id_.certificate, 3);
        const Bytes cert_msg = handshake_message(kCertificate, certificate.out);
        transcript_.add(cert_msg);
        out.push_back({"{Certificate}", hs_write().seal(kContentHandshake, cert_msg)});

        ServerDSA::signature sig;
        const Hash th = transcript_.hash(); // ClientHello..Certificate
        if (const openpqc::status ss = ServerDSA::sign(sig, th, id_.sk, view(kCertificateVerifyContext));
            ss != openpqc::status::ok)
            return fail(Alert::internal_error, std::string("ML-DSA-65 Sign failed (") + openpqc::to_string(ss) + ")");
        Writer verify;
        verify.u16(kSigMLDSA65).vec(sig, 2);
        const Bytes verify_msg = handshake_message(kCertificateVerify, verify.out);
        transcript_.add(verify_msg);
        out.push_back({"{CertificateVerify}", hs_write().seal(kContentHandshake, verify_msg)});

        const Hash mac = finished_mac(keys_.hs_server.finished_key, transcript_.hash());
        const Bytes fin = handshake_message(kFinished, mac);
        transcript_.add(fin);
        out.push_back({"{Finished}", hs_write().seal(kContentHandshake, fin)});
        keys_.application(transcript_.hash()); // ClientHello..server Finished
        state_ = State::wait_finished;
        return true;
    }

    bool on_finished(View record) {
        Bytes msg;
        View body;
        if (!open_handshake(record, kFinished, msg, body)) return false;
        const Hash expected = finished_mac(keys_.hs_client.finished_key, transcript_.hash());
        if (body.size() != expected.size() || opqc_ct_memcmp(body.data(), expected.data(), expected.size()) != 0)
            return fail(Alert::decrypt_error, "the client's Finished does not match the server's transcript");
        transcript_.add(msg);
        state_ = State::connected;
        connected_ = true;
        return true;
    }

    const ServerIdentity& id_;
    State state_ = State::wait_client_hello;
};

// --- The wire ----------------------------------------------------------------------------------

enum class Dir { to_server, to_client };

// Sees every record in transit and returns the records delivered in its place
using Interceptor = std::function<std::vector<Bytes>(Dir, const Outgoing&)>;

struct WireStats {
    std::size_t records = 0, to_server = 0, to_client = 0; // bytes
    double client_s = 0, server_s = 0;                      // time spent in each endpoint
};

// Runs a handshake: delivers the client's records to the server and the server's to the
// client, through intercept if there is one, until the wire is empty or a side fails.
// Returns true if both sides completed it.
bool run_handshake(Client& client, Server& server, const Interceptor& intercept, bool print, WireStats& stats) {
    using clock = std::chrono::steady_clock;
    const auto timed = [](double& seconds, const auto& step) {
        const auto t0 = clock::now();
        const bool ok = step();
        seconds += std::chrono::duration<double>(clock::now() - t0).count();
        return ok;
    };
    std::deque<std::pair<Dir, Outgoing>> wire;
    std::vector<Outgoing> out;
    if (!timed(stats.client_s, [&] { return client.start(out); })) return false;
    for (Outgoing& o : out) wire.emplace_back(Dir::to_server, std::move(o));

    while (!wire.empty()) {
        const auto [dir, item] = std::move(wire.front());
        wire.pop_front();
        const std::vector<Bytes> delivered = intercept ? intercept(dir, item) : std::vector<Bytes>{item.record};
        for (const Bytes& record : delivered) {
            stats.records++;
            (dir == Dir::to_server ? stats.to_server : stats.to_client) += record.size();
            if (print) {
                std::printf("  %-16s  %-22s %6zu bytes\n", dir == Dir::to_server ? "client -> server" : "server -> client",
                            item.label, record.size());
            }
            out.clear();
            const bool ok = dir == Dir::to_server ? timed(stats.server_s, [&] { return server.receive(record, out); })
                                                  : timed(stats.client_s, [&] { return client.receive(record, out); });
            if (!ok) return false;
            const Dir back = dir == Dir::to_server ? Dir::to_client : Dir::to_server;
            for (Outgoing& o : out) wire.emplace_back(back, std::move(o));
        }
    }
    return client.connected() && server.connected();
}

// An active attacker between client and server (scenario 2). It replaces the client's key share
// with its own, decapsulates the server's ciphertext and encapsulates a new one against the
// client's key, so it shares one K with the server and another with the client. It holds both
// sides' handshake keys: it reads the server's flight and re-encrypts it for the client, and it
// could compute a Finished for either side. What it cannot do is sign: the server's
// CertificateVerify covers the server's transcript, which has the attacker's key share in it.
class ManInTheMiddle {
public:
    std::vector<Bytes> intercept(Dir dir, const Outgoing& item) {
        if (dir == Dir::to_server) return {client_hellos_++ == 0 ? replace_key_share(item.record) : item.record};
        return {server_records_++ == 0 ? replace_ciphertext(item.record) : reencrypt(item.record)};
    }

    KEM::shared_secret k_server, k_client; // the K it shares with the server and with the client
    KeySchedule server_side, client_side; // the keys of its connections to each
    std::string certificate_subject;      // read from the server's {Certificate}

private:
    Bytes replace_key_share(const Bytes& record) {
        View msg;
        ClientHello hello;
        if (!split_plaintext_record(record, msg) || !decode_client_hello(msg, hello))
            fatal("attacker: malformed ClientHello");
        std::copy(hello.key_share.begin(), hello.key_share.end(), client_ek_.begin());
        require(KEM::keygen(own_ek_, own_dk_), "ML-KEM-768 KeyGen (attacker)");
        const Bytes forged = encode_client_hello(hello.random, hello.server_name, own_ek_);
        client_transcript_.add(msg);
        server_transcript_.add(forged);
        return plaintext_record(forged);
    }

    Bytes replace_ciphertext(const Bytes& record) {
        View msg;
        ServerHello hello;
        if (!split_plaintext_record(record, msg) || !decode_server_hello(msg, hello) ||
            hello.ciphertext.size() != KEM::ciphertext_bytes) {
            fatal("attacker: malformed ServerHello");
        }
        require(KEM::decaps(k_server, hello.ciphertext.first<KEM::ciphertext_bytes>(), own_dk_),
                "ML-KEM-768 Decaps (attacker)");
        KEM::ciphertext ct;
        require(KEM::encaps(ct, k_client, client_ek_), "ML-KEM-768 Encaps (attacker)");
        const Bytes forged = encode_server_hello(hello.random, ct);
        server_transcript_.add(msg);
        client_transcript_.add(forged);
        server_side.handshake(k_server, server_transcript_.hash());
        client_side.handshake(k_client, client_transcript_.hash());
        return plaintext_record(forged);
    }

    Bytes reencrypt(const Bytes& record) {
        std::uint8_t content_type = 0, type = 0;
        Bytes msg;
        View body;
        if (server_side.hs_server.open(record, content_type, msg) != Alert::none || !split_handshake(msg, type, body))
            fatal("attacker: cannot open the server's record");
        server_transcript_.add(msg);
        Bytes forwarded = msg; // CertificateVerify goes on unchanged: the attacker cannot sign
        if (type == kCertificate) {
            Reader r(body);
            Certificate cert;
            if (parse_certificate(r.vec(3), cert)) certificate_subject = cert.subject;
        } else if (type == kFinished) {
            forwarded = handshake_message(kFinished, finished_mac(client_side.hs_server.finished_key,
                                                                  client_transcript_.hash()));
        }
        client_transcript_.add(forwarded);
        return client_side.hs_server.seal(kContentHandshake, forwarded);
    }

    KEM::public_key client_ek_{}, own_ek_{};
    KEM::secret_key own_dk_;
    Transcript client_transcript_, server_transcript_;
    int client_hellos_ = 0, server_records_ = 0;
};

// --- Scenarios ---------------------------------------------------------------------------------

int g_failures = 0;

// Prints one checked result; detail, if given, goes on the next line (an endpoint's failure)
bool check(bool ok, const std::string& what, const std::string& detail = {}) {
    std::printf("  %-78s %s\n", what.c_str(), ok ? "ok" : "FAILED");
    if (!detail.empty()) std::printf("      %s\n", detail.c_str());
    if (!ok) {
        g_failures++;
        std::fprintf(stderr, "pq_handshake: FAILED: %s%s%s\n", what.c_str(), detail.empty() ? "" : ": ",
                     detail.c_str());
    }
    return ok;
}

std::string side_failure(const char* side, const Endpoint& e) {
    return std::string(side) + ": " + (e.failed() ? e.failure() : std::string("no failure"));
}

std::string quoted(std::string_view s) { return "\"" + std::string(s) + "\""; }

// The CA, the client's trust anchor and the server's identity, set up once before the handshakes
struct Pki {
    CertificateAuthority root{kRootName};
    TrustAnchor anchor{root.name, root.pk};
    ServerIdentity server;

    Pki() { server.certificate = root.issue(kServerName, kValidFrom, kValidUntil, server.pk); }
};

// A client and a server that completed an honest handshake, for the record-layer scenarios
struct Connection {
    Client client;
    Server server;

    explicit Connection(const Pki& pki) : client(pki.anchor, kServerName, kToday), server(pki.server) {
        WireStats stats;
        if (!run_handshake(client, server, nullptr, false, stats))
            fatal("handshake failed: " + side_failure("client", client) + "; " + side_failure("server", server));
    }
};

void honest_handshake(const Pki& pki, int handshakes) {
    std::printf("\n1. honest handshake\n");
    Client client(pki.anchor, kServerName, kToday);
    Server server(pki.server);
    WireStats wire;
    const bool done = run_handshake(client, server, nullptr, true, wire);
    std::printf("  %-40s %6zu bytes in %zu records (client %zu, server %zu)\n", "total", wire.to_server + wire.to_client,
                wire.records, wire.to_server, wire.to_client);
    if (!check(done, "handshake completes on both sides",
               done ? "" : side_failure("client", client) + "; " + side_failure("server", server))) {
        return;
    }
    const KeySchedule& c = client.keys();
    const KeySchedule& s = server.keys();
    check(client.shared_secret() == server.shared_secret() && same_keys(c.ap_client, s.ap_client) &&
                  same_keys(c.ap_server, s.ap_server) && !same_keys(c.ap_client, c.ap_server),
          "both sides hold the same K and application keys, one key per direction");

    const char* const requests[] = {"GET /status", "GET /config", "BYE"};
    const char* const replies[] = {"200 up", "200 group 0x0201", "BYE"};
    for (std::size_t i = 0; i < 3; i++) {
        std::vector<Outgoing> unused;
        const Bytes up = client.send(requests[i]);
        const bool up_ok = server.receive(up, unused) && server.received.size() == i + 1 &&
                           server.received.back() == requests[i];
        check(up_ok, "client -> server  [application data] " + std::to_string(up.size()) + " bytes, record " +
                             std::to_string(i) + ": " + quoted(requests[i]));
        const Bytes down = server.send(replies[i]);
        const bool down_ok = client.receive(down, unused) && client.received.size() == i + 1 &&
                             client.received.back() == replies[i];
        check(down_ok, "server -> client  [application data] " + std::to_string(down.size()) + " bytes, record " +
                               std::to_string(i) + ": " + quoted(replies[i]));
    }

    // Timed without printing; fresh key shares, randoms and signatures every time
    WireStats sum;
    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();
    for (int i = 0; i < handshakes; i++) {
        Client c2(pki.anchor, kServerName, kToday);
        Server s2(pki.server);
        if (!run_handshake(c2, s2, nullptr, false, sum))
            fatal("timed handshake failed: " + side_failure("client", c2) + "; " + side_failure("server", s2));
    }
    const double total = std::chrono::duration<double>(clock::now() - t0).count();
    std::printf("  handshake time, mean of %d handshakes: %.2f ms\n"
                "    client %.2f ms (ML-KEM-768 KeyGen and Decaps, ML-DSA-87 and ML-DSA-65 Verify)\n"
                "    server %.2f ms (ML-KEM-768 Encaps, ML-DSA-65 Sign)\n",
                handshakes, 1e3 * total / handshakes, 1e3 * sum.client_s / handshakes,
                1e3 * sum.server_s / handshakes);
}

void man_in_the_middle(const Pki& pki) {
    std::printf("\n2. a man in the middle replaces the client's key share with its own\n");
    Client client(pki.anchor, kServerName, kToday);
    Server server(pki.server);
    ManInTheMiddle mitm;
    WireStats wire;
    const bool done = run_handshake(
            client, server, [&](Dir dir, const Outgoing& item) { return mitm.intercept(dir, item); }, false, wire);
    check(mitm.k_server == server.shared_secret() && mitm.k_client == client.shared_secret() &&
                  !(client.shared_secret() == server.shared_secret()),
          "the attacker shares one K with the server and another with the client");
    check(same_keys(mitm.client_side.hs_server, client.keys().hs_server) && mitm.certificate_subject == kServerName,
          "it holds the client's handshake keys, read {Certificate} (" + mitm.certificate_subject + ")");
    check(!done && client.alert() == Alert::decrypt_error &&
                  client.state() == Client::State::wait_certificate_verify,
          "the client rejects the server's CertificateVerify", side_failure("client", client));
    check(!client.connected() && !server.failed() && server.state() == Server::State::wait_finished,
          "no connection: the server still waits for a client Finished");
}

void modified_ciphertext(const Pki& pki) {
    std::printf("\n3. the server's ML-KEM ciphertext is modified in transit\n");
    Client client(pki.anchor, kServerName, kToday);
    Server server(pki.server);
    WireStats wire;
    // flips a bit of the last byte of ServerHello, which is the last byte of the ciphertext
    const Interceptor flip_bit = [](Dir dir, const Outgoing& item) {
        std::vector<Bytes> delivered{item.record};
        Bytes& record = delivered.front();
        if (dir == Dir::to_client && std::string_view(item.label) == "ServerHello" && !record.empty())
            record[record.size() - 1] ^= 0x01;
        return delivered;
    };
    const bool done = run_handshake(client, server, flip_bit, false, wire);
    check(client.decaps_result() == openpqc::status::ok,
          "the client's ML-KEM Decaps returns ok (implicit rejection, no error)");
    check(!(client.shared_secret() == server.shared_secret()), "the client's K differs from the server's K");
    // Certificate, CertificateVerify and Finished all travel under keys derived from K, so the
    // first of these records already fails; the wrong K never gets as far as a signature check
    check(!done && client.alert() == Alert::bad_record_mac && client.state() == Client::State::wait_certificate,
          "the client rejects the server's first protected record", side_failure("client", client));
    check(!server.failed() && server.state() == Server::State::wait_finished,
          "no connection: the server still waits for a client Finished");
}

void certificate_checks(Pki& pki) {
    std::printf("\n4. certificates the client must reject\n");
    struct Case {
        const char* what;
        Alert alert;
    };
    const auto attempt = [&](const ServerIdentity& id, const Case& expect) {
        Client client(pki.anchor, kServerName, kToday);
        Server server(id);
        WireStats wire;
        const bool done = run_handshake(client, server, nullptr, false, wire);
        check(!done && client.alert() == expect.alert && client.state() == Client::State::wait_certificate,
              expect.what, side_failure("client", client));
    };

    // A CA the client does not trust, under the trusted CA's name, certifies an impostor's key
    CertificateAuthority rogue(kRootName);
    ServerIdentity impostor;
    impostor.certificate = rogue.issue(kServerName, kValidFrom, kValidUntil, impostor.pk);
    attempt(impostor, {"signed by an untrusted CA that uses the trusted CA's name", Alert::bad_certificate});

    ServerIdentity expired;
    expired.certificate = pki.root.issue(kServerName, 20240101, 20251231, expired.pk);
    attempt(expired, {"issued by the trusted CA, but expired", Alert::certificate_expired});

    ServerIdentity other;
    other.certificate = pki.root.issue("other.example", kValidFrom, kValidUntil, other.pk);
    attempt(other, {"issued by the trusted CA to another server name", Alert::bad_certificate});
}

void modified_record(const Pki& pki) {
    std::printf("\n5. a modified application record\n");
    Connection conn(pki);
    std::vector<Outgoing> unused;
    const bool first = conn.server.receive(conn.client.send("PUT /config sig=mldsa87"), unused);
    // The stream cipher alone is malleable: flipping a ciphertext bit flips the same plaintext
    // bit, here turning the last character '5' into '4'. The MAC is what stops it.
    Bytes record = conn.client.send("PUT /config sig=mldsa65");
    record[record.size() - DEMO_TAG_BYTES - 2] ^= 0x01;
    const bool second = conn.server.receive(record, unused);
    check(first && !second && conn.server.alert() == Alert::bad_record_mac && conn.server.received.size() == 1,
          "\"sig=mldsa65\" with one ciphertext bit flipped (to \"sig=mldsa64\") is rejected",
          side_failure("server", conn.server));
}

void replay_and_reorder(const Pki& pki) {
    std::printf("\n6. replayed and reordered records\n");
    std::vector<Outgoing> unused;
    {
        Connection conn(pki);
        const Bytes r0 = conn.server.send("record 0");
        const bool first = conn.client.receive(r0, unused);
        const bool replay = conn.client.receive(r0, unused);
        check(first && !replay && conn.client.alert() == Alert::bad_record_mac && conn.client.received.size() == 1,
              "record 0 accepted, record 0 replayed: rejected", side_failure("client", conn.client));
    }
    {
        Connection conn(pki);
        const Bytes r0 = conn.server.send("record 0");
        conn.server.send("record 1"); // delayed on the wire
        const Bytes r2 = conn.server.send("record 2");
        const bool first = conn.client.receive(r0, unused);
        const bool early = conn.client.receive(r2, unused);
        check(first && !early && conn.client.alert() == Alert::bad_record_mac && conn.client.received.size() == 1,
              "record 0 accepted, record 2 before record 1: rejected", side_failure("client", conn.client));
    }
}

void usage(std::FILE* f) {
    std::fprintf(f, "usage: pq_handshake [handshakes]\n"
                    "  handshakes  number of honest handshakes whose time is averaged, 1 to 100000 (default 20)\n");
}

} // namespace

int main(int argc, char** argv) {
    int handshakes = 20;
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
        if (*argv[1] == '\0' || *end != '\0' || v < 1 || v > 100000) {
            std::fprintf(stderr, "pq_handshake: handshakes must be an integer from 1 to 100000\n");
            return 1;
        }
        handshakes = static_cast<int>(v);
    }

    std::printf("pq_handshake: a TLS 1.3-like handshake with ML-KEM-768 key shares and ML-DSA certificates\n"
                "Demonstration only, not TLS: no hybrid X25519MLKEM768, and the key derivation and record\n"
                "protection are demo_sym.h's SHAKE256 demo construction, not a standardized AEAD or HKDF.\n");

    Pki pki;
    Certificate cert;
    if (!parse_certificate(pki.server.certificate, cert)) fatal("cannot parse the server certificate");
    std::printf("\nPKI (set up before the handshakes)\n");
    std::printf("  root CA      \"%s\", ML-DSA-87; the client trusts only its %zu-byte public key\n",
                pki.root.name.c_str(), CaDSA::public_key_bytes);
    std::printf("  certificate  %.*s, valid %u..%u, ML-DSA-65 key (%zu bytes), signed by the root\n"
                "               with context \"%.*s\": %zu bytes\n",
                static_cast<int>(cert.subject.size()), cert.subject.data(), cert.not_before, cert.not_after,
                cert.public_key.size(), static_cast<int>(kCertificateContext.size()), kCertificateContext.data(),
                pki.server.certificate.size());

    honest_handshake(pki, handshakes);
    man_in_the_middle(pki);
    modified_ciphertext(pki);
    certificate_checks(pki);
    modified_record(pki);
    replay_and_reorder(pki);

    if (g_failures != 0) {
        std::fprintf(stderr, "pq_handshake: %d checks FAILED\n", g_failures);
        return 1;
    }
    std::printf("\nall scenarios ended as expected\n");
    return 0;
}
