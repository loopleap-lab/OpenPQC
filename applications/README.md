# Application demos

Six programs that put ML-KEM, ML-DSA and SLH-DSA together the way real software does: a secure connection, a file
tool, a busy server, a package repository, secure boot, and a time-stamping service. Each one checks its own results, including the attacks it stages, and exits
with 0 when everything behaved as expected, so CTest runs them as tests.

| Demo | What it does | ML-KEM used for | ML-DSA used for | SLH-DSA used for | Runs on |
|---|---|---|---|---|---|
| [`pq_handshake`](#pq_handshake) | a client and a server set up a secure connection, TLS 1.3 style; five attacks are caught | the key exchange (ML-KEM-768) | the certificate (ML-DSA-87) and the server's signature (ML-DSA-65) | – | CPU |
| [`pqcrypt`](#pqcrypt) | a command-line tool that encrypts and signs files | file encryption (ML-KEM-768) | file signatures (ML-DSA-65) | – | CPU |
| [`handshake_offload`](#handshake_offload) | a server answering 16,384 handshakes, in batches on a GPU, against CPU threads | the server's Encaps (ML-KEM-768) | the server's signatures (ML-DSA-65) | – | GPU and CPU |
| [`batch_verify`](#batch_verify) | checks 4,096 signed packages in one GPU call and finds the damaged ones | – | Verify (ML-DSA-65) | – | GPU and CPU |
| [`secure_boot`](#secure_boot) | a device's boot loader checks signed firmware updates; forgeries, rollbacks and a stolen key are caught | – | the release keys that sign each update (ML-DSA-65) | the vendor's long-lived root key (SLH-DSA-SHA2-128s) and the recovery image (HashSLH-DSA) | CPU |
| [`timestamp_authority`](#timestamp_authority) | a time-stamping service signs tens of thousands of tokens with one key, in GPU batches and on CPU threads | – | – | every token (SLH-DSA-SHA2-128f and -128s); an auditor re-verifies the archive | GPU and CPU |

**Not for production.** The demos also need key derivation and encryption with a symmetric key, which OpenPQC does
not provide. `common/demo_sym.h` builds both from SHAKE256 for the demos only; it is not a standard AEAD or KDF.
Real systems use HKDF with AES-GCM or ChaCha20-Poly1305, and in TLS a hybrid key exchange (X25519MLKEM768).

## Build and run

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build -L applications   # all demos as tests
build/applications/pq_handshake          # one of them
```

The demos use the public API only: `openpqc/openpqc.hpp` (C++) or the C headers on the CPU, and the GPU API
`openpqc/sycl.h` (one context type, `openpqc_gpu`, for every parameter set) on the GPU; they link `OpenPQC::openpqc`
and, for the GPU, `OpenPQC::sycl`. None of them uses the testing interfaces (`openpqc/testing.h`): every random value
comes from the library.

`handshake_offload`, `batch_verify` and `timestamp_authority` are built only with the SYCL backend; with `--cpu-only` they run without a
GPU, and without one otherwise they exit with 77, which CTest reports as skipped.

## The demos

<a id="pq_handshake"></a>

### `pq_handshake` — a TLS 1.3-like handshake from ML-KEM-768 and ML-DSA

A client and a server run a handshake shaped like TLS 1.3. They are two objects in one process that pass each other only byte strings. The client sends a fresh ML-KEM-768 public key. The server encapsulates to it (it makes a ciphertext that only the client can turn into the same shared secret K), sends a certificate signed by a root CA, and signs the transcript hash (SHA3-256 over all handshake messages so far). Both sides then derive keys from K and exchange encrypted records, and the program runs five attacks and checks that each one is caught. Key derivation, the Finished MACs and record encryption come from `applications/common/demo_sym.h`, which is a demonstration construction, not a standard AEAD or KDF.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| Setup: the root CA and the server make key pairs, and the CA signs the server's certificate | ML-DSA-87 KeyGen and Sign (CA), ML-DSA-65 KeyGen (server) | `CaDSA::keygen`, `CaDSA::sign`, `ServerDSA::keygen` |
| ClientHello: the client makes a fresh key pair for this handshake only. Its public key is the key share | ML-KEM-768 KeyGen | `KEM::keygen` |
| ServerHello: the server checks the key share, then makes the ciphertext and K | ML-KEM-768 Encaps | `KEM::encaps` |
| Both sides hash every handshake message, each one preceded by its length (the transcript) | SHA3-256 | `opqc_sponge_init`, `opqc_sponge_absorb`, `opqc_sponge_finalize`, `opqc_sponge_squeeze` |
| CertificateVerify: the server signs the transcript hash | ML-DSA-65 Sign | `ServerDSA::sign` |
| The client gets K back from the ciphertext, then wipes its ML-KEM secret key | ML-KEM-768 Decaps | `KEM::decaps`, `openpqc::secret::wipe` |
| The client checks the certificate with the root CA's public key, the only key it trusts | ML-DSA-87 Verify | `CaDSA::verify` |
| The client checks CertificateVerify with the public key in the certificate | ML-DSA-65 Verify | `ServerDSA::verify` |
| Key schedule: from K and the transcript hash, a record key, an IV and a Finished key for each direction (first for the handshake, then for application data), each an `openpqc::secret<N>`. Finished is a MAC over the transcript hash that shows both sides saw the same messages | demo_sym.h KDF (SHAKE256) | `demo_kdf`, `opqc_ct_memcmp` |
| Protected records: the handshake messages after ServerHello, and the application data | demo_sym.h encryption (SHAKE256 keystream, then a SHAKE256 MAC) | `demo_seal`, `demo_open` |

**The six scenarios** (numbered as in the output; the TLS alert name the program prints is in parentheses)

| # | Attack | What detects it |
|---|---|---|
| 1 | None: an honest handshake, then 3 records each way | Nothing to detect. The program checks that both sides hold the same K and the same keys, and that all 6 records arrive |
| 2 | A man in the middle swaps in its own key share and re-encapsulates to the client, so it shares one K with each side | ML-DSA-65 Verify: the server signed its own transcript, which contains the attacker's key share, and the attacker cannot sign (`decrypt_error`) |
| 3 | One bit of the ML-KEM ciphertext in ServerHello is flipped | Decaps returns no error but gives a different K (implicit rejection: a damaged ciphertext gives a random-looking key instead of an error). The first protected record, {Certificate}, then fails `demo_open` (`bad_record_mac`) |
| 4 | Bad certificates: one signed by a rogue CA that uses the trusted CA's name, one expired, one issued to another server name | ML-DSA-87 Verify under the root key (`bad_certificate`); the validity dates (`certificate_expired`); the subject name (`bad_certificate`) |
| 5 | One ciphertext bit of an application record is flipped ("sig=mldsa65" would read "sig=mldsa64") | The MAC check in `demo_open` (`bad_record_mac`) |
| 6 | A record is replayed, or record 2 arrives before record 1 | The receiver counts records itself, so the nonce (IV XOR sequence number) is wrong and `demo_open` fails (`bad_record_mac`) |

**How the API is called** (from `pq_handshake/pq_handshake.cpp`, error checks left out)

```cpp
#include "openpqc/openpqc.hpp"
using KEM = openpqc::ML_KEM_768;
using CaDSA = openpqc::ML_DSA_87;     // the root CA
using ServerDSA = openpqc::ML_DSA_65; // the server
// Every call returns an openpqc::status ([[nodiscard]]); the secret keys (CaDSA::secret_key, KEM::secret_key),
// K (KEM::shared_secret) and the traffic secrets are openpqc::secret<N>: zeroized when destroyed, not copyable,
// compared in constant time with ==

// Setup, once: the CA's and the server's key pairs; the CA signs the certificate body (tbs)
CaDSA::keygen(pk, sk);
ServerDSA::keygen(pk, sk);
CaDSA::sign(sig, tbs.out, sk, view(kCertificateContext));

// Client, ClientHello: a fresh ML-KEM-768 key pair; the public key ek_ is the key share
KEM::keygen(ek_, dk_);

// Server: Encaps checks the key share (openpqc::status::invalid_public_key if it fails), then gives the
// ciphertext ct (sent in ServerHello) and K
KEM::encaps(ct, k_, hello.key_share.first<KEM::public_key_bytes>());
keys_.handshake(k_, transcript_.hash());  // handshake keys from K and the transcript hash
// ... {Certificate} is sent; CertificateVerify signs the transcript hash (SHA3-256, opqc_sponge_*)
const Hash th = transcript_.hash();       // ClientHello..Certificate
ServerDSA::sign(sig, th, id_.sk, view(kCertificateVerifyContext));

// Client: Decaps gives the same K; the ML-KEM secret key is wiped after this one use
KEM::decaps(k_, hello.ciphertext.first<KEM::ciphertext_bytes>(), dk_);
dk_.wipe();
keys_.handshake(k_, transcript_.hash());
CaDSA::verify(cert.signature, cert.tbs, root_.pk, view(kCertificateContext)); // {Certificate}: status::ok if valid
ServerDSA::verify(sig, th, server_pk_, view(kCertificateVerifyContext));     // th: client's own hash

// Key schedule (inside keys_.handshake()) and Finished; kdf() prefixes the label, calls demo_kdf
kdf(handshake_secret, "handshake secret", k.span(), {});
hs_client.derive("c hs traffic", handshake_secret, transcript_hash); // -> key, iv, finished_key
const Hash expected = finished_mac(keys_.hs_server.finished_key, transcript_.hash()); // demo_kdf
opqc_ct_memcmp(body.data(), expected.data(), expected.size()); // {Finished}: 0 if transcripts match

// One record: nonce n = IV XOR sequence number; the 3-byte record header is the associated data
demo_seal(record.data() + 3, key.data(), n.data(), record.data(), 3, inner.data(), inner.size());
demo_open(inner.data(), key.data(), n.data(), record.data(), 3, record.data() + 3, record.size() - 3);
```

**Run**

```sh
cmake --build build --target pq_handshake
build/applications/pq_handshake        # all six scenarios; exit code 0 if each ends as expected
build/applications/pq_handshake 1000   # number of handshakes to average the time over (1 to 100000, default 20)
```

```
1. honest handshake
  client -> server  ClientHello              1242 bytes
  server -> client  ServerHello              1131 bytes
  server -> client  {Certificate}            6681 bytes
  server -> client  {CertificateVerify}      3353 bytes
  ...
  total                                     12551 bytes in 6 records (client 1314, server 11237)
...
3. the server's ML-KEM ciphertext is modified in transit
  the client's ML-KEM Decaps returns ok (implicit rejection, no error)           ok
  the client's K differs from the server's K                                     ok
  the client rejects the server's first protected record                         ok
      client: bad_record_mac: the record that should hold Certificate fails demo_open
...
all scenarios ended as expected
```

<a id="pqcrypt"></a>

### `pqcrypt` — encrypt files with ML-KEM-768, sign them with ML-DSA-65

Alice and Bob each run `keygen` to get an ML-KEM-768 key pair (for receiving encrypted files) and an ML-DSA-65 key pair (for signing). Alice encrypts a file with Bob's public key and only Bob's secret key decrypts it; with a wrong key, or with a chunk changed, reordered or cut off, `decrypt` fails and writes no output. Alice signs a file and anyone with her public key can verify it; the file is hashed into ML-DSA's external mu (the 64-byte digest that ML-DSA actually signs) while it is read, so the file never has to fit in memory. The file key and the chunk encryption come from `common/demo_sym.h`, a demonstration construction, not a standard AEAD or KDF.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| `keygen`: draw fresh seeds from the OS and expand them into the two key pairs | ML-KEM-768 KeyGen, ML-DSA-65 KeyGen | `opqc_randombytes`, `KEM::keygen_from_seed`, `DSA::keygen_from_seed` |
| Load a secret key file: it holds only the seed (64 bytes for ML-KEM, 32 for ML-DSA) and a hash of the public key; the seed is expanded again and the hash compared, so a damaged seed gives an error | KeyGen from a stored seed (FIPS 203, Section 3.3; FIPS 204, Section 3.6.3), SHA3-256 | `KEM::keygen_from_seed`, `DSA::keygen_from_seed`, `opqc_sha3_256` |
| `encrypt`: make a fresh 32-byte shared secret K and a 1088-byte ciphertext c that only the recipient's secret key turns back into K | ML-KEM-768 Encaps | `KEM::encaps` |
| `encrypt`, `decrypt`: turn K into the file key, tied to the file header, c and the recipient's public key | demo_sym.h KDF (SHAKE256) | `demo_kdf` |
| `encrypt`: encrypt each 64 KiB chunk and append a 32-byte tag (a check value that any change breaks); the nonce (a per-chunk value, never reused) holds the chunk number and a last-chunk flag | demo_sym.h encryption (SHAKE256 keystream + MAC) | `demo_seal` |
| `decrypt`: recover K from c with the secret key | ML-KEM-768 Decaps (implicit rejection: a wrong key gives a random-looking K, not an error, so chunk 0's tag fails) | `KEM::decaps` |
| `decrypt`: check each chunk's tag, then decrypt it; the output file appears only after the last chunk passes | demo_sym.h decryption | `demo_open` |
| `sign`, `verify`: hash the file into mu, 64 KiB at a time: first tr (a hash of the public key), then a 2-byte prefix, the context string (a label signed with the file) and the file | external mu (SHAKE256 over tr and the message) | `openpqc::sponge`, `openpqc::Xof::shake256`, `Xof::absorb`, `Xof::squeeze` |
| `sign` / `verify`: sign mu (hedged: fresh randomness in every signature) / check a signature against mu | ML-DSA-65 Sign / Verify from mu | `DSA::sign_mu` / `DSA::verify_mu` |
| `selftest`: check that the streamed mu equals the library's mu, and that the ordinary verify accepts the signature on the whole file | external mu, ML-DSA-65 Verify | `DSA::external_mu`, `DSA::verify` |

**How the API is called** (from `pqcrypt/pqcrypt.cpp`, error checks left out)

```cpp
#include "openpqc/openpqc.hpp"
using KEM = openpqc::ML_KEM_768;
using DSA = openpqc::ML_DSA_65;

// keygen and the secret key files: the seeds KEM::seed (d || z) and DSA::seed (xi), openpqc::secret<N> like
// the secret keys, are expanded into the key pairs (ML-KEM.KeyGen_internal, ML-DSA.KeyGen_internal)
KEM::keygen_from_seed(keys.pk, keys.sk, seed);       // returns an openpqc::status
DSA::keygen_from_seed(keys.pk, keys.sk, seed);

// encrypt_stream: ML-KEM-768 Encaps to the recipient's public key ek
KEM::ciphertext c;  KEM::shared_secret K;  FileKey key;
KEM::encaps(c, K, ek);                               // fresh K (32 bytes) and c (1088 bytes)
const Header header = make_header(Kind::encrypted);  // the 8-byte file header
// derive_file_key(key, K, header, c, ek): kdf_info = header || c || ek, then
demo_kdf(key.data(), key.size(), file_key_label, K.data(), K.size(), kdf_info.data(), kdf_info.size());
out.write(header);  out.write(c);
for (std::uint64_t i = 0;; i++) {                    // the input in 64 KiB pieces
    chunks.next(piece, last);
    const Nonce nonce = chunk_nonce(i, last);        // i (8 bytes, little-endian) || 0^7 || last flag
    demo_seal(sealed.data(), key.data(), nonce.data(), nullptr, 0, piece.data(), piece.size());  // no associated data
    out.write(ByteSpan(sealed).first(piece.size() + DEMO_TAG_BYTES));   // ciphertext || 32-byte tag
    if (last) return {};
}

// sign_stream -> streamed_mu: mu = SHAKE256(tr || 0x00 || len(ctx) || ctx || file, 64)
std::array<std::uint8_t, 64> tr;
openpqc::sponge(OPQC_SHAKE256_RATE, OPQC_SHAKE_SUFFIX, tr, {pk});   // tr = SHAKE256(pk, 64), pk = keys.pk
auto h = openpqc::Xof::shake256();
const std::array<std::uint8_t, 2> domain = {0, static_cast<std::uint8_t>(ctx.size())};  // pure ML-DSA
h.absorb(tr);  h.absorb(domain);  h.absorb(ctx);     // ctx = "pqcrypt file signature v1"
for (;;) {                                           // the file, 64 KiB per read
    in.read(buf, got);
    h.absorb(ByteSpan(buf).first(got));
    if (got < buf.size()) break;
}
h.squeeze(mu);                                       // 64 bytes (DSA::message_representative)
DSA::sign_mu(sig, mu, keys.sk);                      // ML-DSA-65 Sign from mu, hedged

// verify_stream: the same streamed_mu over the file, then
DSA::verify_mu(sig, mu, pk);                         // openpqc::status::ok: valid signature
```

**Run**

```sh
cmake --build build --target pqcrypt
build/applications/pqcrypt keygen alice    # alice.kem.pk, alice.kem.sk (ML-KEM-768); alice.sig.pk, alice.sig.sk (ML-DSA-65)
build/applications/pqcrypt keygen bob      # never overwrites existing key files
build/applications/pqcrypt encrypt bob.kem.pk report.pdf report.pdf.pqc   # readable only with bob.kem.sk
build/applications/pqcrypt decrypt bob.kem.sk report.pdf.pqc report.out   # report.out appears only if every chunk passes
build/applications/pqcrypt sign alice.sig.sk report.pdf report.pdf.sig
build/applications/pqcrypt verify alice.sig.pk report.pdf report.pdf.sig  # exit 0 only for a valid signature
build/applications/pqcrypt selftest        # 38 in-memory checks: round trips, tampering, streamed mu = library mu
ctest --test-dir build -R app_pqcrypt      # pqcrypt/test_pqcrypt.cmake: keygen, round trips (300 KiB, 2 chunks, empty),
                                           # wrong keys, cut/changed/spliced files, wrong file kinds, signatures, selftest
# exit code: 0 success, 1 failure (wrong key, damaged file, invalid signature), 2 usage error
```

```
$ pqcrypt keygen bob
pqcrypt keygen: ML-KEM-768 and ML-DSA-65 key pairs from fresh seeds
  ...
$ pqcrypt encrypt bob.kem.pk report.pdf report.pdf.pqc
pqcrypt encrypt: report.pdf (300000 bytes) for the holder of bob.kem.pk -> report.pdf.pqc (301256 bytes), 13.2 ms
  1088-byte ML-KEM-768 ciphertext, 5 chunks of up to 65536 bytes with 32-byte tags (demo_sym, not a standardized AEAD)
$ pqcrypt decrypt bob.kem.sk report.pdf.pqc report.out
pqcrypt decrypt: report.pdf.pqc -> report.out (300000 bytes, 5 chunks authenticated), 10.2 ms
$ pqcrypt decrypt alice.kem.sk report.pdf.pqc wrong.out
pqcrypt decrypt: report.pdf.pqc: chunk 0 failed authentication (wrong key, or the file was modified or truncated); wrong.out not written
$ pqcrypt sign alice.sig.sk report.pdf report.pdf.sig
pqcrypt sign: report.pdf (300000 bytes, mu computed while reading) -> report.pdf.sig (3317 bytes), 8.9 ms
  ML-DSA-65, hedged, context "pqcrypt file signature v1"
$ pqcrypt verify alice.sig.pk report.pdf report.pdf.sig
pqcrypt verify: report.pdf (300000 bytes): valid ML-DSA-65 signature by the holder of alice.sig.pk, 2.6 ms
```

<a id="handshake_offload"></a>

### `handshake_offload` — a handshake server on CPU threads and in GPU batches

A server answers the TLS 1.3-style handshakes of 16,384 simulated clients: for each one it runs ML-KEM-768 Encaps on the client's key and signs a hash of the handshake with ML-DSA-65 (CertificateVerify). It does this first on CPU threads, then in GPU batches of 1 to 8192 handshakes, and prints throughput and latency for each batch size. Afterwards the clients check the answers: every client must derive the same traffic key, and the signatures must verify (a sample of them; all with `--quick`). The traffic key comes from `demo_kdf` in `applications/common/demo_sym.h`, a demonstration construction, not a standard KDF.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| Setup: each simulated client makes a key pair and a ClientHello that carries its public key | ML-KEM-768 KeyGen | `openpqc_mlkem768_keygen` |
| Setup: the server makes its signing key. The GPU server copies the private key to the device once | ML-DSA-65 KeyGen | `openpqc_mldsa65_keygen`, `openpqc_gpu_memcpy` |
| GPU server: makes one context per parameter set (ML-KEM-768, ML-DSA-65) plus device and page-locked host buffers once, then copies data in and out on every batch | the GPU API (`openpqc/sycl.h`) | `openpqc_gpu_create`, `openpqc_gpu_malloc`, `openpqc_gpu_malloc_host`, `openpqc_gpu_memcpy_async`, `openpqc_gpu_sync` |
| Encaps on the client's key: the ciphertext goes into the ServerHello and K stays with the server. Encaps also checks the key | ML-KEM-768 Encaps | CPU: `openpqc_mlkem768_encaps`; GPU: `openpqc_gpu_kem_encaps` on the whole batch |
| Transcript hash TH over the ClientHello and the ServerHello, each with its 4-byte length in front | SHA3-256 | CPU and GPU server, on the host: `opqc_sponge_init`, `opqc_sponge_absorb`, `opqc_sponge_finalize`, `opqc_sponge_squeeze` (in `transcript_hash`) |
| CertificateVerify: sign 64 spaces, a label, a zero byte and TH, under a context string | ML-DSA-65 Sign, hedged (fresh random bytes go into each signature) | CPU: `openpqc_mldsa65_sign`; GPU: `openpqc_gpu_sig_sign` with `OPENPQC_GPU_ONE_KEY` (all messages of the batch under the one server key) |
| Traffic key from K and TH | demo_sym.h's KDF (SHAKE256) | CPU and GPU server, on the host: `demo_kdf` (in `traffic_key`) |
| Client check: open the ciphertext, recompute TH and the traffic key, and compare it with the server's (implicit rejection: a damaged ciphertext gives a different K instead of an error, so the comparison catches it) | ML-KEM-768 Decaps | `openpqc_mlkem768_decaps`, `opqc_ct_memcmp` |
| Client check: verify the server's signature (all with `--quick`; otherwise the whole first GPU batch and a sample of at least 1000). The signature of handshake 0, checked against the transcript of handshake 1, must fail | ML-DSA-65 Verify | `openpqc_mldsa65_verify` (CPU library) |

**How the API is called** (from `handshake_offload/handshake_offload.cpp`, error checks left out)

```cpp
#include "openpqc/sycl.h"
// Once: one context per parameter set, sized for the largest batch (in FIPS 140-3 mode, or with the
// developer definitions OPENPQC_*_SYCL_CREATE_SELF_TEST, openpqc_gpu_create also runs a known-answer
// self-test on the device; an ordinary GPU build has no known-answer check of the device); the buffers
// come from openpqc_gpu_malloc (device) and openpqc_gpu_malloc_host (page-locked host)
const openpqc_gpu_config kem_cfg{device, max_batch}, dsa_cfg{device, std::max<std::size_t>(max_batch, 512)};
openpqc_gpu_create(&kem, OPENPQC_ML_KEM_768, &kem_cfg);
openpqc_gpu_create(&dsa, OPENPQC_ML_DSA_65, &dsa_cfg);
openpqc_gpu_memcpy(dsa, d_sk_.get(), server.sk.data(), SK);  // the server's private key, to the device

// One batch of n handshakes, for clients first .. first+n-1 (GpuServer::serve). Every call has a status
// array: entry j is OPENPQC_OK if operation j has a result
// 1) Encaps: the n encapsulation keys, cut out of the ClientHellos, are in page-locked h_ek_
openpqc_gpu_memcpy_async(kem, d_ek_.get(), h_ek_.get(), n * EK);
openpqc_gpu_kem_encaps(kem, d_ct_.get(), d_ss_.get(), d_ek_.get(), d_kem_status_.as<std::int32_t>(), n);
openpqc_gpu_memcpy_async(kem, h_ct_.get(), d_ct_.get(), n * CT);
openpqc_gpu_memcpy_async(kem, h_ss_.get(), d_ss_.get(), n * SS);
openpqc_gpu_memcpy_async(kem, h_kem_status_.get(), d_kem_status_.get(), n * 4);
openpqc_gpu_sync(kem);  // waits for all of the above; status[j] == OPENPQC_ERR_INVALID_PUBLIC_KEY: key j failed its check
// 2) Host work for handshake j (client i = first + j), on all threads from batch 64 on
parallel_for(n >= kParallelHostWork ? threads_ : 1, n, [&](std::size_t j) {
    // ... sh = ServerHello i: a header with a fresh random, then ciphertext j
    transcript_hash(th, c.hello.data() + i * CH, sh);               // SHA3-256 via opqc_sponge_*
    certificate_verify_content(h_msg_.get() + j * CV, th);          // 64 spaces || label || 0 || TH
    traffic_key(r.key.data() + i * KEY, h_ss_.get() + j * SS, th);  // demo_kdf(label, K, TH)
});
opqc_zeroize(h_ss_.get(), n * SS);  // the K are not needed any more
// 3) Sign: the n messages, all CV bytes long, go in with a stride (no offsets); n signatures under the one
// server key (OPENPQC_GPU_ONE_KEY) come back
const openpqc_sign_opts opts{context_string(), kContext.size(), 0, OPENPQC_GPU_ONE_KEY};
const openpqc_gpu_messages messages{d_msg_.get(), nullptr, CV, n * CV};
openpqc_gpu_memcpy_async(dsa, d_msg_.get(), h_msg_.get(), n * CV);
openpqc_gpu_sig_sign(dsa, d_sig_.get(), messages, &opts, d_sk_.get(), d_sign_status_.as<std::int32_t>(), n);
openpqc_gpu_memcpy_async(dsa, h_sig_.get(), d_sig_.get(), n * SIG);
openpqc_gpu_memcpy_async(dsa, h_sign_status_.get(), d_sign_status_.get(), n * 4);
openpqc_gpu_sync(dsa);  // then every status entry must be OPENPQC_OK
std::memcpy(r.signature.data() + first * SIG, h_sig_.get(), n * SIG);
```

**Run**

```sh
cmake --build build --target handshake_offload    # needs the SYCL backend (OPENPQC_HAVE_SYCL)
build/applications/handshake_offload              # 16384 clients, GPU batches 1,16,128,1024,8192 (about 20 s on an L4)
build/applications/handshake_offload --quick      # 256 clients, batches 1,64, all signatures checked (the CTest run)
build/applications/handshake_offload --cpu-only   # CPU server and client checks only; needs no GPU
# --clients N          number of clients (default 16384)
# --batches B1,B2,...  GPU batch sizes
# --threads T          threads for the CPU server, the GPU server's host work and the clients (default: the CPUs this process may use)
# --device D           SYCL device index (default: OPENPQC_SYCL_DEVICE, or the default device)
# exit code: 0 all checks passed, 1 a check or a library call failed, 77 no SYCL device and no --cpu-only (skipped)
```

```
handshake_offload: the server side of 16384 post-quantum handshakes (ML-KEM-768, ML-DSA-65)
...
CPU server, 2 threads: 3323 handshakes/s, latency per handshake 0.51 ms (median), 1.09 ms (p90)
  clients: 16384 of 16384 traffic keys agree, 1024 of 1024 signatures valid, a signature checked against another transcript rejected: ok

GPU server on NVIDIA L4 (DPC++), set up in 14.0 ms; host work on 2 threads from batch 64 on
    batch  timed handshakes/s  latency median        p90   Encaps  host  Sign   client checks
        1  16384         1860         0.53 ms    0.54 ms      27%    1%   71%   16384 keys, 1024 signatures, 1 rejection: ok
       16   1024        20083         0.70 ms    0.95 ms      20%   11%   69%   16384 keys, 1107 signatures, 1 rejection: ok
      128    128        71901         1.69 ms    1.94 ms      11%   23%   67%   16384 keys, 1212 signatures, 1 rejection: ok
     1024     16       136059         7.45 ms    7.71 ms       5%   37%   58%   16384 keys, 2048 signatures, 1 rejection: ok
     8192     10       181986         42.7 ms    43.0 ms       5%   56%   40%   16384 keys, 8738 signatures, 1 rejection: ok
...
```

Bigger batches give more handshakes per second. From batch 16 on, the GPU server beats the 2-thread CPU server (20083 against 3323 per second) and reaches 181986 at batch 8192. However, every handshake waits for its whole batch, so the latency per batch grows from 0.53 ms to 42.7 ms (the wait for a batch to fill is not counted). The Encaps, host and Sign columns split each batch's time between the three stages. At batch 8192 the host work on 2 CPU threads (building the ServerHellos, hashing, the KDF) is the largest part, at 56%.

<a id="batch_verify"></a>

### `batch_verify` — a repository of signed packages, verified on the CPU and the GPU

A package repository has a few maintainers with ML-DSA-65 keys and a manifest that says which maintainer signs which package. The program builds one (4096 packages and 8 maintainers by default), damages about 1 % of the packages in five ways, and checks every package four times: once on CPU threads and three times with GPU batch calls (one call verifies many signatures). A package is valid if its signature verifies under the key of the maintainer the manifest names and its first line names the package the manifest lists. The name check catches a package swapped for another validly signed one, and the run passes if all four verifiers reject exactly the damaged packages.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| Each maintainer makes a key pair | ML-DSA-65 KeyGen | `openpqc_mldsa65_keygen` |
| Each package is signed on CPU threads with the context string `"openpqc-demo package signature"` (a label bound into the signature, so signatures made for other purposes do not verify here). The secret keys are wiped when the setup ends | ML-DSA-65 Sign, hedged (fresh randomness in every signature) | `openpqc_mldsa65_sign`, `opqc_zeroize` |
| About 1 % of packages (at least 5) are damaged, five ways in turn: one byte changed; another package's signature; signed by a maintainer the manifest does not name; one signature bit flipped; another package's file served with that file's valid signature | none: edits after signing (the wrong-maintainer package is signed with another key in the step above) | — |
| [1] CPU: verify every package on T threads | ML-DSA-65 Verify | `openpqc_mldsa65_verify` |
| Make the GPU context, device buffers and page-locked host buffers (pinned memory, faster to copy) once, before timing | the GPU API (`openpqc/sycl.h`) | `openpqc_gpu_create`, `openpqc_gpu_malloc`, `openpqc_gpu_malloc_host` |
| [2] GPU, messages on the device: all packages back to back in one buffer with an offsets array, one public key per package, one call. The GPU also hashes the packages | ML-DSA-65 Verify, GPU batch | `openpqc_gpu_memcpy`, `openpqc_gpu_sig_verify`, `openpqc_gpu_sync` |
| [3] GPU, external mu: the host hashes each package into mu (the 64-byte digest of public key, context and message that the rest of verification works on). The GPU gets 64 bytes per package instead of the package | external mu (SHAKE256 on the host), then ML-DSA-65 Verify from mu, GPU batch | `openpqc_mldsa65_external_mu`, `openpqc_gpu_sig_verify_mu`, `openpqc_gpu_sync` |
| [4] GPU, per maintainer: packages grouped by maintainer, one call per maintainer under that one key. The key's expanded matrix and hash are computed once per launch instead of once per package (here each call is one launch) | ML-DSA-65 Verify, one-key GPU batch | `openpqc_gpu_sig_verify` with `OPENPQC_GPU_ONE_KEY`, `openpqc_gpu_sync` |
| Name check on the host, for every verifier: the first line must be `package <name>` as the manifest lists it | plain comparison, no cryptography | `named_as_listed` (in the program) |

**How the API is called** (from `batch_verify/batch_verify.cpp`, error checks left out)

```cpp
// SIG = OPENPQC_MLDSA65_BYTES, PK = OPENPQC_MLDSA65_PUBLICKEYBYTES, MU = OPENPQC_MLDSA_CRHBYTES (64 bytes)
// context_string(), kContext.size(): the context string "openpqc-demo package signature"
#include "openpqc/sycl.h"
openpqc_gpu* ctx = nullptr;   // ML-DSA-65, max_batch = min(n, 8192) verifications per launch
const openpqc_gpu_config cfg{device, max_batch};
openpqc_gpu_create(&ctx, OPENPQC_ML_DSA_65, &cfg);
// d_* buffers: openpqc_gpu_malloc (device); h_* buffers: openpqc_gpu_malloc_host (page-locked)
const openpqc_sign_opts opts{context_string(), kContext.size(), 0, 0};   // pure ML-DSA, the context string

// [2] messages on the device: package i is d_msg[offsets[i] .. offsets[i + 1])
offsets[0] = 0;
for (size_t i = 0; i < n; i++) offsets[i + 1] = offsets[i] + packages[i].content.size();
// ... copy package i, its signature and its maintainer's public key into h_msg, h_sig, h_pk
openpqc_gpu_memcpy(ctx, d_msg, h_msg, total_bytes);        // likewise d_offsets, d_sig, d_pk
const openpqc_gpu_messages packages{d_msg, d_offsets, 0, total_bytes};
openpqc_gpu_sig_verify(ctx, d_sig, packages, &opts, d_pk, d_status, n);  // one call for all n packages
openpqc_gpu_sync(ctx);                                     // calls are asynchronous
openpqc_gpu_memcpy(ctx, h_status, d_status, n * sizeof(int32_t));
// h_status[i]: OPENPQC_OK = valid, OPENPQC_ERR_INVALID_SIGNATURE = invalid, anything else no verdict;
// then the name check

// [3] external mu: mu of every package on the host (T threads), 64 bytes per package to the GPU
parallel_for(threads, n, [&](size_t i) {
    const Package& p = packages[i];
    const uint8_t* pk = repo.public_key(p.maintainer);
    openpqc_mldsa65_external_mu(h_mu + i * MU, p.content.data(), p.content.size(),
                                context_string(), kContext.size(), pk);
    // ... copy p.signature to h_sig + i * SIG and pk to h_pk + i * PK
});
// after copying h_mu, h_sig, h_pk in; no options: mu already holds the context string
openpqc_gpu_sig_verify_mu(ctx, d_sig, d_mu, nullptr, d_pk, d_status, n);
openpqc_gpu_sync(ctx);

// [4] batch sorted by maintainer (maintainer g: entries start[g] .. start[g + 1] - 1); d_pk: the M keys
const openpqc_sign_opts one_key{context_string(), kContext.size(), 0, OPENPQC_GPU_ONE_KEY};
for (size_t g = 0; g < m; g++) {
    const size_t count = start[g + 1] - start[g];
    if (count == 0) continue;
    const openpqc_gpu_messages group{d_msg, d_offsets + start[g], 0, total_bytes};  // offsets into all of d_msg
    openpqc_gpu_sig_verify(ctx, d_sig + start[g] * SIG, group, &one_key, d_pk + g * PK, d_status + start[g], count);
}
openpqc_gpu_sync(ctx);
```

**Run**

```sh
cmake --build build --target batch_verify     # exists only in a build with the SYCL backend
build/applications/batch_verify               # 4096 packages, 8 maintainers, all four verifiers
build/applications/batch_verify --quick       # 64 packages, 4 maintainers (the CTest run)
build/applications/batch_verify --cpu-only    # setup and the CPU verifier only; no GPU needed
# --packages N (10 to 65536)  --maintainers M (2 to 1024)  --threads T (host threads)
# --device D (SYCL device index; default: the default device, settable with OPENPQC_SYCL_DEVICE)
# exit 0: every verifier matches the faults; 1: a mismatch or a library error; 77: no SYCL device
```

```
  GPU: NVIDIA L4 (DPC++), up to 4096 packages per launch; context and buffers made in 12.53 ms
...
  [1] CPU, 2 threads                   303.5 ms     13498 packages/s   41 invalid: matches the ground truth
  [2] GPU, messages on the device      10.33 ms    396498 packages/s   41 invalid: matches the ground truth
        host 2.57 ms (gather), copy in 2.10 ms (55.6 MB), verify 5.57 ms (1 call), decide 0.098 ms
  [3] GPU, external mu                 46.77 ms     87569 packages/s   41 invalid: matches the ground truth
        host 43.97 ms (mu on 2 threads), copy in 0.844 ms (21.8 MB), verify 1.87 ms (1 call), decide 0.087 ms
  [4] GPU, one call per maintainer     36.30 ms    112843 packages/s   41 invalid: matches the ground truth
        host 2.31 ms (group, gather), copy in 1.81 ms (47.6 MB), verify 32.08 ms (8 calls of 4.01 ms), decide 0.105 ms
...
  the four verifiers reach the same decision for every package

packages found invalid: 41 of 4096, by fault (33 by the signature check, 8 by the name check)
...
result: ok
```

<a id="secure_boot"></a>

### `secure_boot` — signed firmware updates: an SLH-DSA root key, ML-DSA release keys

A device vendor signs firmware updates, and the boot loader of one of its devices checks each one before installing it; the certificate, manifest and package formats are this program's own. The vendor's root key is SLH-DSA-SHA2-128s (its security rests on SHA-256 alone, which suits a key that devices must trust for 10 to 20 years), and its 32-byte public key in ROM is the only key the device holds. The root certifies ML-DSA-65 release keys, which sign each release fast, and it signs an 8 MiB recovery image with HashSLH-DSA (the image is hashed with SHA-256 first, and the root signs the hash). The boot loader runs six checks, two of them against anti-rollback counters (a minimum key version and a minimum SVN, the security version number that security fixes raise); eight scenarios, among them forged certificates, a rollback and the rotation of a stolen release key, check that it accepts and rejects what it should.

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| Setup: the vendor makes its root key pair; the device gets the 32-byte public key in ROM | SLH-DSA-SHA2-128s KeyGen | `RootDSA::keygen` |
| The vendor makes release key 1 (and release key 2 in scenario 7). Secret keys (`openpqc::secret<N>`) are wiped when they go out of scope | ML-DSA-65 KeyGen | `ReleaseDSA::keygen` |
| The root signs a key certificate for each release key: key id, key version, public key, and the models and image types the key may sign for. Context string `"openpqc-demo key certificate"` (a label bound into the signature, so a signature made for another purpose does not verify here) | SLH-DSA-SHA2-128s Sign, hedged (fresh randomness in every signature), about 0.85 s | `RootDSA::sign` |
| Each release: the release key signs a manifest with the model, image type, SVN, version, and the image's size and SHA3-256. Context `"openpqc-demo firmware manifest"` | SHA3-256, ML-DSA-65 Sign, hedged | `opqc_sha3_256`, `ReleaseDSA::sign` |
| Check 1: the key certificate, under the root public key in ROM | SLH-DSA-SHA2-128s Verify | `RootDSA::verify` |
| Check 2: the certificate's key version is not below the device's minimum key version, so a retired release key fails however valid its signatures are | counter comparison, no cryptography | — |
| Check 3: the manifest, under the release key that the certificate certifies | ML-DSA-65 Verify | `ReleaseDSA::verify` |
| Check 4: the image's size and SHA3-256 against the manifest's | SHA3-256 | `opqc_sha3_256` |
| Checks 5 and 6: the model and image type are certified for the key, and match this device and its slot; the SVN is not below the device's minimum for this key version. Installing raises the counters, and a higher key version starts a new SVN sequence | plain comparisons, no cryptography | `verify_update`, `install_update` (in the program) |
| Recovery: the root signs the recovery image (context `"openpqc-demo recovery image"`); the boot loader verifies it under the ROM key, then checks the model in its header | HashSLH-DSA with SHA2-256 as the pre-hash (FIPS 205, Section 10.2.2), Sign and Verify | `RootDSA::prehash_sign`, `RootDSA::prehash_verify` |

**The eight scenarios** (numbered as in the output)

| # | What the device is offered | Outcome |
|---|---|---|
| 1 | firmware 1.3.0 (SVN 3), signed by release key 1 | installed; the minimum SVN rises from 2 to 3. The verification is timed |
| 2 | 1.3.0 with one bit of the image flipped, signatures intact | rejected at check 4 |
| 3 | an attacker's manifest, signed with the attacker's own ML-DSA-65 key and sent with key 1's genuine certificate | rejected at check 3 |
| 4 | key 1's certificate with the attacker's public key put in; a certificate signed by the attacker's own SLH-DSA key | both rejected at check 1 |
| 5 | a rollback to 1.2.0 (SVN 2), validly signed by key 1 | rejected at check 6 |
| 6 | a GW-200 image; radio firmware for the main slot; on a GW-300 that trusts the same root, an image signed by key 1, which is not certified for that model | each rejected at check 5 |
| 7 | key 1 is stolen: the root certifies release key 2 with key version 2, and 1.4.0 signed by key 2 installs. Then the attacker's image, signed with key 1 at SVN 2^32-1 | rejected at check 2. A device that has not installed 1.4.0 yet installs it (the window that key rotation leaves), still installs 1.4.0 afterwards because key version 2 starts a new SVN sequence, and then rejects key 1 too |
| 8 | the recovery image; the same with one bit flipped; key 1's certificate and the root's signature on it, presented as a recovery package | the first verifies; the other two fail HashSLH-DSA Verify (the certificate has another context string and was signed as pure SLH-DSA) |

**How the API is called** (from `secure_boot/secure_boot.cpp`, error checks left out)

```cpp
#include "openpqc/openpqc.hpp"
using RootDSA = openpqc::SLH_DSA_SHA2_128s; // the vendor root key; its public key is in ROM
using ReleaseDSA = openpqc::ML_DSA_65;      // release signing keys, certified by the root

// Vendor: the root key pair, then release key 1 (sk is RootDSA::secret_key / ReleaseDSA::secret_key, an
// openpqc::secret<N>, zeroized when destroyed); every call returns an openpqc::status
RootDSA::keygen(pk, sk);
ReleaseDSA::keygen(pk, sk);
// The root certifies release key 1 (certify): the certificate body (tbs) names the key and its scope
const KeyCertificate c{key.key_id, key.key_version, kAlgMLDSA65, key.pk, models, types};
const Bytes tbs = encode_certificate_tbs(c);
const auto sig = std::make_unique<RootDSA::signature>();   // 7856 bytes
RootDSA::sign(*sig, tbs, sk, view(kCertificateContext));
// A release (release, then sign_manifest): the manifest holds the image's SHA3-256; the release key signs it
const Manifest m{model, type, svn, version, static_cast<std::uint32_t>(image.size()), sha3_256(image)};
const Bytes body = encode_manifest(m);
ReleaseDSA::signature sig;   // 3309 bytes
ReleaseDSA::sign(sig, body, sk, view(kManifestContext));

// Boot loader (verify_update): checks 1 to 6 in order, each signature valid if the call returns
// openpqc::status::ok; cert and m are parsed after their signatures verify
RootDSA::verify(signed_cert.signature, signed_cert.body, dev.rom_root_key, view(kCertificateContext));  // 1
if (cert.key_version < dev.min_key_version) return reject(Check::key_version, /* ... */);              // 2
ReleaseDSA::verify(signed_manifest.signature, signed_manifest.body, release_pk, view(kManifestContext)); // 3
const Hash hash = sha3_256(p.image);  // 4: after the size check; opqc_sha3_256, compared with m.image_hash
/* ... 5: the model and image type, against the certificate's lists and this device's */
if (cert.key_version == dev.min_key_version && m.svn < dev.min_svn) return reject(Check::svn, /* ... */); // 6
// Install (install_update): raise the pair (minimum key version, minimum SVN)
if (v.key_version > dev.min_key_version) {   // a higher key version starts a new SVN sequence
    dev.min_key_version = v.key_version;
    dev.min_svn = v.svn;
} else {
    dev.min_svn = std::max(dev.min_svn, v.svn);
}

// Recovery (sign_recovery, verify_recovery): HashSLH-DSA, kRecoveryPreHash = PreHash::SHA2_256
RootDSA::prehash_sign(*sig, image, kRecoveryPreHash, sk, view(kRecoveryContext));
RootDSA::prehash_verify(sig, image, kRecoveryPreHash, dev.rom_root_key, view(kRecoveryContext));
```

**Run**

```sh
cmake --build build --target secure_boot
build/applications/secure_boot        # all eight scenarios (the CTest run): about 4.5 s on one core,
                                      # most of it in four SLH-DSA-SHA2-128s signatures of about 0.85 s
build/applications/secure_boot 100    # runs (1 to 10000, default 10): timed repetitions, about 50 ms each, of
                                      # a manifest signature, an update and a recovery verification
# exit 0: all 18 checks ok (expected rejections included); 1: a failed check or library call, a bad argument
```

```
  root key       SLH-DSA-SHA2-128s: KeyGen 110 ms, Sign 851 ms (key 1's certificate)
  release key 1  ML-DSA-65: KeyGen 0.29 ms, Sign 1.05 ms (a manifest, mean of 10); key version 1,
...
  root public key (device ROM)        32  (the device's two counters are in replay-protected storage)
  key certificate                   9845  (ML-DSA-65 public key 1952, SLH-DSA signature 7856)
...
  boot loader verification time, mean of 10: 6.32 ms
    SLH-DSA Verify 0.83 ms, ML-DSA-65 Verify 0.28 ms, SHA3-256 of the 1 MiB image 5.21 ms
...
  an attacker's image (SVN 2^32-1) signed with the stolen key 1: rejected    ok
      boot loader: rejected at check 2: release key 1 has key version 1, below the device's minimum 2
...
  verification time, mean of 10: 44.35 ms (SHA-256 of 8 MiB, then SLH-DSA Verify)
...
all scenarios ended as expected
```

SLH-DSA-SHA2-128s signs slowly (about 0.85 s on one core), so the root signs only key certificates and recovery images, a few times a year, and the fast ML-DSA-65 keys (about 1 ms per signature) sign every release. Its verification takes under 1 ms, so the boot loader spends most of its 6 ms hashing the 1 MiB image.

<a id="timestamp_authority"></a>

### `timestamp_authority` — a time-stamping authority signing tokens with SLH-DSA on CPU and GPU

A time-stamping authority (TSA, as in RFC 3161: a service that vouches that a document existed at a given time) gets the SHA3-256 hash of each client's document and returns a token: an 88-byte TSTInfo (the hash, the time, a serial number, the TSA's key id and a few fixed fields, in a fixed layout rather than RFC 3161's DER and CMS) and its signature under the TSA's one SLH-DSA key. SLH-DSA (FIPS 205) rests only on hash functions, which suits tokens that are checked decades later, but signing is slow. So the program issues tokens on CPU threads and in GPU batches, for SLH-DSA-SHA2-128f (fast signing, 17,176-byte tokens) and SLH-DSA-SHA2-128s (7,944-byte tokens, signing about 20 times slower on the CPU). An auditor that holds only the public key then checks every token on the GPU and on the CPU, and both must reject three forged tokens; finally the clients check their own tokens (all of them with `--quick`, otherwise a random sample of 512).

**Where each technique is used**

| Step | Technique | API |
|---|---|---|
| Setup: the TSA, and a second TSA whose key makes one forgery, each make a key pair. The key id in every token is the SHA3-256 hash of the TSA's public key | SLH-DSA-SHA2-128f / 128s KeyGen, SHA3-256 | `openpqc_sig_keygen` (the parameter set as an `openpqc_alg`), `opqc_sha3_256` |
| Each client hashes its document (random bytes, 64 B to 4 KiB). Only the hash (the message imprint) goes to the TSA | SHA3-256 | `opqc_randombytes`, `opqc_sha3_256` |
| CPU server: T threads each take the next request, encode its TSTInfo and sign it with the context string `"openpqc-demo timestamp token"` (a label bound into the signature, so that signatures the key makes for other purposes never verify as tokens) | SLH-DSA Sign, hedged (fresh randomness in every signature) | `openpqc_sig_sign` |
| GPU server, once per set: whether the GPU library has the set, a context sized for the largest batch (at most 2 GiB of workspace, which the library reports before the context exists), device and page-locked host buffers (pinned memory, faster to copy), and the secret key, copied to the device once from page-locked memory that is wiped right after | the GPU API (`openpqc/sycl.h`) | `openpqc_gpu_supports`, `openpqc_gpu_workspace_bytes`, `openpqc_gpu_create`, `openpqc_gpu_malloc`, `openpqc_gpu_malloc_host`, `openpqc_gpu_memcpy`, `opqc_zeroize` |
| GPU server, per batch: B TSTInfos go in (all 88 bytes long: a stride, no offsets), and B signatures under the one TSA key come back, with a status array: an entry other than `OPENPQC_OK` means no signature | SLH-DSA Sign, hedged, one-key GPU batch | `openpqc_gpu_memcpy_async`, `openpqc_gpu_sig_sign` with `OPENPQC_GPU_ONE_KEY`, `openpqc_gpu_sync` |
| After the last batch, the device copy of the secret key is freed: `openpqc_gpu_free` overwrites it with zeros and reports whether it could (the program fails if it could not) | — | `openpqc_gpu_free`, `openpqc_gpu_destroy` |
| Auditor: checks the archive's structure (fields, key id, serials going up by one, genTimes never going back), then every signature in one GPU call. It has its own context and only the public key | SLH-DSA Verify, one-key GPU batch | `openpqc_gpu_sig_verify` with `OPENPQC_GPU_ONE_KEY`, `openpqc_gpu_memcpy` (status array back) |
| Auditor: every signature again, on T CPU threads | SLH-DSA Verify | `openpqc_sig_verify` |
| Forgeries made from archived tokens: the document hash replaced, genTime moved back one day, the same TSTInfo signed with the second TSA's key. The GPU and the CPU must reject all three and accept the originals; the third must verify under the second TSA's key (a sound signature, made with the wrong key) | SLH-DSA Sign (second key), Verify | `openpqc_sig_sign`, `openpqc_gpu_sig_verify`, `openpqc_sig_verify` |
| Clients check their own tokens (all with `--quick`, otherwise a random sample of 512): the fields, their own document hash, the key id (computed from the published public key), genTime within 60 s of their own clock, and the signature | SHA3-256, SLH-DSA Verify | `opqc_sha3_256`, `openpqc_sig_verify` |

**How the API is called** (from `timestamp_authority/timestamp_authority.cpp`, error checks left out)

```cpp
#include "openpqc/openpqc.h"
#include "openpqc/sycl.h"
// The parameter set is chosen at run time: the CPU functions of openpqc/sig.h and the GPU contexts take it
// as an openpqc_alg (kSets: s.alg); shown here for SLH-DSA-SHA2-128f. INFO = 88 (TSTInfo), SK = 64, SIG = 17088
const openpqc_alg alg = OPENPQC_SLH_DSA_SHA2_128F;
const openpqc_sign_opts kTokenOpts{context_string(), kContext.size(), 0, 0};  // pure SLH-DSA, hedged
const openpqc_sign_opts kGpuTokenOpts{context_string(), kContext.size(), 0, OPENPQC_GPU_ONE_KEY};
// Setup: the TSA's key pair; the key id in every token is SHA3-256 of the public key
openpqc_sig_keygen(alg, pk.data(), sk.data());
opqc_sha3_256(key_id.data(), pk.data(), pk.size());
opqc_sha3_256(r.hash.data() + i * HASH, document.data(), document.size());  // client i's request

// CPU server, request i on one of T threads: encode TSTInfo i, then sign it (hedged)
encode(a.info(i), token_info(tsa, r, i));
openpqc_sig_sign(alg, a.sig(i), a.info(i), INFO, &kTokenOpts, tsa.sk.data());

// GPU server, once per set that the GPU library has (openpqc_gpu_supports). launch: the largest batch,
// capped at 2 GiB of workspace (openpqc_gpu_workspace_bytes(alg, launch, &bytes) reports it before the
// context exists); d_*: openpqc_gpu_malloc, h_*: openpqc_gpu_malloc_host (page-locked)
const openpqc_gpu_config cfg{device, launch};
openpqc_gpu_create(&ctx, alg, &cfg);
std::memcpy(staging, tsa.sk.data(), SK);       // staging is page-locked too
openpqc_gpu_memcpy(ctx, d_sk, staging, SK);    // the secret key, to the device once
opqc_zeroize(staging, SK);                     // when staging goes out of scope, right after
// One batch of n tokens: their TSTInfos encoded into h_msg, message j at j * INFO (a stride)
const openpqc_gpu_messages infos{d_msg, nullptr, INFO, n * INFO};
openpqc_gpu_memcpy_async(ctx, d_msg, h_msg, n * INFO);
openpqc_gpu_sig_sign(ctx, d_sig, infos, &kGpuTokenOpts, d_sk, d_status, n);
openpqc_gpu_memcpy_async(ctx, h_sig, d_sig, n * SIG);
openpqc_gpu_memcpy_async(ctx, h_status, d_status, n * sizeof(std::int32_t));
openpqc_gpu_sync(ctx);   // then signature j is complete if h_status[j] == OPENPQC_OK
// After the last batch: free the device key (openpqc_gpu_free waits for the context's work, overwrites
// the memory with zeros and reports whether it could: OPENPQC_ERR_DEVICE if the context had failed), then destroy
openpqc_gpu_free(ctx, d_sk);
openpqc_gpu_destroy(ctx);
// ... forgeries: one TSTInfo signed with the second TSA's key (openpqc_sig_sign)

// Auditor: a new context with only the public key d_pk; the n tokens copied in (blocking)
openpqc_gpu_sig_verify(ctx, d_sig, infos, &kGpuTokenOpts, d_pk, d_status, n);
openpqc_gpu_memcpy(ctx, h_status, d_status, n * sizeof(std::int32_t));
// h_status[i]: OPENPQC_OK valid, OPENPQC_ERR_INVALID_SIGNATURE invalid, anything else no verdict (an error)
// CPU auditor (T threads), the forgeries and the clients: one token at a time
openpqc_sig_verify(alg, a.sig(i), SIG, a.info(i), INFO, &kTokenOpts, pk.data());
```

**Run**

```sh
cmake --build build --target timestamp_authority   # exists only in a build with the SYCL backend; the development option
                                                   # -DOPENPQC_SLHDSA_SYCL_SETS=1,3 puts only SHA2-128s (1) and SHA2-128f (3)
                                                   # into the GPU library (linking: about 1.3 instead of 10 minutes)
build/applications/timestamp_authority             # 128f and 128s, GPU batches 1,16,128,1024,4096: about 58,000 tokens per set,
                                                   # about 77 s on an L4 with 2 CPU threads; 1.2 GB host and 3.3 GB device memory
build/applications/timestamp_authority --quick     # 128f only, batches 1,16, every client checks its token (the CTest run, about 1 s)
build/applications/timestamp_authority --quick --cpu-only   # CPU server, CPU auditor and clients only; needs no GPU
ctest --test-dir build -R app_timestamp_authority  # both runs above as tests (the GPU one is skipped without a device)
# --set 128f|128s       one parameter set only
# --batches B1,B2,...   GPU batch sizes, 1 to 16384 each; 11 batches per size (6 with --quick), at most 262,144 tokens per set
# --cpu-tokens N        tokens the CPU server signs per set (default per thread: 32 for 128f, 2 for 128s; 4 and 1 with --quick)
# --threads T           threads of the setup, the CPU server, the CPU auditor and the clients (default: the CPUs this process may use)
# --device D            SYCL device index (default: OPENPQC_SYCL_DEVICE, or the default device)
# exit code: 0 every check passed, the forgeries rejected; 1 a check or a library call failed, or a bad option;
#            77 no SYCL device, or none of the chosen sets in this build's GPU library (without --cpu-only)
```

```
  parameter set         token  server              tokens/s  latency median        p90
  SLH-DSA-SHA2-128f   17176 B  CPU, 2 threads           110         18.1 ms    18.3 ms
                               GPU, batch 1            4848         0.21 ms    0.21 ms
                               GPU, batch 16          30051         0.53 ms    0.54 ms
                               GPU, batch 128         41218         3.04 ms    3.27 ms
                               ...
  SLH-DSA-SHA2-128s    7944 B  CPU, 2 threads          5.40        369.2 ms   371.6 ms
                               GPU, batch 1            1746         0.57 ms    0.58 ms
                               GPU, batch 16           2434         6.75 ms    6.76 ms
                               ...
  the auditor, tokens verified per second:
    SLH-DSA-SHA2-128f  57979 tokens: GPU 271638 (one call), CPU 1844
    SLH-DSA-SHA2-128s  57919 tokens: GPU 167612 (one call), CPU 5366
...
result: ok
```

On the L4, SLH-DSA-SHA2-128f issues the most tokens at batch 128: 41218 per second, 374 times the 2-thread CPU server. The latency is that of one token on the CPU and of a whole batch on the GPU: a batch of one token takes 0.21 ms, and one token on a CPU thread takes 18.1 ms. SLH-DSA-SHA2-128s tokens are 2.2 times smaller, but the GPU issues 17 times fewer of them per second. Its rate peaks at batch 16 (2434 per second), so larger batches only add latency, up to 2.02 s at batch 4096. Verification goes the other way: on the CPU, 128s tokens verify 2.9 times faster than 128f tokens, but on the GPU 128f tokens verify faster (271638 against 167612 per second).
