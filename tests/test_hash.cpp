// test_hash.cpp  --  FIPS 202 (SHA3 / SHAKE): known answers and incremental vs one-shot
// known answers were generated with Python's hashlib
#include "check.hpp"
#include "Core/hash.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace openpqc::fips202;

namespace {

std::string hex(std::span<const std::uint8_t> b) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string s;
    for (auto x : b) {
        s += digits[x >> 4];
        s += digits[x & 15];
    }
    return s;
}

std::vector<std::uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

std::vector<std::uint8_t> counting(std::size_t n) {
    std::vector<std::uint8_t> m(n);
    for (std::size_t i = 0; i < n; i++) m[i] = static_cast<std::uint8_t>(i);
    return m;
}

const std::string sha3_256_empty =
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
const std::string sha3_256_abc =
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
const std::string sha3_512_abc =
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";
const std::string shake128_empty_32 =
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
const std::string shake256_abc_64 =
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4";
const std::string sha3_256_long =
        "0f96259f82fb8c30d3d702e8a89a475d2e96690a5ee9892a48351864fb492aa5";
const std::string sha3_512_long =
        "5c371829f774959d04ac4b4e49557e4355427407ca960a3acc9643bb5b13cb69"
        "2bbe281f3f4137784551092b4613e016a4f1ff2714f8f67f97d11e3233a9b662";
const std::string shake128_long_400 =
        "9ae12ebc45c0911ebf810ac3d6fb1be6a7fcb7a4265a5c57acee7c5d39fc8138"
        "3741f2de5f546b2f1d5d545d5f691ecd98402d48364437ee8392aa8c9aa5fc1d"
        "ca77d6c2c46244aad054a42f8a56928f59c630078431cdf25039d3c3851e2c67"
        "1826917629d2f28a0b123759314f46808751a9c6f47aae8b635c1933c994a848"
        "fdf949a462b8a08dee5edc071931d4ad8be9f01f0c6ec1d6d3afdc7129e92b38"
        "e11b247ed46a138609a53bd4bdafc4afe13c286acc8bc9c3f631ff186bafc1eb"
        "f3441d232bbe6c97a02cf8b6559952009b516649637047d3e80c917cc0fd17c3"
        "486e4749d19191420cd1f6d4b4c1ba7fe676964f1f7c57e79cdb75197db1738f"
        "53b17d0ea82d035b71d6cb92d225a653c95026995481bde7cb86e8c0c5ab8a2f"
        "f6cf1a6768bd71d522429373f9a29c17c0db07677cb0e5ecae66b3a6f38f5d10"
        "4ce8f4264ca79edbad1369e2ecf0127312ff8769e6a711766d12fcec5b7c85ba"
        "d42d36f10f8b3540fc97f7762b01d10dcfb6ae12867dc39a82e1e2d8c2b778c6"
        "6c644fd3ab24f55c52fb1a70020bf3dd";
const std::string shake256_long_300 =
        "3480d44a3cfac940f64d357410bae92c17468f6b7cb2084ba5b13db072f7bf3f"
        "a06bd70b67209cf6f734edc0dcbb0825d3c129f18e021f58eadc0370856a21ed"
        "35776de8fdacbaef54af139381887696bda6c153ff06987ec3f10f8528940e54"
        "b64a0ed49dcc85bc65f8f18104e1e9991a601a660d9230fa527d47e47192f08f"
        "b682cf910e303ef3786a5e2a3ad6e756e9b61b2c619ae65b3059e6f4858ae73f"
        "5e16c721922376dedddb7180af44cf827ab2072d4e43d1007c012369e5f4192c"
        "f734fa248a3f4fa41c5ebf02a8bd13ea6f9d4ae7fd4941988a343c5651dbc95b"
        "e435780ca701ef69465df91f586af851f3915c7de7489ef20dae43a02e227cbb"
        "ba8048ea269fce01071de1e058111d4d1437954fb4dd339fdc7036468f0b3b2a"
        "7cb8e8a98b56d7caa9907f90";

} // namespace

int main() {
    const auto empty = bytes("");
    const auto abc = bytes("abc");
    const auto m = counting(500);

    std::array<std::uint8_t, 32> h32{};
    std::array<std::uint8_t, 64> h64{};

    sha3_256(h32, empty);
    CHECK_EQ(hex(h32), sha3_256_empty);
    sha3_256(h32, abc);
    CHECK_EQ(hex(h32), sha3_256_abc);
    sha3_256(h32, m);
    CHECK_EQ(hex(h32), sha3_256_long);
    sha3_512(h64, abc);
    CHECK_EQ(hex(h64), sha3_512_abc);
    sha3_512(h64, m);
    CHECK_EQ(hex(h64), sha3_512_long);

    std::vector<std::uint8_t> out(32);
    shake128(out, empty);
    CHECK_EQ(hex(out), shake128_empty_32);
    out.resize(64);
    shake256(out, abc);
    CHECK_EQ(hex(out), shake256_abc_64);
    out.resize(400);
    shake128(out, m);
    CHECK_EQ(hex(out), shake128_long_400);
    out.resize(300);
    shake256(out, m);
    CHECK_EQ(hex(out), shake256_long_300);

    // incremental absorb/squeeze in uneven chunks gives the same bytes as the one-shot API
    for (std::size_t chunk : {1u, 7u, 135u, 136u, 137u, 168u, 169u}) {
        keccak_state st;
        shake128_init(st);
        for (std::size_t i = 0; i < m.size(); i += chunk)
            shake128_absorb(st, std::span(m).subspan(i, std::min(chunk, m.size() - i)));
        shake128_finalize(st);
        std::vector<std::uint8_t> inc(400);
        for (std::size_t i = 0; i < inc.size(); i += chunk)
            shake128_squeeze(std::span(inc).subspan(i, std::min(chunk, inc.size() - i)), st);
        CHECK_EQ(hex(inc), shake128_long_400);

        shake256_init(st);
        for (std::size_t i = 0; i < m.size(); i += chunk)
            shake256_absorb(st, std::span(m).subspan(i, std::min(chunk, m.size() - i)));
        shake256_finalize(st);
        inc.assign(300, 0);
        for (std::size_t i = 0; i < inc.size(); i += chunk)
            shake256_squeeze(std::span(inc).subspan(i, std::min(chunk, inc.size() - i)), st);
        CHECK_EQ(hex(inc), shake256_long_300);
    }

    // absorb_once + squeezeblocks, as ML-KEM uses it, into a buffer larger than the blocks
    {
        keccak_state st;
        shake128_absorb_once(st, m);
        std::vector<std::uint8_t> buf(2 * SHAKE128_RATE + 2, 0);
        shake128_squeezeblocks(buf, 2, st);
        CHECK_EQ(hex(std::span(buf).first(2 * SHAKE128_RATE)), shake128_long_400.substr(0, 4 * SHAKE128_RATE));
    }

    return check::report();
}
