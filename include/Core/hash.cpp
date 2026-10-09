// hash.cpp  --  FIPS 202: SHA3-256, SHA3-512, SHAKE128 and SHAKE256
/* Based on the public domain implementation in crypto_hash/keccakc512/simple/ from
 * http://bench.cr.yp.to/supercop.html by Ronny Van Keer and the public domain "TweetFips202"
 * implementation from https://twitter.com/tweetfips202 by Gilles Van Assche, Daniel J. Bernstein,
 * and Peter Schwabe */

#include "Core/hash.hpp"

#include <algorithm>
#include <bit>
#include <cassert>

namespace openpqc::fips202 {

namespace {

using state_t = std::array<std::uint64_t, 25>;

constexpr std::size_t NROUNDS = 24;

/*************************************************
* Name:        load64
*
* Description: Load 8 bytes into std::uint64_t in little-endian order
*
* Arguments:   - std::span<const std::uint8_t, 8> x: input byte array
*
* Returns the loaded 64-bit unsigned integer
**************************************************/
std::uint64_t load64(std::span<const std::uint8_t, 8> x) {
    std::uint64_t r = 0;
    for (std::size_t i = 0; i < 8; i++)
        r |= std::uint64_t{x[i]} << 8 * i;
    return r;
}

/*************************************************
* Name:        store64
*
* Description: Store a 64-bit integer to array of 8 bytes in little-endian order
*
* Arguments:   - std::span<std::uint8_t, 8> x: output byte array
*              - std::uint64_t u: input 64-bit unsigned integer
**************************************************/
void store64(std::span<std::uint8_t, 8> x, std::uint64_t u) {
    for (std::size_t i = 0; i < 8; i++)
        x[i] = static_cast<std::uint8_t>(u >> 8 * i);
}

/* Keccak round constants */
constexpr std::array<std::uint64_t, NROUNDS> KeccakF_RoundConstants = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
};

/*************************************************
* Name:        KeccakF1600_StatePermute
*
* Description: The Keccak F1600 Permutation
*
* Arguments:   - state_t& state: input/output Keccak state
**************************************************/
void KeccakF1600_StatePermute(state_t& state) {
    std::uint64_t Aba, Abe, Abi, Abo, Abu;
    std::uint64_t Aga, Age, Agi, Ago, Agu;
    std::uint64_t Aka, Ake, Aki, Ako, Aku;
    std::uint64_t Ama, Ame, Ami, Amo, Amu;
    std::uint64_t Asa, Ase, Asi, Aso, Asu;
    std::uint64_t BCa, BCe, BCi, BCo, BCu;
    std::uint64_t Da, De, Di, Do, Du;
    std::uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    std::uint64_t Ega, Ege, Egi, Ego, Egu;
    std::uint64_t Eka, Eke, Eki, Eko, Eku;
    std::uint64_t Ema, Eme, Emi, Emo, Emu;
    std::uint64_t Esa, Ese, Esi, Eso, Esu;

    // copyFromState(A, state)
    Aba = state[ 0];
    Abe = state[ 1];
    Abi = state[ 2];
    Abo = state[ 3];
    Abu = state[ 4];
    Aga = state[ 5];
    Age = state[ 6];
    Agi = state[ 7];
    Ago = state[ 8];
    Agu = state[ 9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (std::size_t round = 0; round < NROUNDS; round += 2) {
        // prepareTheta
        BCa = Aba^Aga^Aka^Ama^Asa;
        BCe = Abe^Age^Ake^Ame^Ase;
        BCi = Abi^Agi^Aki^Ami^Asi;
        BCo = Abo^Ago^Ako^Amo^Aso;
        BCu = Abu^Agu^Aku^Amu^Asu;

        // thetaRhoPiChiIotaPrepareTheta(round, A, E)
        Da = BCu^std::rotl(BCe, 1);
        De = BCa^std::rotl(BCi, 1);
        Di = BCe^std::rotl(BCo, 1);
        Do = BCi^std::rotl(BCu, 1);
        Du = BCo^std::rotl(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = std::rotl(Age, 44);
        Aki ^= Di;
        BCi = std::rotl(Aki, 43);
        Amo ^= Do;
        BCo = std::rotl(Amo, 21);
        Asu ^= Du;
        BCu = std::rotl(Asu, 14);
        Eba =   BCa ^((~BCe)&  BCi );
        Eba ^= KeccakF_RoundConstants[round];
        Ebe =   BCe ^((~BCi)&  BCo );
        Ebi =   BCi ^((~BCo)&  BCu );
        Ebo =   BCo ^((~BCu)&  BCa );
        Ebu =   BCu ^((~BCa)&  BCe );

        Abo ^= Do;
        BCa = std::rotl(Abo, 28);
        Agu ^= Du;
        BCe = std::rotl(Agu, 20);
        Aka ^= Da;
        BCi = std::rotl(Aka, 3);
        Ame ^= De;
        BCo = std::rotl(Ame, 45);
        Asi ^= Di;
        BCu = std::rotl(Asi, 61);
        Ega =   BCa ^((~BCe)&  BCi );
        Ege =   BCe ^((~BCi)&  BCo );
        Egi =   BCi ^((~BCo)&  BCu );
        Ego =   BCo ^((~BCu)&  BCa );
        Egu =   BCu ^((~BCa)&  BCe );

        Abe ^= De;
        BCa = std::rotl(Abe, 1);
        Agi ^= Di;
        BCe = std::rotl(Agi, 6);
        Ako ^= Do;
        BCi = std::rotl(Ako, 25);
        Amu ^= Du;
        BCo = std::rotl(Amu, 8);
        Asa ^= Da;
        BCu = std::rotl(Asa, 18);
        Eka =   BCa ^((~BCe)&  BCi );
        Eke =   BCe ^((~BCi)&  BCo );
        Eki =   BCi ^((~BCo)&  BCu );
        Eko =   BCo ^((~BCu)&  BCa );
        Eku =   BCu ^((~BCa)&  BCe );

        Abu ^= Du;
        BCa = std::rotl(Abu, 27);
        Aga ^= Da;
        BCe = std::rotl(Aga, 36);
        Ake ^= De;
        BCi = std::rotl(Ake, 10);
        Ami ^= Di;
        BCo = std::rotl(Ami, 15);
        Aso ^= Do;
        BCu = std::rotl(Aso, 56);
        Ema =   BCa ^((~BCe)&  BCi );
        Eme =   BCe ^((~BCi)&  BCo );
        Emi =   BCi ^((~BCo)&  BCu );
        Emo =   BCo ^((~BCu)&  BCa );
        Emu =   BCu ^((~BCa)&  BCe );

        Abi ^= Di;
        BCa = std::rotl(Abi, 62);
        Ago ^= Do;
        BCe = std::rotl(Ago, 55);
        Aku ^= Du;
        BCi = std::rotl(Aku, 39);
        Ama ^= Da;
        BCo = std::rotl(Ama, 41);
        Ase ^= De;
        BCu = std::rotl(Ase, 2);
        Esa =   BCa ^((~BCe)&  BCi );
        Ese =   BCe ^((~BCi)&  BCo );
        Esi =   BCi ^((~BCo)&  BCu );
        Eso =   BCo ^((~BCu)&  BCa );
        Esu =   BCu ^((~BCa)&  BCe );

        // prepareTheta
        BCa = Eba^Ega^Eka^Ema^Esa;
        BCe = Ebe^Ege^Eke^Eme^Ese;
        BCi = Ebi^Egi^Eki^Emi^Esi;
        BCo = Ebo^Ego^Eko^Emo^Eso;
        BCu = Ebu^Egu^Eku^Emu^Esu;

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu^std::rotl(BCe, 1);
        De = BCa^std::rotl(BCi, 1);
        Di = BCe^std::rotl(BCo, 1);
        Do = BCi^std::rotl(BCu, 1);
        Du = BCo^std::rotl(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = std::rotl(Ege, 44);
        Eki ^= Di;
        BCi = std::rotl(Eki, 43);
        Emo ^= Do;
        BCo = std::rotl(Emo, 21);
        Esu ^= Du;
        BCu = std::rotl(Esu, 14);
        Aba =   BCa ^((~BCe)&  BCi );
        Aba ^= KeccakF_RoundConstants[round+1];
        Abe =   BCe ^((~BCi)&  BCo );
        Abi =   BCi ^((~BCo)&  BCu );
        Abo =   BCo ^((~BCu)&  BCa );
        Abu =   BCu ^((~BCa)&  BCe );

        Ebo ^= Do;
        BCa = std::rotl(Ebo, 28);
        Egu ^= Du;
        BCe = std::rotl(Egu, 20);
        Eka ^= Da;
        BCi = std::rotl(Eka, 3);
        Eme ^= De;
        BCo = std::rotl(Eme, 45);
        Esi ^= Di;
        BCu = std::rotl(Esi, 61);
        Aga =   BCa ^((~BCe)&  BCi );
        Age =   BCe ^((~BCi)&  BCo );
        Agi =   BCi ^((~BCo)&  BCu );
        Ago =   BCo ^((~BCu)&  BCa );
        Agu =   BCu ^((~BCa)&  BCe );

        Ebe ^= De;
        BCa = std::rotl(Ebe, 1);
        Egi ^= Di;
        BCe = std::rotl(Egi, 6);
        Eko ^= Do;
        BCi = std::rotl(Eko, 25);
        Emu ^= Du;
        BCo = std::rotl(Emu, 8);
        Esa ^= Da;
        BCu = std::rotl(Esa, 18);
        Aka =   BCa ^((~BCe)&  BCi );
        Ake =   BCe ^((~BCi)&  BCo );
        Aki =   BCi ^((~BCo)&  BCu );
        Ako =   BCo ^((~BCu)&  BCa );
        Aku =   BCu ^((~BCa)&  BCe );

        Ebu ^= Du;
        BCa = std::rotl(Ebu, 27);
        Ega ^= Da;
        BCe = std::rotl(Ega, 36);
        Eke ^= De;
        BCi = std::rotl(Eke, 10);
        Emi ^= Di;
        BCo = std::rotl(Emi, 15);
        Eso ^= Do;
        BCu = std::rotl(Eso, 56);
        Ama =   BCa ^((~BCe)&  BCi );
        Ame =   BCe ^((~BCi)&  BCo );
        Ami =   BCi ^((~BCo)&  BCu );
        Amo =   BCo ^((~BCu)&  BCa );
        Amu =   BCu ^((~BCa)&  BCe );

        Ebi ^= Di;
        BCa = std::rotl(Ebi, 62);
        Ego ^= Do;
        BCe = std::rotl(Ego, 55);
        Eku ^= Du;
        BCi = std::rotl(Eku, 39);
        Ema ^= Da;
        BCo = std::rotl(Ema, 41);
        Ese ^= De;
        BCu = std::rotl(Ese, 2);
        Asa =   BCa ^((~BCe)&  BCi );
        Ase =   BCe ^((~BCi)&  BCo );
        Asi =   BCi ^((~BCo)&  BCu );
        Aso =   BCo ^((~BCu)&  BCa );
        Asu =   BCu ^((~BCa)&  BCe );
    }

    // copyToState(state, A)
    state[ 0] = Aba;
    state[ 1] = Abe;
    state[ 2] = Abi;
    state[ 3] = Abo;
    state[ 4] = Abu;
    state[ 5] = Aga;
    state[ 6] = Age;
    state[ 7] = Agi;
    state[ 8] = Ago;
    state[ 9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;}

/*************************************************
* Name:        keccak_absorb
*
* Description: Absorb step of Keccak; incremental.
*
* Arguments:   - state_t& s: Keccak state
*              - std::size_t pos: position in current block to be absorbed
*              - std::size_t r: rate in bytes (e.g., 168 for SHAKE128)
*              - std::span<const std::uint8_t> in: input to be absorbed into s
*
* Returns new position pos in current block
**************************************************/
std::size_t keccak_absorb(state_t& s, std::size_t pos, std::size_t r, std::span<const std::uint8_t> in) {
    while (pos + in.size() >= r) {
        for (std::size_t i = pos; i < r; i++)
            s[i / 8] ^= std::uint64_t{in[i - pos]} << 8 * (i % 8);
        in = in.subspan(r - pos);
        KeccakF1600_StatePermute(s);
        pos = 0;
    }

    for (std::size_t i = 0; i < in.size(); i++)
        s[(pos + i) / 8] ^= std::uint64_t{in[i]} << 8 * ((pos + i) % 8);

    return pos + in.size();
}

/*************************************************
* Name:        keccak_finalize
*
* Description: Finalize absorb step.
*
* Arguments:   - state_t& s: Keccak state
*              - std::size_t pos: position in current block to be absorbed
*              - std::size_t r: rate in bytes (e.g., 168 for SHAKE128)
*              - std::uint8_t p: domain separation byte
**************************************************/
void keccak_finalize(state_t& s, std::size_t pos, std::size_t r, std::uint8_t p) {
    s[pos / 8] ^= std::uint64_t{p} << 8 * (pos % 8);
    s[r / 8 - 1] ^= 1ULL << 63;
}

/*************************************************
* Name:        keccak_squeeze
*
* Description: Squeeze step of Keccak. Squeezes arbitratrily many bytes.
*              Modifies the state. Can be called multiple times to keep
*              squeezing, i.e., is incremental.
*
* Arguments:   - std::span<std::uint8_t> out: output (all out.size() bytes are written)
*              - state_t& s: input/output Keccak state
*              - std::size_t pos: number of bytes in current block already squeezed
*              - std::size_t r: rate in bytes (e.g., 168 for SHAKE128)
*
* Returns new position pos in current block
**************************************************/
std::size_t keccak_squeeze(std::span<std::uint8_t> out, state_t& s, std::size_t pos, std::size_t r) {
    while (!out.empty()) {
        if (pos == r) {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }
        const std::size_t n = std::min(r - pos, out.size());
        for (std::size_t i = 0; i < n; i++)
            out[i] = static_cast<std::uint8_t>(s[(pos + i) / 8] >> 8 * ((pos + i) % 8));
        out = out.subspan(n);
        pos += n;
    }

    return pos;
}

/*************************************************
* Name:        keccak_absorb_once
*
* Description: Absorb step of Keccak;
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - state_t& s: (uninitialized) output Keccak state
*              - std::size_t r: rate in bytes (e.g., 168 for SHAKE128)
*              - std::span<const std::uint8_t> in: input to be absorbed into s
*              - std::uint8_t p: domain-separation byte for different Keccak-derived functions
**************************************************/
void keccak_absorb_once(state_t& s, std::size_t r, std::span<const std::uint8_t> in, std::uint8_t p) {
    s.fill(0);

    while (in.size() >= r) {
        for (std::size_t i = 0; i < r / 8; i++)
            s[i] ^= load64(in.subspan(8 * i).first<8>());
        in = in.subspan(r);
        KeccakF1600_StatePermute(s);
    }

    for (std::size_t i = 0; i < in.size(); i++)
        s[i / 8] ^= std::uint64_t{in[i]} << 8 * (i % 8);

    s[in.size() / 8] ^= std::uint64_t{p} << 8 * (in.size() % 8);
    s[(r - 1) / 8] ^= 1ULL << 63;
}

/*************************************************
* Name:        keccak_squeezeblocks
*
* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
*              Modifies the state. Can be called multiple times to keep
*              squeezing, i.e., is incremental. Assumes zero bytes of current
*              block have already been squeezed.
*
* Arguments:   - std::span<std::uint8_t> out: output blocks (at least nblocks * r bytes)
*              - std::size_t nblocks: number of blocks to be squeezed (written to out)
*              - state_t& s: input/output Keccak state
*              - std::size_t r: rate in bytes (e.g., 168 for SHAKE128)
**************************************************/
void keccak_squeezeblocks(std::span<std::uint8_t> out, std::size_t nblocks, state_t& s, std::size_t r) {
    assert(out.size() >= nblocks * r);

    for (; nblocks > 0; nblocks--) {
        KeccakF1600_StatePermute(s);
        for (std::size_t i = 0; i < r / 8; i++)
            store64(out.subspan(8 * i).first<8>(), s[i]);
        out = out.subspan(r);
    }
}

} // namespace

/*************************************************
* Name:        shake128_init
*
* Description: Initilizes Keccak state for use as SHAKE128 XOF
*
* Arguments:   - keccak_state& state: (uninitialized) Keccak state
**************************************************/
void shake128_init(keccak_state& state) {
    state.s.fill(0);
    state.pos = 0;
}

/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of the SHAKE128 XOF; incremental.
*
* Arguments:   - keccak_state& state: (initialized) output Keccak state
*              - std::span<const std::uint8_t> in: input to be absorbed into s
**************************************************/
void shake128_absorb(keccak_state& state, std::span<const std::uint8_t> in) {
    state.pos = keccak_absorb(state.s, state.pos, SHAKE128_RATE, in);
}

/*************************************************
* Name:        shake128_finalize
*
* Description: Finalize absorb step of the SHAKE128 XOF.
*
* Arguments:   - keccak_state& state: Keccak state
**************************************************/
void shake128_finalize(keccak_state& state) {
    keccak_finalize(state.s, state.pos, SHAKE128_RATE, 0x1F);
    state.pos = SHAKE128_RATE;
}

/*************************************************
* Name:        shake128_squeeze
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes arbitraily many
*              bytes. Can be called multiple times to keep squeezing.
*
* Arguments:   - std::span<std::uint8_t> out: output (all out.size() bytes are written)
*              - keccak_state& state: input/output Keccak state
**************************************************/
void shake128_squeeze(std::span<std::uint8_t> out, keccak_state& state) {
    state.pos = keccak_squeeze(out, state.s, state.pos, SHAKE128_RATE);
}

/*************************************************
* Name:        shake128_absorb_once
*
* Description: Initialize, absorb into and finalize SHAKE128 XOF; non-incremental.
*
* Arguments:   - keccak_state& state: (uninitialized) output Keccak state
*              - std::span<const std::uint8_t> in: input to be absorbed into s
**************************************************/
void shake128_absorb_once(keccak_state& state, std::span<const std::uint8_t> in) {
    keccak_absorb_once(state.s, SHAKE128_RATE, in, 0x1F);
    state.pos = SHAKE128_RATE;
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
*              SHAKE128_RATE bytes each. Can be called multiple times
*              to keep squeezing. Assumes new block has not yet been
*              started (state.pos = SHAKE128_RATE).
*
* Arguments:   - std::span<std::uint8_t> out: output blocks (at least nblocks * SHAKE128_RATE bytes)
*              - std::size_t nblocks: number of blocks to be squeezed (written to output)
*              - keccak_state& state: input/output Keccak state
**************************************************/
void shake128_squeezeblocks(std::span<std::uint8_t> out, std::size_t nblocks, keccak_state& state) {
    keccak_squeezeblocks(out, nblocks, state.s, SHAKE128_RATE);
}

/*************************************************
* Name:        shake256_init
*
* Description: Initilizes Keccak state for use as SHAKE256 XOF
*
* Arguments:   - keccak_state& state: (uninitialized) Keccak state
**************************************************/
void shake256_init(keccak_state& state) {
    state.s.fill(0);
    state.pos = 0;
}

/*************************************************
* Name:        shake256_absorb
*
* Description: Absorb step of the SHAKE256 XOF; incremental.
*
* Arguments:   - keccak_state& state: (initialized) output Keccak state
*              - std::span<const std::uint8_t> in: input to be absorbed into s
**************************************************/
void shake256_absorb(keccak_state& state, std::span<const std::uint8_t> in) {
    state.pos = keccak_absorb(state.s, state.pos, SHAKE256_RATE, in);
}

/*************************************************
* Name:        shake256_finalize
*
* Description: Finalize absorb step of the SHAKE256 XOF.
*
* Arguments:   - keccak_state& state: Keccak state
**************************************************/
void shake256_finalize(keccak_state& state) {
    keccak_finalize(state.s, state.pos, SHAKE256_RATE, 0x1F);
    state.pos = SHAKE256_RATE;
}

/*************************************************
* Name:        shake256_squeeze
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
*              bytes. Can be called multiple times to keep squeezing.
*
* Arguments:   - std::span<std::uint8_t> out: output (all out.size() bytes are written)
*              - keccak_state& state: input/output Keccak state
**************************************************/
void shake256_squeeze(std::span<std::uint8_t> out, keccak_state& state) {
    state.pos = keccak_squeeze(out, state.s, state.pos, SHAKE256_RATE);
}

/*************************************************
* Name:        shake256_absorb_once
*
* Description: Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
*
* Arguments:   - keccak_state& state: (uninitialized) output Keccak state
*              - std::span<const std::uint8_t> in: input to be absorbed into s
**************************************************/
void shake256_absorb_once(keccak_state& state, std::span<const std::uint8_t> in) {
    keccak_absorb_once(state.s, SHAKE256_RATE, in, 0x1F);
    state.pos = SHAKE256_RATE;
}

/*************************************************
* Name:        shake256_squeezeblocks
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
*              SHAKE256_RATE bytes each. Can be called multiple times
*              to keep squeezing. Assumes next block has not yet been
*              started (state.pos = SHAKE256_RATE).
*
* Arguments:   - std::span<std::uint8_t> out: output blocks (at least nblocks * SHAKE256_RATE bytes)
*              - std::size_t nblocks: number of blocks to be squeezed (written to output)
*              - keccak_state& state: input/output Keccak state
**************************************************/
void shake256_squeezeblocks(std::span<std::uint8_t> out, std::size_t nblocks, keccak_state& state) {
    keccak_squeezeblocks(out, nblocks, state.s, SHAKE256_RATE);
}

/*************************************************
* Name:        shake128
*
* Description: SHAKE128 XOF with non-incremental API
*
* Arguments:   - std::span<std::uint8_t> out: output (out.size() bytes are produced)
*              - std::span<const std::uint8_t> in: input
**************************************************/
void shake128(std::span<std::uint8_t> out, std::span<const std::uint8_t> in) {
    keccak_state state;

    shake128_absorb_once(state, in);
    const std::size_t nblocks = out.size() / SHAKE128_RATE;
    shake128_squeezeblocks(out, nblocks, state);
    shake128_squeeze(out.subspan(nblocks * SHAKE128_RATE), state);
}

/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - std::span<std::uint8_t> out: output (out.size() bytes are produced)
*              - std::span<const std::uint8_t> in: input
**************************************************/
void shake256(std::span<std::uint8_t> out, std::span<const std::uint8_t> in) {
    keccak_state state;

    shake256_absorb_once(state, in);
    const std::size_t nblocks = out.size() / SHAKE256_RATE;
    shake256_squeezeblocks(out, nblocks, state);
    shake256_squeeze(out.subspan(nblocks * SHAKE256_RATE), state);
}

/*************************************************
* Name:        sha3_256
*
* Description: SHA3-256 with non-incremental API
*
* Arguments:   - std::span<std::uint8_t, 32> h: output (32 bytes)
*              - std::span<const std::uint8_t> in: input
**************************************************/
void sha3_256(std::span<std::uint8_t, 32> h, std::span<const std::uint8_t> in) {
    state_t s;

    keccak_absorb_once(s, SHA3_256_RATE, in, 0x06);
    KeccakF1600_StatePermute(s);
    for (std::size_t i = 0; i < 4; i++)
        store64(h.subspan(8 * i).first<8>(), s[i]);
}

/*************************************************
* Name:        sha3_512
*
* Description: SHA3-512 with non-incremental API
*
* Arguments:   - std::span<std::uint8_t, 64> h: output (64 bytes)
*              - std::span<const std::uint8_t> in: input
**************************************************/
void sha3_512(std::span<std::uint8_t, 64> h, std::span<const std::uint8_t> in) {
    state_t s;

    keccak_absorb_once(s, SHA3_512_RATE, in, 0x06);
    KeccakF1600_StatePermute(s);
    for (std::size_t i = 0; i < 8; i++)
        store64(h.subspan(8 * i).first<8>(), s[i]);
}

} // namespace openpqc::fips202
