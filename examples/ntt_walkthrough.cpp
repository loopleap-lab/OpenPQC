// ntt_walkthrough.cpp  --  reproduces the worked examples from the NTT guide,
//   checking each result and reporting its latency (median ns per call)
//   q = 7681, n = 4, omega = 3383, psi = 1925
#include "latency.hpp"
#include "NTT-learn/convolution.hpp"
#include "NTT-learn/ntt.hpp"
#include "NTT-learn/ntt_naive.hpp"
#include "NTT-learn/roots.hpp"

#include <cstdio>
#include <sstream>
#include <string>

using namespace openpqc;

static int mismatches = 0;

template <class T>
std::string to_string(const T& v) {
    std::ostringstream os;
    os << v;
    return os.str();
}

// run one walkthrough step: compare against the guide's value, then time it
template <class Fn, class T>
void step(const char* label, const T& expected, Fn&& fn) {
    const auto result = fn();
    const bool ok = result == expected;
    if (!ok) ++mismatches;

    std::printf("  %-26s %-22s %10.1f ns  %s\n", label, to_string(result).c_str(),
                latency::median_ns(fn), ok ? "ok" : "MISMATCH");
    if (!ok) std::printf("  %-26s %-22s (expected)\n", "", to_string(expected).c_str());
}

int main() {
    constexpr u32 Q     = 7681;
    constexpr u32 OMEGA = 3383;              // paper's choice, so numbers match
    constexpr u32 PSI   = 1925;              // paper's psi, PSI^2 == OMEGA
    using R = Roots<Q>;
    using P = ZqX<Q>;

    const P g({1, 2, 3, 4});
    const P h({5, 6, 7, 8});
    const P g_omega = ntt_omega(g, OMEGA), h_omega = ntt_omega(h, OMEGA);
    const P g_psi   = ntt_psi(g, PSI),     h_psi   = ntt_psi(h, PSI);
    const NttPlan<Q> plan(4, PSI);           // twiddle tables, built once
    const P g_fast  = fast_ntt(g, plan),   h_fast  = fast_ntt(h, plan);

#ifndef NDEBUG
    std::printf("note: debug build (asserts on, unoptimised) -- configure with "
                "-DCMAKE_BUILD_TYPE=Release for meaningful latencies\n\n");
#endif
    std::printf("  %-26s %-22s %13s\n", "step", "result", "latency");

    std::printf("-- roots (searched) --\n");
    step("find_psi(4)",          u32{1213}, [&] { return R::find_psi(latency::opaque<u64>(4)); });
    step("omega_from(1925)",     OMEGA, [&] { return R::omega_from(latency::opaque(PSI)); });

    std::printf("-- schoolbook convolutions --\n");
    step("linear_conv",          P({5, 16, 34, 60, 61, 52, 32}), [&] { return linear_conv(g, h); });
    step("cyclic_conv",          P({66, 68, 66, 60}),            [&] { return cyclic_conv(g, h); });
    step("negacyclic_conv",      P({7625, 7645, 2, 60}),         [&] { return negacyclic_conv(g, h); });

    std::printf("-- NTT with omega (positive-wrapped) --\n");
    step("ntt_omega(g)    Ex 3.2",  P({10, 913, 7679, 6764}),   [&] { return ntt_omega(g, OMEGA); });
    step("ntt_omega(h)    Ex 3.3",  P({26, 913, 7679, 6764}),   [&] { return ntt_omega(h, OMEGA); });
    step("intt_omega      Ex 3.4",  g,                          [&] { return intt_omega(g_omega, OMEGA); });
    step("pointwise_mul   eq. 12",  P({260, 4021, 4, 3660}),    [&] { return pointwise_mul(g_omega, h_omega); });
    step("pwc_via_ntt     Ex 3.6",  P({66, 68, 66, 60}),        [&] { return pwc_via_ntt(g, h, OMEGA); });

    std::printf("-- NTT with psi (negative-wrapped) --\n");
    step("ntt_psi(g)      Ex 3.8",  P({1467, 2807, 3471, 7621}), [&] { return ntt_psi(g, PSI); });
    step("ntt_psi(h)      Ex 3.9",  P({2489, 7489, 6478, 6607}), [&] { return ntt_psi(h, PSI); });
    step("intt_psi        Ex 3.10", g,                           [&] { return intt_psi(g_psi, PSI); });
    step("pointwise_mul   Ex 3.12", P({2888, 6407, 2851, 2992}), [&] { return pointwise_mul(g_psi, h_psi); });
    step("nwc_via_ntt     Ex 3.12", P({7625, 7645, 2, 60}),      [&] { return nwc_via_ntt(g, h, PSI); });

    std::printf("-- fast NTT, CT / GS butterflies with NttPlan (bit-reversed order) --\n");
    step("NttPlan(4, psi) psis",    P({1, 3383, 1925, 6468}),    [&] {    // psi^brv(i), built per call
        P table;
        table.coeffs = NttPlan<Q>(latency::opaque<std::size_t>(4), latency::opaque(PSI)).psis;
        return table;
    });
    step("fast_ntt(g)     Ex 4.1",  P({1467, 3471, 2807, 7621}), [&] { return fast_ntt(g, plan); });
    step("fast_ntt(h)     Ex 4.7",  P({2489, 6478, 7489, 6607}), [&] { return fast_ntt(h, plan); });
    step("fast_intt",               g,                           [&] { return fast_intt(g_fast, plan); });
    step("pointwise_mul   Ex 4.7",  P({2888, 2851, 6407, 2992}), [&] { return pointwise_mul(g_fast, h_fast); });
    step("nwc_via_fast    Ex 4.7",  P({7625, 7645, 2, 60}),      [&] { return nwc_via_fast_ntt(g, h, plan); });
    if (mismatches) std::printf("\n%d step(s) did not match the guide\n", mismatches);
    return mismatches ? 1 : 0;
}
