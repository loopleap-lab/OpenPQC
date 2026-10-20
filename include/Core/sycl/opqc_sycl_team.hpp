// opqc_sycl_team.hpp  --  how the kernels of the OpenPQC GPU backends share out work (SYCL device code)
//
// Two kinds of stages, for every scheme:
//
//  * Hashing stages: one work-item per independent unit of work (a sponge: one
//    hash or one XOF stream), across the whole batch: for_each_item.
//  * Arithmetic stages: a team of work-items per operation, several teams per
//    work-group: for_each_team. Polynomials that the team shares (the inputs and
//    outputs of NTTs) live in the team's part of local memory, and the team
//    synchronizes with work-group barriers, which every SYCL device supports
//    (no assumption is made about the sub-group size).
//
// And the conventions that the kernels rely on: the alignment of the buffers,
// which the compiler is told about, and kernels that are always inlined.
#pragma once

#include <sycl/sycl.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>

namespace openpqc::gpu {

// The kernel functions are marked always_inline: without it, DPC++ may compile a
// large kernel body as a function of its own, called with the captured variables
// on the stack and with local memory reached through generic pointers.
#define OPQC_KERNEL_INLINE __attribute__((always_inline))

// Alignment that the kernels tell the compiler about: the caller's buffers are
// 8-byte aligned (an API requirement, checked by the C APIs) and the workspace
// sections 256-byte aligned. With per-operation sizes that are multiples of 16
// bytes this carries over to each operation's data, and the compiler can combine
// a work-item's neighbouring byte and 16-bit accesses into 32- to 128-bit ones.
// (AdaptiveCpp's JIT finds the alignment of kernel arguments at run time; DPC++
// compiles ahead of time and needs to be told.)
inline constexpr std::size_t BUFFER_ALIGN = 8, WORKSPACE_ALIGN = 256;
template <class T>
inline T* buffer(T* p) {
    return std::assume_aligned<BUFFER_ALIGN>(p);
}
template <class T>
inline T* workspace(T* p) {
    return std::assume_aligned<WORKSPACE_ALIGN>(p);
}

// f(i) for every i < n, one work-item each, in work-groups of GroupSize
template <unsigned GroupSize = 128, class F>
void for_each_item(sycl::queue& q, std::size_t n, F f) {
    const std::size_t global = (n + GroupSize - 1) / GroupSize * GroupSize;
    q.parallel_for(sycl::nd_range<1>(global, GroupSize), [=](sycl::nd_item<1> it) OPQC_KERNEL_INLINE {
        const std::size_t i = it.get_global_id(0);
        if (i < n) f(i);
    });
}

// The view of one work-item in a team of TeamSize work-items, with local memory of
// Word elements
template <class Word, unsigned TeamSize>
struct Team {
    static constexpr unsigned size = TeamSize;
    sycl::nd_item<1> item;
    std::size_t op;          // the operation of this team
    unsigned g;              // index of the work-item within its team, 0 .. TeamSize - 1
    bool active;             // false for the padding teams of the last work-group
    Word* local;             // this team's local memory
    void barrier() const { sycl::group_barrier(item.get_group()); }
};

// f(team) for the n operations, TeamsPerGroup teams of TeamSize work-items per
// work-group, with local_words words of local memory per team. Teams beyond n
// repeat operation n - 1 without writing results, so that every work-item of a
// work-group reaches every barrier.
template <class Word, unsigned TeamSize, unsigned TeamsPerGroup, class F>
void for_each_team(sycl::queue& q, std::size_t n, std::size_t local_words, F f) {
    const std::size_t groups = (n + TeamsPerGroup - 1) / TeamsPerGroup;
    q.submit([&](sycl::handler& h) {
        sycl::local_accessor<Word, 1> local(sycl::range<1>(TeamsPerGroup * local_words), h);
        h.parallel_for(sycl::nd_range<1>(groups * TeamsPerGroup * TeamSize, TeamsPerGroup * TeamSize),
                       [=](sycl::nd_item<1> it) OPQC_KERNEL_INLINE {
                           const unsigned t = static_cast<unsigned>(it.get_local_id(0)) / TeamSize;
                           const std::size_t op = it.get_group(0) * TeamsPerGroup + t;
                           f(Team<Word, TeamSize>{it, op < n ? op : n - 1,
                                                  static_cast<unsigned>(it.get_local_id(0)) % TeamSize, op < n,
                                                  &local[t * local_words]});
                       });
    });
}

// OR of `value` over the team (all its work-items must call it). Uses the first
// TeamSize words of the team's local memory, which the caller must not need any more.
template <class Word, unsigned TeamSize>
std::uint32_t team_or(const Team<Word, TeamSize>& t, Word value) {
    Word* scratch = t.local;
    t.barrier();
    scratch[t.g] = value;
    t.barrier();
    std::uint32_t any = 0;
    for (unsigned i = 0; i < TeamSize; i++) any |= scratch[i];
    return any;
}

// Sum of `value` over the team, like team_or
template <class Word, unsigned TeamSize>
std::uint32_t team_sum(const Team<Word, TeamSize>& t, Word value) {
    Word* scratch = t.local;
    t.barrier();
    scratch[t.g] = value;
    t.barrier();
    std::uint32_t sum = 0;
    for (unsigned i = 0; i < TeamSize; i++) sum += scratch[i];
    return sum;
}

// Overwrites the team's first `polys` polynomials of N coefficients in local memory
// with zeros, each work-item its own chunk of N / TeamSize coefficients of each,
// once all of them are done with local memory. Local memory is not cleared between
// kernels, and on some GPUs other processes could read it ("LeftoverLocals").
template <unsigned N, class Word, unsigned TeamSize>
void clear_local(const Team<Word, TeamSize>& t, unsigned polys) {
    constexpr unsigned chunk = N / TeamSize;
    t.barrier();
    for (unsigned p = 0; p < polys; p++) {
#pragma unroll
        for (unsigned x = 0; x < chunk; x++) t.local[N * p + chunk * t.g + x] = 0;
    }
}

} // namespace openpqc::gpu
