// Copyright (c) The OpenPQC project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//
// opqc_sycl_team.hpp  --  how the kernels of the OpenPQC GPU backends share out work (SYCL device code)
//
// Two kinds of stages, for every scheme: hashing stages, one work-item per
// independent unit of work across the whole batch (for_each_item), and
// arithmetic stages, a team of work-items per operation, several teams per
// work-group (for_each_team). And the conventions that the kernels rely on:
// the alignment of the buffers, which the compiler is told about, kernels that
// are always inlined, stores of 16 bytes at a time, and local memory cleared
// before a kernel ends.
//
// Design: ../README.md, "GPU helpers".
#pragma once

#include <sycl/sycl.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>

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

// Stages in which every work-item writes its own output (a polynomial, a node of a hash tree) write
// 16 bytes at a time: the work-items of a warp write to different places, so that each of their 1- to
// 4-byte stores would be a memory transaction of its own (ExpandS of ML-DSA became 4.3-5.7 times
// faster, ML/DSA/README.md). store16 writes the 16 bytes lo || hi (little-endian) to p, which must be
// 16-byte aligned; Store16 collects values of Bits bits (8, 16, 32 or 64), value k of a group at bits
// Bits k, and writes every group of 16 bytes as it is complete (a partial last group is not written).
OPQC_KERNEL_INLINE inline void store16(void* p, std::uint64_t lo, std::uint64_t hi) {
    *static_cast<::sycl::vec<std::uint32_t, 4>*>(p) =
            ::sycl::vec<std::uint32_t, 4>(static_cast<std::uint32_t>(lo), static_cast<std::uint32_t>(lo >> 32),
                                        static_cast<std::uint32_t>(hi), static_cast<std::uint32_t>(hi >> 32));
}

template <unsigned Bits>
struct Store16 {
    static_assert(Bits == 8 || Bits == 16 || Bits == 32 || Bits == 64, "values of 8, 16, 32 or 64 bits");
    static constexpr unsigned per_group = 128 / Bits;
    std::uint8_t* out;          // 16-byte aligned
    std::uint64_t lo = 0, hi = 0;   // the values of the group being collected
    unsigned count = 0;         // values appended so far

    explicit Store16(void* p) : out(static_cast<std::uint8_t*>(p)) {}
    // appends a value of at most Bits bits
    OPQC_KERNEL_INLINE void append(std::uint64_t value) {
        const unsigned p = count % per_group;
        const std::uint64_t v = value << (Bits * (p % (per_group / 2)));
        if (p < per_group / 2) lo |= v;
        else hi |= v;
        if (p == per_group - 1) {
            store16(out + 16 * (count / per_group), lo, hi);
            lo = hi = 0;
        }
        count++;
    }
};

// f(i) for every i < n, one work-item each, in work-groups of GroupSize: the hashing stages, one
// work-item per independent unit of work (a sponge: one hash or one XOF stream), across the whole batch
template <unsigned GroupSize = 128, class F>
void for_each_item(::sycl::queue& q, std::size_t n, F f) {
    const std::size_t global = (n + GroupSize - 1) / GroupSize * GroupSize;
    q.parallel_for(::sycl::nd_range<1>(global, GroupSize), [=](::sycl::nd_item<1> it) OPQC_KERNEL_INLINE {
        const std::size_t i = it.get_global_id(0);
        if (i < n) f(i);
    });
}

// The view of one work-item in a team of TeamSize work-items, with local memory of
// Word elements
template <class Word, unsigned TeamSize>
struct Team {
    static constexpr unsigned size = TeamSize;
    ::sycl::nd_item<1> item;
    std::size_t op;          // the operation of this team
    unsigned g;              // index of the work-item within its team, 0 .. TeamSize - 1
    bool active;             // false for the padding teams of the last work-group
    Word* local;             // this team's local memory
    void barrier() const { ::sycl::group_barrier(item.get_group()); }
};

// f(team) for the n operations, TeamsPerGroup teams of TeamSize work-items per
// work-group, with local_words words of local memory per team. Teams beyond n
// repeat operation n - 1 without writing results, so that every work-item of a
// work-group reaches every barrier. The arithmetic stages: polynomials that the
// team shares (the inputs and outputs of NTTs) live in the team's part of local
// memory, and the team synchronizes with work-group barriers, which every SYCL
// device supports (no assumption is made about the sub-group size).
template <class Word, unsigned TeamSize, unsigned TeamsPerGroup, class F>
void for_each_team(::sycl::queue& q, std::size_t n, std::size_t local_words, F f) {
    const std::size_t groups = (n + TeamsPerGroup - 1) / TeamsPerGroup;
    q.submit([&](::sycl::handler& h) {
        ::sycl::local_accessor<Word, 1> local(::sycl::range<1>(TeamsPerGroup * local_words), h);
        h.parallel_for(::sycl::nd_range<1>(groups * TeamsPerGroup * TeamSize, TeamsPerGroup * TeamSize),
                       [=](::sycl::nd_item<1> it) OPQC_KERNEL_INLINE {
                           const unsigned t = static_cast<unsigned>(it.get_local_id(0)) / TeamSize;
                           const std::size_t op = it.get_group(0) * TeamsPerGroup + t;
                           f(Team<Word, TeamSize>{it, op < n ? op : n - 1,
                                                  static_cast<unsigned>(it.get_local_id(0)) % TeamSize, op < n,
                                                  &local[t * local_words]});
                       });
    });
}

// The type of a team reduction's result: Word itself, or 32 bits for narrower words. A 32-bit result
// would drop the high half of 64-bit words: an OR of the differences between two 64-bit lanes would then
// compare half of each lane, and a verification built on it would accept a value that differs only
// there. Sums are taken modulo 2^(bits of the result); 16-bit words are summed in 32 bits.
template <class Word>
using TeamResult = std::conditional_t<(sizeof(Word) > sizeof(std::uint32_t)), Word, std::uint32_t>;
static_assert(std::is_same_v<TeamResult<std::uint64_t>, std::uint64_t> &&
              std::is_same_v<TeamResult<std::uint16_t>, std::uint32_t>);

// OR of `value` over the team (all its work-items must call it), over every bit of Word. Uses the
// first TeamSize words of the team's local memory, which the caller must not need any more. There is
// no barrier after the reads: a caller that writes those words again calls t.barrier() first (the
// next team_or or team_sum does).
template <class Word, unsigned TeamSize>
TeamResult<Word> team_or(const Team<Word, TeamSize>& t, Word value) {
    static_assert(std::is_unsigned_v<Word>, "team reductions take unsigned words");
    Word* scratch = t.local;
    t.barrier();
    scratch[t.g] = value;
    t.barrier();
    TeamResult<Word> any = 0;
    for (unsigned i = 0; i < TeamSize; i++) any |= scratch[i];
    return any;
}

// Sum of `value` over the team, like team_or
template <class Word, unsigned TeamSize>
TeamResult<Word> team_sum(const Team<Word, TeamSize>& t, Word value) {
    static_assert(std::is_unsigned_v<Word>, "team reductions take unsigned words");
    Word* scratch = t.local;
    t.barrier();
    scratch[t.g] = value;
    t.barrier();
    TeamResult<Word> sum = 0;
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

// The same for local data of any shape (the nodes of a hash tree, for instance): overwrites the team's
// first `words` words of local memory with zeros, work-item g taking the words g, g + TeamSize, ...,
// after a barrier, once all of them are done with local memory. As for clear_local, every work-item of
// the work-group calls it (the barrier is the work-group's), as the last use of local memory in the
// kernel; words must not exceed the team's local_words.
template <class Word, unsigned TeamSize>
OPQC_KERNEL_INLINE void clear_local_words(const Team<Word, TeamSize>& t, std::size_t words) {
    t.barrier();
    for (std::size_t i = t.g; i < words; i += TeamSize) t.local[i] = 0;
}

} // namespace openpqc::gpu
