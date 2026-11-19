/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_fips_mem.c -- the FIPS 140-3 module's own memcpy, memmove and memset (FIPS 140-3 mode only; compiled into
 * every build of the module with its integrity test, cmake/OpenPQCFips.cmake)
 *
 * The module, the shared library libopenpqc, defines these functions itself, with hidden visibility. Every call of
 * them in the module, those that the compilers generate for copies of structures and for zeroization included, is
 * then bound to these definitions when the library is linked, and the module imports none of them, so that no
 * definition outside the module can run in their place (OPQC_FIPS_MEM_API, below).
 *
 * Design: README.md, "FIPS 140-3 mode".
 */

#include <stddef.h>
#include <stdint.h>

/* x86-64 only, the platform of FIPS 140-3 mode (CMakeLists.txt) */
#if !defined(__x86_64__) || !defined(__LP64__)
#error "the module's memory functions are written for x86-64, the only platform of FIPS 140-3 mode"
#endif

/*
 * Hidden. An imported function is bound by its name when the module is loaded, so the program's own definition of
 * it, one in a library named in LD_PRELOAD, or one that an auditing library (LD_AUDIT, DT_AUDIT) binds instead,
 * would run in its place: a memcpy that put a changed byte of the module back as the integrity test copies its
 * image (opqc_fips_integrity.c) would hide the change, and a memset that did nothing would leave the values that
 * opqc_zeroize is to destroy.
 *
 * Not instrumented by AddressSanitizer or UndefinedBehaviorSanitizer: the integrity test copies the module's whole
 * image with memcpy, the red zones that AddressSanitizer puts around the module's global variables included, and a
 * read of a red zone is reported as an error that ends the process. AddressSanitizer checks the C library's memcpy,
 * memmove and memset in its interceptors, which the module's calls never reach. In the code it instruments, Clang
 * calls the sanitizer's __asan_memcpy, __asan_memmove and __asan_memset instead, which check the ranges; GCC leaves
 * the check to the interceptors, so in a FIPS 140-3 build with AddressSanitizer by GCC the ranges of the module's
 * own calls of these functions are not checked (a sanitizer build without the mode checks them).
 */
#define OPQC_FIPS_MEM_API __attribute__((visibility("hidden"), no_sanitize("address", "undefined")))
#define OPQC_FIPS_MEM_LOCAL __attribute__((no_sanitize("address", "undefined")))

/* The prototypes of the C library (C11 7.24.2.1, 7.24.2.2, 7.24.6.1) and of its _FORTIFY_SOURCE variants (the
 * compilers' __builtin___memcpy_chk and its kin). <string.h> is not included: with _FORTIFY_SOURCE it defines
 * memcpy itself, as an inline function. The variants that _FORTIFY_SOURCE makes the compilers call (__memcpy_chk,
 * __memmove_chk, __memset_chk) are defined here for the same reason as the functions; where the C library's would
 * report a buffer overflow and end the program, these end it with a trap. The test fips_integrity lists the
 * module's imports (nm -D -u) and fails if any of these is among them. */
OPQC_FIPS_MEM_API void *memcpy(void *restrict dst, const void *restrict src, size_t n);
OPQC_FIPS_MEM_API void *memmove(void *dst, const void *src, size_t n);
OPQC_FIPS_MEM_API void *memset(void *dst, int c, size_t n);
OPQC_FIPS_MEM_API void *__memcpy_chk(void *restrict dst, const void *restrict src, size_t n, size_t dst_bytes);
OPQC_FIPS_MEM_API void *__memmove_chk(void *dst, const void *src, size_t n, size_t dst_bytes);
OPQC_FIPS_MEM_API void *__memset_chk(void *dst, int c, size_t n, size_t dst_bytes);

/* Unaligned accesses that may alias any object */
typedef uint64_t opqc_fips_u64 __attribute__((may_alias, aligned(1)));
typedef uint32_t opqc_fips_u32 __attribute__((may_alias, aligned(1)));
typedef uint16_t opqc_fips_u16 __attribute__((may_alias, aligned(1)));

/* Up to 32 bytes are moved with unaligned loads and stores of 8, 4, 2 and 1 bytes, every byte loaded before any is
 * stored, which is right for overlapping ranges too; more with the string instructions (rep movsb, rep stosb; for a
 * move to a higher address that overlaps its source, backwards, with the direction flag set and cleared again),
 * which processors since Ivy Bridge run as fast block moves. There is no loop: a compiler may recognise a copying
 * or filling loop and replace it with a call of memcpy or memset, which here would call itself. */
#define OPQC_FIPS_SHORT_BYTES 32u

/* n <= 32 bytes from s to d, every byte loaded before any is stored (the ranges may overlap) */
static inline OPQC_FIPS_MEM_LOCAL void move_short(unsigned char *d, const unsigned char *s, size_t n)
{
    if (n >= 16) {
        const uint64_t a = *(const opqc_fips_u64 *)s, b = *(const opqc_fips_u64 *)(s + 8);
        const uint64_t y = *(const opqc_fips_u64 *)(s + n - 16), z = *(const opqc_fips_u64 *)(s + n - 8);
        *(opqc_fips_u64 *)d = a;
        *(opqc_fips_u64 *)(d + 8) = b;
        *(opqc_fips_u64 *)(d + n - 16) = y;
        *(opqc_fips_u64 *)(d + n - 8) = z;
    } else if (n >= 8) {
        const uint64_t a = *(const opqc_fips_u64 *)s, z = *(const opqc_fips_u64 *)(s + n - 8);
        *(opqc_fips_u64 *)d = a;
        *(opqc_fips_u64 *)(d + n - 8) = z;
    } else if (n >= 4) {
        const uint32_t a = *(const opqc_fips_u32 *)s, z = *(const opqc_fips_u32 *)(s + n - 4);
        *(opqc_fips_u32 *)d = a;
        *(opqc_fips_u32 *)(d + n - 4) = z;
    } else if (n >= 2) {
        const uint16_t a = *(const opqc_fips_u16 *)s, z = *(const opqc_fips_u16 *)(s + n - 2);
        *(opqc_fips_u16 *)d = a;
        *(opqc_fips_u16 *)(d + n - 2) = z;
    } else if (n == 1) {
        *d = *s;
    }
}

/* n bytes from s to d, from the lowest address up (rep movsb with the direction flag clear, as the ABI keeps it) */
static inline OPQC_FIPS_MEM_LOCAL void move_up(unsigned char *d, const unsigned char *s, size_t n)
{
    __asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(n) : : "memory");
}

/* n > 0 bytes from s to d, from the highest address down: for d inside [s, s + n) */
static inline OPQC_FIPS_MEM_LOCAL void move_down(unsigned char *d, const unsigned char *s, size_t n)
{
    d += n - 1;
    s += n - 1;
    __asm__ volatile("std\n\trep movsb\n\tcld" : "+D"(d), "+S"(s), "+c"(n) : : "memory", "cc");
}

void *memcpy(void *restrict dst, const void *restrict src, size_t n)
{
    if (n <= OPQC_FIPS_SHORT_BYTES) {
        move_short((unsigned char *)dst, (const unsigned char *)src, n);
    } else {
        move_up((unsigned char *)dst, (const unsigned char *)src, n);
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (n <= OPQC_FIPS_SHORT_BYTES) {
        move_short(d, s, n);
    } else if ((uintptr_t)d - (uintptr_t)s >= n) {
        move_up(d, s, n); /* d below s (the difference wraps around), or the ranges apart */
    } else {
        move_down(d, s, n);
    }
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const uint64_t v = 0x0101010101010101u * (uint64_t)(unsigned char)c;
    if (n > OPQC_FIPS_SHORT_BYTES) {
        __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(c) : "memory");
    } else if (n >= 16) {
        *(opqc_fips_u64 *)d = v;
        *(opqc_fips_u64 *)(d + 8) = v;
        *(opqc_fips_u64 *)(d + n - 16) = v;
        *(opqc_fips_u64 *)(d + n - 8) = v;
    } else if (n >= 8) {
        *(opqc_fips_u64 *)d = v;
        *(opqc_fips_u64 *)(d + n - 8) = v;
    } else if (n >= 4) {
        *(opqc_fips_u32 *)d = (uint32_t)v;
        *(opqc_fips_u32 *)(d + n - 4) = (uint32_t)v;
    } else if (n >= 2) {
        *(opqc_fips_u16 *)d = (uint16_t)v;
        *(opqc_fips_u16 *)(d + n - 2) = (uint16_t)v;
    } else if (n == 1) {
        *d = (unsigned char)c;
    }
    return dst;
}

void *__memcpy_chk(void *restrict dst, const void *restrict src, size_t n, size_t dst_bytes)
{
    if (n > dst_bytes) __builtin_trap();
    return memcpy(dst, src, n);
}

void *__memmove_chk(void *dst, const void *src, size_t n, size_t dst_bytes)
{
    if (n > dst_bytes) __builtin_trap();
    return memmove(dst, src, n);
}

void *__memset_chk(void *dst, int c, size_t n, size_t dst_bytes)
{
    if (n > dst_bytes) __builtin_trap();
    return memset(dst, c, n);
}
