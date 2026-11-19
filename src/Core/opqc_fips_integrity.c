/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * opqc_fips_integrity.c -- the pre-operational software integrity test of the
 * FIPS 140-3 module (ISO/IEC 19790:2012, Section 7.10.2; opqc_fips.h)
 *
 * The module is the shared library libopenpqc, an ELF64 shared object of
 * x86-64 Linux. The test computes HMAC-SHA-256 (FIPS 198-1, the approved
 * integrity technique) over the module's image as the dynamic loader mapped
 * and relocated it, and compares it with the value that the build computed
 * from the file when it linked the library (cmake/openpqc_fips_seal.c, run
 * right after the link). Both compute the same message (measure, below).
 *
 * Design: README.md, "FIPS 140-3 mode".
 */

#include <elf.h>
#include <stdint.h>
#include <string.h>

#include "opqc_ct.h"
#include "opqc_fips.h"
#include "opqc_hmac.h"
#include "opqc_platform.h"

/*
 * Platform. x86-64 ELF64 (this file does not compile elsewhere), and the GNU C library's loader, the only one
 * tested: rule 2 (the canonical form, below) follows how it relocates the dynamic section in place. Configuring
 * refuses FIPS mode on other systems, processors, pointer sizes and compilers (the top-level CMakeLists.txt), but
 * does not check the C library: with a loader that relocates the dynamic section differently (musl's, for one),
 * this test is expected to fail and leave the module in its error state (not tested).
 */
#if !defined(__x86_64__) || !defined(__LP64__)
#error "the integrity test knows the dynamic relocations of x86-64 ELF64 only; configure refuses FIPS mode elsewhere"
#endif

#define OPQC_FIPS_RECORD_BYTES 64
#define OPQC_FIPS_CHUNK_BYTES 2048
#define OPQC_FIPS_PAGE_BYTES 4096u /* the page of x86-64, which the loader maps segments in */
#define OPQC_FIPS_DT_RELR 36       /* not in every <elf.h> yet */
#define OPQC_FIPS_PHDR_BYTES 56u   /* sizeof(Elf64_Phdr), e_phentsize */
#define OPQC_FIPS_MAX_SEGMENTS 64u

/* The image readers below (image_*) are not instrumented by AddressSanitizer or UndefinedBehaviorSanitizer, and
 * not inlined into a function that is: they read every byte of the module, the red zones that AddressSanitizer
 * puts between its global variables included, and at any alignment the file gives. */
#if defined(__has_attribute)
#if __has_attribute(no_sanitize)
#define OPQC_FIPS_IMAGE_READ __attribute__((noinline, no_sanitize("address", "undefined")))
#endif
#endif
#if !defined(OPQC_FIPS_IMAGE_READ)
#define OPQC_FIPS_IMAGE_READ __attribute__((noinline))
#endif

/* The expected value, in a writable section of its own. Not static, and read through a volatile pointer: the
 * compiler must not assume it keeps the value written here. The record (section .openpqc_fips_mac, 64 bytes,
 * written by the seal tool):
 *   bytes  0..15  "OpenPQC-FIPS-MAC" (in the source; the tool checks it)
 *   bytes 16..19  1 when sealed (le32); the source has 0, so an unsealed library
 *                 fails the test
 *   bytes 20..23  the number of covered segments (le32)
 *   bytes 24..31  the number of covered bytes, the sum of their end - start
 *                 (le64)
 *   bytes 32..63  the HMAC-SHA-256 */
extern uint8_t opqc_fips_integrity_record[OPQC_FIPS_RECORD_BYTES];
__attribute__((used, section(".openpqc_fips_mac"), aligned(64))) uint8_t
        opqc_fips_integrity_record[OPQC_FIPS_RECORD_BYTES] = {'O', 'p', 'e', 'n', 'P', 'Q', 'C', '-',
                                                              'F', 'I', 'P', 'S', '-', 'M', 'A', 'C'};

/* Defined by the linker (GNU ld, gold, lld, mold) in the module itself: its ELF header and its dynamic section, as
 * loaded: the test finds the image through them. __ehdr_start is the ELF header as loaded (from which e_phoff
 * gives the program header table, and the header's link-time address the load base B), and _DYNAMIC the dynamic
 * section, which must be where the table says. Hidden: the compiler reaches them relative to the code, with no
 * relocation and no import. */
extern const uint8_t __ehdr_start[] __attribute__((visibility("hidden")));
extern const uint8_t _DYNAMIC[] __attribute__((visibility("hidden")));

/* --- the handler of libstdc++'s assertions ------------------------------------------------------------------- */

/* The module's C++ code (the schemes' layers) uses std::span and std::array, whose element access checks the index
 * when libstdc++'s assertions are on: with _GLIBCXX_ASSERTIONS, which libstdc++ defines by default in code that is
 * not optimized (-O0, CMake's Debug; bits/c++config.h of GCC 16) and which some distributions add to the flags of
 * their packages. A failed check calls std::__glibcxx_assert_fail, a function of libstdc++.so that prints the
 * condition and aborts. Imported, it would be a function outside the module that the module calls by its name, which
 * the program or a preloaded library could define in libstdc++'s place, and the module would need the C++ runtime,
 * which it does not otherwise. The module defines it itself, under its mangled name and hidden: when the module is
 * linked, every call of it in the module binds here (a hidden definition takes the references of the other objects),
 * and nothing is imported (the build's check, cmake/openpqc_fips_check.cmake). It ends the process at once: a failed
 * check is a defect of the module, after which nothing of it may run. Unused when the assertions are off. */
__attribute__((visibility("hidden"), noreturn, cold, used)) void
opqc_fips_glibcxx_assert_fail(const char *file, int line, const char *function, const char *condition)
        __asm__("_ZSt21__glibcxx_assert_failPKciS0_S0_");

void opqc_fips_glibcxx_assert_fail(const char *file, int line, const char *function, const char *condition)
{
    (void)file;
    (void)line;
    (void)function;
    (void)condition;
    __builtin_trap();
}

/* The key is fixed and public (an integrity technique, not authentication): the 32 ASCII bytes
 * "OpenPQC FIPS 140-3 integrity key". */
static const uint8_t opqc_fips_integrity_key[32] = {'O', 'p', 'e', 'n', 'P', 'Q', 'C', ' ', 'F', 'I', 'P',
                                                     'S', ' ', '1', '4', '0', '-', '3', ' ', 'i', 'n', 't',
                                                     'e', 'g', 'r', 'i', 't', 'y', ' ', 'k', 'e', 'y'};

/* --- HMAC-SHA-256, one compiled copy ------------------------------------------------------------------------ */

/* The known-answer test and the integrity value run these three functions (the *_impl ones). Each is called only
 * from the wrapper below it, indirectly, through its address passed through an empty assembler statement: the
 * compiler cannot tell which function the call reaches, so it can neither inline it there nor make a copy of it
 * specialised for the call's arguments (constant propagation into a clone). Each therefore exists once in the
 * machine code, and the code that passes the known-answer test is the code that computes the integrity value. The
 * address is computed in the code (an instruction relative to itself), not loaded from a pointer in the module's
 * relocated data: the test checks such a pointer only as it computes the integrity value, so a pointer changed in
 * memory before the self-tests would otherwise send the test's own calls elsewhere. Init and finalize run once per
 * value and are compiled for size (cold): GCC would otherwise inline the unrolled SHA-256 into each of them, three
 * times in finalize. */
static __attribute__((cold)) void integrity_hmac_init_impl(opqc_hmac_sha256_state *s, const uint8_t *key,
                                                           size_t keylen)
{
    opqc_hmac_sha256_init(s, key, keylen);
}

static void integrity_hmac_absorb_impl(opqc_hmac_sha256_state *s, const uint8_t *text, size_t len)
{
    opqc_hmac_sha256_absorb(s, text, len);
}

static __attribute__((cold)) int integrity_hmac_finalize_impl(opqc_hmac_sha256_state *s, uint8_t *out,
                                                              unsigned outlen)
{
    return opqc_hmac_sha256_finalize(s, out, outlen);
}

static void integrity_hmac_init(opqc_hmac_sha256_state *s, const uint8_t *key, size_t keylen)
{
    void (*f)(opqc_hmac_sha256_state *, const uint8_t *, size_t) = integrity_hmac_init_impl;
    __asm__ volatile("" : "+r"(f));
    f(s, key, keylen);
}

static void integrity_hmac_absorb(opqc_hmac_sha256_state *s, const uint8_t *text, size_t len)
{
    void (*f)(opqc_hmac_sha256_state *, const uint8_t *, size_t) = integrity_hmac_absorb_impl;
    __asm__ volatile("" : "+r"(f));
    f(s, text, len);
}

static int integrity_hmac_finalize(opqc_hmac_sha256_state *s, uint8_t *out, unsigned outlen)
{
    int (*f)(opqc_hmac_sha256_state *, uint8_t *, unsigned) = integrity_hmac_finalize_impl;
    __asm__ volatile("" : "+r"(f));
    return f(s, out, outlen);
}

/* RFC 4231, Sections 4.3 and 4.8, test cases 2 (a key shorter than the block, as the integrity key) and 7 (a key
 * longer than the block, 131 bytes of 0xaa, hashed first; a text of several blocks) */
static const uint8_t kat2_key[4] = {'J', 'e', 'f', 'e'};
static const char kat2_data[] = "what do ya want for nothing?";
static const uint8_t kat2_mac[32] = {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
                                     0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
                                     0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
static const char kat7_data[] = "This is a test using a larger than block-size key and a larger than block-size data. "
                                "The key needs to be hashed before being used by the HMAC algorithm.";
static const uint8_t kat7_mac[32] = {0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f,
                                     0xbc, 0xd5, 0xb0, 0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07,
                                     0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2};

/* HMAC(key, data) through integrity_hmac, the data in two pieces (the first 16 bytes, then the rest: kept in the
 * state's buffer, then whole blocks and a rest, as the image's pieces are), compared with mac; 1 if equal */
static int integrity_hmac_case(const uint8_t *key, size_t keylen, const char *data, size_t len, const uint8_t *mac)
{
    uint8_t out[OPQC_HMAC_SHA256_BYTES];
    opqc_hmac_sha256_state st;
    integrity_hmac_init(&st, key, keylen);
    integrity_hmac_absorb(&st, (const uint8_t *)data, 16);
    integrity_hmac_absorb(&st, (const uint8_t *)data + 16, len - 16);
    const int ok = integrity_hmac_finalize(&st, out, sizeof out) == 0 && opqc_ct_memcmp(out, mac, sizeof out) == 0;
    opqc_zeroize(&st, sizeof st);
    opqc_zeroize(out, sizeof out);
    return ok;
}

/* 0 if integrity_hmac gives the known answers: the algorithm before its use (ISO/IEC 19790:2012 AS10.20; FIPS
 * 140-3 IG 10.2.A). The integrity test first computes HMAC-SHA-256 of RFC 4231's test cases 2 and 7 and compares
 * them with the known answers, with the same three compiled functions that then compute the integrity value
 * (integrity_hmac_*, above), and fails if either differs. The CAST of HMAC-SHA-256 in opqc_fips.c, which runs
 * before this test, checks the copy of the header-only opqc_hmac.h compiled there.
 * The test library openpqc_fips_break compares the first with its
 * known answer changed in one bit when OPENPQC_FIPS_TEST_BREAK is "integrity_hmac" (opqc_fips.h), so that a correct
 * computation fails. */
static int integrity_hmac_kat(void)
{
    uint8_t expected[sizeof kat2_mac], key7[131];
    memcpy(expected, kat2_mac, sizeof expected);
#if defined(OPQC_FIPS_TEST_BREAK)
    if (opqc_fips_test_breaks("integrity_hmac")) expected[0] = (uint8_t)(expected[0] ^ 1u);
#endif
    memset(key7, 0xaa, sizeof key7);
    const int ok = integrity_hmac_case(kat2_key, sizeof kat2_key, kat2_data, sizeof kat2_data - 1, expected) &&
                   integrity_hmac_case(key7, sizeof key7, kat7_data, sizeof kat7_data - 1, kat7_mac);
    return ok ? 0 : -1;
}

/* --- reading the image ---------------------------------------------------------------------------------------- */

/* The test calls no function of the C library or of the loader to find or read the image, and copies it with the
 * module's own memcpy (opqc_fips_mem.c): the module imports none of the functions on this path, so none can be
 * replaced by the program's own definition, a preloaded library or an auditing library (a memcpy that put a
 * changed byte back as the test copies it). */

/* n bytes at the address a of the process to buf, with the module's own memcpy (opqc_fips_mem.c) */
static OPQC_FIPS_IMAGE_READ void image_copy(void *buf, uintptr_t a, size_t n)
{
    memcpy(buf, (const void *)a, n);
}

/* The n-byte little-endian field (n <= 8) at the address a (the target's own byte order: little-endian) */
static OPQC_FIPS_IMAGE_READ uint64_t image_field(uintptr_t a, size_t n)
{
    uint64_t v = 0;
    memcpy(&v, (const void *)a, n);
    return v;
}

/* --- the canonical form ------------------------------------------------------------------------------------- */

/*
 * The canonical form of a byte is the byte as loaded, which is the file's byte
 * (zero past the end of the file, as the loader maps it), except at the places
 * below, where the loader writes or the packaging tools rewrite; there it is a
 * value that does not depend on the address the module was loaded at (the load
 * base B), which the seal tool takes from the file and this test from memory:
 *
 *   1. in a writable segment, the slots that the dynamic relocations write (the
 *      tables DT_RELA and DT_JMPREL, which lie in a covered read-only segment):
 *      the 8 bytes of an R_X86_64_RELATIVE slot as le64(value - B), which must
 *      be the relocation's addend, so that the module's pointers to itself (its
 *      tables in .data.rel.ro, .init_array, .fini_array, the GOT, .data) are
 *      checked as loaded; the slots of the other types (R_X86_64_64, GLOB_DAT,
 *      JUMP_SLOT, DTPMOD64, DTPOFF64, TPOFF64, IRELATIVE: 8 bytes; TLSDESC: 16),
 *      whose values are addresses in other objects, TLS module numbers and
 *      offsets or run-time resolutions, as zeros;
 *   2. in a writable segment, the entries of the dynamic section (PT_DYNAMIC)
 *      that the loader relocates in place, before the first DT_NULL: the value
 *      minus B, which is the value in the file. The GNU C library's loader adds
 *      B to the entries DT_HASH, DT_GNU_HASH, DT_PLTGOT, DT_STRTAB, DT_SYMTAB,
 *      DT_JMPREL and DT_VERSYM, and to DT_RELA when its value is not zero, of an
 *      object whose dynamic section is writable (elf/get-dynamic-info.h; it also
 *      does so for DT_RELR, which the module must not have; on x86-64 it leaves
 *      DT_REL as it is, which the module must not have either), and to no other.
 *      A DT_RELA of zero, which it leaves as it is, is refused below: zero minus
 *      B is an address above B. Every other entry is covered as loaded, and an
 *      entry whose value is an address (DT_INIT, DT_FINI, the three array tags,
 *      DT_VERDEF, DT_VERNEED, ...) must lie below B: such a value, changed in the
 *      file by B, would send the loader to another place of the module, and is
 *      not taken for a relocated one;
 *   3. the 64-byte record of the expected value (opqc_fips_integrity_record),
 *      as zeros, wherever its bytes of the file are mapped;
 *   4. the ELF header's e_shoff, e_shnum and e_shstrndx (file offsets 40 to
 *      47 and 60 to 63), as zeros, wherever they are mapped: they locate the
 *      section header table, which is not loaded, and strip and objcopy rewrite
 *      them, so a stripped copy of the module, or one with a debug link, is
 *      still the sealed module.
 */

static void le64(uint8_t out[8], uint64_t v)
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t load_le(const uint8_t *p, int n)
{
    uint64_t v = 0;
    for (int i = n - 1; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static uint64_t page_down(uint64_t a)
{
    return a & ~(uint64_t)(OPQC_FIPS_PAGE_BYTES - 1u);
}

static uint64_t page_up(uint64_t a)
{
    return page_down(a + (OPQC_FIPS_PAGE_BYTES - 1u));
}

/* The width of the slot that a dynamic relocation of this type writes (rule 1); 0 for R_X86_64_NONE and for the
 * types the module must not have */
static uint64_t relocation_width(uint64_t type)
{
    switch (type) {
    case R_X86_64_64:
    case R_X86_64_GLOB_DAT:
    case R_X86_64_JUMP_SLOT:
    case R_X86_64_RELATIVE:
    case R_X86_64_DTPMOD64:
    case R_X86_64_DTPOFF64:
    case R_X86_64_TPOFF64:
    case R_X86_64_IRELATIVE:
        return 8;
    case R_X86_64_TLSDESC:
        return 16;
    default:
        return 0;
    }
}

/* The dynamic tags whose value is an address (d_ptr): those of the gABI and the GNU ones */
static int address_tag(uint64_t tag)
{
    switch (tag) {
    case DT_PLTGOT:
    case DT_HASH:
    case DT_STRTAB:
    case DT_SYMTAB:
    case DT_RELA:
    case DT_INIT:
    case DT_FINI:
    case DT_REL:
    case DT_DEBUG:
    case DT_JMPREL:
    case DT_INIT_ARRAY:
    case DT_FINI_ARRAY:
    case DT_PREINIT_ARRAY:
    case OPQC_FIPS_DT_RELR:
    case DT_VERSYM:
    case DT_VERDEF:
    case DT_VERNEED:
        return 1;
    default:
        return tag >= DT_ADDRRNGLO && tag <= DT_ADDRRNGHI;
    }
}

/* The entries of the dynamic section that the loader relocates in place (rule 2), as a bit; 0 for the others */
static unsigned relocated_in_place(uint64_t tag)
{
    switch (tag) {
    case DT_HASH:
        return 1u << 0;
    case DT_GNU_HASH:
        return 1u << 1;
    case DT_PLTGOT:
        return 1u << 2;
    case DT_STRTAB:
        return 1u << 3;
    case DT_SYMTAB:
        return 1u << 4;
    case DT_RELA:
        return 1u << 5;
    case DT_JMPREL:
        return 1u << 6;
    case DT_VERSYM:
        return 1u << 7;
    default:
        return 0;
    }
}

/* What the test knows of the loaded module (link-time addresses; base is B) */
typedef struct {
    uintptr_t base;
    uintptr_t phdr;                /* the program header table, as loaded */
    unsigned phnum;
    uint64_t dynamic, dynamic_bytes; /* PT_DYNAMIC */
    int dynamic_writable;            /* in a writable segment: rule 2 applies */
    uint64_t dynamic_used;           /* the bytes of its entries before the first DT_NULL */
    uint64_t pltgot;                 /* DT_PLTGOT, 0 if none */
    uintptr_t rela[2];               /* DT_RELA, DT_JMPREL, as loaded */
    size_t count[2];
    uint64_t record_offset;          /* the record's offset in the file */
} opqc_fips_layout;

/* The program header i, from the table as loaded */
static void program_header(const opqc_fips_layout *m, unsigned i, Elf64_Phdr *ph)
{
    image_copy(ph, m->phdr + (uintptr_t)i * OPQC_FIPS_PHDR_BYTES, sizeof *ph);
}

/* [a, a + len) lies inside the file part of a PT_LOAD segment of the module: a writable one (writable 1), a
 * read-only one (0), or either (-1); its segment's PF_W in *w if found */
static int inside_w(const opqc_fips_layout *m, uint64_t a, uint64_t len, int writable, int *w)
{
    for (unsigned i = 0; i < m->phnum; i++) {
        Elf64_Phdr ph;
        program_header(m, i, &ph);
        if (ph.p_type != PT_LOAD) continue;
        const int is_writable = (ph.p_flags & PF_W) != 0;
        if (writable >= 0 && is_writable != (writable != 0)) continue;
        if (a >= ph.p_vaddr && len <= ph.p_filesz && a - ph.p_vaddr <= ph.p_filesz - len) {
            if (w != NULL) *w = is_writable;
            return 1;
        }
    }
    return 0;
}

static int inside(const opqc_fips_layout *m, uint64_t a, uint64_t len, int writable)
{
    return inside_w(m, a, len, writable, NULL);
}

/* The value of a dynamic entry as the file has it (rule 2): what the loader added to it in place taken off */
static uint64_t dynamic_value(const opqc_fips_layout *m, uint64_t tag, uint64_t value)
{
    return m->dynamic_writable && relocated_in_place(tag) != 0 ? value - (uint64_t)m->base : value;
}

/* The dynamic section's entries that the canonical form needs, and the requirements on the dynamic section, the
 * relocations and immediate binding; 1 if they hold.
 *
 * Immediate binding. The module is linked with -z now (DF_BIND_NOW in DT_FLAGS
 * and DF_1_NOW in DT_FLAGS_1; cmake/OpenPQCFips.cmake), and this test and the
 * seal tool refuse a module that has neither flag. With it, the value of every
 * JUMP_SLOT slot, which rule 1 leaves out, is the loader's: before any code of
 * the module runs, the loader resolves each JUMP_SLOT relocation from its
 * covered record and the symbol that record names, and it never reads the
 * slot's value in the file. Under lazy binding it would: it would add B to
 * that value and the first call through the slot would jump there, so a change
 * of the file would change what the module calls without changing a covered
 * byte. GOT[1] and GOT[2], the two words after the one DT_PLTGOT points to,
 * are covered as loaded: the loader writes its own data there only when it
 * prepares the module for lazy binding, which the flag rules out; if it does so
 * anyway (an auditing library with PLT hooks, LD_AUDIT, or LD_PROFILE naming
 * the module), the test fails.
 */
static int read_dynamic(opqc_fips_layout *m)
{
    uint64_t at[2] = {0, 0}, bytes[2] = {0, 0}, rela_entry = 0, plt_type = 0;
    int have[2] = {0, 0}, bind_now = 0, null = 0;
    unsigned seen = 0, flags_seen = 0;
    for (uint64_t e = m->dynamic; e + 16 <= m->dynamic + m->dynamic_bytes; e += 16) {
        const uint64_t tag = image_field(m->base + (uintptr_t)e, 8);
        if (tag == DT_NULL) {
            m->dynamic_used = e - m->dynamic;
            null = 1;
            break;
        }
        const unsigned bit = relocated_in_place(tag);
        if ((seen & bit) != 0) return 0; /* twice: the loader relocates only the last one */
        seen |= bit;
        const unsigned flag = tag == DT_FLAGS ? 1u : tag == DT_FLAGS_1 ? 2u : 0u;
        if ((flags_seen & flag) != 0) return 0; /* twice: the loader honours only the last one */
        flags_seen |= flag;
        const uint64_t value = dynamic_value(m, tag, image_field(m->base + (uintptr_t)e + 8, 8));
        if (address_tag(tag) && value >= (uint64_t)m->base) return 0; /* a value relocated where rule 2 has none */
        switch (tag) {
        case DT_RELA:
            at[0] = value;
            have[0] = 1;
            break;
        case DT_RELASZ:
            bytes[0] = value;
            break;
        case DT_RELAENT:
            rela_entry = value;
            break;
        case DT_JMPREL:
            at[1] = value;
            have[1] = 1;
            break;
        case DT_PLTRELSZ:
            bytes[1] = value;
            break;
        case DT_PLTREL:
            plt_type = value;
            break;
        case DT_PLTGOT:
            m->pltgot = value;
            break;
        case DT_REL:
        case OPQC_FIPS_DT_RELR:
        case DT_TEXTREL:
            return 0;
        case DT_FLAGS:
            if ((value & DF_TEXTREL) != 0) return 0;
            if ((value & DF_BIND_NOW) != 0) bind_now = 1;
            break;
        case DT_FLAGS_1:
            if ((value & DF_1_NOW) != 0) bind_now = 1;
            break;
        default:
            break;
        }
    }
    if (!null) return 0;     /* no DT_NULL in the section */
    if (!bind_now) return 0; /* linked without -z now: the loader may bind it lazily (above) */
    if (have[0] && rela_entry != sizeof(Elf64_Rela)) return 0;
    if (have[1] && plt_type != DT_RELA) return 0;
    for (int t = 0; t < 2; t++) {
        if (!have[t]) continue;
        if (bytes[t] % sizeof(Elf64_Rela) != 0 || !inside(m, at[t], bytes[t], 0)) return 0;
        m->rela[t] = m->base + (uintptr_t)at[t];
        m->count[t] = (size_t)(bytes[t] / sizeof(Elf64_Rela));
        for (size_t i = 0; i < m->count[t]; i++) {
            Elf64_Rela r;
            image_copy(&r, m->rela[t] + i * sizeof r, sizeof r);
            const uint64_t type = ELF64_R_TYPE(r.r_info);
            if (type == R_X86_64_NONE) continue;
            const uint64_t w = relocation_width(type);
            if (w == 0 || !inside(m, r.r_offset, w, 1)) return 0;
        }
    }
    return m->pltgot == 0 || inside(m, m->pltgot, 24, 1);
}

/* Puts len bytes of src, meant for the address at, over the part of buf that holds [va, va + n) */
static void overlay(uint8_t *buf, uint64_t va, size_t n, uint64_t at, const uint8_t *src, uint64_t len)
{
    if (at >= va + n || at + len <= va) return;
    for (uint64_t i = 0; i < len; i++) {
        const uint64_t a = at + i;
        if (a >= va && a - va < n) buf[a - va] = src[i];
    }
}

/* Zeros over the part of buf, which holds the bytes of the file from offset file on (n of them), that holds the
 * file's bytes [at, at + len) */
static void zero_file(uint8_t *buf, uint64_t file, size_t n, uint64_t at, uint64_t len)
{
    for (uint64_t i = 0; i < len; i++) {
        const uint64_t f = at + i;
        if (f >= file && f - file < n) buf[f - file] = 0;
    }
}

/* buf = the canonical form of the module's bytes [va, va + n) of the segment ph, from memory (rules 1 to 4) */
static void canonical(const opqc_fips_layout *m, const Elf64_Phdr *ph, uint64_t va, uint8_t *buf, size_t n)
{
    image_copy(buf, m->base + (uintptr_t)va, n);
    if ((ph->p_flags & PF_W) != 0) {
        for (int t = 0; t < 2; t++) {
            for (size_t i = 0; i < m->count[t]; i++) {
                Elf64_Rela r;
                image_copy(&r, m->rela[t] + i * sizeof r, sizeof r);
                const uint64_t type = ELF64_R_TYPE(r.r_info), w = relocation_width(type);
                if (w == 0 || r.r_offset >= va + n || r.r_offset + w <= va) continue;
                uint8_t slot[16];
                memset(slot, 0, sizeof slot);
                if (type == R_X86_64_RELATIVE)
                    le64(slot, image_field(m->base + (uintptr_t)r.r_offset, 8) - (uint64_t)m->base);
                overlay(buf, va, n, r.r_offset, slot, w);
            }
        }
        if (m->dynamic_writable) {
            for (uint64_t e = m->dynamic; e < m->dynamic + m->dynamic_used; e += 16) {
                if (e >= va + n || e + 16 <= va) continue;
                const uint64_t tag = image_field(m->base + (uintptr_t)e, 8);
                uint8_t entry[16];
                le64(entry, tag);
                le64(entry + 8, dynamic_value(m, tag, image_field(m->base + (uintptr_t)e + 8, 8)));
                overlay(buf, va, n, e, entry, sizeof entry);
            }
        }
    }
    /* the file offset of va (p_vaddr and p_offset are equal modulo the page, so this holds below p_vaddr too) */
    const uint64_t file = ph->p_offset + va - ph->p_vaddr;
    zero_file(buf, file, n, m->record_offset, OPQC_FIPS_RECORD_BYTES);
    zero_file(buf, file, n, 40, 8); /* e_shoff */
    zero_file(buf, file, n, 60, 4); /* e_shnum, e_shstrndx */
}

/* --- the image -------------------------------------------------------------------------------------------- */

/*
 * Covered bytes: every byte that the loader maps from the file, except the end
 * of a writable segment's last page. The loader maps each PT_LOAD segment in
 * whole pages (4096 bytes on x86-64), from the page that holds its first byte
 * through the page that holds its last, so the bytes of the file that share
 * those pages are mapped too, with the segment's protection, although no
 * section holds them. For each PT_LOAD program header, in program-header
 * order, writable segments included, the message holds
 *
 *   le64(start) || le64(end - start) || the canonical form of [start, end)
 *
 * (le64: 8 bytes, least significant first), where start is p_vaddr rounded
 * down to its page and end is p_vaddr + p_filesz, rounded up to the end of its
 * page for a segment that is not writable. The rest of a writable segment's
 * last page is not covered: there the zero-filled .bss begins, which the
 * module writes as it runs (without .bss, those bytes are mapped writable and
 * not executable, and nothing in the module refers to them).
 *
 * Why these bytes are the module: they are all of the module that is in
 * memory, as the loader made it from the file: its code (.init, .plt, .text,
 * .fini), its constants (.rodata, holding the CASTs' known answers and this
 * test's key, and the constant tables that contain pointers, .data.rel.ro),
 * its initialized data (.data), and the tables by which the loader links and
 * starts it (the ELF and program headers, dynamic symbols and strings, hash
 * tables, version records, relocation tables, the dynamic section, the GOT,
 * .init_array, .fini_array) and the unwinding tables (.eh_frame and its
 * header), with the file's bytes around them in the same pages. Not covered:
 * what the loader does not map (the section header table and the sections that
 * are not allocated, .symtab, .strtab, .comment, debugging sections, outside
 * the segments' pages), the zero-filled .bss and .tbss and the rest of a
 * writable segment's last page, the values of the relocation slots of rule 1
 * other than RELATIVE (the loader computes them from the covered relocation
 * records and from other objects' symbols), the record, and the three fields
 * of rule 4.
 */

static int in_segment(uint64_t a, const Elf64_Phdr *ph)
{
    return a >= ph->p_vaddr && a - ph->p_vaddr < ph->p_memsz;
}

/* The covered range of a segment: [*start, *end) */
static void covered_range(const Elf64_Phdr *ph, uint64_t *start, uint64_t *end)
{
    *start = page_down(ph->p_vaddr);
    *end = (ph->p_flags & PF_W) != 0 ? ph->p_vaddr + ph->p_filesz : page_up(ph->p_vaddr + ph->p_filesz);
}

/*
 * The module's layout from its ELF header and program headers as loaded; 1 if the requirements hold.
 *
 * Requirements, checked here and by the seal tool (otherwise the test fails,
 * or the build stops): an x86-64 ELF64 shared object, 4096-byte pages; every
 * PT_LOAD readable, its p_vaddr and p_offset equal modulo the page size, the
 * segments' pages in ascending order without overlap, a read-only one with
 * p_memsz == p_filesz (nothing of it zero-filled); the ELF header and the
 * program header table (e_phoff, e_phnum entries of 56 bytes) in the first page
 * of the file and in the file part of the read-only segment that maps file
 * offset 0, and a PT_PHDR, if there is one, naming that table: the loader maps
 * the segments that this table describes, so it is the covered one; one dynamic
 * section, in the file part of a segment whose writability its own program
 * header (PF_W) states, without an entry of rule 2 twice before DT_NULL;
 * DF_BIND_NOW or DF_1_NOW, with DT_FLAGS and DT_FLAGS_1 at most once each (the
 * loader honours the last entry of each, and this test must read the flags it
 * honours); relocation tables of type RELA (no DT_REL, no
 * DT_RELR, no text relocations) inside a read-only segment, every relocation of
 * a type listed in rule 1 (or R_X86_64_NONE), its slot inside the file part of
 * a writable segment; GOT[0..2] and the record inside the file part of a
 * writable segment; this function's code in an executable segment; and here, B
 * above the module's highest link-time address (rule 2). Nothing of the module
 * writes to the covered bytes of its writable segment as it runs (its state
 * variables start as zero, in .bss), so the test gives the same answer whenever
 * it runs. Several of these requirements are defence in depth: for a file that
 * the seal tool sealed, breaking one of them changes covered bytes, so the
 * integrity value differs anyway (an entry of rule 2 twice, no DT_NULL, the
 * PF_W of PT_DYNAMIC differing from its segment's, an address entry at or
 * above B, a PT_PHDR that names another table, a table past the file part of
 * the header's segment), and no test fails without them; they refuse a file
 * whose integrity value was computed by other means. The tests show such a
 * refusal for a program header table outside the header's page and for
 * DT_FLAGS and DT_FLAGS_1 twice (tests/fips_integrity.cmake).
 */
static int locate(opqc_fips_layout *m)
{
    const uintptr_t ehdr = (uintptr_t)__ehdr_start;
    uint8_t ident[EI_NIDENT];
    image_copy(ident, ehdr, sizeof ident);
    if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 || ident[EI_MAG2] != ELFMAG2 ||
        ident[EI_MAG3] != ELFMAG3 || ident[EI_CLASS] != ELFCLASS64 || ident[EI_DATA] != ELFDATA2LSB)
        return 0;
    if (image_field(ehdr + 16, 2) != ET_DYN || image_field(ehdr + 18, 2) != EM_X86_64) return 0;
    const uint64_t phoff = image_field(ehdr + 32, 8);
    const uint64_t phentsize = image_field(ehdr + 54, 2), phnum = image_field(ehdr + 56, 2);
    /* the table in the header's page, which is mapped (the segment that maps the header starts there) */
    if (phentsize != OPQC_FIPS_PHDR_BYTES || phnum == 0 || phnum > OPQC_FIPS_MAX_SEGMENTS ||
        phoff > OPQC_FIPS_PAGE_BYTES || phnum * OPQC_FIPS_PHDR_BYTES > OPQC_FIPS_PAGE_BYTES - phoff)
        return 0;
    m->phdr = ehdr + (uintptr_t)phoff;
    m->phnum = (unsigned)phnum;

    const uintptr_t record = (uintptr_t)(const void *)opqc_fips_integrity_record;
    const uintptr_t code = (uintptr_t)&opqc_fips_integrity_test;
    int ok = 1, headers = 0, dynamics = 0, phdrs = 0;
    uint64_t header = 0, header_filesz = 0, top = 0, previous_end = 0, dynamic_flags = 0;
    Elf64_Phdr table;
    memset(&table, 0, sizeof table);
    for (unsigned i = 0; i < m->phnum; i++) {
        Elf64_Phdr ph;
        program_header(m, i, &ph);
        if (ph.p_type == PT_DYNAMIC) {
            m->dynamic = ph.p_vaddr;
            m->dynamic_bytes = ph.p_filesz;
            dynamic_flags = ph.p_flags;
            dynamics++;
        }
        if (ph.p_type == PT_PHDR) {
            table = ph;
            phdrs++;
        }
        if (ph.p_type != PT_LOAD) continue;
        if ((ph.p_flags & PF_R) == 0 || ph.p_filesz > ph.p_memsz) ok = 0;
        if ((ph.p_flags & PF_W) == 0 && ph.p_memsz != ph.p_filesz) ok = 0;
        if (ph.p_align == 0 || ph.p_align % OPQC_FIPS_PAGE_BYTES != 0 ||
            (ph.p_vaddr - ph.p_offset) % OPQC_FIPS_PAGE_BYTES != 0)
            ok = 0;
        if (page_down(ph.p_vaddr) < previous_end) ok = 0; /* the pages in ascending order, without overlap */
        previous_end = page_up(ph.p_vaddr + ph.p_memsz);
        if (ph.p_offset == 0) {
            if ((ph.p_flags & PF_W) != 0) ok = 0; /* the headers in a read-only segment */
            header = ph.p_vaddr;
            header_filesz = ph.p_filesz;
            headers++;
        }
        if (ph.p_vaddr + ph.p_memsz > top) top = ph.p_vaddr + ph.p_memsz;
    }
    /* B, from the header's address as loaded and as linked; then the module's own symbols where the table says */
    m->base = ehdr - (uintptr_t)header;
    const uint64_t table_end = phoff + phnum * OPQC_FIPS_PHDR_BYTES;
    ok = ok && headers == 1 && dynamics == 1 && table_end <= header_filesz && (uint64_t)m->base > top;
    if (ok && phdrs != 0)
        ok = phdrs == 1 && table.p_offset == phoff && table.p_vaddr == header + phoff &&
             table.p_filesz == phnum * OPQC_FIPS_PHDR_BYTES && table.p_memsz == table.p_filesz;
    ok = ok && (uintptr_t)_DYNAMIC == m->base + (uintptr_t)m->dynamic && m->dynamic_bytes % 16 == 0 &&
         inside_w(m, m->dynamic, m->dynamic_bytes, -1, &m->dynamic_writable) &&
         ((dynamic_flags & PF_W) != 0) == (m->dynamic_writable != 0);
    if (!ok) return 0;
    const uint64_t record_vaddr = (uint64_t)(record - m->base), code_vaddr = (uint64_t)(code - m->base);
    int code_covered = 0, holds_record = 0;
    for (unsigned i = 0; i < m->phnum; i++) {
        Elf64_Phdr ph;
        program_header(m, i, &ph);
        if (ph.p_type != PT_LOAD) continue;
        if ((ph.p_flags & PF_X) != 0 && in_segment(code_vaddr, &ph)) code_covered = 1;
        if (in_segment(record_vaddr, &ph)) {
            holds_record = 1;
            m->record_offset = ph.p_offset + record_vaddr - ph.p_vaddr;
        }
    }
    return code_covered && holds_record && inside(m, record_vaddr, OPQC_FIPS_RECORD_BYTES, 1) && read_dynamic(m);
}

/* The integrity value of the module's covered segments, and their number and bytes; 1 if computed */
static int measure(const opqc_fips_layout *m, uint32_t *segments, uint64_t *bytes, uint8_t mac[OPQC_HMAC_SHA256_BYTES])
{
    opqc_hmac_sha256_state st;
    uint8_t buf[OPQC_FIPS_CHUNK_BYTES];
    integrity_hmac_init(&st, opqc_fips_integrity_key, sizeof opqc_fips_integrity_key);
    for (unsigned i = 0; i < m->phnum; i++) {
        Elf64_Phdr ph;
        program_header(m, i, &ph);
        if (ph.p_type != PT_LOAD) continue;
        uint64_t start, end;
        covered_range(&ph, &start, &end);
        uint8_t where[16];
        le64(where, start);
        le64(where + 8, end - start);
        integrity_hmac_absorb(&st, where, sizeof where);
        for (uint64_t va = start; va < end;) {
            const size_t n = end - va < sizeof buf ? (size_t)(end - va) : sizeof buf;
            canonical(m, &ph, va, buf, n);
            integrity_hmac_absorb(&st, buf, n);
            va += n;
        }
        (*segments)++;
        *bytes += end - start;
    }
    const int ok = integrity_hmac_finalize(&st, mac, OPQC_HMAC_SHA256_BYTES) == 0;
    opqc_zeroize(buf, sizeof buf);
    opqc_zeroize(&st, sizeof st);
    return ok;
}

int opqc_fips_integrity_test(void)
{
    if (integrity_hmac_kat() != 0) return -1;

    opqc_fips_layout m;
    memset(&m, 0, sizeof m);
    uint32_t segments = 0;
    uint64_t bytes = 0;
    uint8_t mac[OPQC_HMAC_SHA256_BYTES];
    memset(mac, 0, sizeof mac);
    const int measured = locate(&m) && measure(&m, &segments, &bytes, mac);

    uint8_t rec[OPQC_FIPS_RECORD_BYTES];
    const volatile uint8_t *r = opqc_fips_integrity_record;
    for (size_t i = 0; i < sizeof rec; i++) rec[i] = r[i];

    static const uint8_t magic[16] = {'O', 'p', 'e', 'n', 'P', 'Q', 'C', '-', 'F', 'I', 'P', 'S', '-', 'M', 'A', 'C'};
    const int ok = measured && opqc_ct_memcmp(rec, magic, sizeof magic) == 0 && load_le(rec + 16, 4) == 1 &&
                   load_le(rec + 20, 4) == segments && load_le(rec + 24, 8) == bytes &&
                   opqc_ct_memcmp(rec + 32, mac, OPQC_HMAC_SHA256_BYTES) == 0;
    opqc_zeroize(rec, sizeof rec);
    opqc_zeroize(mac, sizeof mac);
    opqc_zeroize(&m, sizeof m);
    return ok ? 0 : -1;
}
