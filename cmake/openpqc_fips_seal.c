/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * openpqc_fips_seal.c -- the post-link step of FIPS 140-3 mode: stores the
 * integrity value of the module in the linked shared library
 *
 *   openpqc_fips_seal <library>            computes and writes the value
 *   openpqc_fips_seal --verify <library>   checks it (exit status 1 if wrong)
 *   openpqc_fips_seal --print <library>    prints the record, in hex
 *
 * The value is the HMAC-SHA-256 that src/Core/opqc_fips_integrity.c computes
 * when the module is loaded, over the same message, which that file's header
 * describes: for every PT_LOAD segment, in program-header order,
 * le64(start) || le64(end - start) || the canonical form of [start, end), where
 * start is p_vaddr rounded down to its page (4096 bytes) and end is p_vaddr +
 * p_filesz, rounded up to the end of its page for a segment that is not
 * writable, with the key "OpenPQC FIPS 140-3 integrity key". Here the bytes come
 * from the file (p_offset), which is what the loader maps (zeros past the end
 * of the file), and the canonical form of the places the loader writes is taken
 * from the file too: in a writable segment, an R_X86_64_RELATIVE slot is its
 * relocation's addend, the slots of the other relocation types are zeros, and
 * the dynamic section is as in the file (the link-time addresses); wherever
 * they are mapped, the record and the ELF header's e_shoff, e_shnum and
 * e_shstrndx are zeros. GOT[1] and GOT[2] are covered as they are in the file:
 * the module is linked with -z now, and the loader writes them only for lazy
 * binding. The value goes into the 64-byte record of the section
 * .openpqc_fips_mac (layout in opqc_fips_integrity.c), which lies in a writable
 * segment.
 *
 * Refused, with exit status 2 and the file unchanged: a file that is not an
 * x86-64 ELF64 shared object, and everything the integrity test's requirements
 * exclude (opqc_fips_integrity.c): a PT_LOAD that is not readable, a read-only
 * one that the loader extends with zeros, one whose p_vaddr and p_offset differ
 * modulo the page or whose alignment is not a multiple of it, segments whose
 * pages overlap or are not in ascending order, an ELF header outside a
 * read-only segment, a program header table outside the first page of the file
 * or outside the file part of the read-only segment that maps file offset 0
 * (the loader maps the segments that this table describes, so the integrity
 * value must cover it), a PT_PHDR that names another table, no dynamic section
 * or more than one, a dynamic section outside the file's segments or whose
 * program header's PF_W differs from its segment's (the loader decides from the
 * former whether it relocates the section in place, the integrity test from the
 * latter), an entry that the loader relocates in place (rule 2 of
 * opqc_fips_integrity.c) twice before DT_NULL, a library linked without -z now
 * (neither DF_BIND_NOW in DT_FLAGS nor DF_1_NOW in DT_FLAGS_1: the loader could
 * bind it lazily, from values of the file that the integrity value leaves out),
 * DT_FLAGS or DT_FLAGS_1 twice (the loader honours the last entry of each),
 * DT_REL, DT_RELR or text relocations, relocation tables outside a read-only
 * segment, a relocation of an unknown type or whose slot is not in the file
 * part of a writable segment, GOT[0..2] outside a writable segment, and a record
 * that is missing, too small, not in a writable segment, or without its magic.
 * The section header table is read only to find the record (--verify and
 * --print need it too; the module's own test does not).
 *
 * A build tool: it runs on the build machine (CMake runs it right after the
 * link of the library, and through CMAKE_CROSSCOMPILING_EMULATOR in a cross
 * build).
 */

#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Core/opqc_hmac.h"

#define RECORD_SECTION ".openpqc_fips_mac"
#define RECORD_BYTES 64
#define PAGE_BYTES 4096u /* the page of x86-64, which the loader maps segments in */
#define TAG_RELR 36      /* DT_RELR, not in every <elf.h> yet */

static const uint8_t integrity_key[32] = {'O', 'p', 'e', 'n', 'P', 'Q', 'C', ' ', 'F', 'I', 'P',
                                          'S', ' ', '1', '4', '0', '-', '3', ' ', 'i', 'n', 't',
                                          'e', 'g', 'r', 'i', 't', 'y', ' ', 'k', 'e', 'y'};
static const uint8_t record_magic[16] = {'O', 'p', 'e', 'n', 'P', 'Q', 'C', '-',
                                         'F', 'I', 'P', 'S', '-', 'M', 'A', 'C'};

static const char *program = "openpqc_fips_seal";

static int fail(const char *path, const char *why)
{
    fprintf(stderr, "%s: %s: %s\n", program, path, why);
    return 2;
}

typedef struct {
    uint32_t type, flags;
    uint64_t offset, vaddr, filesz, memsz;
} segment;

typedef struct {
    const uint8_t *data;
    size_t size;
    segment seg[64];
    unsigned nseg;
    uint64_t header, dynamic, dynamic_bytes, dynamic_flags, pltgot, record_offset;
    uint64_t rela[2], rela_bytes[2];
} module;

/* An unsigned little-endian field of n bytes at offset off; 0 past the end of the file (callers check bounds) */
static uint64_t field(const module *m, uint64_t off, unsigned n)
{
    if (off > m->size || n > m->size - off) return 0;
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++) v = (v << 8) | m->data[off + n - 1 - i];
    return v;
}

static void put_le(uint8_t *p, uint64_t v, unsigned n)
{
    for (unsigned i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t page_down(uint64_t a)
{
    return a & ~(uint64_t)(PAGE_BYTES - 1u);
}

static uint64_t page_up(uint64_t a)
{
    return page_down(a + (PAGE_BYTES - 1u));
}

/* [a, a + len) lies inside the file part of a PT_LOAD segment: a writable one (writable 1), a read-only one (0),
 * or either (-1); its file offset in *off */
static int inside(const module *m, uint64_t a, uint64_t len, int writable, uint64_t *off)
{
    for (unsigned i = 0; i < m->nseg; i++) {
        const segment *s = &m->seg[i];
        if (s->type != PT_LOAD) continue;
        if (writable >= 0 && ((s->flags & PF_W) != 0) != (writable != 0)) continue;
        if (a >= s->vaddr && len <= s->filesz && a - s->vaddr <= s->filesz - len) {
            if (off != NULL) *off = s->offset + (a - s->vaddr);
            return 1;
        }
    }
    return 0;
}

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

/* The entries of the dynamic section that the GNU C library's loader relocates in place, adding the load base
 * (rule 2 of opqc_fips_integrity.c), as a bit; 0 for the others */
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

/* The dynamic section's entries (until DT_NULL): the relocation tables and DT_PLTGOT; NULL if they meet the
 * requirements, or why not */
static const char *read_dynamic(module *m)
{
    uint64_t off = 0, rela_entry = 0, plt_type = 0;
    int have[2] = {0, 0}, bind_now = 0, null = 0;
    unsigned seen = 0, flags_seen = 0;
    if (!inside(m, m->dynamic, m->dynamic_bytes, -1, &off)) return "the dynamic section is outside the segments";
    const int writable = inside(m, m->dynamic, m->dynamic_bytes, 1, NULL);
    if (writable != ((m->dynamic_flags & PF_W) != 0))
        return "the dynamic section's program header and its segment differ in PF_W: the loader would relocate it in "
               "place where the integrity test does not expect it, or not where it does";
    for (uint64_t e = 0; e + 16 <= m->dynamic_bytes; e += 16) {
        const uint64_t tag = field(m, off + e, 8), value = field(m, off + e + 8, 8);
        if (tag == DT_NULL) {
            null = 1;
            break;
        }
        const unsigned bit = relocated_in_place(tag);
        if ((seen & bit) != 0)
            return "an entry of the dynamic section that the loader relocates in place appears twice (the loader "
                   "relocates the last one only)";
        seen |= bit;
        const unsigned flag = tag == DT_FLAGS ? 1u : tag == DT_FLAGS_1 ? 2u : 0u;
        if ((flags_seen & flag) != 0)
            return "DT_FLAGS or DT_FLAGS_1 appears twice (the loader honours the last one only, and the integrity test "
                   "must read the flags it honours)";
        flags_seen |= flag;
        switch (tag) {
        case DT_RELA:
            m->rela[0] = value;
            have[0] = 1;
            break;
        case DT_RELASZ:
            m->rela_bytes[0] = value;
            break;
        case DT_RELAENT:
            rela_entry = value;
            break;
        case DT_JMPREL:
            m->rela[1] = value;
            have[1] = 1;
            break;
        case DT_PLTRELSZ:
            m->rela_bytes[1] = value;
            break;
        case DT_PLTREL:
            plt_type = value;
            break;
        case DT_PLTGOT:
            m->pltgot = value;
            break;
        case DT_REL:
            return "REL relocations (DT_REL): the integrity test knows RELA only";
        case TAG_RELR:
            return "packed relative relocations (DT_RELR): link without -z pack-relative-relocs";
        case DT_TEXTREL:
            return "text relocations: the loader would change read-only bytes";
        case DT_FLAGS:
            if ((value & DF_TEXTREL) != 0) return "text relocations: the loader would change read-only bytes";
            if ((value & DF_BIND_NOW) != 0) bind_now = 1;
            break;
        case DT_FLAGS_1:
            if ((value & DF_1_NOW) != 0) bind_now = 1;
            break;
        default:
            break;
        }
    }
    if (!null) return "the dynamic section has no DT_NULL";
    if (!bind_now)
        return "not linked with -z now (no DF_BIND_NOW in DT_FLAGS, no DF_1_NOW in DT_FLAGS_1): the loader could bind "
               "it lazily, from slot values of the file that the integrity value leaves out";
    if (have[0] && rela_entry != 24) return "DT_RELAENT is not 24";
    if (have[1] && plt_type != DT_RELA) return "DT_PLTREL is not DT_RELA";
    for (int t = 0; t < 2; t++) {
        if (!have[t]) {
            m->rela_bytes[t] = 0;
            continue;
        }
        uint64_t table = 0;
        if (m->rela_bytes[t] % 24 != 0 || !inside(m, m->rela[t], m->rela_bytes[t], 0, &table))
            return "a relocation table outside the read-only segments";
        m->rela[t] = table; /* from here on: its file offset */
        for (uint64_t r = 0; r < m->rela_bytes[t]; r += 24) {
            const uint64_t where = field(m, table + r, 8), type = field(m, table + r + 8, 8) & 0xffffffffu;
            if (type == R_X86_64_NONE) continue;
            const uint64_t w = relocation_width(type);
            if (w == 0) return "a dynamic relocation of a type the integrity test does not know";
            if (!inside(m, where, w, 1, NULL)) return "a relocation that writes outside the writable segments' file part";
        }
    }
    if (m->pltgot != 0 && !inside(m, m->pltgot, 24, 1, NULL)) return "GOT[0..2] outside a writable segment";
    return NULL;
}

/* Puts len bytes of src, meant for the address at, over the part of buf that holds [va, va + n) */
static void overlay(uint8_t *buf, uint64_t va, uint64_t n, uint64_t at, const uint8_t *src, uint64_t len)
{
    if (at >= va + n || at + len <= va) return;
    for (uint64_t i = 0; i < len; i++) {
        const uint64_t a = at + i;
        if (a >= va && a - va < n) buf[a - va] = src[i];
    }
}

/* Zeros over the part of buf, which holds the bytes of the file from offset file on (n of them), that holds the
 * file's bytes [at, at + len) */
static void zero_file(uint8_t *buf, uint64_t file, uint64_t n, uint64_t at, uint64_t len)
{
    for (uint64_t i = 0; i < len; i++) {
        const uint64_t f = at + i;
        if (f >= file && f - file < n) buf[f - file] = 0;
    }
}

/* buf (n bytes: the file's bytes of [va, va + n) of the segment s) to their canonical form */
static void canonical(const module *m, const segment *s, uint64_t va, uint8_t *buf, uint64_t n)
{
    if ((s->flags & PF_W) != 0) {
        for (int t = 0; t < 2; t++) {
            for (uint64_t r = 0; r < m->rela_bytes[t]; r += 24) {
                const uint64_t where = field(m, m->rela[t] + r, 8);
                const uint64_t type = field(m, m->rela[t] + r + 8, 8) & 0xffffffffu;
                const uint64_t w = relocation_width(type);
                if (w == 0) continue;
                uint8_t slot[16];
                memset(slot, 0, sizeof slot);
                if (type == R_X86_64_RELATIVE) put_le(slot, field(m, m->rela[t] + r + 16, 8), 8); /* the addend */
                overlay(buf, va, n, where, slot, w);
            }
        }
    }
    const uint64_t file = s->offset + va - s->vaddr; /* p_vaddr and p_offset are equal modulo the page */
    zero_file(buf, file, n, m->record_offset, RECORD_BYTES);
    zero_file(buf, file, n, 40, 8); /* e_shoff */
    zero_file(buf, file, n, 60, 4); /* e_shnum, e_shstrndx */
}

/* Seals, verifies or prints the record of the file whose size bytes are at data */
static int seal(const char *path, const uint8_t *data, size_t size, int verify, int print)
{
    static module m; /* large (the segment table): not on the stack */
    memset(&m, 0, sizeof m);
    m.data = data;
    m.size = size;
    if (size < 64 || memcmp(data, ELFMAG, SELFMAG) != 0) return fail(path, "not an ELF file");
    if (data[EI_CLASS] != ELFCLASS64 || data[EI_DATA] != ELFDATA2LSB || field(&m, 18, 2) != EM_X86_64)
        return fail(path, "not an x86-64 ELF64 object: the integrity test knows x86-64's relocations only");
    if (field(&m, 16, 2) != ET_DYN) return fail(path, "not a shared object");

    const uint64_t phoff = field(&m, 32, 8), shoff = field(&m, 40, 8);
    const uint64_t phentsize = field(&m, 54, 2), phnum = field(&m, 56, 2);
    const uint64_t shentsize = field(&m, 58, 2), shnum = field(&m, 60, 2), shstrndx = field(&m, 62, 2);
    if (phnum == 0 || phnum > 64 || phentsize != 56 || phoff > size || phnum * phentsize > size - phoff)
        return fail(path, "bad program headers");
    if (shnum == 0 || shentsize < 64 || shoff > size || shnum * shentsize > size - shoff || shstrndx >= shnum)
        return fail(path, "bad section headers");

    int have_header = 0, have_dynamic = 0, have_phdr = 0;
    uint64_t previous_end = 0, header_filesz = 0;
    segment phdr_segment;
    memset(&phdr_segment, 0, sizeof phdr_segment);
    for (uint64_t i = 0; i < phnum; i++) {
        const uint64_t b = phoff + i * phentsize;
        segment *s = &m.seg[m.nseg++];
        s->type = (uint32_t)field(&m, b, 4);
        s->flags = (uint32_t)field(&m, b + 4, 4);
        s->offset = field(&m, b + 8, 8);
        s->vaddr = field(&m, b + 16, 8);
        s->filesz = field(&m, b + 32, 8);
        s->memsz = field(&m, b + 40, 8);
        if (s->type == PT_DYNAMIC) {
            if (have_dynamic) return fail(path, "more than one dynamic section (PT_DYNAMIC)");
            m.dynamic = s->vaddr;
            m.dynamic_bytes = s->filesz;
            m.dynamic_flags = s->flags;
            have_dynamic = 1;
        }
        if (s->type == PT_PHDR) {
            if (have_phdr) return fail(path, "more than one PT_PHDR");
            phdr_segment = *s;
            have_phdr = 1;
        }
        if (s->type != PT_LOAD) continue;
        if ((s->flags & PF_R) == 0) return fail(path, "a segment that is not readable");
        if (s->filesz > s->memsz || ((s->flags & PF_W) == 0 && s->memsz != s->filesz))
            return fail(path, "a read-only segment that the loader extends with zeros");
        if (s->offset > size || s->filesz > size - s->offset) return fail(path, "a segment past the end of the file");
        const uint64_t align = field(&m, b + 48, 8);
        if (align == 0 || align % PAGE_BYTES != 0 || (s->vaddr - s->offset) % PAGE_BYTES != 0)
            return fail(path, "a segment not aligned to the page, or whose address and file offset differ modulo it");
        if (page_down(s->vaddr) < previous_end) return fail(path, "segments whose pages overlap or are not in order");
        previous_end = page_up(s->vaddr + s->memsz);
        if (s->offset == 0) {
            if (have_header) return fail(path, "two segments map the ELF header");
            m.header = s->vaddr;
            header_filesz = s->filesz;
            have_header = 1;
        }
    }
    if (!have_header || !inside(&m, m.header, 64, 0, NULL)) return fail(path, "the ELF header is not in a read-only segment");
    /* The program header table: in the file part of the read-only segment that maps the header, and in the first
     * page, which the integrity test reads before it knows the segments */
    if (phoff > PAGE_BYTES || phnum * phentsize > PAGE_BYTES - phoff || phoff + phnum * phentsize > header_filesz)
        return fail(path, "the program header table is not in the first page of the file, in the read-only segment "
                          "that maps the ELF header: the integrity value would not cover the table the loader maps "
                          "the segments by");
    if (have_phdr && (phdr_segment.offset != phoff || phdr_segment.vaddr != m.header + phoff ||
                      phdr_segment.filesz != phnum * phentsize || phdr_segment.memsz != phdr_segment.filesz))
        return fail(path, "PT_PHDR does not name the program header table of the ELF header");
    if (!have_dynamic || m.dynamic_bytes % 16 != 0) return fail(path, "no dynamic section");
    const char *why = read_dynamic(&m);
    if (why != NULL) return fail(path, why);

    /* The record: the section .openpqc_fips_mac */
    const uint64_t strb = shoff + shstrndx * shentsize;
    const uint64_t stroff = field(&m, strb + 24, 8), strsize = field(&m, strb + 32, 8);
    if (stroff > size || strsize > size - stroff) return fail(path, "bad section name table");
    uint64_t rec_addr = 0, rec_off = 0, rec_size = 0;
    int found = 0;
    for (uint64_t i = 0; i < shnum; i++) {
        const uint64_t b = shoff + i * shentsize;
        const uint64_t name = field(&m, b, 4);
        const size_t len = sizeof RECORD_SECTION;
        if (name >= strsize || len > strsize - name || memcmp(data + stroff + name, RECORD_SECTION, len) != 0)
            continue;
        if (field(&m, b + 4, 4) != SHT_PROGBITS) return fail(path, RECORD_SECTION " is not PROGBITS");
        rec_addr = field(&m, b + 16, 8);
        rec_size = field(&m, b + 32, 8);
        found = 1;
    }
    if (!found) return fail(path, "no section " RECORD_SECTION " (not the FIPS 140-3 module)");
    if (rec_size < RECORD_BYTES || !inside(&m, rec_addr, RECORD_BYTES, 1, &rec_off))
        return fail(path, RECORD_SECTION " too small, or not in the file part of a writable segment");
    m.record_offset = rec_off;
    if (memcmp(data + rec_off, record_magic, sizeof record_magic) != 0)
        return fail(path, RECORD_SECTION " without its magic");

    /* The message: every PT_LOAD segment's covered range, in its canonical form */
    opqc_hmac_sha256_state st;
    opqc_hmac_sha256_init(&st, integrity_key, sizeof integrity_key);
    uint64_t count = 0, bytes = 0;
    for (unsigned i = 0; i < m.nseg; i++) {
        const segment *s = &m.seg[i];
        if (s->type != PT_LOAD) continue;
        const uint64_t start = page_down(s->vaddr);
        const uint64_t end = (s->flags & PF_W) != 0 ? s->vaddr + s->filesz : page_up(s->vaddr + s->filesz);
        const uint64_t first = s->offset + start - s->vaddr, n = end - start; /* its file offset, its length */
        uint8_t *copy = (uint8_t *)calloc(n > 0 ? (size_t)n : 1, 1); /* zeros past the end of the file */
        if (copy == NULL) return fail(path, "out of memory");
        memcpy(copy, data + first, (size_t)(n <= size - first ? n : size - first));
        canonical(&m, s, start, copy, n);
        uint8_t where[16];
        put_le(where, start, 8);
        put_le(where + 8, n, 8);
        opqc_hmac_sha256_absorb(&st, where, sizeof where);
        opqc_hmac_sha256_absorb(&st, copy, (size_t)n);
        free(copy);
        count++;
        bytes += n;
    }

    uint8_t record[RECORD_BYTES];
    memcpy(record, record_magic, sizeof record_magic);
    put_le(record + 16, 1, 4);
    put_le(record + 20, count, 4);
    put_le(record + 24, bytes, 8);
    if (opqc_hmac_sha256_finalize(&st, record + 32, OPQC_HMAC_SHA256_BYTES) != 0) return fail(path, "HMAC failed");

    if (print || verify) {
        for (size_t i = 0; i < RECORD_BYTES; i++) printf("%02x", data[rec_off + i]);
        printf("\n");
        if (print) return 0;
        const int ok = memcmp(data + rec_off, record, RECORD_BYTES) == 0;
        fprintf(stderr, "%s: %s: %s (%llu segments, %llu bytes)\n", program, path, ok ? "sealed" : "NOT sealed",
                (unsigned long long)count, (unsigned long long)bytes);
        return ok ? 0 : 1;
    }

    FILE *fp = fopen(path, "r+b");
    if (fp == NULL) return fail(path, "cannot open for writing");
    const int written = fseek(fp, (long)rec_off, SEEK_SET) == 0 && fwrite(record, 1, RECORD_BYTES, fp) == RECORD_BYTES;
    if (fclose(fp) != 0 || !written) return fail(path, "cannot write the record");
    printf("%s: %s: sealed, %llu segments, %llu bytes\n", program, path, (unsigned long long)count,
           (unsigned long long)bytes);
    return 0;
}

int main(int argc, char **argv)
{
    int verify = 0, print = 0;
    if (argc == 3 && strcmp(argv[1], "--verify") == 0) {
        verify = 1;
    } else if (argc == 3 && strcmp(argv[1], "--print") == 0) {
        print = 1;
    } else if (argc != 2) {
        fprintf(stderr, "usage: %s [--verify | --print] <library>\n", program);
        return 2;
    }
    const char *path = argv[argc - 1];

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) return fail(path, "cannot open");
    long end = -1;
    if (fseek(fp, 0, SEEK_END) == 0) end = ftell(fp);
    uint8_t *data = end > 0 && fseek(fp, 0, SEEK_SET) == 0 ? (uint8_t *)malloc((size_t)end) : NULL;
    const int read = data != NULL && fread(data, 1, (size_t)end, fp) == (size_t)end;
    fclose(fp);
    const int rc = read ? seal(path, data, (size_t)end, verify, print) : fail(path, "cannot read");
    free(data);
    return rc;
}
