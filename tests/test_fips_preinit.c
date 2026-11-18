/*
 * Copyright (c) The OpenPQC project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * test_fips_preinit.c -- the FIPS 140-3 module's services called before its constructor has run: the test
 * fips_preinit (tests/fips_preinit.cmake)
 *
 * The program's DT_PREINIT_ARRAY runs before the initialization functions of every shared object (the ELF gABI,
 * "Initialization and Termination Functions"), so the module's constructor has not run its power-on self-tests yet
 * when the function below calls openpqc_fips_status() and openpqc_kem_keygen(). The module's once-guard
 * (opqc_fips_check, Core/opqc_fips.h) must run the self-tests then, before any service runs, and the result must
 * be the same as through the constructor:
 *
 *   test_fips_preinit operational   the module as built: at preinit, openpqc_fips_status() is 0 and an ML-KEM-768
 *                                   key pair is made; in main, encapsulation and decapsulation with it agree, and
 *                                   the module is still operational
 *   test_fips_preinit error         a copy of the module that fails its integrity test (found first through
 *                                   LD_LIBRARY_PATH, set by the test): at preinit, openpqc_fips_status() is -12 and
 *                                   key generation returns -12 without writing; in main, too
 *   test_fips_preinit tampered      the module as built, with one pointer of its relocated read-only data (an
 *                                   R_X86_64_RELATIVE slot in PT_GNU_RELRO, found through its own relocation table)
 *                                   changed in memory before the self-tests run, and restored after them: the
 *                                   integrity test checks the loaded image, so the result is that of "error"
 *
 * (A self-test broken through the test library's environment variable cannot be used here: glibc has not set
 * environ yet when it runs the preinit functions, so getenv() sees nothing.) The program prints the path of the
 * module it runs with: the one loaded object whose file name begins with the module's, libopenpqc.so (the test runs
 * the program with a copy under the module's SONAME). It does not find the module through the address of one of
 * the module's functions taken here: in a program that is not position-independent (an ELF executable of type
 * EXEC, which some compilers link by default), that address is the program's own PLT entry for the function.
 * Exit status 0 if every check holds, 1 otherwise.
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* dl_iterate_phdr */
#endif

#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "openpqc/openpqc.h"

static int pre_ran, pre_status = 99, pre_keygen = 99, pre_indicator = 99, pre_untouched;
static uint8_t pk[OPENPQC_MLKEM768_PUBLICKEYBYTES], sk[OPENPQC_MLKEM768_SECRETKEYBYTES];

static int all(const uint8_t *p, size_t n, uint8_t v)
{
    for (size_t i = 0; i < n; i++)
        if (p[i] != v) return 0;
    return 1;
}

/* The module among the loaded objects: the one whose file name (after the last '/') begins with "libopenpqc.so" */
static int is_module(const char *path)
{
    static const char name[] = "libopenpqc.so";
    if (path == NULL) return 0;
    const char *slash = strrchr(path, '/');
    return strncmp(slash != NULL ? slash + 1 : path, name, sizeof name - 1) == 0;
}

typedef struct {
    int count;        /* loaded objects that are the module */
    const char *name; /* the last one's file */
} module_search;

static int find_module(struct dl_phdr_info *info, size_t size, void *data)
{
    module_search *f = (module_search *)data;
    (void)size;
    if (is_module(info->dlpi_name)) {
        f->count++;
        f->name = info->dlpi_name;
    }
    return 0;
}

/* An R_X86_64_RELATIVE slot of the module inside its PT_GNU_RELRO range, from its relocation table as loaded */
typedef struct {
    uintptr_t slot;     /* the slot found, 0 if none */
    uintptr_t relro[2]; /* PT_GNU_RELRO, as loaded */
} slot_search;

static int find_slot(struct dl_phdr_info *info, size_t size, void *data)
{
    slot_search *f = (slot_search *)data;
    (void)size;
    if (!is_module(info->dlpi_name)) return 0;
    const uintptr_t base = (uintptr_t)info->dlpi_addr;
    const ElfW(Dyn) *dyn = NULL;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        const uintptr_t start = base + (uintptr_t)ph->p_vaddr;
        if (ph->p_type == PT_DYNAMIC) dyn = (const ElfW(Dyn) *)start;
        if (ph->p_type == PT_GNU_RELRO) {
            f->relro[0] = start;
            f->relro[1] = start + (uintptr_t)ph->p_memsz;
        }
    }
    if (dyn == NULL) return 0;
    uintptr_t rela = 0;
    size_t bytes = 0;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_RELA) rela = (uintptr_t)dyn->d_un.d_ptr >= base ? (uintptr_t)dyn->d_un.d_ptr
                                                                           : base + (uintptr_t)dyn->d_un.d_ptr;
        if (dyn->d_tag == DT_RELASZ) bytes = (size_t)dyn->d_un.d_val;
    }
    const ElfW(Rela) *r = (const ElfW(Rela) *)rela;
    for (size_t i = 0; rela != 0 && i < bytes / sizeof *r; i++) {
        const uintptr_t at = base + (uintptr_t)r[i].r_offset;
        if (ELF64_R_TYPE(r[i].r_info) == R_X86_64_RELATIVE && at >= f->relro[0] && at + 8 <= f->relro[1]) {
            f->slot = at; /* the last one: in .data.rel.ro, past .init_array and .fini_array */
        }
    }
    return 1;
}

static int pre_tampered;

/* Changes one relocated pointer of the module in memory, runs the self-tests, and puts the pointer back */
static int status_with_tampered_image(void)
{
    slot_search f;
    memset(&f, 0, sizeof f);
    (void)dl_iterate_phdr(find_slot, &f);
    if (f.slot == 0) return 99;
    /* the slot is 8-byte aligned, so in one page; the loader made the pages of PT_GNU_RELRO up to its last page
     * boundary read-only, and left the rest writable */
    const uintptr_t page = (uintptr_t)sysconf(_SC_PAGESIZE);
    const uintptr_t first = f.slot & ~(page - 1);
    const int read_only = first + page <= (f.relro[1] & ~(page - 1));
    if (mprotect((void *)first, page, PROT_READ | PROT_WRITE) != 0) return 98;
    uint64_t value;
    memcpy(&value, (const void *)f.slot, sizeof value);
    const uint64_t changed = value + 16;
    memcpy((void *)f.slot, &changed, sizeof changed);
    const int st = openpqc_fips_status(); /* the power-on self-tests, through the once-guard */
    memcpy((void *)f.slot, &value, sizeof value);
    if (read_only) (void)mprotect((void *)first, page, PROT_READ);
    pre_tampered = 1;
    return st;
}

static void before_constructors(int argc, char **argv, char **envp)
{
    (void)envp;
    pre_ran = 1;
    pre_indicator = openpqc_fips_service_approved(); /* no service yet on this thread */
    if (argc == 2 && strcmp(argv[1], "tampered") == 0) {
        pre_status = status_with_tampered_image();
    } else {
        pre_status = openpqc_fips_status(); /* runs the power-on self-tests through the once-guard */
    }
    memset(pk, 0xA5, sizeof pk);
    memset(sk, 0xA5, sizeof sk);
    pre_keygen = openpqc_kem_keygen(OPENPQC_ML_KEM_768, pk, sk);
    pre_untouched = all(pk, sizeof pk, 0xA5) && all(sk, sizeof sk, 0xA5);
}

__attribute__((used, section(".preinit_array"))) static void (*const preinit_entry)(int, char **,
                                                                                     char **) = before_constructors;

int main(int argc, char **argv)
{
    const int tampered = argc == 2 && strcmp(argv[1], "tampered") == 0;
    const int expect_error = tampered || (argc == 2 && strcmp(argv[1], "error") == 0);
    if (argc != 2 || (!expect_error && strcmp(argv[1], "operational") != 0)) {
        fprintf(stderr, "usage: test_fips_preinit operational|error|tampered\n");
        return 2;
    }
    module_search found;
    memset(&found, 0, sizeof found);
    (void)dl_iterate_phdr(find_module, &found);
    printf("module: %s\n", found.count == 1 ? found.name : "?");
    int failures = 0;
#define CHECK(ok, what)                                                                                        \
    do {                                                                                                       \
        const int ok_ = (ok);                                                                                  \
        printf("%s %s\n", ok_ ? "ok  " : "FAIL", what);                                                        \
        failures += !ok_;                                                                                      \
    } while (0)
    printf("at preinit: ran %d, indicator %d, openpqc_fips_status %d, openpqc_kem_keygen %d\n", pre_ran,
           pre_indicator, pre_status, pre_keygen);
    CHECK(found.count == 1, "one loaded object is the module");
    CHECK(pre_ran, "the program's preinit function ran");
    CHECK(pre_indicator == 0, "the indicator before any service is 0");
    if (tampered) CHECK(pre_tampered, "a relocated pointer of the module was changed in memory, and restored");
    if (!expect_error) {
        CHECK(pre_status == 0, "at preinit, the self-tests ran and passed: openpqc_fips_status() == 0");
        CHECK(pre_keygen == OPENPQC_OK, "at preinit, ML-KEM-768 key generation works");
        uint8_t ct[OPENPQC_MLKEM768_CIPHERTEXTBYTES], k1[OPENPQC_MLKEM_BYTES], k2[OPENPQC_MLKEM_BYTES];
        CHECK(openpqc_kem_encaps(OPENPQC_ML_KEM_768, ct, k1, pk) == OPENPQC_OK &&
                      openpqc_kem_decaps(OPENPQC_ML_KEM_768, k2, ct, sk) == OPENPQC_OK && memcmp(k1, k2, sizeof k1) == 0,
              "in main, the key pair made at preinit works");
        CHECK(openpqc_fips_status() == 0, "in main, still operational");
    } else {
        CHECK(pre_status == OPENPQC_ERR_ERROR_STATE,
              "at preinit, the self-tests ran and one failed: openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE");
        CHECK(pre_keygen == OPENPQC_ERR_ERROR_STATE && pre_untouched,
              "at preinit, key generation returns -12 and writes nothing");
        CHECK(openpqc_fips_status() == OPENPQC_ERR_ERROR_STATE, "in main, still in the error state");
        memset(pk, 0xA5, sizeof pk);
        memset(sk, 0xA5, sizeof sk);
        CHECK(openpqc_kem_keygen(OPENPQC_ML_KEM_768, pk, sk) == OPENPQC_ERR_ERROR_STATE &&
                      all(pk, sizeof pk, 0xA5) && all(sk, sizeof sk, 0xA5),
              "in main, key generation returns -12 and writes nothing");
    }
    printf("%d failed\n", failures);
    return failures != 0;
}
