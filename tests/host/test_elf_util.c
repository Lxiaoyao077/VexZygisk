/* INFO: Host-side tests for the ELF reader.

   The loader only ever runs on a device, where a failure shows up as a module
   that silently does not load. These tests run the same code on the build host
   so a broken parse fails the build instead.

   Two inputs are used:

     - a synthetic ELF whose symbol table exists only inside a compressed
       .gnu_debugdata section, which is what a stripped system library looks
       like. Every symbol found in it comes through the mini-debug path.
     - the test binary itself, a genuine compiler output with real hash
       tables, so the ordinary lookups are covered too. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <link.h>

#include "elf_util.h"

static int g_failures = 0;

#define CHECK(condition, ...)                                              \
  do {                                                                     \
    if (!(condition)) {                                                    \
      g_failures++;                                                        \
      printf("FAIL %s:%d: ", __FILE__, __LINE__);                          \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

/* INFO: The synthetic ELF carries no program headers, so the bias stays zero
         and every symbol address is the load base plus the address stored in
         the table. */
#define SYNTHETIC_BASE 0x400000u

static void check_synthetic(const char *path) {
  printf("-- %s\n", path);

  ElfImg *img = ElfImg_create(path, (void *)(uintptr_t)SYNTHETIC_BASE);
  CHECK(img != NULL, "%s: ElfImg_create failed", path);
  if (img == NULL) return;

  /* The addresses come from the symbol table embedded in the compressed
     section, so a non-zero result means the whole chain worked: finding the
     section, decompressing it, and reading the ELF inside. */
  CHECK(getSymbAddress(img, "zygote_probe_alpha") == (ElfW(Addr))SYNTHETIC_BASE + 0x1000,
        "%s: alpha at 0x%lx", path, (unsigned long)getSymbAddress(img, "zygote_probe_alpha"));

  CHECK(getSymbAddress(img, "zygote_probe_beta") == (ElfW(Addr))SYNTHETIC_BASE + 0x2000,
        "%s: beta at 0x%lx", path, (unsigned long)getSymbAddress(img, "zygote_probe_beta"));

  CHECK(getSymbAddress(img, "zygote_probe_object") == (ElfW(Addr))SYNTHETIC_BASE + 0x3000,
        "%s: object at 0x%lx", path, (unsigned long)getSymbAddress(img, "zygote_probe_object"));

  CHECK(getSymbAddress(img, "zygote_probe_missing") == 0,
        "%s: an absent symbol must resolve to nothing", path);

  /* Symbols from the mini-debug table are merged into the same array as the
     ones from the file, and their names live in the decompressed buffer
     rather than in the mapped file, so both have to be walked here. */
  CHECK(ElfImg_load_symbols(img), "%s: load_symbols failed", path);
  if (ElfImg_load_symbols(img)) {
    CHECK(img->symtabs_count_ == 3, "%s: expected 3 symbols, got %zu", path, img->symtabs_count_);

    const char *names_seen = "";
    for (size_t i = 0; i < img->symtabs_count_; i++) {
      const char *name = getSymbName(img, img->symtabs_[i]);

      CHECK(name != NULL && name[0] != '\0', "%s: unnamed symbol at index %zu", path, i);
      if (name == NULL) continue;

      CHECK(strncmp(name, "zygote_probe_", 13) == 0, "%s: unexpected symbol %s", path, name);

      if (strstr(name, "alpha") != NULL) names_seen = "alpha";
    }

    CHECK(strcmp(names_seen, "alpha") == 0, "%s: alpha missing from the walk", path);
  }

  ElfImg_destroy(img);
}

static void check_real_binary(const char *path) {
  printf("-- %s (real binary)\n", path);

  ElfImg *img = ElfImg_create(path, (void *)(uintptr_t)0x10000000u);
  CHECK(img != NULL, "%s: ElfImg_create failed", path);
  if (img == NULL) return;

  /* A genuine compiler output exercises the hash lookups, which the
     synthetic file never reaches. */
  CHECK(getSymbAddress(img, "main") != 0, "%s: main not found", path);
  CHECK(getSymbAddress(img, "elf_util_test_symbol_does_not_exist") == 0,
        "%s: an absent symbol must resolve to nothing", path);

  ElfImg_destroy(img);
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("usage: %s <synthetic-prefix> <real-binary>\n", argv[0]);

    return 2;
  }

  char plain[4096];
  char crc[4096];

  snprintf(plain, sizeof(plain), "%s-plain.elf", argv[1]);
  snprintf(crc, sizeof(crc), "%s-crc.elf", argv[1]);

  check_synthetic(plain);

  /* Android puts a CRC32 in front of the stream and the GNU toolchain does
     not; both layouts have to resolve. */
  check_synthetic(crc);

  check_real_binary(argv[2]);

  if (g_failures == 0) {
    printf("all checks passed\n");

    return 0;
  }

  printf("%d check(s) failed\n", g_failures);

  return 1;
}
