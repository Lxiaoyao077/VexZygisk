/* INFO: Host-side tests for what identifies the HyperOS spawner.

         This is the one question the whole Zygisk Next runtime of a boot hangs
         off: entry() hands a process it does not recognise as the spawner to
         hook_functions(), and the JNI hooks are what crashed the spawner and left
         every application unable to start. Both answers are pure text and bytes,
         so they are held still here rather than argued about on a device -
         the device can only ever say "no runtime", after the fact.

         The header is included, not linked, so the two predicates are reachable
         without the loader around them. The ELF half is exercised for whatever
         ABI this suite is built for; what ships is the AArch64 branch of the
         same predicate, and only the two machine constants differ. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <elf.h>
#include <link.h>

#include "check.h"
#include "zn_spawner.h"

static void check_path_predicate(void) {
  static const struct {
    const char *path;
    bool want;
  } cases[] = {
    { "/system_ext/bin/hyos_spawner", true },
    { "/bin/hyos_spawner", true },
    { "/hyos_spawner", true },
    { "/system_ext/bin/hyos_spawner.bak", false },
    { "/system_ext/bin/xhyos_spawner", false },
    { "/system_ext/bin/hyos_spawnerX", false },
    { "/system_ext/bin/hyos_spawner/", false },
    { "hyos_spawner", false },
    { "/system_ext/bin/", false },
    { "", false },
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    bool got = zn_spawner_path_is_image(cases[i].path, strlen(cases[i].path));

    CHECK(got == cases[i].want, "\"%s\" answered %d, wanted %d", cases[i].path, got, cases[i].want);
  }

  CHECK(!zn_spawner_path_is_image(NULL, 32), "a NULL path was accepted");
}

/* INFO: A header that is the spawner's image: an ELF for this ABI, executable,
         little endian. Only the fields the predicate reads are set. */
static size_t make_image(unsigned char *buffer, size_t size) {
  ElfW(Ehdr) header;

  memset(&header, 0, sizeof(header));
  memcpy(header.e_ident, ELFMAG, SELFMAG);
  header.e_ident[EI_CLASS] = sizeof(void *) == 8 ? ELFCLASS64 : ELFCLASS32;
  header.e_ident[EI_DATA] = ELFDATA2LSB;
  header.e_type = ET_DYN;
  header.e_machine = ZN_SPAWNER_ELF_MACHINE;

  CHECK(size >= sizeof(header), "the fixture buffer is too small");

  memset(buffer, 0, size);
  memcpy(buffer, &header, sizeof(header));

  return sizeof(header);
}

static void set_ident(unsigned char *buffer, size_t index, unsigned char value) {
  buffer[offsetof(ElfW(Ehdr), e_ident) + index] = value;
}

static void set_u16(unsigned char *buffer, size_t offset, uint16_t value) {
  memcpy(buffer + offset, &value, sizeof(value));
}

static void check_elf_predicate(void) {
  unsigned char buffer[256];
  const size_t header_size = make_image(buffer, sizeof(buffer));

  CHECK(zn_spawner_elf_is_image(buffer, sizeof(buffer)), "a valid image was refused");
  CHECK(zn_spawner_elf_is_image(buffer, header_size), "an image of exactly one header was refused");

  CHECK(!zn_spawner_elf_is_image(NULL, sizeof(buffer)), "a NULL image was accepted");
  CHECK(!zn_spawner_elf_is_image(buffer, header_size - 1), "a truncated image was accepted");

  /* Every field the predicate reads, one at a time. */
  make_image(buffer, sizeof(buffer));
  buffer[0] = 'X';
  CHECK(!zn_spawner_elf_is_image(buffer, sizeof(buffer)), "a wrong magic was accepted");

  make_image(buffer, sizeof(buffer));
  set_ident(buffer, EI_CLASS, sizeof(void *) == 8 ? ELFCLASS32 : ELFCLASS64);
  CHECK(!zn_spawner_elf_is_image(buffer, sizeof(buffer)), "an image of the other class was accepted");

  make_image(buffer, sizeof(buffer));
  set_ident(buffer, EI_DATA, ELFDATA2MSB);
  CHECK(!zn_spawner_elf_is_image(buffer, sizeof(buffer)), "a big-endian image was accepted");

  make_image(buffer, sizeof(buffer));
  set_u16(buffer, offsetof(ElfW(Ehdr), e_type), ET_REL);
  CHECK(!zn_spawner_elf_is_image(buffer, sizeof(buffer)), "a relocatable object was accepted");

  make_image(buffer, sizeof(buffer));
  set_u16(buffer, offsetof(ElfW(Ehdr), e_type), ET_EXEC);
  CHECK(zn_spawner_elf_is_image(buffer, sizeof(buffer)), "a non-PIE executable was refused");

#if ZN_SPAWNER_ELF_MACHINE != EM_NONE
  make_image(buffer, sizeof(buffer));
  set_u16(buffer, offsetof(ElfW(Ehdr), e_machine), EM_NONE);
  CHECK(!zn_spawner_elf_is_image(buffer, sizeof(buffer)), "an image for another machine was accepted");
#endif
}

int main(void) {
  check_path_predicate();
  check_elf_predicate();

  if (g_failures == 0) {
    printf("all zn spawner checks passed\n");

    return 0;
  }

  printf("%d zn spawner check(s) failed\n", g_failures);

  return 1;
}
