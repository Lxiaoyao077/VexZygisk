#ifndef ZN_SPAWNER_H
#define ZN_SPAWNER_H

/* INFO: What identifies HyperOS's app spawner. It lives in a header because the
         whole Zygisk Next runtime of a boot hangs off the one question it
         answers, and because two of the three answers are pure text and bytes -
         so the host test suite can hold them still (tests/host/test_zn_spawner.c)
         while the device cannot be asked.

         Getting it wrong is not a degraded feature, it is the other branch:
         entry() hands a process it does not recognise as the spawner to
         hook_functions(), and the JNI hooks are what crashed the spawner and
         left every application unable to start. So the answer is taken from two
         independent places and either one is enough:

           - the executable's own name, which is what this used to answer from
             alone. It is right whenever /proc/self/exe is readable and names the
             spawner; it is one unreadable link away from being wrong.
           - the image mapped at offset zero, which is what NyaZygisk and
             YukiZygisk (its valid_spawner_mapping) decide from. It survives a
             rename and an unreadable /proc/self/exe, and it is safe to ask in
             any process the ptracer reaches: execve replaces the address space,
             so an application that execs app_process64 no longer carries the
             spawner's image, and a process that merely forked from the spawner
             is never injected a second time.

         The image test is deliberately stricter than the name test: a mapping
         that happens to be named like the spawner is only the spawner if what is
         mapped really is an ELF for this ABI. */

#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ZN_SPAWNER_BASE_NAME "hyos_spawner"

/* INFO: The image has to be one this process could execute, and the ABI is the
         one this copy of the library was built for. `ElfW` already follows the
         ABI, so only the machine has to be spelled out. */
#if defined(__aarch64__)
  #define ZN_SPAWNER_ELF_MACHINE EM_AARCH64
#elif defined(__arm__)
  #define ZN_SPAWNER_ELF_MACHINE EM_ARM
#elif defined(__x86_64__)
  #define ZN_SPAWNER_ELF_MACHINE EM_X86_64
#else
  #define ZN_SPAWNER_ELF_MACHINE EM_NONE
#endif

/* INFO: A path whose last component is the spawner's file name, as a whole
         component: ".../bin/hyos_spawner" matches, ".../bin/xhyos_spawner" and
         ".../bin/hyos_spawner.old" do not, and neither does a bare file name
         with no directory in front of it - a real /proc/self/exe target is
         absolute. */
static inline bool zn_spawner_path_is_image(const char *path, size_t len) {
  static const char kBase[] = ZN_SPAWNER_BASE_NAME;
  const size_t base_len = sizeof(kBase) - 1;

  if (path == NULL) return false;
  if (len <= base_len) return false;
  if (path[len - base_len - 1] != '/') return false;

  return memcmp(path + len - base_len, kBase, base_len) == 0;
}

/* INFO: Whether a mapping starts with the spawner's executable header.
         `available_size` is how much of the mapping may be read, and the caller
         is responsible for the mapping being readable at all: a PROT_NONE
         mapping is in the listing and must never be dereferenced.

         The header is copied out rather than read in place - nothing promises
         the address the caller passed is aligned for ElfW(Ehdr), and the
         .gnu_debugdata path in elf_util.c went to the same trouble for the same
         reason. */
static inline bool zn_spawner_elf_is_image(const unsigned char *image, size_t available_size) {
  if (image == NULL) return false;
  if (available_size < sizeof(ElfW(Ehdr))) return false;

  ElfW(Ehdr) header;
  memcpy(&header, image, sizeof(header));

  if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) return false;
  if (header.e_ident[EI_CLASS] != (sizeof(void *) == 8 ? ELFCLASS64 : ELFCLASS32)) return false;
  if (header.e_ident[EI_DATA] != ELFDATA2LSB) return false;
  if (header.e_type != ET_DYN && header.e_type != ET_EXEC) return false;

  return header.e_machine == ZN_SPAWNER_ELF_MACHINE;
}

#endif /* ZN_SPAWNER_H */
