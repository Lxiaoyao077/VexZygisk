/* INFO: Some libc functions, such as memcpy, have hardware-accelerated paths,
           noticeably SIMD/NEON.

         SIMD/NEON have their own set of registers, which are caller-saved. That
           means that if a function uses them, it is expected to restore them before
           returning. However, libc functions do not restore them, and they leave
           data in them.

         To address this, we provide a function to clear these registers. To assure
           we will not leave the string data in the registers, which can be abused
           to detect VexZygisk.
*/

#ifndef REGISTERS_H
#define REGISTERS_H

#include <stddef.h>

#ifdef __aarch64__
  /* INFO: In ARM64, we clear the following registers:
             NEON: q0, q1, ..., q7 
             GPR : x6, x7, x11, x12, x13, x14, x15, x16, x17
  */
  __attribute__((always_inline))
  static inline void registers_clear(void) {
    __asm__ volatile(
      "mov x6, xzr\n"
      "mov x7, xzr\n"
      "mov x11, xzr\n"
      "mov x12, xzr\n"
      "mov x13, xzr\n"
      "mov x14, xzr\n"
      "mov x15, xzr\n"
      "mov x16, xzr\n"
      "mov x17, xzr\n"
      "movi v0.16b, #0\n"
      "movi v1.16b, #0\n"
      "movi v2.16b, #0\n"
      "movi v3.16b, #0\n"
      "movi v4.16b, #0\n"
      "movi v5.16b, #0\n"
      "movi v6.16b, #0\n"
      "movi v7.16b, #0\n"
      : : : "x6","x7","x11","x12","x13","x14","x15","x16","x17",
            "v0","v1","v2","v3","v4","v5","v6","v7"
    );
  }
#elif defined(__arm__)
  /* INFO: In ARM32, we clear the following registers:
             NEON: q0, q1, q2, q3
             GPR : r0, r1, r2, r3, r12 (ip)
  */
  __attribute__((always_inline))
  static inline void registers_clear(void) {
    __asm__ volatile(
      "mov r0, #0\n"
      "mov r1, #0\n"
      "mov r2, #0\n"
      "mov r3, #0\n"
      "mov ip, #0\n"
      "veor q0, q0, q0\n"
      "veor q1, q1, q1\n"
      "veor q2, q2, q2\n"
      "veor q3, q3, q3\n"
      "veor q8, q8, q8\n"
      "veor q9, q9, q9\n"
      "veor q10, q10, q10\n"
      "veor q11, q11, q11\n"
      "veor q12, q12, q12\n"
      "veor q13, q13, q13\n"
      "veor q14, q14, q14\n"
      "veor q15, q15, q15\n"
      : : : "r0","r1","r2","r3","ip",
            "q0","q1","q2","q3","q8","q9","q10","q11",
            "q12","q13","q14","q15"
    );
  }
#endif

#endif /* REGISTERS_H */
