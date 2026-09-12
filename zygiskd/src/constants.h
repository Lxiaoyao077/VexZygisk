#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stdbool.h>
#include <stdint.h>

#define PROCESS_NAME_MAX_LEN (256 + 1)

#define ZYGOTE_INJECTED LP_SELECT(5, 4)
#define DAEMON_SET_INFO LP_SELECT(7, 6)

/* INFO: Plain macros rather than a typed enum: 1u << 31 does not fit an int,
         and a fixed underlying type is a C23 extension. */
#define PROCESS_GRANTED_ROOT (1u << 0)
#define PROCESS_ON_DENYLIST (1u << 1)
/* INFO: Tells the loader whether any Zygisk Next module exists at all, so a
         device without one can skip the per-fork ReadZnModules round trip
         entirely. It is a global fact from the last module load, not
         per-process, and never reaches modules (the loader strips it). */
#define PROCESS_ZN_PRESENT (1u << 2)
#define PROCESS_IS_MANAGER (1u << 27)
#define PROCESS_ROOT_IS_APATCH (1u << 28)
#define PROCESS_ROOT_IS_KSU (1u << 29)
#define PROCESS_IS_FIRST_STARTED (1u << 31)

enum DaemonSocketAction {
  ZygoteInjected         = 0,
  GetProcessFlags        = 1,
  GetInfo                = 2,
  ReadModules            = 3,
  RequestCompanionSocket = 4,
  GetModuleDir           = 5,
  ZygoteRestart          = 6,
  UpdateMountNamespace   = 7,
  RemoveModule           = 8,
  ReadZnModules          = 9,
  SpawnZnCompanion       = 10
};

enum RootImplState {
  Supported,
  TooOld,
  Inexistent,
  Abnormal
};

/* INFO: The two namespaces the loader can ask for. Clean is what a denylisted
         process switches into when the mounts could not be taken out of the
         zygote; Root is the zygote's own view, captured while a revert-only
         zygote still has them, and what a trusted process switches back into
         to regain them. */
enum MountNamespaceState {
  Clean,
  Root
};

#endif /* CONSTANTS_H */
