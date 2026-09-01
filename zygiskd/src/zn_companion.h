#ifndef ZN_COMPANION_H
#define ZN_COMPANION_H

/* INFO: Entry point of "zygiskd zn-companion <fd>", the process hosting a
         Zygisk Next module's companion on behalf of the target. */
void zn_companion_entry(int fd);

#endif /* ZN_COMPANION_H */
