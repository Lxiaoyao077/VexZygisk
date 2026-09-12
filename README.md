# VexZygisk

VexZygisk is a standalone implementation of Zygisk for KernelSU and APatch, based on ReZygisk.

The codebase has been rewritten to C entirely, bringing not only a much cleaner codebase that is easier to follow, but also lighter binaries that are also faster. Custom linkers also have been introduced to future-proof VexZygisk against future detections: standard Zygisk modules are mapped by the built-in csoloader instead of the system linker, defeating linker-based detection on that path, while Zygisk Next modules keep loading through the system linker as their contract expects.

The project builds for **one root solution at a time**: the KernelSU flavour and the APatch flavour are separate archives produced by the same CI run, and each one carries only its own backend — no traces of the other root solution ship inside.

## Why?

The latest releases of Zygisk Next are not open-source, reserving entirely the code for its developers. Not only does that limit our ability to contribute to the project, but also impossibilities the audit of the code, which is a major security concern, as Zygisk Next is a module that runs with superuser (root) privileges, having access to the entire system.

The Zygisk Next developers are famous and trusted in the Android community, however, this doesn't mean that the code is not malicious or vulnerable. There may be good reasons to keep it closed-source, but this project takes the opposite view.

## Advantages

- FOSS (Forever)
- Zygisk Next module support
- KernelSU **and** APatch support, as dedicated builds
- Denylist handled by reverting the mounts out of zygote, with the cached clean namespace as the fallback

## Root solution support

Each archive targets exactly one root solution and refuses to install from anything else:

| Archive | Root solution | Install from |
|---------|---------------|--------------|
| `VexZygisk-<ver>-release.zip` | KernelSU | KernelSU app |
| `VexZygisk-APatch-<ver>-release.zip` | APatch | APatch app |

- The KernelSU flavour talks to the KernelSU kernel interface directly (ioctl based) and requires a recent kernel and ksud.
- The APatch flavour reads the `apd` package configuration (`/data/adb/ap/package_config`) for root grants and the denylist, and recognises both the `me.bmax.apatch` and `me.yuki.folk` managers. It needs a reasonably recent APatch (`APATCH_VER_CODE >= 10762`).
- The APatch archive ships its own `sepolicy.rule` written against the `su` domain (APatch builds on magiskpolicy), while the KernelSU one uses the `ksu` domain.

## Mount handling

Revert-only is the default mount mode, and it takes two halves that have to
travel together.

The module and root mounts are reverted from zygote itself, once, before the
first app fork — the approach OnyxZygisk calls *revert only* — so every process
forked afterwards starts out unable to see them and a denylisted app needs no
namespace switch at all.

Reverting alone would also hide the mounts from the apps that are meant to keep
working, so a process that is **not** on the denylist is switched back into the
namespace captured immediately before the revert. It keeps seeing everything
the mounts carry, a metamodule's themes and overlays included. Leaving this half
out is what makes the mode look broken: every app would then run in a view that
never had the mounts.

A metamodule owns all module mounting on both KernelSU and APatch, and what it
hangs there is indistinguishable from a root trace to the selection. The
switch-back above is what covers that — not a narrower selection.

Dropping a marker next to the module falls back to the namespace-only model, in
which zygote keeps its mounts and denylisted apps are isolated through the
cached clean namespace:

```sh
touch /data/adb/rezygisk/disable-revert   # or /data/adb/modules/rezygisk/disable-revert
```

Reverting is also skipped, and the namespace fallback used instead, when an
exact `/product` mount is among the traces, which some ROMs overlay with zygote
resources. That refusal is decided once, so mountinfo is not re-parsed before
every fork.

## Zygisk Next support

VexZygisk speaks the Zygisk Next API, so modules written against it — recent LSPosed builds among them — can load through it.

- Modules are listed through `zn_modules.txt`, with per-target resolution and optional companions. A companion is forked from the daemon so it keeps the daemon's privileged SELinux domain instead of the restricted domain of the process that loaded the module.
- Module libraries are handed over as memfds rather than descriptors of the files themselves, so an unprivileged target can load them without touching the module files' own mode and SELinux label.
- Zygisk and Zygisk Next modules are served side by side: a module may ship both a `zygisk/<arch>.so` and a `zn_modules.txt` (LSPosed does), and each is handled by its own path without excluding the other.

## Dependencies

| Tool            | Description                            |
|-----------------|----------------------------------------|
| `Android NDK`   | Native Development Kit for Android     |

### C/C++ Dependencies

| Dependency        | Description                                              |
|-------------------|----------------------------------------------------------|
| `PLTI`            | Simple PLT Hook for Android, used by the injector itself |
| `LSPlt`           | PLT hooking library for Android, serves the ZN `pltHook` API |
| `Dobby`           | In-process inline hooking engine, serves the ZN `inlineHook` API |
| `CSOLoader`       | Custom ELF loader, maps standard Zygisk modules          |
| `xz-embedded`     | XZ decompression for ELF `.gnu_debugdata`                |

## Installation

### 1. Select the right zip

Two things decide which archive you need:

**Root solution** — pick the flavour matching your root manager (`VexZygisk` for KernelSU, `VexZygisk-APatch` for APatch). The installer checks the manager you are flashing from and aborts otherwise, so a mismatch cannot brick anything — it simply refuses to install.

**Build type** — `release` should be the one chosen for most cases, it removes app-level logging and offers more optimized binaries. `debug` offers the opposite, with heavy logging and no optimizations. For this reason, **you should only use it for debugging purposes** and **when obtaining logs for creating an Issue**.

As for branches, you should always use the `main` branch, unless told otherwise by the developers, or if you want to test upcoming features and are aware of the risks involved.

### 2. Flash the zip

Flash it from the matching root manager: go to the `Modules` section of the KernelSU or APatch app and select the zip you downloaded.

After flashing, check the installation logs to ensure there are no errors, and if everything is fine, you can reboot your device.

### 3. Verify the installation

After rebooting, you can verify if VexZygisk is working properly by checking the module description in the `Modules` section of your root manager. The description should indicate that the necessary daemons are running, and it should look similar to this: `[Monitor: ✅, VexZygisk 64-bit: ✅] Standalone implementation of Zygisk.`

You can also ask the tracer directly, from a root shell:

```sh
/data/adb/modules/rezygisk/bin/zygisk-ptrace64 info
```

which prints the daemon PID, the root solution in use, and the loaded modules.

> [!NOTE]
> Only the Zygote matching the bitness of your device's primary ABI is injected. On 64-bit devices the secondary 32-bit Zygote is left untouched, as it is rarely used and injecting it brings no benefit; 32-bit only devices keep full support.

## Building

The whole project builds with plain `make` (plus the NDK pointed at by `NDK_PATH`):

```sh
make all                       # KernelSU flavour: debug + release
make apatch                    # APatch flavour: release, into build-apatch/
make ROOT_IMPL=apatch release  # explicit form
```

- `ROOT_IMPL` selects the backend (`ksu`, the default, or `apatch`); both flavours build from the same sources and land in separate trees so their caches never mix.
- A CI run on `main` produces both release archives plus a generated `update.json`, and runs the host-side unit tests (`tests/host/`) that exercise the ELF reader and the mini-debug decompressor against glibc before anything is published.

## Support

If something is not working, open an [Issue](https://github.com/Lxiaoyao077/VexZygisk/issues) with a log from the `debug` build attached.

## Contribution

Pull requests are welcome. Keep the existing code style and test your changes with a `debug` build before submitting.

## Credits & Acknowledgements

This repository stands on other projects' work; the credits below map the
pieces to their sources.

* [ReZygisk](https://github.com/PerformanC/ReZygisk): The base project this repository forks and rewrites in C
* [NyaZygisk](https://github.com/HSSkyBoy/NyaZygisk): The HyperOS Runtime support (hyos_spawner interception, the runtime table, the fork and SELinux hooks that deliver `onAppSpecialized`) and the Zygisk Next fixes ported from here — symbol lookup confined to the library's own tables, `pltHook` backup semantics, the monitor's spawner handling and the upgrade-time `module.prop` guard
* [ZygiskNext](https://github.com/Dr-TSNG/ZygiskNext): The original Zygisk Next module architecture and the API VexZygisk speaks
* [ZygiskNextNext](https://github.com/VeryBaaad/ZygiskNextNext): Reference implementation for the standalone Zygisk Next API
* [Magisk](https://github.com/topjohnwu/Magisk): The foundation of modern Android root and Zygisk itself
* [OnyxZygisk](https://github.com/OnyxZygisk/OnyxZygisk): The revert-only zygote mount model, both halves — reverting the mounts out of zygote and switching a trusted process back into the root namespace captured beforehand
* [KernelSU](https://github.com/tiann/KernelSU): The kernel interface the KernelSU flavour talks to
* [APatch](https://github.com/bmax121/APatch): The kernel patch that the APatch flavour manages alongside
* [Dobby](https://github.com/LSPosed/Dobby): In-process code hooking engine behind the ZN `inlineHook` API
* [LSPlt](https://github.com/LSPosed/LSPlt): PLT hooking library behind the ZN `pltHook` API
* [PLTI](https://github.com/PerformanC/PLTI): PLT hooking used by the injector itself
* [CSOLoader](https://github.com/ThePedroo/CSOLoader): The custom ELF loader that maps standard Zygisk modules
* [xz-embedded](https://tukaani.org/xz/embedded.html): Public-domain XZ decompressor for `.gnu_debugdata`

## License

VexZygisk is licensed under [AGPL 3.0](./LICENSE). You can read more about it on [Open Source Initiative](https://opensource.org/licenses/AGPL-3.0).
