# VexZygisk

VexZygisk is a standalone implementation of Zygisk for KernelSU, based on ReZygisk.

The codebase has been rewritten to C entirely, bringing not only a much cleaner codebase that is easier to follow, but also a lighter binaries that are also faster. Custom linkers also have been introduced to future-proof VexZygisk against future detections, not using system linker at all in normal circunstances, defeating any linker-based detection.

## Why?

The latest releases of Zygisk Next are not open-source, reserving entirely the code for its developers. Not only does that limit our ability to contribute to the project, but also impossibilities the audit of the code, which is a major security concern, as Zygisk Next is a module that runs with superuser (root) privileges, having access to the entire system.

The Zygisk Next developers are famous and trusted in the Android community, however, this doesn't mean that the code is not malicious or vulnerable. There may be good reasons to keep it closed-source, but this project takes the opposite view.

## Advantages

- FOSS (Forever)
- Zygisk Next module support

## Zygisk Next support

VexZygisk speaks the Zygisk Next API, so modules written against it — recent LSPosed builds among them — can load through it.

- Modules are listed through `zn_modules.txt`, with per-target resolution and optional companions. A companion is forked from the daemon so it keeps the daemon's privileged SELinux domain instead of the restricted domain of the process that loaded the module.
- Module libraries are handed over as memfds rather than descriptors of the files themselves, so an unprivileged target can load them without touching the module files' own mode and SELinux label.
- Zygisk and Zygisk Next modules are served side by side: a module may ship both a `zygisk/<arch>.so` and a `zn_modules.txt` (LSPosed does), and each is handled by its own path without excluding the other.

## Dependencies

| Tool            | Description                            |
|-----------------|----------------------------------------|
| `Android NDK`   | Native Development Kit for Android     |

### C Dependencies

| Dependency  | Description                   |
|-------------|-------------------------------|
| `PLTI`      | Simple PLT Hook for Android   |
| `CSOLoader` | SOTA Linux custom linker      |

## Installation

### 1. Select the right zip

The selection of the build/zip is important, as it will determine how hidden and stable VexZygisk will be. This, however, is not a hard task:

- `release` should be the one chosen for most cases, it removes app-level logging and offers more optimized binaries.
- `debug`, however, offers the opposite, with heavy logging and no optimizations, For this reason, **you should only use it for debugging purposes** and **when obtaining logs for creating an Issue**.

As for branches, you should always use the `main` branch, unless told otherwise by the developers, or if you want to test upcoming features and are aware of the risks involved.

### 2. Flash the zip

After choosing the right build, you should flash it using the KernelSU app. You can do this by going to the `Modules` section of your root manager and selecting the zip you downloaded.

After flashing, check the installation logs to ensure there are no errors, and if everything is fine, you can reboot your device.

### 3. Verify the installation

After rebooting, you can verify if VexZygisk is working properly by checking the module description in the `Modules` section of your root manager. The description should indicate that the necessary daemons are running, and it should look similar to this: `[Monitor: ✅, VexZygisk 64-bit: ✅] Standalone implementation of Zygisk.`

> [!NOTE]
> Only the Zygote matching the bitness of your device's primary ABI is injected. On 64-bit devices the secondary 32-bit Zygote is left untouched, as it is rarely used and injecting it brings no benefit; 32-bit only devices keep full support.

## Support

If something is not working, open an [Issue](https://github.com/Lxiaoyao077/VexZygisk/issues) with a log from the `debug` build attached.

## Contribution

Pull requests are welcome. Keep the existing code style and test your changes with a `debug` build before submitting.

## License

VexZygisk is licensed under [AGPL 3.0](./LICENSE). You can read more about it on [Open Source Initiative](https://opensource.org/licenses/AGPL-3.0).
