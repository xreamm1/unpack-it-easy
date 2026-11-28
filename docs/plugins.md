# Third-party decompiler plugins

Plugins are external native executables selected explicitly in the UI. Built-in detection and decompiler routes are unchanged. UIE does not download plugins, load DLLs into its process, or search the analyzed sample's directory for plugins. Install only tools you trust: enabling a plugin authorizes an external program to run with your account's access. A checksum pins its bytes; it does not establish that the program is safe.

Put JSON manifests in `engines/plugins/` next to UIE, or `plugins/` beneath the directory selected by `UIE_ENGINES_DIR` / `TOKER_ENGINES_DIR`. A missing `enabled` field or `enabled: false` disables the manifest. Only lowercase `.json` files are read; up to 128 files of 64 KiB each. An invalid enabled manifest or duplicate ID fails listing with an error.

This is illustrative configuration for a separately installed executable, **not a bundled plugin**. Replace its path, SHA-256, extension whitelist, and literal options with values documented by your decompiler before enabling it. The zero hash deliberately cannot verify a normal executable.

```json
{
  "id": "my-decompiler",
  "name": "My installed decompiler",
  "enabled": false,
  "executable": "C:\\TrustedTools\\MyDecompiler\\decompile.exe",
  "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "extensions": ["bin"],
  "args": ["--input", "{input}", "--output", "{output}"],
  "timeout_seconds": 600
}
```

On Linux/macOS use an absolute native executable path such as `/opt/my-decompiler/decompile`. On Windows the executable must end in `.exe`. Scripts, DLLs, and common shell/interpreter launchers are rejected. Executables are never resolved through PATH. Compute the executable's SHA-256 locally (for example, Windows `Get-FileHash -Algorithm SHA256`); replacing or updating the tool requires updating the manifest's hash.

IDs contain 1–64 lowercase ASCII letters, digits, or hyphens and begin with a letter or digit. Display names are 1–128 bytes without control characters or path separators. Extensions are 1–16 lowercase ASCII letters/digits, without a leading dot; at most 32 are allowed. Input matching is case-insensitive. Unknown manifest fields are rejected. Timeout defaults to the built-in tool timeout, and must be from 1 through that timeout (currently 3600 seconds).

`args` is an array of up to 128 distinct command-line arguments, each at most 4096 bytes. It must contain `{input}` and `{output}` as complete array elements. These are the only substitutions: embedded forms such as `--out={output}`, environment expansion, shell commands, and arbitrary template expressions are unsupported. Every other element is passed literally; UIE never assembles a shell command.

UIE copies the sample to a new `plugin-work/input.<extension>` in the result directory and runs the tool with that fresh working directory, never the sample directory. `{input}` is the absolute staged file path; `{output}` is the absolute, newly created `source/` directory. The executable must read the sample as data and write recovered files below `{output}`. Exit zero means the tool completed, but UIE also requires at least one recovered regular file. Nonzero exits, cancellation, timeouts, missing output, and invalid output trees are failures; partial files and `plugin.log` remain for inspection. Retries need a fresh result directory.

`plugin-report.json` records the plugin, pinned executable hash, file count, result/error, and `functional_equivalence: false`. Output is unverified recovered text/data, never a promise of original source or a working rebuild. Post-run validation rejects links/reparse points, special files, more than 100,000 entries, and more than 512 MiB of recovered files. These are validation limits, not a filesystem sandbox or live disk quota; a trusted plugin still has the account's access. Timeout/cancellation and process resource controls are inherited from UIE's common tool runner. No network isolation is added by the plugin protocol; offline settings do not enforce a network firewall for third-party programs.

The integration API is `plugins::list() -> Result<Vec<Plugin>, String>` (public `id`, `name`, `extensions`) and `plugins::run(id, input, settings, output, cancel, events) -> Result<(), String>`. Listing validates configuration without executing or hashing installed binaries. Running re-reads enabled configuration, checks the extension and executable checksum immediately before launch, and uses the common runner. Select a plugin explicitly; do not feed the list into automatic route overrides. Install tools in a trusted location with trusted dependencies: executable pinning does not pin dynamically loaded libraries or prevent concurrent replacement by another process.
