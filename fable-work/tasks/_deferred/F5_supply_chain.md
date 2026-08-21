# F5 — Phase 158: supply chain & developer tooling

**Priority 5.** `ADVERSARY_ANALYSIS.md` §B7. Size: M.

Untouched by all 133 phases, and on a developer or technician workstation it is the softest
surface in the building. It is also where an MSP gets hit *through* its own staff.

## Detect

- **VS Code / Cursor / VSCodium extensions** — `~\.vscode\extensions\`, `~\.cursor\extensions\`.
  Extensions run arbitrary code at editor startup, can be sideloaded from a `.vsix` with no
  signature requirement, and nobody audits them. Flag: an extension whose `package.json` declares
  `"activationEvents": ["*"]` or `onStartupFinished` **and** ships a minified/obfuscated bundle;
  an extension directory whose publisher does not match its `publisher` field; recently installed
  extensions with network-capable dependencies.
- **`.vscode/tasks.json` with `"runOn": "folderOpen"`** — opening a repository executes it. This
  is a genuine drive-by on a developer box. Also `.vscode/settings.json` pointing
  `python.defaultInterpreterPath` or `terminal.integrated.env.*` somewhere unexpected.
- **Git hooks** — `.git\hooks\` containing anything other than the shipped `.sample` files.
  `post-checkout`, `post-merge` and `pre-commit` execute on ordinary developer actions.
- **`.gitconfig` weaponisation** — `core.fsmonitor`, `core.sshCommand`, `diff.*.textconv`,
  `filter.*.clean/smudge` and aliases beginning with `!`. Any of these execute a command on
  routine git operations, and `core.fsmonitor` fires on *every* git command.
- **Package manager install hooks** — `package.json` `preinstall`/`postinstall` in project roots,
  `setup.py` in an unexpected location, `.npmrc` pointing at a non-default registry.
- **Typosquat check** — dependency names one edit away from a very popular package. Keep this
  narrow and INFO-only; a full typosquat engine is out of scope and would be noisy.
- **MSBuild inline tasks** — `.csproj`/`.targets` containing `<UsingTask>` with inline C#.
- **Jupyter kernel specs** — `kernel.json` with an unexpected `argv[0]`.

## The false-positive problem is the whole task

A developer box has thousands of these files legitimately. Almost everything here is **INFO**.
Escalate only on a concrete malicious construct:

- a hook or task that references an encoded PowerShell command, a downloader, or a raw IP;
- an extension bundle containing an obviously exfiltrating URL (reuse the existing webhook/C2
  keys — do not invent a second copy);
- a `.gitconfig` alias or `textconv` that shells out to something outside the git toolchain.

Scope hard with `Get-ScanFiles` and prune `node_modules`, `.venv`, `site-packages` and build
output. Walking a developer's `node_modules` will blow the wall-clock budget and find nothing.

## Deliverables

Phase 158, signature keys (`devtool_paths_raw`, `devtool_hook_rules`, `devtool_benign_paths`),
tests covering the FP-heavy paths — specifically, prove that a stock `.git\hooks` directory of
`.sample` files and a normal VS Code install produce **zero** findings.
