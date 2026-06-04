# Changelog

All notable changes to this fork (poppopjmp/Noriben) are documented here.
This fork tracks upstream [Rurik/Noriben](https://github.com/Rurik/Noriben)
and adds analyst-focused features on top. Versions follow loose semantic
versioning.

## [2.4.0] - 2026-06-04

Detection-engineering exports.

### Added
- **`--gen-sigma`** — write Sigma detection rules (`*.sigma.yml`) for dropped
  executables, registry persistence, network endpoints, named pipes, and
  suspicious command lines, each tagged with MITRE ATT&CK. Includes a small
  built-in YAML emitter (no PyYAML dependency).
- **`--diff`** now also writes a self-contained **HTML diff report**
  (`*.diff.html`) alongside the in-report text diff.
- `tests/test_detection_exports.py` (11 cases). Suite total: 66 tests.

### Changed
- Suggested YARA rules now also include autostart/Run **value names**, which
  commonly appear verbatim in the binary.

## [2.3.0] - 2026-06-04

Reverse-engineer-focused sharing and comparison.

### Added
- **Named pipe & mutex extraction** from captured activity (common infection
  markers); surfaced in the summary, JSON report, and exports.
- **`--gen-yara`** — write a suggested YARA rule (`*.suggested.yar`) built from
  behavioral indicators (dropped file names, mutexes, named pipes, hosts).
- **`--diff <baseline.iocs.json>`** — show what changed between two runs
  (added/removed processes, files, hashes, registry keys, hosts, pipes,
  mutexes, and ATT&CK techniques).
- **`--stix`** — export IOCs as a STIX 2.1 bundle (`*.stix.json`).
- **`--misp`** — export IOCs as a MISP event (`*.misp.json`).
- Matching `gen_yara`, `stix_export`, `misp_export` keys in `Noriben.config`.
- `tests/test_exports.py` (11 cases). Suite total: 55 tests.

## [2.2.0] - 2026-06-04

Automated triage for reverse engineers.

### Added
- **Behavioral Summary & Indicators of Compromise** section at the top of every
  report: activity counts, dropped-file hashes, and network endpoints.
- **Heuristic MITRE ATT&CK tagging** of registry, file, and command-line
  activity (persistence, service creation, scheduled tasks, LOLBINs, recovery
  inhibition, defense evasion, etc.) with the evidence that triggered each tag.
- **`--json`** — structured, machine-readable `*.iocs.json` report (processes,
  files, registry, network, IOCs, ATT&CK) for ingestion by other tooling. The
  IOC summary is also fed to the AI analysis to ground its assessment.
- `tests/test_analysis.py` (18 cases).

### Fixed
- `open_file_with_assoc()` no longer crashes when reprocessing a CSV on Linux
  (previously called the macOS-only `open`); now uses `xdg-open`, respects
  `--headless`, and never raises.

## [2.1.0] - 2026-06-04

AI-assisted analysis and alignment with upstream through v2.0.4.

### Added
- **`--ai`** — send the generated report to any OpenAI-compatible Chat
  Completions endpoint (local Ollama, OpenAI, LM Studio, vLLM, LiteLLM) for an
  automated behavioral analysis and Benign/Suspicious/Malicious risk verdict,
  saved as `*_AI_Analysis.md`. All AI failures are non-fatal. Configurable via
  `--ai-provider` / `--ai-model` / `--ai-url` or the `[Noriben] ai_*` keys.
- **`--version`** flag.
- Project tooling: `requirements.txt`, `pyproject.toml`, `.gitignore`, unit
  tests, and GitHub Actions CI (byte-compile + pyflakes + tests on
  Python 3.8–3.12).
- `tests/test_ai_analysis.py`, `tests/test_file_handling.py`,
  `tests/test_network_parsing.py`.

### Changed
- Aligned with upstream Noriben **v2.0.1 – v2.0.4**: standard `logging`
  library, full `--cmd` command lines, non-Windows CSV reprocessing,
  `--disable-file-hash`, regular-file checks, chunked file hashing, IPv6-safe
  remote-host parsing, and updated Windows 11 PMC filters / approvelists.

### Fixed
- Python 2 `unicode()` crash in `NoribenRead.py` (decodes archive bytes on
  Python 3 instead).
- Missing `requests` module no longer clobbers the stdlib `json` module.
- Removed dead/unused variables flagged by pyflakes.
- Integration fixes for the upstream merge: added missing `import stat`;
  `--disable-file-hash` now sets the same config key `parse_csv` reads; `--pml`
  resolves Procmon before use (reference-before-set crash) while keeping
  `--csv` Procmon-free for non-Windows reprocessing.

## [2.0.0] - 2023-08 (upstream baseline)

Fork point from upstream Rurik/Noriben v2.0.0. See the changelog header in
`Noriben.py` for the full upstream history prior to this.

[2.3.0]: https://github.com/poppopjmp/Noriben/releases/tag/v2.3.0
[2.2.0]: https://github.com/poppopjmp/Noriben/releases/tag/v2.2.0
[2.1.0]: https://github.com/poppopjmp/Noriben/releases/tag/v2.1.0
