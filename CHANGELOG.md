# Changelog

All notable changes to this fork (poppopjmp/Noriben) are documented here.
This fork tracks upstream [Rurik/Noriben](https://github.com/Rurik/Noriben)
and adds analyst-focused features on top. Versions follow loose semantic
versioning.

## [3.2.2] - 2026-06-04

### Fixed
- **Corrupted timeline CSV when reprocessing a PML (`--pml`).** `parse_csv()`
  builds the timeline as pre-formatted CSV row strings, but that path passed
  them to `csv.writerows()`, which treats each string as an iterable of
  characters — producing one column per character instead of a usable timeline.
  All three output paths now share a single `write_timeline()` helper so they
  cannot diverge again, with a round-trip test asserting the output parses back
  to the expected columns.

## [3.2.1] - 2026-06-04

Performance and robustness hardening.

### Performance
- Approvelist filters are now environment-expanded and compiled **once and
  cached**, instead of on every (event, filter) pair. Filtering is ~**4x
  faster** (~60s → ~14s of filter time on a 100k-event capture). Output was
  verified byte-identical to the previous implementation across a differential
  test of the shipped filter lists.

### Fixed
- A failure in the analytics or export layer could abort `parse_csv()` and lose
  the **primary text report** — the one irreplaceable output. Analytics and
  every exporter are now individually fail-safe and degrade to the raw event
  report, with the error surfaced to the user.
- Extracted IOCs (URLs, public IPv4 addresses, cryptocurrency wallets, e-mail
  addresses) were missing from `--diff` and `--merge`, so a **changed C2 URL or
  ransom wallet did not show up** when comparing samples. They are now first
  class in both.

### Changed
- The diff category/label list is defined once and shared by the text and HTML
  renderers (they had been duplicated, which is how the gap above appeared). A
  test now asserts the two can never drift apart.
- `tests/test_robustness.py` and `tests/test_ioc_coverage.py` added.
  Suite total: 139 tests.

## [3.2.0] - 2026-06-04

Usability & sharing.

### Added
- **`--md`** — write a clean Markdown report (`*.report.md`) for tickets, wikis,
  and pull requests (verdict, classification, ATT&CK by tactic, IOCs, tree).
- **`--selftest`** — validate the analysis engine against a synthetic sample
  (no Procmon needed) for a quick install/health check; now also run in CI,
  including a console-script (`noriben`) smoke test.
- **`--merge`** now also emits a consolidated ATT&CK Navigator layer
  (`Noriben_consolidated.navigator.json`) showing technique frequency across
  runs.
- `tests/test_reporting.py` (5 cases). Suite total: 122 tests.

## [3.1.0] - 2026-06-04

Answers "what is it?" alongside "is it bad?".

### Added
- **Threat classification** — a deterministic best guess at the malware
  category (Ransomware, Downloader/Dropper, Backdoor/RAT, Infostealer, Worm,
  Cryptominer, Wiper) from the observed ATT&CK techniques and indicators, shown
  next to the verdict and in the JSON/HTML.
- **Automatic IOC enrichment** — extracts URLs, public IPv4 addresses,
  Bitcoin/Ethereum wallet addresses, and e-mail addresses from command lines,
  registry data, file paths, and network activity. Surfaced in the report,
  JSON (`enriched_iocs` + `iocs.*`), HTML dashboard, and MISP export.
- `tests/test_classification.py` (10 cases). Suite total: 117 tests.

## [3.0.2] - 2026-06-04

### Added
- **`--navigator`** — export a MITRE ATT&CK Navigator layer (`*.navigator.json`)
  that can be loaded directly in the official ATT&CK Navigator to visualize the
  run's technique coverage on the matrix (techniques scored by evidence count).
- `tests/test_navigator.py` (5 cases). Suite total: 107 tests.

## [3.0.1] - 2026-06-04

Much broader MITRE ATT&CK mapping.

### Added
- Greatly expanded behavioral ATT&CK heuristics across **Execution,
  Persistence, Privilege Escalation, Defense Evasion, Credential Access,
  Discovery, Lateral Movement, Collection, Command and Control, and Impact**.
- Every detected technique now carries its **tactic**.
- New **"ATT&CK Coverage by Tactic"** report section, an `attack_by_tactic`
  grouping in the JSON report, and a tactic column in the HTML dashboard.
- Risk scoring extended to weight credential access, destructive impact,
  lateral movement, exfiltration, privilege escalation, and reconnaissance.
- `tests/test_attack_map.py` (16 cases). Suite total: 102 tests.

### Fixed
- Several command-line rules used a leading `\b` before `-`/`/` flags (which can
  never match), so e.g. `certutil -urlcache`, `bitsadmin /transfer`,
  `net user /add`, and `taskkill /im` were missed. Now detected.

## [3.0.0] - 2026-06-04

Major release — make a clear call on a sample at a glance.

### Added
- **Deterministic verdict & risk-scoring engine** — an explainable
  Malicious / Suspicious / Likely-Benign call with a 0–100 score, a confidence
  level, and the list of contributing reasons. Computed offline from the
  observed behavior and ATT&CK techniques (no AI required). Shown as a banner
  at the top of every report and included in the JSON report.
- **Process tree** reconstruction (parent → child) in the text report and JSON.
- **`--html`** — a single-file HTML dashboard with the verdict, ATT&CK
  techniques, IOCs, process tree, and activity tables for easy reading and
  sharing.
- `tests/test_verdict.py` (12 cases). Suite total: 86 tests.

### Notes
- Fully backward compatible: all 2.x outputs and flags are unchanged; the new
  verdict/tree are additive and `build_json_report()` keeps working for callers
  that don't pass them.

## [2.5.0] - 2026-06-04

Consolidated multi-run analysis.

### Added
- **`--merge`** — aggregate several `*.iocs.json` reports (files, globs, or a
  folder) into one summary that highlights which IOCs and ATT&CK techniques are
  **shared across runs** vs. unique to a sample (useful for profiling a malware
  family). Writes `Noriben_consolidated.{txt,json,html}`.
- `tests/test_consolidate.py` (8 cases). Suite total: 74 tests.

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
