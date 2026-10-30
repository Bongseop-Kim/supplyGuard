# Open-source SBOM/SCA tooling and demo targets (as of 2026-10-30)

Method note: versions, licenses, release dates and repo metadata below come from live GitHub API (`gh api repos/<r>/releases/latest`, `gh api repos/<r>`) and `brew info` queries run on 2026-10-30. Items marked **[unverified]** come from prior knowledge and were not confirmed against a fetched source in this session. None of the tools are installed on the local machine yet (`which` returned not found for all five).

## 1. Tool facts: Syft, Grype, OSV-Scanner v2, Trivy, cdxgen, Dependency-Track

### Takeaway
All candidates are Apache-2.0 and actively maintained, with releases in October 2026. For an agent that has to prioritize findings, **Grype** gives the most built-in signal: EPSS, KEV, a composite risk score and `--sort-by risk`. **OSV-Scanner v2** is the only one with built-in automated fixes (`osv-scanner fix`, npm/Maven, experimental). A practical stack is Syft (SBOM) → Grype (scan and prioritize) → OSV-Scanner (cross-check plus `fix` for npm), with Trivy as an optional second opinion pinned to a known-good version.

### Cited Findings

**Versions / license / install (live data, 2026-10-30)**
| Tool | Latest GitHub release | Date | Homebrew stable | License |
|---|---|---|---|---|
| Syft | v1.55.0 | 2026-10-19 | 1.55.0 | Apache-2.0 |
| Grype | v0.121.0 | 2026-10-19 | 0.121.0 | Apache-2.0 |
| OSV-Scanner | v2.7.0 | 2026-10-12 | 2.7.0 | Apache-2.0 |
| Trivy | v0.76.1 | 2026-10-21 | 0.76.1 | Apache-2.0 |
| cdxgen | v13.5.0 | 2026-10-23 | **12.9.0 (Homebrew lags one major)** | Apache-2.0 |
| Dependency-Track | 5.2.1 | 2026-10-25 | n/a (Docker server) | Apache-2.0 |
Sources: https://github.com/anchore/syft/releases, https://github.com/anchore/grype/releases, https://github.com/google/osv-scanner/releases, https://github.com/aquasecurity/trivy/releases, https://github.com/CycloneDX/cdxgen/releases, https://github.com/DependencyTrack/dependency-track/releases (queried via GitHub API); Homebrew formulae via `brew info`.

**Syft**
- Installs via a curl script (`get.anchore.io/syft`), Homebrew, Docker, Scoop, Chocolatey or Nix. Catalogs Alpine apk, dpkg, RPM, Go, Python, Java, JavaScript, Ruby, Rust, PHP and .NET packages ("many more"). Scans images (OCI/Docker/Singularity), filesystems and archives. Outputs CycloneDX, SPDX and Syft JSON, can convert between formats, and can produce in-toto signed attestations — [anchore/syft README](https://github.com/anchore/syft)
- Format versions: CycloneDX 1.2–1.6 selectable with `@version` (JSON/XML), and SPDX 2.2/2.3 JSON and tag-value, with SPDX 2.3 as the default — **[unverified; README did not list versions]**. See https://oss.anchore.com/docs/ for the format reference.

**Grype**
- Installs via curl script, Homebrew, Docker, Chocolatey or MacPorts. Inputs are images, directories and SBOMs (`grype sbom:./sbom.json` or stdin). The README advertises "threat and risk prioritization using EPSS, KEV, and risk scoring" and OpenVEX support — [anchore/grype README](https://github.com/anchore/grype)
- Table columns are NAME, INSTALLED, FIXED-IN, TYPE, VULNERABILITY, SEVERITY, EPSS and RISK, and the annotations column shows KEV. JSON match types are `exact-direct-match`, `exact-indirect-match` and `cpe-match`; the docs say `cpe-match` needs verification. A KEV listing is treated as maximum threat and overrides EPSS. The default sort is risk-based — [Understanding Grype results](https://oss.anchore.com/docs/guides/vulnerability/interpreting-results/)
- Data sources: GitHub Security Advisories (language ecosystems), NVD (CVE metadata), CISA KEV, EPSS, and the Alpine, Debian, Ubuntu, RHEL, SUSE, ALAS and ELSA distribution feeds — [same page](https://oss.anchore.com/docs/guides/vulnerability/interpreting-results/)
- Config: `sort-by` takes `package|severity|epss|risk|kev|vulnerability`. Output formats are `table|template|json|cyclonedx`. Other options: `only-fixed`, `only-notfixed`, `ignore-wontfix`, `fail-on-severity` (exit 1). DB settings: `auto-update: true`, `validate-age: true`, `max-allowed-built-age: 120h` (a scan refuses a DB older than 5 days), `update-url: https://grype.anchore.io/databases`, `cache-dir: ~/.cache/grype/db`, `max-update-check-frequency: 2h` — [Grype configuration reference](https://oss.anchore.com/docs/reference/grype/configuration/)
- Exact JSON key names for the EPSS, KEV and risk values were not in the fetched docs. A community post shows `epss` and `percentile` values in `grype db search vuln` output — [Anchore community discourse](https://anchorecommunity.discourse.group/t/another-look-at-grype-new-features/481). **Gap:** confirm the exact JSON paths by running `grype -o json` and inspecting the output (likely `matches[].vulnerability.{severity,cvss[],fix.versions,fix.state,epss[],knownExploited[]}` and `matches[].vulnerability.risk` — **[unverified]**).
- Offline use: `grype db import <archive>` with `auto-update: false` **[the import command is unverified in fetched docs; the config keys are verified]**.

**OSV-Scanner v2**
- Release history: v2.3.2 (Jan 15) added bun.lock support. v2.3.3 (Feb 12) added Python `pylock` and `--exclude`. v2.3.5 (Mar 25) added transitive scanning of `requirements.txt` through the deps.dev API. v2.4.0 (Jun 18) added **CycloneDX 1.7**. v2.6.0 (Sep 14) added a license-violation filter to the HTML report and secured guided-remediation file operations (via osv-scalibr). v2.7.0 (Oct 12) added severity and ratings to CycloneDX output and purls in JSON, and fixed `--offline` with `--download-offline-databases` — [osv-scanner releases](https://github.com/google/osv-scanner/releases). The release-page dates show only day and month; the year 2026 is inferred from the latest-release API date of 2026-10-12.
- Uses osv.dev as its data source. osv.dev aggregates GHSA, PyPA, the Go vuln DB, RustSec and others **[well known; not re-fetched]**. EPSS and KEV are not mentioned in the v2.3–v2.7 release notes — [releases](https://github.com/google/osv-scanner/releases). Plan to enrich OSV findings with EPSS/KEV yourself (FIRST EPSS API, CISA KEV JSON).
- Offline: `--offline-vulnerabilities` / `--download-offline-databases` (local DB zip per ecosystem) — [releases v2.5.1/v2.7.0](https://github.com/google/osv-scanner/releases)

**Trivy**
- Language-package advisory sources: npm uses the Node.js Ecosystem Security WG plus GHSA. pip uses GHSA. Maven uses GHSA. Go uses GHSA plus the Go vuln DB. Rust uses OSV. C/C++ uses the GitLab Advisories Community feed with a one-month delay. Severity comes from the vendor first, then a CVSS mapping, then an NVD fallback, and `--vuln-severity-source` overrides the order. The vulnerability-scanner docs do not mention EPSS or KEV — [Trivy vulnerability scanner docs](https://trivy.dev/latest/docs/scanner/vulnerability/)
- DBs: `trivy-db`, `trivy-java-db` and `trivy-checks`, pulled as OCI artifacts from `mirror.gcr.io/aquasec` first and then `ghcr.io/aquasecurity`. Flags: `--skip-db-update`, `--skip-java-db-update`, `--db-repository` (several values allowed for fallback), and `trivy clean --vuln-db` — [Trivy DB docs](https://trivy.dev/latest/docs/configuration/db/)
- JSON fields include `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Status`, `Severity`, `CVSS{nvd,ghsa,...}` and `PrimaryURL`. SBOM output is CycloneDX (1.6) and SPDX (2.3) **[unverified; from prior knowledge]**.

**cdxgen**
- Installs via standalone executables (recommended for CI), `brew install cdxgen`, the `ghcr.io/cdxgen/cdxgen` container, or npm. **v13 renamed the npm package to `@cdxgen/cdxgen`** (it was `@cyclonedx/cdxgen`). **The npm, pnpm, bun, Deno and library installs require Node.js >= 24.** Generates CycloneDX 1.6, 1.7 (default) and 2.0, and can downgrade to 1.4/1.5. Exports SPDX 3.0.1 JSON-LD. `--evidence`, `--profile appsec` and `evinse` add reachability and evidence data, and Node.js projects get babel AST "required" usage detection. Has a `--server` mode on port 9090 and a `--bom-audit` option. Supports Java, JS/TS, Python, C, Go, PHP, .NET, Ruby, Rust, Scala, Deno, Bun and containers — [CycloneDX/cdxgen README](https://github.com/CycloneDX/cdxgen)
- The local environment has Node 22, so the npm install will not work. Use the standalone binary or the Docker image. Homebrew only has 12.9.0, which is behind v13.5.0 (`brew info`, 2026-10-30).

**Dependency-Track**
- Latest is 5.2.1 (2026-10-25), Apache-2.0 (GitHub API). It is a server platform (Docker Compose) that ingests CycloneDX SBOMs and correlates them against NVD, GHSA, OSV and others. It supports EPSS **[unverified for v5]**. It is too heavy for a local CLI demo; at most, cite it as an optional dashboard.

### Inferences
- Grype's `risk` sort plus KEV/EPSS gives the agent a deterministic baseline ranking. The LLM can then explain or reorder that ranking instead of inventing scores.
- Feed Grype the Syft SBOM rather than letting it rescan the directory. That gives a reproducible SBOM → scan step and matches the pipeline narrative.
- Running OSV-Scanner alongside Grype shows scanner disagreement, which the literature in section 3 documents, and its `fix` command gives a non-LLM baseline to compare against the LLM remediation plan.
- Grype's 5-day DB-age guard means demos have to refresh the DB or turn off `validate-age` when running offline. Plan a "freeze DB snapshot" step so demo runs are reproducible:
  - Disable auto-update for pinned runs: `GRYPE_DB_AUTO_UPDATE=false` (config `db.auto-update: false`); import a saved archive with `grype db import <archive>`.
  - Record DB provenance per run: `grype db status -o json` (schema version, build/creation timestamp, checksum) stored with the scan output.
  - Age check when auto-update is off or offline: compare the recorded build timestamp with the run time; with `validate-age` on (default max 120h) Grype refuses stale DBs, so for intentionally frozen snapshots set `GRYPE_DB_VALIDATE_AGE=false` and instead log the computed DB age in the run record and flag runs whose DB age exceeds policy.
  - Confirm JSON keys locally before parsing: `grype <target> -o json | jq '.matches[0].vulnerability'` (risk, EPSS, KEV field paths). (Env var/flag names to be verified against `grype --help` / config docs for the installed version.)

### Gaps
- Exact Grype JSON key names for risk, EPSS and KEV need to be confirmed locally (`grype <target> -o json | jq '.matches[0].vulnerability'`).
- Syft and Trivy SBOM spec versions were not confirmed from fetched docs.
- Whether Trivy 0.76 added EPSS/KEV enrichment was not confirmed. The fetched docs do not mention it.

## 2. OSV-Scanner guided remediation (`osv-scanner fix`)

### Takeaway
`osv-scanner fix` computes and applies dependency upgrades to fix vulnerabilities in **npm (package.json and package-lock.json) and Maven (pom.xml) only**, with no PyPI support. It has a non-interactive mode with stable JSON output, so the agent can use it as a fix oracle. It is labelled experimental.

### Cited Findings
- The feature is experimental and "might change or be removed with only a minor version update" — [Guided remediation docs](https://google.github.io/osv-scanner/experimental/guided-remediation/)
- Strategies:
  - **in-place** replaces vulnerable versions in the npm lockfile while respecting existing constraints. It is lower risk but fixes fewer issues.
  - **relax/relock** re-resolves from the manifest and bumps direct dependency constraints. It fixes more but can break more.
  - **override** forces versions through Maven `<dependencyManagement>`. It is available non-interactively and for Maven only.
  — [same](https://google.github.io/osv-scanner/experimental/guided-remediation/)
- Flags:
  - Filters: `--min-severity` (CVSS), `--max-depth`, `--upgrade-config` (major/minor/patch/none, globally or per package; default major), `--ignore-dev`, `--vulns`, `--ignore-vulns`, `--no-introduce`, `--data-source=native`
  - Non-interactive runs: `--strategy`, `-M` (manifest), `-L` (lockfile), `--apply-top=<n>`
  - Output: `--format=json`, which the docs describe as stable for automation
  - `--interactive` (TUI) works for npm only
  — [same](https://google.github.io/osv-scanner/experimental/guided-remediation/)
- Limits:
  - It ignores `osv-scanner.toml`.
  - npm: it does not evaluate non-registry dependencies (git, path, URL), treats peerDependencies as if `--legacy-peer-deps` were set, ignores `overrides`, and only partly supports workspaces.
  - Maven: profile support is limited, property-based groupId/artifactId may not update correctly, and encrypted settings.xml values are not supported.
  - It edits manifests and lockfiles but does not reinstall. You must run `npm ci` or `npm install` afterwards.
  - It can trigger package-manager scripts and registry access, so use caution on untrusted projects.
  — [same](https://google.github.io/osv-scanner/experimental/guided-remediation/)
- v2.6.0 hardened the guided-remediation file operations — [releases](https://github.com/google/osv-scanner/releases)

### Inferences
- This is a strong reason to pick **npm** as the demo ecosystem. The agent can call `osv-scanner fix --strategy=in-place --format=json` to get candidate patches, have the LLM review them for breaking-change risk (major bumps, changelogs), apply them, then run `npm ci && npm test` and rescan.
- "LLM vs osv-scanner fix" makes a good evaluation axis for the portfolio: fixed-vuln count, number of major bumps, and test pass rate.
- Because `fix` can run lifecycle scripts, run it in a Docker container or with `npm ci --ignore-scripts`.

### Gaps
- No source confirmed PyPI or uv support in guided remediation. Assume it is absent.

## 3. Published comparisons of SBOM/SCA tool accuracy and disagreement

### Takeaway
The literature consistently finds that SBOM generators and SCA scanners disagree substantially on the same project. Studies attribute the disagreement to package identification (purl/CPE), manifest-vs-lockfile ambiguity, and advisory-database differences. A multi-scanner cross-check with lockfile-based input is therefore justified and gives the demo a story to tell.

### Cited Findings
- **Imtiaz, Thorn, Williams (ESEM 2021)** compared 9 SCA tools on OpenMRS (Maven and npm). Vulnerability counts varied widely, the authors found database accuracy to be the key differentiator, and they recommend against relying on a single tool — [arXiv 2108.12078](https://arxiv.org/abs/2108.12078)
- **Zhao et al. (ESEC/FSE 2023)** evaluated 6 SCA tools on 21,130 Maven modules. Proper scan-mode support cut false positives by 18.28% and false negatives by 8.72% — [SMU InK record](https://ink.library.smu.edu.sg/sis_research/9317) (via search summary; not fully fetched)
- **Benedetti, Cofano, Brighente, Conti (arXiv 2409.06390, Sep 2024)** studied Python SBOM generators. State-of-the-art generators "cannot provide sbom accurate enough for vulnerability scanner to identify more than 20% of the vulnerabilities". The authors' PIP-sbom improves precision and recall by 60% and cuts false positives by 10x — [arXiv 2409.06390](https://arxiv.org/abs/2409.06390) (the 20% figure is from the search snippet of https://arxiv.org/html/2409.06390)
- **SBOMproof (arXiv 2510.05798, 2025)** finds SBOM tools largely incompatible. Inconsistent package-identifier representation leads to missing or mismatched entries — [arXiv 2510.05798](https://arxiv.org/pdf/2510.05798) (search snippet)
- **"A Reality Check on SBOM-based Vulnerability Management" (arXiv 2511.20313, 2025)** argues that inconsistencies come from ambiguous inputs, such as manifest vs lockfile, rather than from inherent tool flaws — [arXiv 2511.20313](https://arxiv.org/html/2511.20313v2) (search snippet)
- **Rosso, Jaffar, Brighente, Conti (arXiv 2512.17710, Dec 2025)** evaluated 7 SBOM-based vulnerability scanners using 16 crafted ground-truth SBOMs. "Multiple SVS-tools silently fail on valid input SBOMs" and give a false sense of security. The abstract does not name the tools — [arXiv 2512.17710](https://arxiv.org/abs/2512.17710)
- **Bhuiyan et al. (arXiv 2607.04614, Jul 2026)** studied 10,000 GitHub repos across 10 ecosystems and compared GitHub's SBOM generator with Syft, Trivy and Microsoft SBOM Tool. GitHub SBOMs are not NTIA-compliant. GitHub "often outperforms Syft and Trivy on version and license information". The search snippet says the tools "significantly diverge" on vulnerability counts in most languages — [arXiv 2607.04614](https://arxiv.org/abs/2607.04614)
- A container-image study reports that 30–70% of some installations are missed by prominent SBOM tools — [ORCA, arXiv 2509.09322](https://arxiv.org/pdf/2509.09322) (search snippet; not verified in full text)
- A systematic literature review calls SBOM generation tools "often immature, incomplete, and inconsistent" — [arXiv 2506.03507](https://arxiv.org/pdf/2506.03507) (search snippet)
- Industry benchmark: Doyensec compared Semgrep, Snyk and Dependabot with manual TP/FP labelling focused on reachability — [Doyensec SCA Benchmark PDF](https://www.doyensec.com/resources/Doyensec_Software_Composition_Analysis_Benchmark.pdf) (not fetched)

### Inferences
- Design choice: always feed lockfiles (package-lock.json, uv.lock), not loose manifests. Report union, intersection and discrepancies across Grype and OSV-Scanner rather than trusting either one alone.
- The finding that scanners silently fail on valid SBOMs (2512.17710) argues for a sanity check in the agent: the SBOM component count should roughly match the lockfile package count.

### Gaps
- I found no 2024–2026 head-to-head paper that names Grype vs OSV-Scanner vs Trivy recall on npm specifically. The 2512.17710 tool list would need the full PDF.
- The numeric results of 2607.04614 per tool were not extracted.

## 4. Trivy supply-chain compromise (2026)

### Takeaway
This incident is confirmed and serious: **GHSA-69fq-xp46-6x23 / CVE-2026-33634 (Critical, CWE-506)**, in March 2026. A malicious Trivy **v0.69.4** release was published, **trivy-action** and **setup-trivy** tags were hijacked to deliver an infostealer, and malicious Docker Hub images **v0.69.5 and v0.69.6** were pushed. The current v0.76.1 is after the incident. Trivy is still usable, but pin it by version and digest, verify it with cosign, and prefer the official Homebrew formula, which was not affected.

### Cited Findings
- Exposure windows (UTC):
  - trivy v0.69.4: 2026-03-19 18:22 to about 21:42
  - trivy-action: 2026-03-19 about 17:43 to 2026-03-20 about 05:40
  - setup-trivy: 2026-03-19 about 17:43 to about 21:44
  - Docker Hub v0.69.5/v0.69.6: 2026-03-22 15:43 to 2026-03-23 about 01:40
  — [GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- Mechanism for v0.69.4: an imposter `actions/checkout` commit downloaded malicious Go source from a typosquat domain, and goreleaser ran with `--skip=validate`. The build was distributed through GHCR, ECR Public, Docker Hub, deb/rpm and get.trivy.dev — [GHSA](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- Tag hijacking: **76 of 77** trivy-action tags were force-pushed to infostealer commits. The payload dumped Runner.Worker memory and harvested SSH, cloud, k8s, Docker and .env secrets. All 7 setup-trivy tags (v0.2.0–v0.2.6) were also replaced. Root cause: an attack that started in late February 2026 continued because credential rotation after the March 1 disclosure was not atomic — [GHSA](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- Not affected: v0.69.3 and earlier, images pulled by digest, source builds, the **official Homebrew formula**, and trivy-action 0.35.0. The custom `aquasecurity/homebrew-trivy` tap *was* compromised. Indicators of compromise: `scan.aquasecurtiy.org` and 45.148.10.212 — [GHSA](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- Sources disagree on tag counts (75/76 vs 76/77); the advisory states 76 of 77 — [netresearch incident report](https://github.com/netresearch/.github/issues/1), [Upwind](https://www.upwind.io/feed/trivy-supply-chain-incident-github-actions-compromise-breakdown)
- Microsoft published detection and defense guidance on 2026-03-24 — [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)
- The same actor ("TeamPCP") later compromised Checkmarx GitHub Actions — [Sysdig](https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions); a Phoenix Security post claims the attack was ongoing — [Phoenix Security](https://phoenix.security/trivy-supply-chain-compromise-teampcp-weaponised-scanner-ongoing-attack/) (vendor blog, treat with caution)

### Inferences
- For the portfolio, this incident is a useful story in its own right ("a security scanner was the supply-chain vector"). It justifies tool pinning in the agent itself: record tool version and checksum in each run report, and use `brew install trivy` from homebrew-core rather than the Aqua tap.
- Make Trivy optional rather than the core scanner. Grype or OSV-Scanner can serve as primary.

### Gaps
- Whether any later (post-0.69) Trivy incidents occurred through October 2026 was not checked.

## 5. npm vs pip/PyPI as demo ecosystem

### Takeaway
**Recommend npm.** It has a deterministic lockfile (`package-lock.json`) that every tool reads, it is the only ecosystem besides Maven with `osv-scanner fix` support, its upgrade-and-test loop is simple (`npm ci && npm test`), and good legal vulnerable sample apps with lockfiles exist. Python/uv is a viable second target, but there is no automated fix oracle and the sample apps use pinned `requirements.txt` without lockfiles or tests.

### Cited Findings
- Guided remediation supports npm and Maven only — [OSV guided remediation](https://google.github.io/osv-scanner/experimental/guided-remediation/)
- OSV-Scanner Python support has improved: `pylock` extractor (v2.3.3) and transitive `requirements.txt` resolution via deps.dev (v2.3.5) — [osv-scanner releases](https://github.com/google/osv-scanner/releases)
- Trivy's Python advisories come from GHSA (pip) only. Node has two sources (Node Security WG plus GHSA) — [Trivy vuln docs](https://trivy.dev/latest/docs/scanner/vulnerability/)
- Python SBOM generators miss most vulnerabilities in one study (state-of-the-art SBOM output let scanners find at most about 20% of vulnerabilities) — [arXiv 2409.06390](https://arxiv.org/html/2409.06390) (snippet)
- pygoat ships an unlocked `requirements.txt` with old pins (Django==4.2, PyYAML==5.1, urllib3==1.26.9, PyJWT==2.4.0, cryptography==39.0.1, Werkzeug==2.1.2, requests==2.28.2) and no test suite in the repo root — repo contents via GitHub API, https://github.com/adeyosemanputra/pygoat/blob/master/requirements.txt

### Inferences
- npm advantages: transitive vulns are visible in the lockfile, `npm audit` is available as a fourth baseline, and the semver/major-bump risk is easy for an LLM to reason about. Downside: deep transitive trees mean many fixes need `overrides`, which `osv-scanner fix` ignores. That gap is a good place for the LLM to add value.
- pip with uv: `uv lock` / `uv lock --upgrade-package X` is fast and deterministic and works with Python 3.14. However, old vulnerable pins such as PyYAML 5.1 or cryptography 39 may not build or install on Python 3.14 (no wheels). That is a real reproducibility risk **[inference; not tested]**.
- npm with Node 22 has a similar risk with very old native modules (e.g., `bcrypt`, `libxmljs` in DVNA), so choose a target without native addons or use Docker.

### Gaps
- Whether OSV-Scanner reads `uv.lock` was not confirmed in this session (likely yes via osv-scalibr) **[unverified]**.

## 6. Candidate sample repositories

### Takeaway
Best fit: **snyk-labs/nodejs-goof**. It is small (about 9 MB), Apache-2.0, has a committed `package-lock.json`, deliberately old pinned dependencies (lodash 4.17.4, marked 0.3.5, moment 2.15.1, st 0.2.4, express 4.12.4, adm-zip 0.4.7, mongoose 4.2.4), and a `tests/` directory. Its `npm test` runs `snyk test` and must be replaced with a real test runner. **OWASP NodeGoat** is the runner-up: it has a lockfile and grunt/Cypress tests but has not been pushed since 2024 and needs MongoDB. **OWASP Juice Shop** is too big (322 MB repo, TypeScript/Angular, Node 22–26) and has no committed lockfile, so it is a poor fit for a clean upgrade-test-rescan loop.

### Cited Findings (all metadata from GitHub API, 2026-10-30)
| Repo | Language | License | Last push | Stars | Repo size | Lockfile | Tests |
|---|---|---|---|---|---|---|---|
| [snyk-labs/nodejs-goof](https://github.com/snyk-labs/nodejs-goof) (alias snyk/goof) | JavaScript (Express, Mongo/MySQL) | Apache-2.0 | 2026-10-29 | 548 | ~9 MB | package-lock.json yes | `tests/` dir; `npm test` = `snyk test` (needs replacing); `tap` in deps |
| [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | JavaScript (Express, MongoDB) | Apache-2.0 | 2024-06-15 | 2,086 | ~9 MB | package-lock.json yes | `npm test` → grunt test; Cypress e2e (`test:ci`) |
| [appsecco/dvna](https://github.com/appsecco/dvna) | JavaScript (Express, MySQL, Sequelize) | MIT | 2024-03-27 | 779 | ~3 MB | **no lockfile** | **none** (`test` echoes error) |
| [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | TypeScript (Express + Angular) | MIT | 2026-10-29 | 14,291 | ~322 MB | **no package-lock in root** | extensive: frontend, server unit (node --test), API, Cypress e2e; v20.3.0, engines node 22–26 |
| [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat) | Python (Django 4.2) | MIT | 2026-10-22 | 353 | ~19 MB | requirements.txt pins only | no test suite visible in root |

- NodeGoat deps include `marked 0.3.5`, `needle 2.2.4`, `bcrypt-nodejs 0.0.3`, `helmet ^2`, `mongodb ^2.1.18` and `swig` (from package.json). DVNA deps include `mathjs 3.10.1`, `node-serialize 0.0.4`, `libxmljs ^0.19.1` (native) and `bcrypt ^1.0.3` (native). nodejs-goof includes `method-override: latest` and `morgan: latest`, which are unpinned but resolved by the lockfile (package.json contents via GitHub API).
- All five repos are intentionally vulnerable training apps published by OWASP, Snyk or Appsecco for education, so using them locally for a demo is legal under their licenses (MIT or Apache-2.0).

### Inferences
- Recommended plan: fork nodejs-goof. Replace `npm test` with a small, real test suite (e.g., supertest smoke tests on routes, and unit tests touching lodash, marked and moment behavior) so "upgrade breaks test" scenarios are meaningful. Run it in Docker (Node 22 for the app, Mongo container) for isolation. The upgrades of marked 0.3.5 → 4.x and lodash 4.17.4 → 4.17.21 give a natural contrast: lodash is a safe patch bump, while marked is a breaking major bump that an LLM plan has to handle.
- Alternatively, build a purpose-made minimal fixture repo (about 10 pinned vulnerable npm packages plus jest tests) alongside goof. It is more controllable and fully licensed by you. Use goof as the "real-world" demo and the fixture for CI regression.
- Avoid DVNA (no lockfile, no tests, native modules) and Juice Shop (size, no lockfile, its intentional vulns are app-level rather than dependency-level).

### Gaps
- Whether nodejs-goof's `tests/` directory has runnable unit tests, and what they cover, was not inspected.
- Juice Shop's `.npmrc` probably sets `package-lock=false`; this was not confirmed.
- Exact vulnerability counts per repo (e.g., Grype findings on nodejs-goof) need a local run.
