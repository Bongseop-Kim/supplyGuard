# Prioritizing OSS dependency vulnerabilities: CVSS + KEV + EPSS + SSVC + reachability/context

Research date: 2026-10-30. Legend: **[V]** = checked in this session against the cited page. **[U]** = from prior knowledge or a secondary or search-snippet source, not opened in this session. Verify before quoting in deliverables. Vendor numbers are labeled **(vendor claim)**.

---

## Q1. How CVSS v3.1/v4.0, CISA KEV, FIRST EPSS, and CISA SSVC work, and how they are recommended to combine

### Takeaway
Each signal answers a different question. CVSS Base measures severity, not risk. EPSS gives the probability of exploitation activity in the next 30 days. KEV is a binary, evidence-based record that exploitation has happened. SSVC is a decision tree that combines exploitation status with impact and mission context to produce Track, Track\*, Attend or Act. The standard way to combine them is as layers: KEV (or SSVC Exploitation=active) overrides everything; EPSS ranks the non-KEV remainder; CVSS impact and asset or service context set the urgency tier. FIRST and CISA publish **no numeric thresholds** for EPSS. Any cutoff is a local policy choice.

### Cited Findings
**CVSS v4.0**
- **[V]** CVSS v4.0 metric groups are Base, Threat, Environmental and Supplemental. The only Threat metric is Exploit Maturity (E), with values Attacked (A), POC (P), Unreported (U), and Not Defined (X). Not Defined defaults to **Attacked**, the worst case. Supplemental metrics (Automatable, Recovery, Provider Urgency, etc.) "do not change the score." — [FIRST CVSS v4.0 Specification](https://www.first.org/cvss/v4-0/specification-document)
- **[V]** The required score labels are CVSS-B, CVSS-BT, CVSS-BE and CVSS-BTE. The spec says consumers should enrich Base with Threat and Environmental metrics to get "a more comprehensive input to risk assessment," and that CVSS is only one input to risk. v4.0 was published 2023-11-01; document v1.2 is dated 2024-06-18. — [FIRST CVSS v4.0 Specification](https://www.first.org/cvss/v4-0/specification-document)
- Design implication (inference, using the spec's own fields): the pipeline can compute **CVSS-BT** by setting E=Attacked when the CVE is in KEV, E=POC when a public exploit exists, and E=Unreported otherwise. This turns threat intelligence into a spec-native CVSS v4 score instead of an ad hoc multiplier.

**EPSS**
- **[V]** EPSS outputs a **probability** (0 to 1) of exploitation activity in the next **30 days**, and a **percentile** (its rank among all scored CVEs). Probabilities are "global"; percentiles are "relative." FIRST recommends reporting the probability as the primary value, e.g. "15.3% (92nd)." A 10% probability sits at about the 88th percentile. — [FIRST EPSS: Probability, Percentiles, and Binning](https://www.first.org/epss/articles/prob_percentile_bins)
- **[V]** FIRST does **not** bin EPSS into labels. It calls cutoffs "subjective" with "no universal 'right' answer." — [same](https://www.first.org/epss/articles/prob_percentile_bins)
- **[V]** The same article says "only around 5% of all vulnerabilities are ever exploited in the wild." — [same](https://www.first.org/epss/articles/prob_percentile_bins)
- **[V/U]** EPSS **v4** was released 2025-03-17 (the Empirical Security page shows "March 16" with no year; Infosecurity Europe and others say 17 March 2025). v4 changes: exploitation telemetry now includes malware and endpoint detections (about 12K vulns/month); adds RSS and web mentions, Shodan, and HackerOne Hacktivity; uses cve.org CNA/ADP data as a **backup to NVD enrichment**; groups CWEs into 22 top-level categories; stops scoring REJECTED CVEs. — [Empirical Security, "Introducing EPSS v4"](https://research.empiricalsecurity.com/research/introducing-epss-version-4); [Infosecurity Europe](https://infosecurityeurope.com/en-gb/blog/future-thinking/how-to-integrate-epssv4-vulnerability-system.html)
- **[V]** Author's comparison (30-day window): a "CVSS ≥ 7" policy gives **effort 50.7%, coverage 74.6%, efficiency about 6%**. EPSS at the same coverage gives **effort about 6%, efficiency 47%**, roughly 8x less effort. The methodology is not detailed on the page. The author (Jay Jacobs) is an EPSS SIG co-chair at a commercial company. — [Empirical Security](https://research.empiricalsecurity.com/research/introducing-epss-version-4)
- **[U]** API: `GET https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY`. Bulk CSV is at `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz` (previously epss.cyentia.com). Scores update **daily**. Optional parameters include `date=` and `scope=time-series`, plus percentile/epss filters. This could not be confirmed this session; FIRST's `/epss/model` and `/epss/data_stats` pages returned 404. Check [https://www.first.org/epss/api](https://www.first.org/epss/api) before implementing.

**CISA KEV**
- **[U]** KEV inclusion criteria: (1) an assigned CVE ID, (2) reliable evidence of active exploitation, (3) clear remediation guidance. BOD 22-01 sets federal remediation due dates. Each entry has `dateAdded`, `dueDate` and `knownRansomwareCampaignUse`. The JSON feed is `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. — [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (not opened this session)
- **[U, secondary]** 245 KEV additions in 2025 (about 20% growth), taking the catalog to **1,484** at year-end. 94 of the 2025 additions were CVEs from 2024 or earlier. 304 of 1,484 (20.5%) are flagged as used by ransomware. — [Cyble](https://cyble.com/blog/cisa-kev-2025-exploited-vulnerabilities-growth/); [SC World](https://www.scworld.com/brief/exploited-vulnerabilities-accelerate-in-2025-cisa-kev-catalog-shows). A count of 1,665 entries at catalog version 2026.08.11 comes from one unverified secondary source: [Axis Intelligence](https://axis-intelligence.com/cisa-kev-statistics/).

**SSVC**
- **[V]** CISA's SSVC tree uses five decision points: **Exploitation, Technical Impact, Automatable, Mission Prevalence, Public Well-being Impact**. Outcomes:
  - **Track**: no action now; remediate within standard timelines.
  - **Track\***: monitor closely; standard timelines.
  - **Attend**: supervisory attention; remediate sooner than standard.
  - **Act**: leadership involvement; remediate ASAP.

  CISA gives **no day counts**. SSVC was created by SEI and CISA in 2019; CISA's customized tree dates from 2020. — [CISA SSVC page](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
- **[U]** Decision-point values in the CISA SSVC Guide (Nov 2022 PDF):
  - Exploitation: none / PoC / active
  - Technical Impact: partial / total
  - Automatable: no / yes
  - Mission Prevalence: minimal / support / essential
  - Public Well-being Impact: minimal / material / irreversible
  - Mission & Well-being is collapsed to low / medium / high.

  CISA's "Vulnrichment" ADP container adds SSVC Exploitation, Automatable and Technical Impact values to CVE records on cve.org. — [CISA SSVC Guide PDF](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf) (not opened this session)

### Inferences
- A concrete combined decision function, implementable as an SSVC-style tree where each step is auditable:
  1. `exploitation = active` if the CVE is in KEV (or has an Attacked/known-ransomware signal). Otherwise `poc` if EPSS ≥ a local threshold (e.g. 0.1, about the 88th percentile) or a public PoC exists. Otherwise `none`.
  2. `technical_impact = total` if CVSS C/I/A are all High, or if the vulnerability is RCE- or auth-bypass-class. Otherwise `partial`.
  3. `automatable` comes from the CVSS v4 Supplemental AU metric, CISA Vulnrichment, or "AV:N & PR:N & UI:N".
  4. `mission_prevalence` and `wellbeing` come from **service context**: SBOM to service mapping, internet exposure, data classification, business criticality.
  5. `reachability` (see Q3) acts as a modifier. If the vulnerability is *not reachable* and backed by a VEX `vulnerable_code_not_in_execute_path` statement, downgrade one level, but **never below Track\*** for KEV items.
- EPSS percentiles shift as new CVEs are scored. Store the **probability and model version and date** with each decision so decisions can be reproduced.

### Gaps
- Could not fetch FIRST's official EPSS API and data pages (404 at the tried URLs). The endpoint, update cadence and v4 date need checking on first.org.
- Did not open the CISA SSVC Guide PDF this session. The value sets above come from prior knowledge.
- No official FIRST or CISA numeric EPSS threshold exists. This was confirmed for FIRST; CISA was not checked.

---

## Q2. How real tools prioritize

### Takeaway
Tools are converging on "threat (KEV/EPSS) × impact (CVSS) × context (reachability, transitive depth, business criticality)," but the formulas are mostly opaque. Only Dependency-Track's legacy inherited risk score is a published formula, and it is a severity-count heuristic with no exploitability signal.

### Cited Findings
**OWASP Dependency-Track**
- **[V]** Analysis states: EXPLOITABLE, IN_TRIAGE, FALSE_POSITIVE, NOT_AFFECTED, NOT_SET. A full audit trail records who changed each state and when. — [DT Analysis States](https://docs.dependencytrack.org/triage/analysis-states/)
- **[V]** DT "incorporat[es] support for EPSS," "consumes and produces CycloneDX VEX," and has a policy engine with global and per-project policies. — [DT docs home](https://docs.dependencytrack.org/)
- **[U]** Inherited Risk Score = `critical×10 + high×5 + medium×3 + low×1 + unassigned×5`. This is a count-weighted severity sum with no EPSS or KEV input. Policy conditions include Severity, CPE, PURL, Component age, License, CWE, Version, Coordinates, and (in 4.x) EPSS / vulnerability ID. Analysis justifications and responses mirror CycloneDX VEX: justifications such as `code_not_reachable` and `requires_configuration`; responses `can_not_fix`, `will_not_fix`, `update`, `rollback`, `workaround_available`. Not re-checked this session: see [DT Suppression/Auditing](https://docs.dependencytrack.org/triage/auditing-basics/) and [Policy Compliance](https://docs.dependencytrack.org/usage/policy-compliance/).
- **[U]** Native KEV support in DT v4 was not confirmed this session. Treat it as a gap or as something to verify in the DT v5 / Hyades docs.

**Grype (Anchore)**
- **[V]** The table shows an **EPSS** column as "score (percentile)", e.g. `94.4% (99th)`, plus a **KEV** annotation and a **RISK** column, "combining CVSS, EPSS, and other severity metrics into a single numeric value (0.0 to 100.0)."
  - Risk components: **Threat** (EPSS, but if the CVE is in KEV, Grype "automatically treats it as maximum threat (overriding EPSS)"), **Impact** (CVSS from multiple sources), and **Context** (extra weight for known ransomware use).
  - Output is sorted by risk by default. `--sort-by` accepts kev, severity, epss, package and vulnerability.
  - **No formula is published.**
  - Source: [Anchore: Interpreting Grype results](https://oss.anchore.com/docs/guides/vulnerability/interpreting-results/)
- **[V]** Grype supports OpenVEX "for filtering and augmenting scan results." — [anchore/grype README](https://github.com/anchore/grype)

**Snyk**
- **[V]** The **Risk Score** (0 to 1000, Early Access) combines Impact and Likelihood subscores.
  - **Impact**: CVSS C/I/A and Scope, distro provider urgency for containers, and project business criticality.
  - **Likelihood**: exploit maturity, EPSS (daily; missing data defaults to **0.01055**; malicious packages get EPSS = 1), age (CVEs under one year old score higher), CVSS exploitability metrics, social trends, and package popularity.
  - **Reachability** (Java and JavaScript) raises likelihood "and transitive depth is not considered." **Transitive depth** lowers likelihood.
  - Risk Score replaces Priority Score for Open Source and Container once enabled. API fields still say "priority," and Risk Score is not available in the CLI.
  - The page does not mention KEV.
  - Source: [Snyk Docs: Risk Score](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/risk-score)

**GitHub Dependabot, Trivy, Semgrep, Endor**
- **[U]** GitHub shows EPSS score and percentile on GitHub Advisory Database pages and Dependabot alerts (added around late 2024), and Dependabot auto-triage rules can filter alerts by EPSS. Not verified this session; see [GitHub Docs: Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts).
- **[U]** Trivy's default output is vendor or NVD severity. Exploitability context comes through VEX (OpenVEX, CycloneDX, CSAF, and the VEX Hub repository) rather than a risk score. EPSS/KEV support in core Trivy was not verified.
- **Semgrep Supply Chain / Endor Labs**: see Q3.

### Inferences
- For a portfolio design, follow **Grype's structure (KEV overrides EPSS; CVSS for impact; ransomware bonus)** plus **Snyk's context modifiers (reachability up, transitive depth down, business criticality)**. Publish the formula, since both vendors keep theirs opaque. That transparency is a real differentiator.
- Use DT's analysis-state vocabulary, which is CycloneDX-aligned, as the triage state machine so results round-trip with DT.

### Gaps
- Dependabot EPSS behavior, Trivy EPSS/KEV, and DT KEV support were not verified this session.
- No tool publishes a reproducible risk formula except DT's legacy count score.

---

## Q3. Reachability analysis: what it is, how much it reduces alerts, and false-negative risk

### Takeaway
Function-level reachability builds a call graph from application entry points and checks for a path to the vulnerable symbol(s) named in the advisory. Academic data shows that very few dependency-level alerts are reachable: under 1% of Maven packages have a reachable path to vulnerable code. Vendor claims of 90–97% noise reduction are consistent with that, but they are vendor-reported. Static call graphs miss reflection, dynamic dispatch, and serialization or config-driven paths. "Unreachable" should therefore lower priority, never close a finding automatically, and it needs an advisory with symbol-level data.

### Cited Findings
- **[V]** govulncheck "only surfaces vulnerabilities that actually affect you, based on which functions in your code are transitively calling vulnerable functions." It uses the curated Go vuln DB (OSV format; sources are NVD, GHSA and maintainer reports; the Go Security team reviews package, symbol and version data). — [Go: Vulnerability Management](https://go.dev/doc/security/vuln/)
- **[U]** govulncheck limitations: reflection, unsafe/cgo, and approximated interface dispatch. Binary mode (`-mode=binary`) is coarser than source mode. Check the [govulncheck docs](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck).
- **[V]** Maven study of about 3M packages (Mir et al., SANER 2023): **less than 1% of packages** have a reachable call path to vulnerable code in their dependencies, "far lower than a naive dependency-based analysis." About **1/3 of packages** are flagged vulnerable only when all transitive dependencies are included. The OPAL call graphs favor soundness over precision. — [arXiv 2301.07972](https://arxiv.org/abs/2301.07972)
- **[U, snippet]** Dietrich et al. (ACM SCORED 2024): Java dynamic features cause static analysis to miss call edges, which leads to reachability false negatives. — [ACM DL](https://dl.acm.org/doi/pdf/10.1145/3689944.3696165). Reflection is a known source of false negatives that static tools deliberately exclude. — [Breaking Down SCA (USask)](https://harvest.usask.ca/bitstreams/b9aa13e1-073c-4a41-95b6-5035a7acfd2a/download)
- **[U, snippet]** A comparison of 9 SCA tools on Maven/npm found the reachability-based Eclipse Steady had no false positives but some false negatives. — [arXiv 2108.12078](https://arxiv.org/pdf/2108.12078). Also relevant: ACSAC 2025, "Supply Chain Reaction: Enhancing the Precision of Vulnerability Triage" — [PDF](https://www3.cs.stonybrook.edu/~mikepo/papers/supply.acsac25.pdf) (not opened).
- **(vendor claim) [U]** Endor Labs says 90.5% of vulnerabilities are unreachable at function level, 95% of OSS vulnerabilities sit in transitive dependencies, and claims 92% (elsewhere "up to 95%" or "97%") SCA noise reduction. An independent reviewer calls the 97% figure a vendor best case from customer data. — [Endor Labs: reachability](https://www.endorlabs.com/learn/how-to-use-reachability-to-reduce-vulnerability-alerts); [Endor SCA use case](https://www.endorlabs.com/use-case/sca-with-reachability); [AppSecSanta review](https://appsecsanta.com/endor-labs)
- **[V]** Snyk reachability (Java, JavaScript) checks whether the vulnerable method is called, and only raises likelihood. — [Snyk Risk Score](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/risk-score)
- No primary Semgrep report with reachability reduction numbers was found this session.

### Inferences
- Use a three-state reachability field: `reachable` / `unreachable` / `unknown`. `unknown` is the default when the language has no call-graph support or the advisory has no symbol data. Treat `unknown` like `reachable` for scoring.
- Map `unreachable` to VEX `vulnerable_code_not_in_execute_path` with tool name, version and a call-graph evidence hash. Re-check on every code change.
- Real-world exploitation of deserialization and logging CVEs often runs through reflection or config (e.g. Log4Shell via JNDI lookup). This is why "unreachable" must never suppress KEV items.

### Gaps
- No independent benchmark of reachability false-negative *rates* across tools was found. Semgrep's own numbers were not found.

---

## Q4. VEX (CycloneDX VEX, OpenVEX, CSAF): recording "not_affected" for auditability

### Takeaway
All three formats encode a product × vulnerability × status statement with a machine-readable justification. OpenVEX is the lightest. CycloneDX VEX embeds in or links to the SBOM and is native to Dependency-Track. CSAF VEX is the advisory-grade format vendors use. Record every downgrade as a VEX statement with justification, author, timestamp and evidence, so prioritization decisions can be audited.

### Cited Findings
- **[V]** OpenVEX v0.2.0:
  - Statuses: `not_affected`, `affected`, `fixed`, `under_investigation`.
  - Five `not_affected` justifications: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.
  - `not_affected` requires a `justification` or `impact_statement`; the machine-readable justification is preferred.
  - `affected` must carry an `action_statement`. The spec's field table and text conflict on this.
  - Source: [OpenVEX spec](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
- **[U]** CycloneDX (1.4+) `vulnerabilities[].analysis`:
  - **state**: `resolved`, `resolved_with_pedigree`, `exploitable`, `in_triage`, `false_positive`, `not_affected`
  - **justification**: `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control`
  - **response**: `can_not_fix`, `will_not_fix`, `update`, `rollback`, `workaround_available`
  - plus `detail`, `firstIssued` and `lastUpdated`
  - Source: [CycloneDX VEX guide](https://cyclonedx.org/capabilities/vex/) (not opened this session)
- **[U]** CSAF 2.0 VEX profile: `product_status` (known_affected, known_not_affected, fixed, under_investigation), and `flags` labels matching the CISA minimum VEX justifications. — [OASIS CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) (not opened)

### Inferences
- Internal canonical model: use CycloneDX analysis, because it is richer and DT-native. Add an exporter to OpenVEX for Grype/Trivy filtering, with a mapping such as `code_not_reachable` → `vulnerable_code_not_in_execute_path`.
- Store `decision_inputs` (CVSS vector, EPSS probability, percentile and date, KEV dateAdded, reachability result and tool version, service context) next to each VEX statement, so the decision can be replayed.

### Gaps
- The CycloneDX and CSAF field lists were not re-verified this session.

---

## Q5. Known limitations and criticisms

### Takeaway
Each signal has a structural blind spot:
- **CVSS Base**: severity inflation, plus missing scores now that the NVD has backed off.
- **EPSS**: population-level probability with no local context; it lags for new CVEs and depends on exploit telemetry.
- **KEV**: high precision but low recall; US-government-centric; skewed to enterprise and network products rather than library CVEs.
- **Reachability**: false negatives.
- **NVD**: since April 2026, enrichment is limited to selected CVEs, so pipelines need CNA/ADP and OSV/GHSA fallbacks.

### Cited Findings
- **[V]** A CVSS ≥ 7 policy forces work on 50.7% of CVEs for 74.6% coverage, with about 6% efficiency. This is the core "CVSS inflation / poor efficiency" argument. — [Empirical Security (EPSS v4)](https://research.empiricalsecurity.com/research/introducing-epss-version-4)
- **[V]** CVSS v4 defaults an undefined Exploit Maturity to Attacked, the worst case. CVSS-B scores are therefore worst-case unless Threat metrics are supplied. — [FIRST CVSS v4.0 spec](https://www.first.org/cvss/v4-0/specification-document)
- **[V]** EPSS percentiles are relative and shift. FIRST has no official bins. EPSS v3 accuracy "degraded slightly over two years," which motivated v4. v4 added CNA/ADP data because NVD enrichment was unreliable. — [FIRST binning](https://www.first.org/epss/articles/prob_percentile_bins); [Empirical Security](https://research.empiricalsecurity.com/research/introducing-epss-version-4)
- **[U, multiple secondary]** NVD:
  - Effective **2026-04-15**, NIST stopped trying to enrich every CVE and moved to risk-based triage.
  - Full enrichment now goes to KEV CVEs, software used by the federal government, and EO 14028 "critical software."
  - About **29,000** unenriched backlog CVEs published before 2026-03-01 were moved to "Not Scheduled" (KEV CVEs excepted).
  - NIST will stop routinely adding its own CVSS score and will rely on the CNA's score.
  - Specific CVEs can be requested via nvd@nist.gov.
  - NIST cites a **263%** rise in submissions from 2020 to 2025.
  - Sources: [Help Net Security, 2026-04-16](https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/); [The Hacker News, Apr 2026](https://thehackernews.com/2026/04/nist-limits-cve-enrichment-after-263.html); [The Record](https://therecord.media/nist-to-limit-work-on-cve-entries-surge); [CSA research note, 2026-04-29](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/). The primary NIST notice is on [nvd.nist.gov/general/news](https://nvd.nist.gov/general/news) (not opened). There was a 2024 backlog crisis before this (enrichment largely paused from Feb 2024); not re-verified.
- **[U]** KEV only lists CVEs with exploitation evidence plus clear remediation. It covers about 1.5K of more than 250K CVEs (see the counts in Q1), so absence from KEV is **not** evidence of non-exploitation.
- **[V]** Transitivity: about 1/3 of Maven packages are vulnerable only through transitive dependencies. — [arXiv 2301.07972](https://arxiv.org/abs/2301.07972). Snyk lowers likelihood for transitive depth. — [Snyk](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/risk-score). Remediation of transitive vulnerabilities often depends on the direct dependency releasing a fix (inference).

### Inferences
- The pipeline must not depend on NVD CVSS alone. Fall back in this order: CNA score in the cve.org record, then CISA ADP Vulnrichment, then GHSA/OSV severity, then "unscored". Treat "unscored" as medium plus EPSS, never as zero.
- EPSS for brand-new CVEs is low until signals arrive. Add an "age < N days and no EPSS history" recheck rule, similar to Snyk's age factor.

### Gaps
- No primary NIST notice was opened. Current (Oct 2026) NVD backlog size is unknown, and no post-April-2026 data was found.

---

## Q6. Published empirical numbers

### Takeaway
Of all published CVEs, only a small share is ever exploited (FIRST says about 5%). KEV holds about 1.5K entries. Under 1% of Maven packages reach vulnerable code. EPSS gives the same coverage as CVSS ≥ 7 at about 1/8 the effort. Vendors report 90–97% alert reduction from reachability.

### Cited Findings
| Metric | Value | Source | Status |
|---|---|---|---|
| Share of vulns ever exploited in the wild | about 5% | [FIRST EPSS article](https://www.first.org/epss/articles/prob_percentile_bins) | [V] |
| CVSS ≥ 7 policy | effort 50.7%, coverage 74.6%, efficiency about 6% | [Empirical Security](https://research.empiricalsecurity.com/research/introducing-epss-version-4) | [V], author is EPSS co-chair at a vendor |
| EPSS v4, same coverage | effort about 6%, efficiency 47% | same | [V] |
| EPSS v4 exploitation telemetry | about 12K vulns/month | same | [V] |
| KEV size, end of 2025 | 1,484 (245 added in 2025) | [Cyble](https://cyble.com/blog/cisa-kev-2025-exploited-vulnerabilities-growth/) | [U] secondary |
| KEV entries with known ransomware use | 304/1,484 (20.5%) | [Cyble](https://cyble.com/blog/cisa-kev-2025-exploited-vulnerabilities-growth/) | [U] |
| Maven packages with a reachable path to vulnerable code | < 1% of about 3M | [arXiv 2301.07972](https://arxiv.org/abs/2301.07972) | [V] |
| Maven packages vulnerable only via transitive deps | about 1/3 | same | [V] |
| Function-level unreachable share | 90.5% | [Endor Labs](https://www.endorlabs.com/learn/how-to-use-reachability-to-reduce-vulnerability-alerts) | vendor claim |
| SCA noise reduction via reachability | 92% (up to 97%) | [Endor Labs](https://www.endorlabs.com/use-case/sca-with-reachability) | vendor claim |
| NVD submission growth, 2020–2025 | +263% | [The Hacker News](https://thehackernews.com/2026/04/nist-limits-cve-enrichment-after-263.html) | [U] secondary |
| NVD backlog moved to "Not Scheduled" | about 29,000 CVEs | [Help Net Security](https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/) | [U] secondary |

### Inferences
- A defensible demo claim is something like "KEV + EPSS + reachability reduces the action queue by X% on our sample SBOM." Measure X on your own data and report it next to the published reference points above, rather than repeating vendor percentages.

### Gaps
- The VulnCheck exploitation reports (e.g. 2025 time-to-exploit, share of KEV exploited on or before disclosure) were not retrieved.
- There is no independent, peer-reviewed measurement of combined KEV + EPSS + reachability alert reduction on real enterprise portfolios.
