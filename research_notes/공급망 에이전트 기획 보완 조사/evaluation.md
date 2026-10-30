# Evaluating a Software Supply Chain Security Agent (Vulnerability Prioritization + LLM Remediation)

Context: evaluation plan for a portfolio project (LOTTE AX Challenge 2026; judging on business impact, agent completeness incl. accuracy/performance/stability, AI understanding). Research date: 2026-10-30. Labels used: **[peer-reviewed]** = conference/journal paper; **[preprint]** = arXiv only; **[vendor]** = company report/marketing; **[gov]** = government directive; **[secondary]** = press coverage of a primary source.

## 1. Metrics for vulnerability management and SCA evaluation (with 2024–2026 industry figures)

### Takeaway
Industry reports measure remediation speed (mean/median time to fix), backlog ("security debt"), and how much noise prioritization removes (alert reduction via reachability/runtime context). Academic SCA studies show scanners disagree a lot and accuracy depends mainly on the vulnerability database and dependency resolution, so precision/recall must be measured against a curated ground truth (e.g., OSV). Federal KEV timelines changed in June 2026: BOD 22-01 (2 weeks / 6 months) was replaced by BOD 26-04's risk-tiered model (3 / 14 / 60 days / fix-on-upgrade).

### Cited Findings
**Regulatory SLAs (KEV)**
- [gov] BOD 22-01 (issued 2021-11-03): KEV remediation default of **2 weeks** for CVEs, **6 months** for CVE IDs assigned before 2021; KEV inclusion requires a CVE ID, clear remediation guidance, and reliable evidence of in-the-wild exploitation; CISA adds to KEV within 24h of exploitation evidence. The page now states BOD 22-01 is **revoked and superseded by BOD 26-04** (page dated 2026-06-10) — [CISA BOD 22-01](https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities)
- [vendor summary of gov] BOD 26-04 (issued 2026-06-10, replaces BOD 22-01 and BOD 19-02) uses four variables — publicly exposed, in KEV, automatable, technical impact (total vs partial control). Tiers: **3 days with forensic triage** (KEV + total control), **3 days without triage** (exposed + automatable + total control, even non-KEV), **14 days** (most KEV and several high-risk non-KEV combos), **60 days** (lower risk), **"fix on system upgrade"** (no criteria met). Agencies: update processes within 60 days, full compliance within 180 days (~Dec 2026) — [Tenable FAQ](https://www.tenable.com/blog/cisa-bod-26-04-FAQ-vulnerability-remediation-impact). Full 16-combination table is in Appendix A of the directive on cisa.gov (not verified directly here).
- [secondary] Verizon data cited in BOD 26-04 coverage: only 26% of KEVs were fully remediated in 2025, down from 38% — [Tenable/aggregated coverage via search](https://www.insidegovernmentcontracts.com/2026/06/cisa-releases-binding-operational-directive-on-prioritizing-security-updates-based-on-risk/) (primary Verizon DBIR not checked).

**Remediation speed / backlog**
- [vendor] Veracode State of Software Security 2025 (15th ed., ~1.3M apps, Feb 2025): time to fix flaws rose from **171 to 252 days** over five years (~+47%); **74%** of organizations have security debt, roughly half of it critical. Outlets disagree whether 252 is mean or median — [Veracode press release](https://www.veracode.com/press-release/veracode-reveals-half-of-organizations-burdened-by-critical-security-debt/); [Cyentia publication page](https://www.cyentia.com/publication/2025-state-of-software-security/)
- [vendor] Veracode blog: leading teams fix half their flaws in ~5 weeks vs over a year for laggards (half-life metric) — [Veracode blog](https://www.veracode.com/blog/breaking-free-from-security-debt/)
- [vendor] Datadog State of DevSecOps 2025 (Apr 2025): after adding runtime context, only **18%** of CVSS-critical vulns remained critical; library-fix time averaged **62 days (Maven), 46 (.NET), 19 (npm)**; 44% of Java services had known-exploited vulns vs ~2% average elsewhere; services deployed < monthly had dependencies 47% more outdated — [Datadog press release](https://www.datadoghq.com/about/latest-news/press-releases/datadog-state-of-devops-2025/); [report](https://www.datadoghq.com/state-of-devsecops/)
- [vendor] Datadog updated web edition (~Feb 2026): 87% of orgs have ≥1 exploitable vuln affecting 40% of services; Java 59%, .NET 47%, Rust 40%; dependencies in < monthly-deployed services 70% more outdated (median 295 vs 172 days behind latest). The 44% vs 59% Java figures appear to use different methodology — [Datadog State of DevSecOps](https://www.datadoghq.com/state-of-devsecops/)

**Alert reduction / prioritization**
- [vendor] Endor Labs 2024 Dependency Management Report (Sep 2024): reachability-based prioritization lets orgs focus on **< 5%** of total vulnerabilities; a related claim holds for < 9.5% of vulnerabilities across seven languages; 80% of reachable vulns have ≤1% predicted exploit probability (EPSS) — [Intelligent CIO](https://www.intelligentcio.com/north-america/2024/09/12/endor-labs-releases-comprehensive-report-on-open-source-software-dependency-management/); [TFIR](https://tfir.io/2024-dependency-management-report-insights-into-open-source-vulnerabilities-and-ways-to-prioritize-the-greatest-risks/)
- [vendor marketing] Endor Labs: "cut SCA findings by 92%" via function-level reachability — [Endor Labs](https://www.endorlabs.com/use-case/sca-with-reachability)
- [vendor] Sonatype 9th report (2023): a fix was already available ~96% of the time for vulnerable downloads (only ~4% unavoidable) — [SD Times](https://sdtimes.com/security/sonatype-shines-light-on-current-state-of-supply-chain-security-in-latest-report/); 10th report (Oct 2024): 156% surge in OSS malware, 6.6T downloads — [Sonatype press release](https://www.sonatype.com/en/press-releases/sonatypes-10th-annual-state-of-the-software-supply-chain-report)
- [vendor] Sonatype 2026 report (released 2026-01-28): OSS malware +75%; 1.2M+ malicious packages analyzed; open-source adoption +67% YoY — [SD Times](https://sdtimes.com/security/report-ai-hallucinates-27-of-upgrade-recommendations-for-open-source-projects/); [Sonatype press release](https://www.sonatype.com/press-releases/sonatype-research-reveals-open-malware-grows-75-percent)

**Scanner accuracy (academic)**
- [peer-reviewed, ESEM 2021] Imtiaz et al. compared 9 SCA tools on OpenMRS (Maven + npm); reported vulnerability counts varied widely; vulnerability-database quality was the main differentiator — [arXiv 2108.12078](https://arxiv.org/abs/2108.12078v1)
- [peer-reviewed, ESEC/FSE 2023] Java SCA study: most of six tools did not fully support dependency scenarios in the proposed evaluation model, reducing accuracy — [AMiner entry](https://aminer.org/pub/656eb2f5939a5f4082a50a56/software-composition-analysis-for-vulnerability-detection-an-empirical-study-on-java-projects)
- [preprint, 2026-04-22] Mandl et al., OSV-derived ground truth mapping vulnerabilities to concrete package versions across ecosystems, with an open-source tool to rebuild the dataset from current OSV; finds systematic differences between detectors — [arXiv 2604.21111](https://arxiv.org/abs/2604.21111) (search summary says it argues recall and overlap capture different aspects; not verified in full text)
- [preprint, 2026] GitHub SBOM completeness study reports component-detection precision/recall/F1 per language, e.g., Java: Microsoft SBOM Tool P 79.3% / R 98.4%; JavaScript: GitHub SBOM P 88.2% / R 86.7%; Trivy and Syft lower recall on JS — [arXiv 2607.04614](https://arxiv.org/pdf/2607.04614) (from search summary; numbers should be re-checked in PDF)

### Inferences
- A defensible metric set for the prioritization half: (a) detection precision/recall/F1 vs OSV ground truth at (package, version, advisory) granularity; (b) **alert reduction ratio** = 1 − (prioritized "act now" findings / raw findings), reported alongside **recall of known-critical items** (KEV-listed / high-EPSS) so noise reduction is not bought by dropping real risk; (c) SBOM component coverage (detected components / lockfile-resolved components, direct vs transitive); (d) SLA-tier assignment accuracy using the BOD 26-04 four-variable model (a nice "business impact" hook since it is brand new, June 2026).
- For business impact, frame time savings against public baselines: 252-day fix time (Veracode), 19–62 day library fix (Datadog), 26% KEV full-remediation (Verizon via coverage). A demo agent cannot measure real MTTR; instead report "time from scan to merge-ready PR" and compare qualitatively.
- Cite BOD 22-01 as historical; using it as the current rule in Oct 2026 would be outdated.

### Gaps
- Could not access the BOD 26-04 Appendix A full table directly; tier details come from Tenable.
- Did not find Endor Labs 2025/2026 report figures; Sonatype 2025 (11th) report fix-availability figure not verified.
- Veracode 2026 SoSS ("82% security debt") seen only in a search snippet; unverified.
- No single authoritative precision/recall number for SCA tools on Java+npm.

## 2. Metrics for LLM/agent code repair and security patching (how benchmarks define success)

### Takeaway
Benchmarks converge on a staged, execution-based funnel: patch applies → builds → vulnerability no longer triggers (PoC/crash/rescan) → existing tests still pass (no regression) → (strictest) semantic equivalence to reference via fuzzing/differential testing. Headline success rates for security patching remain low (SEC-bench best 34%; Google internal 15%), so honest reporting of a funnel is expected.

### Cited Findings
- [peer-reviewed via benchmark, widely used] SWE-bench: a task is "resolved" only if the patch applies and all FAIL_TO_PASS tests (fail before fix, pass after) pass and all PASS_TO_PASS tests (regression checks) keep passing; headline metric % Resolved. SWE-bench Verified = 500 human-validated tasks, released Aug 2024 by OpenAI Preparedness + authors — [HF dataset README](https://huggingface.co/datasets/princeton-nlp/SWE-bench/blob/refs%2Fpr%2F2/README.md?code=true); [guide](https://jonathanding.github.io/llm-learning/en/articles/swe-bench-guide)
- [vendor/open benchmark] Meta AutoPatchBench (CyberSecEval 4, announced 2025-04-29): C/C++ fuzzing crashes from ARVO. Checks: patched code builds; original crashing input no longer crashes; patch survives extended fuzzing; strictest tier = white-box **differential testing** vs reference fix ("correct patches"). Reported share metrics: `shr_patches_generated`, `shr_passing_fuzzing`, `shr_correct_patches`. Dataset files: full 142 cases, lite 120 (single-hunk fixable), sample 20 (docs) — Meta blog says 136 / 113 — [CyberSecEval docs](https://meta-llama.github.io/PurpleLlama/CyberSecEval/docs/benchmarks/autopatch); [Meta engineering blog](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/). Note count discrepancy between docs and blog.
- [peer-reviewed, NeurIPS 2025] SEC-bench: multi-agent scaffold builds repos/harnesses, reproduces vulns in isolated containers, generates gold patches; 200 verified real-world CVE instances at ~$0.87/instance; tasks = PoC generation and vulnerability patching; best agents: **18.0%** PoC, **34.0%** patching — [arXiv 2506.11791](https://arxiv.org/pdf/2506.11791); [NeurIPS 2025](https://proceedings.neurips.cc/paper_files/paper/2025/hash/a9168f1c54e5147027f1e8cf83e1a775-Abstract-Conference.html)
- [peer-reviewed, ICML 2025] CVE-Bench (Zhu et al.) is an **exploitation** benchmark (40 critical web-app CVEs, zero-day and one-day settings; best agent exploits up to 13%) — not a repair benchmark; useful only as a model of sandboxed, reproducible CVE evaluation — [arXiv 2503.17332](https://arxiv.org/pdf/2503.17332); [ICML](https://icml.cc/virtual/2025/poster/46522)
- [peer-reviewed, SANER 2024] BUMP: 571 reproducible **breaking dependency updates** from 153 Java/Maven projects, Dockerized; breaking = build passes before the version bump and fails after (compile/test failures) — [arXiv 2401.09906](https://arxiv.org/pdf/2401.09906); [GitHub chains-project/bump](https://github.com/chains-project/bump). Breaking-Good explains root causes for 70% of BUMP cases — [arXiv 2407.03880](https://arxiv.org/pdf/2407.03880)
- [preprint, 2026] "Update from Hell" / DEPBENCH extends breaking-update repair across ecosystems as an agent task — [arXiv 2608.30300](https://arxiv.org/pdf/2608.30300) (details not verified)
- [vendor tech report, 2024] Google "AI-powered patching" (Keller & Nowakowski): Gemini pipeline fixed **15%** of sanitizer bugs found in unit tests; pipeline = find → reproduce/isolate → LLM fix → test fixes → surface best fix for **human review**; Google noted it is far from autonomously fixing 90–95% — [Google Research](https://research.google/pubs/ai-powered-patching-the-future-of-automated-vulnerability-fixes/); [PDF](https://storage.googleapis.com/gweb-research2023-media/pubtools/7563.pdf); [TechTarget](https://techtarget.com/searchsecurity/feature/How-AI-driven-patching-could-transform-cybersecurity)
- [peer-reviewed, ICLR 2025] pass@k measures discovery (any of k succeed); τ-bench's **pass^k** = probability all k i.i.d. trials succeed — a consistency metric; gpt-4o pass^8 < 25% in retail — [arXiv 2406.12045](https://arxiv.org/pdf/2406.12045)
- [secondary] IDC: developers accept 39% of AI-generated code without revision (human acceptance baseline) — [SD Times](https://sdtimes.com/security/report-ai-hallucinates-27-of-upgrade-recommendations-for-open-source-projects/)

### Inferences
- For an SCA-remediation agent (dependency bumps, not source patches), the natural funnel is: **(1) valid proposal** (version exists in registry, satisfies advisory) → **(2) lockfile resolves / install succeeds** → **(3) build/compile succeeds** → **(4) existing tests pass (PASS_TO_PASS analogue, regression rate)** → **(5) vulnerability eliminated on rescan** (OSV/osv-scanner shows advisory gone, no new advisories introduced) → **(6) human acceptance** (reviewer would merge). Report each stage as a share of N cases, like AutoPatchBench's share metrics.
- Report pass@1 and pass^3 (run each case 3 times) to show consistency, plus cost (tokens/USD) and latency per case (SEC-bench reports cost per instance, a precedent).
- Use BUMP-style "breaking update" cases (major version bumps) as a hard subset to show the agent detects/handles breakage rather than only trivial patch bumps.
- Position results against public baselines (SEC-bench 34%, Google 15%) carefully: those are source-level patches in C/C++; dependency bumps are easier, so a much higher fix rate is plausible but not directly comparable.

### Gaps
- Could not verify DEPBENCH numbers or PatchBench (arXiv 2609.04075) details.
- No public benchmark found specifically for LLM-driven *dependency version upgrade* remediation success rate beyond Sonatype's hallucination study.

## 3. Evaluating LLM explanations and grounding (hallucination, LLM-as-judge, citation correctness)

### Takeaway
The dominant failure for dependency-remediation LLMs is fabricated versions/packages: Sonatype measured 27.76% hallucinated upgrade recommendations from GPT-5 (Jan 2026), and USENIX Security 2025 measured 5.2%–21.7% hallucinated package names. Grounding claims should therefore be checked deterministically (registry lookup + OSV range check), with LLM-as-judge reserved for prose quality and calibrated against human labels.

### Cited Findings
- [vendor] Sonatype 2026 State of the Software Supply Chain (2026-01-28): ~37,000 AI-driven upgrade recommendations (GPT-5, popular package managers) — **27.75–27.76%** hallucination rate, 10,000+ non-existent versions recommended, sometimes suggested actual malware packages; CTO Brian Fox: AI helps only when constrained by real registry data, vulnerability/malware intelligence, and policy — [SD Times](https://sdtimes.com/security/report-ai-hallucinates-27-of-upgrade-recommendations-for-open-source-projects/); [Dark Reading](https://darkreading.com/application-security/ai-powered-dependency-decisions-security-bugs); [Sonatype Guide page](https://sonatype.com/products/sonatype-guide)
- [peer-reviewed, USENIX Security 2025] Spracklen et al.: 16 code LLMs, 576k samples (Python, JavaScript); 205,474 unique hallucinated package names; rates from ~5.2% (commercial) to ~21.7% (open-source); 58% of hallucinations repeated across queries (enables "slopsquatting"); mitigations (e.g., RAG, self-refinement) reduce hallucinations — [USENIX](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen); [arXiv 2406.10279](https://arxiv.org/abs/2406.10279v3)
- [peer-reviewed, NeurIPS 2023 D&B] LLM-as-judge pitfalls: position bias, verbosity bias, self-enhancement bias, limited reasoning on math/grading; strong judges reach ~80% agreement with humans, similar to human-human — Zheng et al., "Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena" — [arXiv 2306.05685](https://arxiv.org/abs/2306.05685) (from prior knowledge; not re-fetched in this session)
- [spec] OSV schema encodes affected ranges with `introduced` / `fixed` / `last_affected` events per package ecosystem, which allows mechanical checking that a proposed version is outside all affected ranges — [OSV schema](https://ossf.github.io/osv-schema/) (from prior knowledge; not re-fetched)

### Inferences
- **Deterministic grounding checks** (each a binary metric):
  1. *Version existence*: proposed (package, version) exists in npm/PyPI/Maven Central registry API → "hallucinated version rate" (directly comparable to Sonatype's 27.76% baseline — strong AI-understanding talking point).
  2. *Advisory satisfaction*: proposed version ≥ OSV `fixed` and not in any other affected range for that advisory.
  3. *No new advisories*: proposed version has no other known OSV/GHSA advisories (or fewer/lower severity).
  4. *Not malicious/yanked*: check OSV MAL- entries / registry yanked/deprecated flags.
  5. *Citation correctness*: every CVE/GHSA ID cited in the explanation exists and refers to the same package; every claimed fact (CVSS, KEV status, EPSS) matches the source API at eval time.
- Compare "LLM-only" vs "LLM + tool-grounded" variants (ablation) to show the grounding layer's measurable effect.
- If using LLM-as-judge for explanation quality (clarity, actionability), use a rubric, randomize order, use a different model family than the generator, and report agreement (e.g., Cohen's kappa or % agreement) with a small human-labeled subset (e.g., 30 items).

### Gaps
- Sonatype's per-model breakdown (other frontier models) and grounded-vs-ungrounded comparison numbers not found.
- No benchmark found specifically scoring vulnerability *explanation* faithfulness.

## 4. Building a small reproducible eval set and reporting failures honestly

### Takeaway
Follow the SEC-bench/BUMP/CVE-Bench pattern at small scale: pin each case to a commit + lockfile in a container, take ground truth from OSV/GHSA `fixed` versions, define success with executable checks, and publish per-stage funnels with categorized failures.

### Cited Findings
- [preprint, 2026] OSV can be turned into version-level ground truth with a reproducible rebuild tool — [arXiv 2604.21111](https://arxiv.org/abs/2604.21111)
- [peer-reviewed] BUMP packages each case as Docker images for long-term reproducibility, publishes on Zenodo — [arXiv 2401.09906](https://arxiv.org/pdf/2401.09906); [GitHub](https://github.com/chains-project/bump)
- [peer-reviewed] SEC-bench verifies each instance (reproducible PoC + gold patch) in isolated environments and reports construction cost per instance — [arXiv 2506.11791](https://arxiv.org/pdf/2506.11791)
- [vendor] AutoPatchBench offers full/lite/sample subsets so others can run cheaply (20-case sample) — [CyberSecEval docs](https://meta-llama.github.io/PurpleLlama/CyberSecEval/docs/benchmarks/autopatch)
- [peer-reviewed] SWE-bench Verified exists because original tasks included unsolvable/ill-specified items; human validation of the eval set matters — [guide](https://jonathanding.github.io/llm-learning/en/articles/swe-bench-guide)
- [peer-reviewed] SWE-bench guides note the most common failure mode is "fixed the bug but broke an existing test" (PASS_TO_PASS regression) — [qaskills guide](https://qaskills.sh/blog/swe-bench-explained-guide-2026) [secondary]

### Inferences (proposed plan)
- **Size**: ~10 repos × 3–5 CVEs = 30–50 cases, across npm, PyPI, Maven (Datadog shows ecosystem fix-time differences, which justifies multi-ecosystem). Stratify: direct vs transitive; patch/minor vs major (breaking) bump; KEV-listed vs not; reachable vs unreachable; 2–3 "no fix available" cases (agent should say so, not invent); 2–3 malicious-package cases.
- **Sources**: small public demo apps or pinned historic commits of OSS repos whose lockfile contains known-vulnerable versions; ground truth from OSV API (`fixed` events) cross-checked with GHSA; record snapshot date because OSV/KEV/EPSS change.
- **Per-case record**: repo URL + commit SHA, lockfile hash, advisory IDs, ground-truth min fixed version, expected priority tier, test command, container image digest.
- **Seeds**: fixed random seeds/temperature where possible; run each case k=3 times.
- **Reporting**: funnel table per stage; confusion matrix for prioritization; failure taxonomy (hallucinated version, unresolvable lockfile, build break, test regression, vuln not eliminated, timeout, tool/API error); 2–3 worked failure examples shown in full; separate "dev set used for prompt tuning" from "held-out test set" to avoid overfitting claims.

### Gaps
- No published guideline specific to "small" SCA-agent eval sets; plan above is synthesized from benchmark practices.

## 5. Agent reliability / operational metrics

### Takeaway
Report consistency (pass^k), robustness under faults, and standard ops metrics (run success rate, retry counts, timeout rate, idempotency, cost/latency percentiles); τ-bench and ReliabilityBench provide citable framing.

### Cited Findings
- [peer-reviewed, ICLR 2025] τ-bench pass^k: all k trials succeed; under independence pass^k ≈ (pass^1)^k; gpt-4o < 50% task success and pass^8 < 25% (retail) — [arXiv 2406.12045](https://arxiv.org/pdf/2406.12045); [ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/hash/1b126cc38b8638e07bef37e7b2bb72bf-Abstract-Conference.html)
- [preprint, Jan 2026] ReliabilityBench extends beyond consistency to robustness (perturbations) and fault tolerance (injected tool/API failures) for agents under production-like stress — [arXiv 2601.06112](https://arxiv.org/pdf/2601.06112)
- [peer-reviewed] SEC-bench reports cost per instance ($0.87) as a first-class metric — [arXiv 2506.11791](https://arxiv.org/pdf/2506.11791)

### Inferences
- Operational metrics to report: **end-to-end run success rate** (pipeline completes with valid output, independent of fix correctness); **pass^3**; **retry rate** and **retries-to-success**; **timeout rate** with configured limits per stage; **idempotency test** (re-running on an already-fixed repo yields no new PR / no duplicate change; same input → same PR diff modulo LLM wording); **fault-injection results** (registry API 5xx, OSV timeout, malformed LLM JSON) → graceful degradation rate; **p50/p95 latency** and **USD/tokens per case**; **schema-valid output rate** for structured LLM outputs.
- Mapping to judging criteria: accuracy → Sec. 1–3 metrics; performance → latency/cost; stability → run success, pass^k, fault-injection; AI utilization → grounded vs ungrounded ablation and hallucination-rate comparison vs Sonatype baseline.

### Gaps
- No industry-standard numeric targets for agent run success/timeout rates were found; thresholds must be self-defined and justified.
