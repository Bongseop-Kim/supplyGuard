# Automated Dependency Vulnerability Remediation: Bot-based and LLM/Agent-based Patching (as of 2026-10-30)

Scope note: supports the design of "AI 에이전트 기반의 자동 조치안 도출 및 보안 개선 워크플로우" (LOTTE AX Challenge 2026). [PR] = peer-reviewed or academic preprint; [V] = vendor claim (not independently verified).

## Q1. Empirical evidence on Dependabot/Renovate security PRs (merge rate, time-to-merge, breakage, developer response)

### Takeaway
Bot security PRs are mostly accepted (roughly 60-75% merge rates across studies) and often merged fast, but when they are rejected it is mostly due to workflow friction (concurrent manual updates, noise), not build breakage. Noise and weak compatibility signals cause developers to throttle or abandon bots.

### Cited Findings
- [PR] Alfadel et al., "On the Use of Dependabot Security Pull Requests", MSR 2021: 15,243 Dependabot security PRs in 2,904 active open-source JavaScript projects; 65.42% merged, often within a day. — [MSR 2021 page](https://2021.msrconf.org/details/msr-2021-technical-papers/25/On-the-Use-of-Dependabot-Security-Pull-Requests); [PDF](https://realiselab.github.io/publications/On-the-Use-of-Dependabot-Security-Pull-Requests.pdf)
- [PR] Same study: manual analysis found 7 reasons for non-merge, mostly concurrent modification of the affected dependency (developers updated it themselves) rather than Dependabot failures; only 3.2% of manually examined PRs suffered build breakage. Vulnerability severity and breaking-change risk were not strongly correlated with time to merge; prior experience with Dependabot security PRs was associated with faster merges. — [PDF](https://realiselab.github.io/publications/On-the-Use-of-Dependabot-Security-Pull-Requests.pdf)
- [PR] He, He, Zhang, Zhou, "Automating Dependency Updates in Practice: An Exploratory Study on GitHub Dependabot", IEEE TSE 49(8):4004-4022, 2023 (arXiv June 2022, v3 May 2023): projects reduce technical lag after adopting Dependabot and developers respond well to its PRs, but Dependabot "compatibility scores" are too sparse to reduce developers' suspicion of updates, developers often configure it to reduce notifications, and 11.3% of studied projects deprecated Dependabot in favor of alternatives. Proposes an ideal bot along four dimensions: configurability, autonomy, transparency, self-adaptability. — [arXiv](https://arxiv.org/abs/2206.07230v3); [DBLP](https://dblp.org/rec/journals/tse/HeHZZ23); [author page](https://hehao98.github.io/publication/2022-dependabot)
- [PR] He et al. report a 74.53% merge rate for Dependabot (version + security) PRs, higher than the 65.42% Alfadel et al. found for Dependabot Preview security PRs; another large-sample study reports 59.5% acceptance. Samples/scope differ, so rates are not directly comparable. — [arXiv PDF](https://arxiv.org/pdf/2206.07230); [VEM/SBC study on Dependabot adoption](https://sol.sbc.org.br/index.php/vem/article/view/36870)
- [V/docs] Renovate defaults: it raises PRs and leaves merging to humans unless `automerge` is enabled; it "only automerges branches which are up-to-date and green"; with no tests you must explicitly set `ignoreTests: true`; with GitHub platform automerge and no required status check selected, "GitHub might automerge PRs with failing tests!". — [Renovate config options](https://docs.renovatebot.com/configuration-options/)
- [V/docs] Renovate: "Renovate always creates security PRs, even if the concurrent PR limit is already reached"; security PRs are titled with `[SECURITY]`. `osvVulnerabilityAlerts` (experimental, default false) creates PRs for vulnerabilities from OSV but only for direct dependencies. — [Renovate config options](https://docs.renovatebot.com/configuration-options/)
- [V/docs] Renovate `minimumReleaseAge` makes Renovate wait before proposing an update (adds a "pending" status check); docs note npm packages under 72 hours old can be unpublished and recommend `3 days` for npm in that case. `prCreation=approval` creates the PR only after Dependency Dashboard approval (a human-approval gate). — [Renovate config options](https://docs.renovatebot.com/configuration-options/)

### Inferences
- A realistic baseline for "deterministic version-bump" remediation acceptance is ~60-75% merged; the agent's value-add is in the remaining cases (conflicts, breaking upgrades, transitive deps with no direct fix) and in reducing noise (grouping, prioritization by reachability/exploitability).
- He et al.'s "transparency" and "compatibility score sparsity" findings justify the agent attaching evidence (changelog diff, test results, rescan result) to every PR.

### Gaps
- I did not retrieve exact median time-to-merge numbers from He et al. or newer 2024-2026 Dependabot/Renovate studies (e.g., grouped security updates, Dependabot + Copilot integration) in this pass.
- No peer-reviewed Renovate-specific security-PR merge-rate study was located.

## Q2. Breaking changes from dependency upgrades (frequency, semver violations)

### Takeaway
Semver compliance has improved, but breaking changes in non-major releases still occur; most breaking changes touch APIs clients don't use, so actual client impact is lower. Compilation failures are the most common breakage class in benchmarks (BUMP).

### Cited Findings
- [PR] Ochoa et al., "Breaking Bad? Semantic Versioning and Impact of Breaking Changes in Maven Central" (EMSE 2021; ICSE 2023 journal-first): 119,879 library upgrades, 293,817 clients; 83.4% of upgrades comply with semver; most breaking changes affect code no client uses; only 7.9% of clients are affected; compliance improving over time. — [arXiv](https://arxiv.org/pdf/2110.07889); [ICSE 2023 JF](https://conf.researchr.org/details/icse-2023/icse-2023-journal-first-papers/83/Breaking-Bad-Semantic-Versioning-and-Impact-of-Breaking-Changes-in-Maven-Central)
- [PR] Raemaekers et al. (2014/2017), the study Ochoa replicates: about one third of Maven releases introduced at least one breaking change, at similar rates for minor and major releases (contradicted in magnitude by Ochoa's replication). — [TU Delft record](https://research.tudelft.nl/en/publications/semantic-versioning-and-impact-of-breaking-changes-in-the-maven-r/)
- [PR] BUMP benchmark (Reyes et al., KTH; Java): 571 reproducible breaking dependency updates from 153 Java projects; 243 (43%) are compilation failures (others: test failures, Java version incompatibility, Werror, classpath conflicts). — [Byam paper describing BUMP](https://arxiv.org/html/2505.07522v3)

### Inferences
- The agent should treat even minor/patch bumps as potentially breaking and always verify via build+test, rather than trusting semver.
- Reachability analysis (whether the client calls the changed API) explains why many "breaking" releases don't break clients - a useful prioritization signal.

### Gaps
- npm/PyPI semver-violation rates were not retrieved in this pass (known literature exists, e.g., npm breaking-change studies, but not verified here).
- Breaking-Good (Reyes et al., explaining breaking dependency updates via build log analysis) is cited in Byam's references but I did not retrieve its own results.

## Q3. LLM/agent-based repair of dependency upgrades and vulnerability fixes (success rates, failure types)

### Takeaway
Peer-reviewed/academic success rates for fully automated fixes are modest: ~20-34% end-to-end on realistic benchmarks (27% full-build fix on BUMP, 34% on SEC-bench, ~20% on Vul4J-era studies, 15% in Google's production pipeline). Vendor claims are much higher (e.g., Snyk ~80% "fix accuracy", Copilot Autofix 3x faster) but use different, unaudited metrics. Dominant failure modes: hallucinated APIs/packages, compiles-but-fails-tests, introducing new errors, incomplete fixes.

### Cited Findings: dependency-upgrade repair
- [PR preprint] Byam (Reyes et al., arXiv 2505.07522, v1 May 2025, v3 Feb 2026): LLM repair of client code after breaking Java dependency updates on 103 BUMP compilation-failure cases. Best: o3-mini fully fixes 27% of builds and 78% of individual compilation errors. Others (best prompt): DeepSeek V3 21% build / 73% errors; Gemini 2.0 Flash 20% / 74%; GPT-4o-mini 17% / 71%; Qwen2.5-32B 13% / 72%. — [arXiv v3](https://arxiv.org/html/2505.07522v3)
- [PR preprint] Byam failure modes: (1) calls to non-existent APIs in the new dependency version (e.g., invented `getEnchantment()`); (2) unresolved symbols plus newly introduced malformed code; (3) compiles but a test fails (logback->slf4j swap broke `doAppend()` behavior); (4) complex prompts may overfit (Qwen); (5) Qwen2.5-32B median "relative error fixed ratio" 0% - fixing as many errors as it introduces. — [arXiv v3](https://arxiv.org/html/2505.07522v3)
- [PR preprint] BigBag (arXiv 2606.24446, 2026) on 157 BUMP compilation-failure cases reports 33.3% cross-project fix rate. — [HF papers](https://huggingface.co/papers/2606.24446)
- [PR] Fruntke & Krinke, "Automatically fixing dependency breaking changes", FSE 2025: LLM-based APR of breaking dependency changes is feasible and can be optimized for better repair outcomes. — [FSE 2025](https://conf.researchr.org/details/fse-2025/fse-2025-research-papers/38/Automatically-fixing-dependency-breaking-changes)
- [PR workshop] Tawosi et al. (J.P. Morgan AI Research), "LLM Agents for Automated Dependency Upgrades", arXiv 2510.03480 (Oct/Nov 2025, ASE 2025 AISM workshop): multi-agent loop that applies changes until build and all tests pass; 71.4% precision on three synthetic Java repos; fewer tokens than SOTA baselines. Small synthetic evaluation. — [arXiv](https://arxiv.org/abs/2510.03480v2)

### Cited Findings: vulnerability repair
- [PR] SEC-bench (UIUC, NeurIPS 2025, arXiv 2506.11791): state-of-the-art LLM code agents reach at most 34.0% on vulnerability patching and 18.0% on PoC generation; the 34.0% is attributed to OpenHands + Claude 3.7 Sonnet. Patches are judged by compiling and stopping the PoC sanitizer crash without new issues. — [NeurIPS 2025](https://proceedings.neurips.cc/paper_files/paper/2025/hash/a9168f1c54e5147027f1e8cf83e1a775-Abstract-Conference.html); [arXiv](https://arxiv.org/pdf/2506.11791); [benchmarklist](https://benchmarklist.com/benchmarks/sec_bench/)
- [PR] Wu et al., "How Effective Are Neural Networks for Fixing Security Vulnerabilities", ISSTA 2023 (Vul4J + VJBench, Java): Codex best at ~10.2 fixes (20.4%); many generated patches didn't compile; ~8.7 on transformed (anti-memorization) data; many CWE types (e.g., CWE-325, CWE-444) unfixed by any model. — [arXiv](https://arxiv.org/abs/2305.18607v1); [PDF](https://www.cs.purdue.edu/homes/lintan/publications/vulfix-issta23.pdf)
- [Industry tech report] Google, "AI-powered patching: the future of automated vulnerability fixes" (2024): Gemini pipeline fixed 15% of sanitizer bugs found in unit tests (hundreds of patches); all fixes go to human review; pipeline covers C/C++, Java, Go. — [Google Research](https://research.google/pubs/pub52980/)
- [V] Google DeepMind CodeMender (announced 2025-10-06): 72 security fixes upstreamed to OSS projects over ~6 months (codebases up to 4.5M LOC); all patches reviewed by human researchers before submission; uses validation (e.g., checking for regressions) before proposing. — [DeepMind blog](https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/)
- [V] GitHub Copilot Autofix (GA Aug 2024): public beta data May-July 2024 - median 28 min to commit an autofix for PR-time alerts vs 1.5 h manual; SQLi 18 min vs 3.7 h; XSS 22 min vs ~3 h. Measures time, not correctness. — [GitHub blog](https://github.blog/news-insights/product-news/secure-code-more-than-three-times-faster-with-copilot-autofix/); [TechTarget](https://www.techtarget.com/cybersecurity/news/366603045/GitHub-Copilot-Autofix-tackles-vulnerabilities-with-AI)
- [V] OpenAI Aardvark (announced Oct 2025; now "Codex Security", rolling out to Enterprise/Business/Edu as of 2026-03-06 per secondary source): claims 92% recall of known + synthetically introduced vulns on internal "golden" repos; validates exploitability in a sandbox; attaches a Codex-generated patch for human review / one-click patching. No published false-positive or patch-correctness rate. — [OpenAI](https://openai.com/index/introducing-aardvark); [VentureBeat](https://venturebeat.com/security/meet-aardvark-openais-in-house-security-agent-for-code-analysis-and-patching)
- [V] Snyk Agent Fix (formerly DeepCode AI Fix): Snyk claims >80% "fix accuracy"; docs say it moved to a new agentic architecture in May 2026 with "significantly higher fix accuracy" (no new number). — [Snyk blog](https://snyk.io/blog/find-auto-fix-prioritize-intelligently-snyks-ai-powered-code); [Snyk docs](https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-code/manage-code-vulnerabilities/fix-code-vulnerabilities-automatically); [agentic architecture blog](https://snyk.io/pt-BR/blog/snyk-agent-fix-agentic-architecture/)
- [PR] Hallucinated dependencies: Spracklen et al., "We Have a Package for You!" (USENIX Security 2025): 576,000 Python/JS samples from 16 LLMs; 19.7% of recommended packages did not exist (205,474 unique hallucinated names); commercial models ≥5.2% vs open-source 21.7%; 43% of hallucinated names repeated in all 10 re-queries (enables "slopsquatting"). — [secondary summary, Netwrix](https://netwrix.com/en/resources/blog/slopsquatting/); 2026 follow-up on newer models: [alphaxiv 2605.17062](https://www.alphaxiv.org/abs/2605.17062.md)

### Inferences
- Plan KPIs around ~20-35% fully-automated fix rate for non-trivial cases (breaking upgrades, code-level vulns), and much higher for simple version bumps where a fixed version exists. Vendor "80%" or "3x faster" numbers should not be used as baselines without stating metric differences.
- Failure taxonomy for the agent's verifier: (a) non-existent package/version/API (verify against registry + lockfile + compile); (b) incomplete fix (rescan still flags CVE / PoC still triggers); (c) regression (tests fail); (d) net-new errors; (e) non-compiling patch.
- Partial success (78% of errors fixed, 27% full builds) suggests value in a "draft PR + explanation" mode for humans even when full automation fails.

### Gaps
- CVE-Bench (exploitation of web-app CVEs) is about exploiting, not patching; I did not retrieve its numbers. No independent audit of Copilot Autofix / Snyk / Codex Security patch correctness was found.
- No public success-rate data found for Endor Labs or Socket remediation features, nor for Anthropic Claude security review features, in this pass.

## Q4. Workflow safeguards for safe remediation (sandbox builds, test+rescan, HITL approval, PR workflow, policy gates)

### Takeaway
Every credible system (academic and vendor) converges on: generate in isolation -> build/test validation -> rescan/PoC re-run -> human-reviewed PR. No major vendor auto-merges AI-authored security patches by default.

### Cited Findings
- Google's pipeline: LLM-generated fixes are tested and then sent to human review; does not auto-commit. — [Google Research](https://research.google/pubs/pub52980/)
- DeepMind CodeMender: all patches human-reviewed before upstream submission. — [DeepMind blog](https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/)
- OpenAI Aardvark/Codex Security: sandboxed exploit validation; patch attached for human review; nothing applied without approval. — [OpenAI](https://openai.com/index/introducing-aardvark)
- SEC-bench defines success as: compiles + PoC no longer triggers sanitizer + no new issues (i.e., build + exploit rescan as the oracle). — [arXiv](https://arxiv.org/pdf/2506.11791)
- Tawosi et al. agent loop: iterate until build succeeds and all tests pass. — [arXiv](https://arxiv.org/abs/2510.03480v2)
- Renovate gates: automerge only when branch up to date and checks green; required status checks needed; `minimumReleaseAge` cooldown (3 days recommended for npm unpublish window); `prCreation=approval` / Dependency Dashboard approval as human gate. — [Renovate config options](https://docs.renovatebot.com/configuration-options/)
- OpenSSF "Security-Focused Guide for AI Code Assistant Instructions" (Best Practices + AI/ML WGs, 2025-08-01): recommends instruction files covering application security, supply-chain safety (e.g., vetted dependencies), platform specifics; the developer remains responsible and must not skimp on review and testing. — [OpenSSF guide](https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions); [OpenSSF blog](https://openssf.org/?p=8932)

### Inferences
- Recommended pipeline for the portfolio: SCA detect -> agent proposes fix (version bump; code changes if breaking) -> verify package/version exists in registry & meets cooldown -> sandboxed build+tests -> SCA/SAST rescan (CVE gone, no new CVEs) -> risk-tiered policy gate (auto-merge only patch-level, tests green, no API changes; else human approval) -> PR with evidence.
- SLSA-style provenance for agent-built artifacts and pinned lockfiles prevent the agent from introducing unvetted artifacts.

### Gaps
- I did not retrieve specific SLSA text about AI agents; SLSA guidance applies generically (build provenance, isolated builders) but no AI-specific SLSA doc was verified.

## Q5. Security risks of LLM agents on untrusted repos and mitigations

### Takeaway
Repo content, issues, advisories and dependency READMEs are attacker-controlled input; with broad tokens and an outbound channel (PR creation) an agent can be hijacked to leak data ("lethal trifecta"). Mitigations are architectural: least-privilege, scoped tokens, isolation, treat retrieved content as untrusted, human approval.

### Cited Findings
- Invariant Labs (May 2025): the official GitHub MCP server can be abused via a malicious issue in a public repo; agent reads it, pulls private-repo data, and leaks it in an auto-created PR on the public repo. No server bug needed; cannot be fixed by server patch, requires architectural controls. Broad PATs are the amplifier; repo-scoped tokens block it. — [Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability); [DevClass](https://devclass.com/2025/05/27/researchers-warn-of-prompt-injection-vulnerability-in-github-mcp-with-no-obvious-fix/); [GitHub issue #844](https://github.com/github/github-mcp-server/issues/844)
- Simon Willison's "lethal trifecta": access to private data + exposure to malicious instructions + ability to exfiltrate. — [DevClass](https://devclass.com/2025/05/27/researchers-warn-of-prompt-injection-vulnerability-in-github-mcp-with-no-obvious-fix/)
- OWASP Top 10 for Agentic Applications (OWASP GenAI Security Project, published 2025-12-09; ASI01-ASI10): ASI01 Agent Goal Hijack (malicious instructions in content the agent reads; mitigate by treating retrieved content as untrusted, alerting on goal/tool shifts); ASI02 Tool Misuse & Exploitation (mitigate with least-privilege functions). Extends, not replaces, OWASP Top 10 for LLM Apps. — [Teleport summary](https://goteleport.com/blog/owasp-top-10-agentic-applications); [Cycode summary](https://cycode.com/blog/owasp-top-10-agentic-applications/)
- Slopsquatting: attackers register package names that LLMs repeatedly hallucinate; term coined April 2025 by Seth Larson (PSF). — [Netwrix](https://netwrix.com/en/resources/blog/slopsquatting/)

### Inferences
- Design controls: read-only, repo-scoped tokens for analysis; separate write identity only for PR creation; no secrets in build sandbox (network egress allowlist to package registries only); treat advisory text, READMEs, changelogs, issues as data (never instructions); validate every package name/version against registry + age/reputation (Socket-style) before install; human approval for any change touching CI config, build scripts, or lockfile sources.
- Running untrusted install scripts (npm postinstall, setup.py) during verification builds is itself a supply-chain risk - use ephemeral, network-restricted sandboxes.

### Gaps
- Official OWASP Agentic Top 10 text was not fetched directly (secondary summaries used). Specific incidents of prompt injection via security advisories (GHSA/OSV text) were not found.
