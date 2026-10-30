# Knowledge sources and retrieval approaches for an LLM supply-chain security agent (as of 2026-10-30)

Labels: [PR] = peer-reviewed, [PP] = arXiv preprint (no venue listed), [V] = vendor/project claim or documentation, [2nd] = secondary/aggregator source.

## 1. Candidate corpora: structure, licensing, APIs, freshness (lookup vs embed)

### Takeaway
Nearly all the high-value vulnerability and threat-intelligence feeds are already structured JSON records: KEV, Vulnrichment/CVE records, OSV/GHSA, OpenSSF malicious-packages and EPSS. They belong in an exact-key lookup (by CVE, GHSA, MAL or package+version), not in a vector index. The unstructured, embed-worthy material is narrow: KEV "notes" and the vendor advisory text they link to, patch commit diffs and messages, PoC and exploit code, Nuclei templates, and CWE/CAPEC/ATT&CK descriptions.

### Cited Findings
- **CISA KEV**
  - The JSON feed is at `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` and the CSV at `.../csv/known_exploited_vulnerabilities.csv`. A JSON schema (`.../feeds/known_exploited_vulnerabilities_schema.json`) was listed as updated 09-02-2026, and the license is at `.../licenses/kev/license.txt`. — [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) [V]
  - Each entry has these fields: vendor/project, product, CVE ID, vulnerability name, description, related CWE(s), known ransomware campaign use ("Known"/"Unknown"), date added, due date, required action and "Additional Notes".
  - As of 2026-10-30 the catalog page also shows a new field, "Forensic triage required per BOD 26-04".
  - The catalog showed 1,764 entries, the newest dated 2026-10-14 to 2026-10-29. All 20 most recent entries had ransomware use = "Unknown". — [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) [V]
  - The Notes field holds vendor advisory links, NVD links and BOD 26-04 references. Some entries also give context such as affected third-party components. These notes are the main free text worth embedding or following. — [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) [V]
- **CISA Vulnrichment**
  - Adds the SSVC decision points Exploitation, Automatable and Technical Impact (SSVC tree 2.0.3). For higher-risk CVEs it also adds CWE and CVSS, and for KEV CVEs a KEV block (date added plus reference). — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) [V]
  - Data is JSON CVE records in CISA's ADP container, organized in year folders. It is available via GitHub and the CVE Services API, licensed CC0-1.0.
  - CISA stopped adding CPE strings on 2024-12-10. CISA removes its own assessments if the CNA later supplies CWE, CVSS or CPE. — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) [V]
- **OSV.dev**
  - Aggregates GitHub Advisory DB (CC-BY 4.0), PyPI, Go, RustSec (CC0), OSS-Fuzz, Red Hat, Ubuntu (CC-BY-SA), Chainguard/Wolfi (CC-BY-NC-ND), the OpenSSF Malicious Packages repo (Apache-2.0) and others. It also converts Debian, Alpine and NVD CVEs for open-source software. — [OSV data sources](https://google.github.io/osv.dev/data/) [V]
  - Licenses vary per source, and there is no single license for the aggregate. — [OSV data sources](https://google.github.io/osv.dev/data/) [V]
  - Bulk data is at `gs://osv-vulnerabilities/all.zip` and per ecosystem at `gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip`. Export is described as "continuous". For incremental sync, use `modified_id.csv`, which is in reverse chronological order. — [OSV data sources](https://google.github.io/osv.dev/data/) [V]
  - API: `POST /v1/query`, `/v1/querybatch` and `GET /v1/vulns/{id}`. — [OSV data sources](https://google.github.io/osv.dev/data/) [V]
- **OpenSSF malicious-packages**
  - More than 15,000 malware reports in OSV format, using `MAL-` IDs (e.g. MAL-2025-6812). They can be queried through the OSV API and OSV-Scanner. Retracted reports are kept in a separate folder. — [awesome.ecosyste.ms summary of ossf/malicious-packages](https://awesome.ecosyste.ms/projects/github.com%2Fossf%2Fmalicious-packages) [2nd]; [ossf/malicious-packages](https://redirect.github.com/ossf/malicious-packages) [V]
  - The GitHub Advisory Database now imports the OpenSSF reports, extending malware advisories and Dependabot alerts beyond npm to eight ecosystems (incl. PyPI, Maven). It skips records tagged `ghsa-malware` to avoid duplicates. Malware alerts are opt-in. — [GitHub blog: How we took malware advisories beyond npm](https://github.blog/security/supply-chain-security/how-we-took-malware-advisories-beyond-npm/) [V]; timing reported as recent on [Cybersecuritynews, 2026-09-01](https://cybersecuritynews.com/github-expands-supply-chain-malware-detection/) [2nd]
- **EPSS**
  - v3 used 1,477 features to predict exploitation activity. — [Jacobs et al., arXiv 2302.14172](https://arxiv.org/pdf/2302.14172) [PP; later published at WEIS 2023 per authors, not verified here]
  - EPSS v4 was released on 2025-03-17, according to secondary sources. — [Infosecurity Europe blog](https://infosecurityeurope.com/en-gb/blog/future-thinking/how-to-integrate-epssv4-vulnerability-system.html) [2nd]
  - A consultant blog claims v4 features include public-exploit availability from GitHub, Exploit-DB, Metasploit and Nuclei, plus NLP features from descriptions. I could not verify this on first.org. — [ayinedjimi-consultants](https://ayinedjimi-consultants.fr/articles/ia-gestion-vulnerabilites-priorisation-epss) [2nd, unverified]
  - EPSS publishes a probability (0–1) and a percentile, both as decimals. — [FIRST EPSS article](https://www.first.org/epss/articles/prob_percentile_bins) [V]
  - SEI/CMU criticism: EPSS lacks transparency and depends on existing CVE IDs, which limits it for zero-days. — [summarized in Infosecurity Europe blog](https://infosecurityeurope.com/en-gb/blog/future-thinking/how-to-integrate-epssv4-vulnerability-system.html) [2nd]

### Inferences
- Proposed classification:
  - **Structured lookup (SQL/KV keyed by CVE/GHSA/MAL/purl):** KEV, Vulnrichment SSVC, EPSS daily scores, OSV/GHSA affected-version ranges, MAL- entries, and the CWE/CAPEC/ATT&CK ID graph.
  - **Embed (vector or hybrid BM25):** advisory prose and KEV notes, the commit message, diff and changed function names from patch commits, PoC/exploit code and Nuclei template matchers (these reveal the attack precondition: endpoint, config, input vector), and CWE/CAPEC descriptions and mitigations.
- "Pre-training on KEV" is a poor fit:
  - KEV is a small (~1.8k rows), frequently appended table that the agent needs exactly and up to date (due dates, ransomware flag, new BOD fields). Exact lookup beats parametric memory.
  - The KEV schema itself changes (the BOD 26-04 field appeared in 2026). Weights trained on an older snapshot would miss such changes, while a lookup tool would not.
- For the "org-wide response to a new KEV entry or malicious package" scenario, do a diff-based daily sync: KEV JSON plus OSV `modified_id.csv`. Then run an exact join against the org's SBOM inventory (purl/CPE). The LLM is needed for the judgment layer, not for matching.

### Gaps
- Not verified in this session (fetch budget):
  - NVD API 2.0 rate limits and its 2024–2026 enrichment backlog
  - Exploit-DB license (GPL-2.0 per memory) and CSV
  - Metasploit module metadata (BSD, `modules_metadata_base.json`)
  - Nuclei templates (MIT; `classification.cve-id` field)
  - PoC-in-GitHub (nomi-sec) structure
  - CWE/CAPEC/ATT&CK STIX bundles (ATT&CK in STIX 2.1 via mitre-attack/attack-stix-data)
  - A report writer should cite primary docs for these before relying on them.
- The KEV license text and the exact JSON field names were not reproduced on the page; the catalog's display label is "Known To Be Used in Ransomware Campaigns?". The JSON key `knownRansomwareCampaignUse` comes from background knowledge and should be checked against the schema file.
- The official EPSS v4 feature list (first.org "/epss/model" returned 404) and API (`api.first.org/data/v1/epss`) were not confirmed.

## 2. Evidence: RAG vs fine-tuning vs plain prompting on security/CTI/vuln tasks

### Takeaway
Fine-tuning or continued pretraining helps on fixed-label classification (CVE→CWE). RAG helps when the task depends on facts that change or are code-specific. Plain frontier models already do reasonably well on binary "affected/not affected" judgments but are weak on fine-grained justification. No study found does a head-to-head RAG vs fine-tune comparison on exploitability judgment.

### Cited Findings
- **CTIBench** (Alam et al., NeurIPS 2024 Datasets & Benchmarks) [PR]
  - Tasks: CTI-MCQ (knowledge), CTI-RCM (CVE→CWE root-cause mapping), CTI-VSP (CVSS vector prediction), CTI-ATE (ATT&CK technique extraction) and CTI-TAA (threat-actor attribution).
  - Models evaluated: GPT-3.5, GPT-4, Gemini-1.5, LLaMA3-70B and 8B.
  - Finding: LLMs have general CTI understanding but sometimes misattribute. No RAG arm was found in the summaries.
  - Sources: [NeurIPS proceedings](https://proceedings.neurips.cc/paper_files/paper/2024/hash/5acd3c628aa1819fbf07c39ef73e7285-Abstract.html); [arXiv 2406.07599](https://arxiv.org/abs/2406.07599)
- **Foundation-Sec-8B** (Cisco Foundation AI)
  - Llama-3.1-8B with continued pretraining on a curated security corpus. Submitted 2025-04-28, CC BY 4.0 paper; model is Apache-2.0. — [arXiv 2504.21039](https://arxiv.org/abs/2504.21039) [PP]
  - Model-card results (5-shot), Foundation-Sec-8B vs Llama-3.1-8B vs Llama-3.1-70B: CTI-MCQA 67.39 / 64.14 / 68.23, and CTI-RCM 75.26 / 66.43 / 72.66. — [HF model card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B) [V]
  - The training data cutoff is 2025-04-10. The card states it "may not know recent vulnerabilities" and recommends supplementing it with current threat intelligence. — [HF model card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B) [V]
  - The report claims parity with GPT-4o-mini: 0.8 points behind on MCQA and 6.1 ahead on RCM. — [arXiv 2504.21039 v1 html](https://arxiv.org/html/2504.21039v1) [PP/V]
  - A reasoning variant (Jan 2026) reports CTIBench-MCQA of about 69.1, comparable to Llama-3.3-70B. — [arXiv 2601.21051](https://arxiv.org/html/2601.21051v1) [PP]
- **SECURE benchmark** (Bhusal et al., arXiv 2405.20441, v4 2024-10-30) [PP]
  - ICS-focused benchmark with six datasets and seven models. — [arXiv 2405.20441](https://arxiv.org/abs/2405.20441)
  - A secondary summary reports that on the CWE task Llama3-8B+RAG scored 77.3% vs a fine-tuned model at 85%, with mixed results on other tasks. — [search summary of arXiv 2405.20441 PDF](https://arxiv.org/pdf/2405.20441) [numbers not verified from full text]
- **SOC LLM survey** (arXiv 2509.10858) [PP]
  - Cites work in which large decoder LLMs with RAG beat small fine-tuned encoder models on mapping procedures to ATT&CK tactics.
  - Lists fine-tuned V2W-BERT at F1 0.972 for CVE→CWE. — [arXiv 2509.10858](https://arxiv.org/pdf/2509.10858)
- **Vul-RAG** (Du et al., arXiv 2406.11147, v3 2025-06-17) [PP]
  - Uses "knowledge-level RAG": multi-dimensional knowledge distilled from historical vulnerabilities and their fixes.
  - Without it, LLMs reach only 0.06–0.14 accuracy at telling vulnerable code from patched code. Vul-RAG raises accuracy by 16–24%, and lifts manual detection from 60% to 77%.
  - It found 10 new Linux kernel bugs, 6 of which received CVEs. — [arXiv 2406.11147](https://arxiv.org/abs/2406.11147)
- **Code vulnerability detection: RAG vs SFT vs dual-agent** (arXiv 2601.00254, Jan 2026) [PP]
  - The RAG approach scored the highest accuracy (0.86) and F1 (0.85) among those tested. — [arXiv 2601.00254](https://arxiv.org/html/2601.00254v1)
  - Contrasting study: arXiv 2601.08691 reports that fine-tuning beat zero-shot and few-shot on all code-vuln-analysis tasks. — [arXiv 2601.08691](https://arxiv.org/html/2601.08691v1) [PP]
- **VEX-Bench** (Shi et al., arXiv 2609.08040, submitted 2026-09-07, accepted to EMNLP 2026) [PR-accepted] — the closest benchmark to this project's "real exploitability in a specific codebase" goal
  - 75 expert-labeled real cases mined from GitHub, in Python, Java and Go. Nine models in three agent harnesses.
  - GPT-5.5 and Claude Opus 4.6 reach about 80% F1 on binary affected/not-affected. Only GPT-5.5 exceeds 70% macro-F1 on fine-grained VEX justification.
  - It notes that Dependabot-style coarse matching produces many false alerts. — [arXiv 2609.08040](https://arxiv.org/abs/2609.08040)
- A CEUR-WS paper describes a plan-and-execute LLM agent with retrieval that assesses CVE exploitability in Docker containers using environment data and source code, producing VEX justifications. — [CEUR-WS Vol-3920 paper09](https://ceur-ws.org/Vol-3920/paper09.pdf) [PR workshop]

### Inferences
- Recommendation for this agent: use a frontier general model with tool-based retrieval rather than fine-tuning.
  - The evidence that best matches the task (VEX-Bench, Vul-RAG, the CEUR agent) comes from agentic or RAG setups grounded in code plus advisory and patch knowledge.
  - Fine-tuning gains are concentrated on static label-mapping tasks (CWE), which a lookup handles anyway.
- A small security model (Foundation-Sec-8B) could be an optional on-prem or offline component, for example for CWE mapping or summarization in data-sovereign settings. Its own card says it needs external current threat intelligence.
- The highest-value knowledge for evidence-based exploitability judgment is the **patch diff → vulnerable function/condition**, structured like Vul-RAG's knowledge. The agent can then search the target codebase for reachability of that function or condition. This is "RAG over fix knowledge plus code search", not RAG over CVE descriptions.

### Gaps
- None of the sources found reports the vendor products Sec-Gemini, Microsoft Security Copilot or Google Threat Intelligence + Gemini, and their architectures were not researched (budget). Their vendor announcements would be needed.
- SecLLMHolmes, CyberMetric and SecQA were not fetched.
- I found no published head-to-head RAG vs fine-tune study on exploitability or VEX judgment.

## 3. Knowledge graph / GraphRAG approaches

### Takeaway
Several 2023–2025 works link CVE–CWE–CAPEC–ATT&CK in Neo4j-style graphs for RAG: PNNL CyRAG/GraphCyRAG, CyKG-RAG and CTI-Thinker. They mostly claim better reasoning and explainability, with little rigorous comparison against vector RAG.

### Cited Findings
- **PNNL CyRAG / GraphCyRAG** (2024-11-18) uses Neo4j knowledge graphs over CVE, CWE, CAPEC and ATT&CK. It retrieves interconnected information to reason about attack vectors and mitigations. — [PNNL publication](https://www.pnnl.gov/publications/retrieval-augmented-generation-robust-cyber-defense) [V/PR-unclear]; [NODES 2025 talk](https://neo4j.com/nodes-2025/agenda/cyrag-retrieval-augmented-generation-for-robust-cyber-defense/) [V]
- **CyKG-RAG** is a knowledge-graph-enhanced RAG for cybersecurity that builds on ontologies covering CVE, CVSS and CAPEC. — [CEUR-WS Vol-3950 paper1](https://ceur-ws.org/Vol-3950/paper1.pdf) [PR workshop]
- **CTI-Thinker** (Springer *Cybersecurity*, 2025) builds an ATT&CK-aligned CTI knowledge graph plus a GraphRAG reasoning engine. — [Crossref 10.1186/s42400-025-00505-y](https://api.crossref.org/works/10.1186%2FS42400-025-00505-Y) [PR]
- **VKG2AG** (2025) builds a vulnerability knowledge graph from CVE records to generate attack graphs. It references SecKG2vec embeddings linking CVE, CWE and CAPEC. — [SciTePress 2025](https://www.scitepress.org/publishedPapers/2025/135267/pdf/index.html) [PR]
- **Program Knowledge Graph** (arXiv 2312.04818, 2023) combines CVE/CWE data with program call graphs. An LLM generates graph queries to find vulnerabilities in code. — [arXiv 2312.04818](https://arxiv.org/html/2312.04818v1) [PP]
- A cyber-knowledge-completion study found RAG-based mapping beat nearest-neighbor mapping for CAPEC and ATT&CK. — [arXiv 2409.16176](https://arxiv.org/pdf/2409.16176) [PP]

### Inferences
- For this agent, the useful "graph" is mostly the **org-side dependency graph** linked to vulnerability IDs: SBOM component (purl) → repo/service → owner → deployment/exposure, joined to CVE/GHSA/MAL → CWE → CAPEC/ATT&CK.
  - This is ordinary relational or graph data that can be queried deterministically, for example "which services transitively include package X ≤ version Y, internet-facing, owned by team Z".
  - Full Microsoft-style GraphRAG (LLM-extracted entity graphs plus community summaries) adds cost with no demonstrated benefit for ID-keyed vulnerability data.
- A pragmatic design:
  - a property graph or relational tables for SBOM↔vuln↔asset↔owner, accessed via tool calls
  - vector retrieval for advisory, patch and PoC text
  - the CWE→CAPEC→ATT&CK edges taken from MITRE's own structured releases rather than LLM extraction.

### Gaps
- No rigorous benchmark comparing GraphRAG vs vector RAG on vulnerability tasks was found. The Neo4j "80% more truthful" claim is a vendor claim, not evaluated here.

## 4. Historical KEV entries as exemplars / exploit prediction

### Takeaway
LLM exploit-likelihood judgment is only moderately accurate and biased toward over-prediction. Few-shot exemplars help (best F1 about 0.75–0.79 on SSVC Exploitation in one preprint), but no study found tests retrieval of similar KEV CVEs as exemplars. EPSS remains the calibrated statistical baseline.

### Cited Findings
- **"Prompting the Priorities"** (Al Haddad et al., arXiv 2510.18508, 2025-10-21) [PP]
  - Setup: ChatGPT, Claude, Gemini and DeepSeek, 12 prompting techniques, 384 VulZoo vulnerabilities, over 165k queries. Predicts the SSVC points Exploitation, Automatable, Technical Impact and Mission & Wellbeing.
  - Results: exemplar prompting improved accuracy, all models over-predicted risk, and only DeepSeek reached "fair" weighted agreement. The authors conclude LLMs do not replace expert judgment. — [arXiv 2510.18508](https://arxiv.org/abs/2510.18508)
  - A search snippet reports Few-shot-with-Explanation F1 0.75 and Gemini F1 0.79 on Exploitation. — [arXiv 2510.18508 html](https://arxiv.org/html/2510.18508)
- **Polar** (arXiv 2510.01552) uses LLM reasoning over advisories and KEV to score severity and exploitation likelihood, validated against Exploit-DB, KEV and VirusTotal. — [arXiv 2510.01552](https://arxiv.org/html/2510.01552v1) [PP]
- **TRIAGE** (arXiv 2508.18439) maps CVEs to ATT&CK with MITRE methodology prompting plus an in-context-learning module, evaluated on 296 KEV CVEs. — [arXiv 2508.18439](https://arxiv.org/abs/2508.18439v2) [PP]
- arXiv 2509.23573 uses EPSS as ground truth and as the calibration reference for LLM-based exploitation forecasts. It also studies vulnerabilities of LLM-assisted CTI. — [arXiv 2509.23573](https://arxiv.org/html/2509.23573v1) [PP]
- **AEAS** (arXiv 2509.17832) is an "Actionable Exploit Assessment System" that assesses public exploit artifacts. — [arXiv 2509.17832](https://arxiv.org/pdf/2509.17832) [PP; details not fetched]

### Inferences
- Use KEV history as **retrievable exemplars for explanation**, not as a classifier training set. Given a new CVE, retrieve the k most similar KEV entries (same CWE, product class, attack vector, PoC availability) to ground "why this is likely or unlikely to be exploited". Always show EPSS, KEV status, Vulnrichment SSVC "Exploitation" and PoC/Metasploit/Nuclei existence as hard signals.
- This is a hypothesis to test in the project's own evaluation. No published result was found that retrieval of similar KEV exemplars improves exploitation prediction.
- Because the evidence shows LLMs over-predict risk, the agent's judgment should be anchored on evidence such as reachability in code, configuration preconditions and exposure. Exemplars alone should not drive it.

### Gaps
- No study directly comparing LLM vs EPSS on exploitation prediction was found.
- No study of KEV-exemplar retrieval was found.
- The full results tables of 2510.18508 were not read.

## 5. Freshness and knowledge-cutoff issues

### Takeaway
Model weights are always stale for this domain. For example, Foundation-Sec-8B has a 2025-04-10 cutoff, while KEV received entries as recently as 2026-10-29. All CVE, KEV, malicious-package and EPSS facts must come from daily-synced indexes and tools, with record timestamps cited in agent outputs.

### Cited Findings
- Foundation-Sec-8B's cutoff is 2025-04-10. Its model card says it may not know recent vulnerabilities and should be supplemented with current threat intelligence. — [HF model card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B) [V]
- KEV continuously adds entries (e.g. 20 entries dated 2026-10-14 to 2026-10-29) and has evolved its schema, with the BOD 26-04 forensic-triage field. — [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) [V]
- OSV exports continuously and provides `modified_id.csv` for incremental pulls. — [OSV data](https://google.github.io/osv.dev/data/) [V]
- Vulnrichment assessments can be removed when CNAs add data, so cached copies can diverge from the current record. — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) [V]
- OpenSSF malicious-package reports can be retracted, and retracted reports go to a separate folder. — [ecosyste.ms summary](https://awesome.ecosyste.ms/projects/github.com%2Fossf%2Fmalicious-packages) [2nd]

### Inferences
Freshness design:
- **Daily or hourly jobs:**
  - KEV JSON diff per CVE ID on the full record (not only `dateAdded`), so changes to `knownRansomwareCampaignUse`, `notes`, `requiredAction`, `dueDate` are re-indexed
  - OSV `modified_id.csv` delta, including MAL- entries, withdrawals and retractions
  - EPSS daily score file
  - a Vulnrichment git pull
- **Re-embedding:** only the changed advisory, notes and patch text.
- **Event-driven:** a new KEV or MAL record triggers an SBOM join, which drives org-wide response.
- **Provenance:** store `source`, `modified` and `fetched_at` with every record so the LLM can cite how fresh its evidence is. Treat withdrawn or retracted records as tombstones, not deletions.

### Gaps
- No academic measurement of LLM hallucination rates on post-cutoff CVEs was found in this session.
