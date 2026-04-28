# SOC & Defensive Security Portfolio

> Enterprise security operations work, case studies, and incident response simulations.

Maintained by **Chima Anthony Ukachukwu** — Cybersecurity Analyst (SOC + AI Security)
Portfolio: [chimaukachukwu.com](https://chimaukachukwu.com) · LinkedIn: [chima-anthony-u](https://linkedin.com/in/chima-anthony-u)

---

## What this repo is

A consolidated set of case studies and methodology notes from defensive security work — production SOC operations, threat intelligence automation, detection engineering, and structured industry simulations. Sanitized to remove client-identifiable details and protected indicators; the methodologies, architecture choices, and lessons learned are public.

---

## 1. MISP Threat Intelligence Automation — Hobby Lobby Corporate IS

**Context.** Internship in Hobby Lobby's Corporate Information Systems Network Security team (May–Aug 2024). Embedded with the SOC team to operationalize the [MISP (Malware Information Sharing Platform)](https://www.misp-project.org/) for threat intelligence ingestion and enrichment.

**Problem.** The team had MISP available but no standardized deployment pattern, no automated ingestion of community feeds, and no documented onboarding for new analysts. Analysts were manually pulling indicators when they remembered to.

**What I built.**

1. **Containerized deployment.** Migrated MISP to a Docker-Compose-based deployment with versioned configuration, allowing fast spin-up of clean instances for testing and a documented rollback path.
2. **Feed ingestion automation.** Wrote Python scripts to pull from a curated set of community threat feeds (CIRCL OSINT, abuse.ch, AlienVault OTX, etc.), normalize indicators, and push them into MISP on a scheduled cadence.
3. **Enrichment pipeline.** Configured MISP's enrichment modules and added Python wrappers for two internal data sources, so indicators arrived already cross-referenced against the org's existing telemetry.
4. **Documentation.** Wrote a setup runbook and an analyst quick-start guide so the next intern wouldn't have to reverse-engineer the deployment.

**Outcome.** The team had a reproducible MISP environment with daily auto-updated indicators by the end of the internship. Presented the work to senior IT staff at end-of-internship review.

**Stack.** MISP, Docker, Docker-Compose, Python (`requests`, `pymisp`), Linux (Ubuntu), Splunk (downstream consumer).

**What I'd do differently.** The feed ingestion script was a single cron-triggered process. A queue-based worker (Celery + Redis) would be more resilient to slow/failed feeds and scale better as more sources are added.

---

## 2. Splunk SOC Monitoring Walkthrough

A condensed walkthrough of the SOC monitoring workflow I learned and contributed to during the same internship. Sanitized — no real alert content, no infrastructure details.

**Daily analyst loop:**

1. **Triage queue.** Open Splunk Enterprise Security, scan the notable events dashboard for high-severity items overnight.
2. **First-pass classification.** For each notable: true positive, false positive, benign-but-suspicious, or insufficient context. Tag accordingly.
3. **Pivot.** For true positives, pivot from the notable to underlying raw events using SPL searches (saved searches I learned to write and tune).
4. **Correlate.** Cross-reference with MISP indicators, Microsoft Defender alerts, and Imperva WAF logs.
5. **Document.** Every action — even "marked false positive after review" — gets a one-line note in the case management tool. Future-me (and the next analyst) will need that trail.
6. **Hand off.** End-of-shift summary for the next analyst: open cases, pending pivots, anything that needs eyes-on.

**Detection engineering principles I work by:**

- **Detections should be testable.** If I can't write a synthetic event that triggers it, I can't be sure it works.
- **Tune for the org, not the vendor default.** Out-of-the-box rules generate noise that drowns real signal. Every rule that fires should have a documented "why we care" and a tuned threshold.
- **Document the "why," not just the "what."** A detection's note should answer: what behavior, why is it suspicious here, what's the false-positive profile, what should the analyst do.

---

## 3. Forage Cybersecurity Simulations

Completed structured virtual experience programs with several Forage program partners. Each one is a scoped problem set with deliverables; I treat them as exercises in writing for a non-technical executive audience.

| Program | Focus | Deliverable I produced |
|---|---|---|
| **Mastercard** | Threat intelligence | Phishing campaign analysis report and recommended employee training updates |
| **PwC** | Cybersecurity consulting | Risk assessment matrix and remediation roadmap for a hypothetical client |
| **AIG** | Incident management | Post-incident review write-up and policy enforcement recommendations |
| **Tata Group** | Network security | Network segmentation plan with endpoint protection strategy |
| **Telstra** | SOC operations | Phishing detection workflow and escalation matrix |

These are simulation exercises, not real internships at the named companies. They are useful as structured reasoning practice, not as substitutes for production experience.

---

## 4. Methodology and tools

**Tools I work with regularly:**

- **SIEM:** Splunk Enterprise Security, Microsoft Sentinel (lab)
- **EDR:** Microsoft Defender for Endpoint
- **WAF:** Imperva (production), ModSecurity (lab)
- **Threat intel:** MISP, AlienVault OTX, CIRCL OSINT feeds
- **Vulnerability management:** Nessus, Nmap
- **Packet analysis:** Wireshark, tcpdump
- **Scripting:** Python, PowerShell, Bash
- **Container / lab:** Docker, VirtualBox, Windows Server, Ubuntu
- **Compliance frameworks:** NIST CSF, ISO 27001, HIPAA

**Operating principles:**

- **Document in real time.** Notes written after the fact lose detail.
- **Treat every false positive as a tuning opportunity.** A false positive that fires twice is an unsolved problem.
- **Bias toward actionable detections.** A detection that fires but no one knows what to do with it isn't a detection — it's noise.
- **Build for the next analyst, not for myself.** Every script, runbook, and detection should be readable by someone who hasn't been in the conversation that produced it.

---

## Other portfolio repos

- [`ai-red-teaming-frameworks`](https://github.com/chima-ukachukwu-sec/ai-red-teaming-frameworks) — AI/LLM offensive evaluation frameworks
- [`ai-evaluation-safety-portfolio`](https://github.com/chima-ukachukwu-sec/ai-evaluation-safety-portfolio) — NDA-compliant AI safety evaluation case studies
- [`portfolio-chima-ukachukwu`](https://github.com/chima-ukachukwu-sec/portfolio-chima-ukachukwu) — Source for [chimaukachukwu.com](https://chimaukachukwu.com)

---

## Contact

- **Email:** chima.ukachukwu.sec@gmail.com
- **LinkedIn:** [chima-anthony-u](https://linkedin.com/in/chima-anthony-u)
- **Portfolio:** [chimaukachukwu.com](https://chimaukachukwu.com)
