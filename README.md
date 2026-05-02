# **HECTOR – Explainable Port Risk Assessment System**

HECTOR is a cybersecurity tool that converts raw Nmap scan results into **prioritized, explainable risk insights**.

Unlike traditional scanners that only list open ports, HECTOR identifies:
**what is risky, why it is risky, and what should be prioritized for remediation.**

---

## Core Idea

HECTOR uses a **hybrid risk scoring model** combining:

* **Heuristic risk (H)** — domain knowledge of services
* **CVSS score (C)** — real-time CVE data from NVD
* **Port weight (W)** — contextual exposure relevance

**Final Score = (0.4H + 0.6C) × W**
(with fallback logic when data is unavailable)

The primary contribution of this project is the design and implementation of an **explainable hybrid risk-scoring engine**.

The model combines:

* **Heuristic service risk knowledge** (domain-specific rules)
* **CVSS-based vulnerability intelligence** (NVD integration)
* **Port-level contextual weighting** (practical exposure sensitivity)

These components are fused into a **single normalized risk score**, which is further mapped to operational severity levels (LOW, MEDIUM, HIGH, CRITICAL).

This approach ensures that the system:

* **Accounts for real-world context**, not just theoretical severity
* **Maintains interpretability**, with full visibility into scoring factors
* **Supports prioritization**, enabling efficient remediation decisions

---
## **System Architecture**

The system follows a modular pipeline:

<img width="750" height="350" alt="image" src="https://github.com/user-attachments/assets/88a07cab-f7da-4994-b593-e5c50f518053" />

---

## Output

For each open port:

* Risk score (0–10)
* Severity (LOW → CRITICAL)
* CVE mapping
* Attack classification
* Full scoring breakdown (transparent and auditable)

<img width="1919" height="1033" alt="Screenshot 2026-04-30 120518" src="https://github.com/user-attachments/assets/dd3e641d-90f8-4809-8ef0-ea9cb0e8a2fb" />


<img width="1902" height="968" alt="Screenshot 2026-04-30 121416" src="https://github.com/user-attachments/assets/971baca5-cf00-4339-a89d-169739a4edb0" />


<img width="1917" height="1029" alt="Screenshot 2026-04-29 192953" src="https://github.com/user-attachments/assets/4ba302a6-f731-415e-a2c1-75afd096aee5" />


<img width="1881" height="1035" alt="Screenshot 2026-04-29 193016" src="https://github.com/user-attachments/assets/ed08b6ba-0187-40ed-91ed-32c0a4740838" />


<img width="1873" height="1029" alt="Screenshot 2026-04-29 193136" src="https://github.com/user-attachments/assets/e8536410-275a-4cf5-8d23-a5c5b6192b75" />


<img width="1888" height="966" alt="Screenshot 2026-04-29 193408" src="https://github.com/user-attachments/assets/4efc5b6c-ab89-47b3-a8cb-fabb49ccfa74" />


---

## Key Features

### Hybrid Risk Scoring

* Combines heuristics, CVSS, and contextual weighting
* Produces more realistic prioritization than single-source models

### Explainability by Design

* Complete visibility into scoring components
* No black-box logic; fully reproducible results

### CVE Intelligence Integration

* Live NVD integration
* Service-to-vulnerability mapping
* Contextual enrichment of scan findings

### Temporal Risk Tracking

* Snapshot-based scan history
* Tracks evolution of risk over time

### Practical Scanning

* Nmap-based scanning engine
* Supports IPs, domains, and URLs
* Input normalization with single-target enforcement

---

## Technology Stack


| Layer       | Technology        | Rationale                                       |
| ----------- | ----------------- | ----------------------------------------------- |
| Frontend    | React             | Structured, modular UI for analytical workflows |
| Backend     | Flask (Python)    | Lightweight API layer for orchestration         |
| Scanning    | Nmap              | Industry-standard network discovery tool        |
| Risk Engine | Python            | Flexibility for custom scoring logic            |
| Data Source | NVD (CVE)         | Authoritative vulnerability intelligence        |
| Storage     | Local persistence | Efficient snapshot-based history tracking       |

---

## Differentiation

* Hybrid scoring model (heuristics + CVE + context)
* Fully explainable risk computation
* Temporal tracking of exposure

---

## Impact

* Converts scan results into actionable priorities
* Reduces manual analysis overhead
* Enables consistent and auditable risk assessment
* Supports continuous monitoring of security posture

---

## Conclusion

HECTOR is an explainable vulnerability triage system that integrates scanning, enrichment, and scoring into a single pipeline.

Its value lies in interpreting and prioritizing exposure with clarity, context, and transparency.

---

## TL;DR

HECTOR does not just detect vulnerabilities — it prioritizes and explains them.
