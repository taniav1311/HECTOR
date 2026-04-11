

# **HECTOR – Explainable Port Risk Assessment System**

## **Overview**

HECTOR is a security analysis platform that transforms raw network scan results into a **prioritized, explainable risk assessment**.

Conventional port scanners enumerate exposed services but provide limited guidance on remediation. HECTOR addresses this gap by integrating **scan data, vulnerability intelligence, and contextual scoring** into a unified decision framework.

---

## **Technical Contribution**

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
<img width="1016" height="474" alt="image" src="https://github.com/user-attachments/assets/88a07cab-f7da-4994-b593-e5c50f518053" />

---

## **Key Features**

### **1. Hybrid Risk Scoring Engine**

* Weighted fusion of heuristic and CVSS scores
* Port-sensitive risk adjustment
* Deterministic and reproducible scoring logic

---

### **2. Explainability by Design**

Each finding exposes:

* Heuristic contribution
* CVSS contribution
* Base score computation
* Port weighting factor
* Final risk score and severity classification

This ensures the system remains **auditable and transparent**, rather than a black-box predictor.

---

### **3. CVE Intelligence Integration**

* Integration with **NVD data sources**
* Service-to-vulnerability mapping
* Contextual enrichment of scan findings

---

### **4. Temporal Risk Tracking**

* Persistent storage for selected hosts
* Snapshot-based scan history
* Visualization of **risk evolution over time**

This extends the system from a one-time scanner to a **continuous assessment tool**.

---

### **5. Robust and Practical Scanning**

* Nmap-based scanning with fallback strategies
* Support for IPs, domains, and URLs
* Input normalization to enforce safe, single-target scans

---

## **Technology Stack**

| Layer       | Technology        | Rationale                                       |
| ----------- | ----------------- | ----------------------------------------------- |
| Frontend    | React             | Structured, modular UI for analytical workflows |
| Backend     | Flask (Python)    | Lightweight API layer for orchestration         |
| Scanning    | Nmap              | Industry-standard network discovery tool        |
| Risk Engine | Python            | Flexibility for custom scoring logic            |
| Data Source | NVD (CVE)         | Authoritative vulnerability intelligence        |
| Storage     | Local persistence | Efficient snapshot-based history tracking       |

---

## **Novelty and Differentiation**

HECTOR distinguishes itself in three key ways:

1. **Hybrid Scoring Model**
   Moves beyond single-source scoring by combining **local heuristics and external CVE intelligence**.

2. **Explainable Risk Computation**
   Every score is **fully decomposable**, enabling verification and trust.

3. **Temporal Risk Perspective**
   Introduces **time-based analysis of exposure**, which is typically absent in basic scanning tools.

---

## **Impact**

HECTOR bridges the gap between **technical detection and operational decision-making**.

* Converts scan outputs into **prioritized actions**
* Reduces cognitive load in vulnerability analysis
* Enables **repeatable and auditable security assessments**
* Supports monitoring of **security posture over time**

---

## **Conclusion**

HECTOR is an **explainable vulnerability triage system** that integrates scanning, enrichment, and scoring into a coherent analytical pipeline.

Its primary value lies not in detecting exposure, but in **interpreting and prioritizing it with clarity and rigor**.
