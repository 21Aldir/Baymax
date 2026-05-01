# Baymax — AI-Powered GRC Gap Analysis

<img width="824"  alt="image" src="https://github.com/user-attachments/assets/90ba2728-4ecd-47e9-970a-498f1ca27420" />

> *Policy health check for GRC professionals.* Upload a security policy, pick a framework (NIST CSF 2.0, ISO/IEC 27001:2022, or SOC 2), and get a gap analysis with cited evidence, a compliance score, and prioritized remediation recommendations — all exportable to a polished executive PDF report.

<!-- ╔══════════════════════════════════════════════════════════╗
     ║  SCREENSHOT — Hero / landing screen                      ║
     ╚══════════════════════════════════════════════════════════╝ -->
<img width="824" height="776" alt="image" src="https://github.com/user-attachments/assets/cfb763ee-08c5-4b90-b330-c302b6578b2f" />


---

## Table of contents

- [What problem does it solve?](#what-problem-does-it-solve)
- [Features](#features)
- [Supported frameworks](#supported-frameworks)
- [Architecture](#architecture)
- [How the analysis works](#how-the-analysis-works)
- [Tech stack](#tech-stack)
- [Usage](#usage)
- [Project structure](#project-structure)


---

## What problem does it solve?

A manual gap analysis against a framework like NIST CSF 2.0 (106 subcategories), ISO 27001:2022 (93 controls), or SOC 2 can take **days of GRC analyst time** per document: read the policy, map every paragraph to the relevant controls, cite the evidence, assign a status (met / partial / missing), and write up actionable recommendations.

**Baymax automates the first pass** of that work:

- Takes the policy as input (PDF or TXT).
- Validates that the document is actually security / compliance related (pre-filter).
- Maps the content against the selected framework using an LLM (Gemini 2.5 Flash).
- For every control returns: status, compliance level (%), **verbatim evidence quote**, actionable recommendation, confidence score, and priority.
- Generates an executive-ready PDF report for auditors or steering committees.

> The goal is not to replace the analyst, but to **shrink the time between "I have the policy" and "I have a defensible starting point"** from days to minutes.

---

## Features

- **Multi-framework**: NIST CSF 2.0, ISO/IEC 27001:2022 Annex A, SOC 2 Trust Services Criteria.
- **Pre-validation of the document** — rejects non-security documents before spending tokens on the analysis.
- **Verbatim evidence quotes** from the document (≤150 chars per control) — auditor-friendly, no fabrication.
- **Weighted compliance score**: `(met + 0.5·partial) / total · 100`.
- **Prioritized remediations** (high / medium / low) sorted by urgency in the report.
- **In-memory caching** (SHA-256 of doc + framework key) — re-analyzing the same document is instant.
- **Executive PDF export** with summary, per-control detail table, and a prioritized recommendations block.
- **Zero-evidence filter**: the model only returns controls with actual findings, avoiding noise from trivially-missing controls.
- **Single-page UI** with smooth transitions (anime.js), dark theme, and Space Grotesk typography.

---

## Supported frameworks

| Framework | Version | Controls / Items | Source |
|---|---|---|---|
| **NIST Cybersecurity Framework** | CSF 2.0 (Feb 2024) | 6 functions · 22 categories · 106 subcategories | NIST CSWP 29 |
| **ISO/IEC 27001** | 2022 (Annex A) | 93 controls | ISO/IEC 27001:2022 + 27002:2022 |
| **SOC 2** | TSC 2017 (rev. 2022) | Common Criteria + additional categories | AICPA |

Frameworks live as declarative JSON files in `frameworks/` — adding a new one is a matter of writing the file and registering its key in `FRAMEWORK_FILES`.

<!-- ╔══════════════════════════════════════════════════════════╗
     ║  SCREENSHOT — Framework selector                         ║
     ╚══════════════════════════════════════════════════════════╝ -->

<img width="636" height="641" alt="image" src="https://github.com/user-attachments/assets/2cda8c45-47dd-4447-9324-92e07be06ab4" />


---

## Architecture

```
┌─────────────────┐    POST /analyze    ┌──────────────────────┐
│   Browser       │  ─────────────────▶ │   Flask (app.py)     │
│   (index.html)  │  multipart upload   │                      │
└────────┬────────┘                     └─────────┬────────────┘
         │                                        │
         │  JSON result                           │ 1. extract_text (pypdf)
         │ ◀───────────────────────────────────── │ 2. SHA-256 hash → cache lookup
         │                                        │ 3. is_compliance_document?
         │                                        │ 4. build_prompt(controls)
         │  POST /export-pdf                      │ 5. Haiku 4.5 Flash
         │ ─────────────────────────────────────▶ │ 6. parse → JSON array
         │  application/pdf                       │ 7. compute_score
         │ ◀───────────────────────────────────── │ 8. cache + return
         │   (reportlab)                          │
                                                  ▼
                                        ┌──────────────────────┐
                                        │  Claude  API   │
                                        │  (Haiku/Sonnet)  │
                                        └──────────────────────┘
```

**Two endpoints, no database.** State lives in memory (`_validation_cache` and `_analysis_cache`); uploads are temporary and deleted after the analysis completes.

---
<img width="242" height="386" alt="image" src="https://github.com/user-attachments/assets/c25c7563-38b1-4a51-bc3e-50470396b0f8" />

## How the analysis works

1. **Extraction** (`pdf_to_markdown`): the PDF is converted to lightweight Markdown — ALL-CAPS lines are promoted to `##`, Title Case to `###`, and bullets are normalized. This gives the LLM a hierarchical structure that's easier to map than flat text.
2. **Hash + cache**: SHA-256 of the extracted text. If this document has already been analyzed against this framework, the cached result is returned immediately.
3. **Relevance pre-filter**: before the expensive analysis, Claude is asked with `max_tokens=5` whether the document deals with infosec / compliance / privacy / governance. If the answer doesn't start with "YES", the request aborts with a clear error. This avoids spending 32K tokens analyzing a restaurant menu.
4. **Analysis prompt** (`build_prompt`): the model receives a role ("senior GRC analyst"), a 12K-character excerpt of the document, the slimmed `{id, name}` list of controls, and a strict JSON contract for the output.
5. **Defensive parsing** (`parse`): code fences are stripped, the first `[` and last `]` are located, and `json.loads` runs on that slice. Resilient to the "thinking" preambles Gemini 2.5 sometimes emits.
6. **Scoring**: `(met + 0.5 × partial) / total × 100`. Controls that the model omitted due to total absence of evidence don't penalize the score (design decision — see below).
7. **PDF (`/export-pdf`)**: ReportLab renders a 4-section layout — meta header, executive summary, color-coded per-control detail table, and a recommendations block sorted by priority.

<!-- ╔══════════════════════════════════════════════════════════╗
     ║  SCREENSHOT — Results view with score                    ║
     ╚══════════════════════════════════════════════════════════╝ -->

<img width="901" height="446" alt="image" src="https://github.com/user-attachments/assets/1d74db16-958b-4c6c-acf3-309216a3aa40" />


---

## Tech stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11+, Flask 3 |
| **LLM** | Anthropic Claude Haiku 4.5  |
| **PDF in** | pypdf 4 |
| **PDF out** | ReportLab 4 (Platypus) |
| **Frontend** | Vanilla HTML/CSS/JS + anime.js for transitions |
| **Typography** | Space Grotesk + Space Mono (Google Fonts) |
| **Config** | python-dotenv (`.env`) |

No database, no frontend framework, no container — a single `python app.py` boots the whole thing.

---


## Usage

1. **Upload** a security policy (PDF or TXT, up to 16 MB).
2. **Select** one of the three available frameworks.
3. **Wait** ~10–30 seconds — the analysis runs in a single LLM call.
4. **Review** the results: overall score, met/partial/missing distribution, per-control evidence, and recommendations.
5. **Export** to an executive PDF to share with stakeholders.

<!-- ╔══════════════════════════════════════════════════════════╗
     ║  SCREENSHOT — Generated PDF report (pages 1-2)           ║
     ╚══════════════════════════════════════════════════════════╝ -->

<img width="1196" height="140" alt="image" src="https://github.com/user-attachments/assets/049cb829-2569-4567-ba4f-244154a1cc0c" />

<img width="776" height="308" alt="image" src="https://github.com/user-attachments/assets/5ab22f4c-30ff-41b8-b12a-dd1d9c090194" />

<img width="660" height="445" alt="image" src="https://github.com/user-attachments/assets/6800d9a0-d408-4930-bf9e-461405421859" />
<img width="675" height="590" alt="image" src="https://github.com/user-attachments/assets/f563da84-bb9d-4f7d-a90e-b0ae54f4621f" />



## Screenshots

<!-- Replace these with your real screenshots. Suggested naming:
     docs/screenshots/01-hero.png
     docs/screenshots/02-framework-selector.png
     docs/screenshots/03-results.png
     docs/screenshots/04-pdf-report.png
     docs/screenshots/05-recommendations.png
-->


---

## Project structure

```
Baymax/
├── app.py                    # Flask app + analysis and PDF logic
├── requirements.txt
├── frameworks/
│   ├── nist_csf.json         # NIST CSF 2.0 — 106 subcategories
│   ├── iso_27001.json        # ISO/IEC 27001:2022 — 93 controls
│   └── soc2.json             # SOC 2 TSC
├── templates/
│   └── index.html            # SPA — every screen lives in one HTML file
├── static/
│   └── style.css
└── uploads/                  # Temporary — files are deleted after analysis
```

---

Roadmap ideas:

- [ ] Multi-framework crosswalk (one control mapped against all three at once).
- [ ] Per-organization history + diff between revisions of the same policy.
- [ ] Integration with evidence repositories (Drive / SharePoint).
- [ ] HIPAA, PCI DSS, CIS Controls support.
- [ ] "Assistant" mode: chat about the findings, not just a static report.

---


---

<sub>Built by E.Aldir Alcalá · 2026 · Questions or feedback: [LinkedIn(https://www.linkedin.com/in/aldiralcala/)</sub>
