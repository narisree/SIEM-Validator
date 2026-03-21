# SIEM Use Case Validation Agent

An AI-powered Streamlit application that guides security analysts through the validation of SIEM detection rules against acceptance checkpoints. Generates a professional PDF report with pass/fail status and AI assessments.

## Features

- **9 Validation Checkpoints** covering logs, rule logic, query aspects, enrichment, MITRE ATT&CK, alert grouping, testing, production validation, and false positive rates
- **AI-Powered Validation** using Claude API for judgment-heavy checkpoints (rule-vs-objective, MITRE mapping, enrichment, grouping, test results)
- **SPL Query Parsing** — automatically extracts indexes, sourcetypes, fields, lookups, thresholds, and time ranges
- **Splunk-Optional** — analysts can paste exported data instead of requiring live API access
- **PDF Report Generation** with summary dashboard, checkpoint-by-checkpoint results, and AI assessments
- **Live Sidebar Tracker** showing real-time pass/fail/review status

## Setup

### Prerequisites
- Python 3.9+
- Claude API key (optional, for AI validation features)

### Installation

```bash
pip install -r requirements.txt
```

### Running Locally

```bash
streamlit run app.py
```

### Deploy to Streamlit Community Cloud

1. Push this repo to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Connect your GitHub repo
4. Set the main file as `app.py`
5. Deploy

## Usage

1. **Enter use case information** — name, ID, analyst, description/objective
2. **Paste the SPL query** — the app auto-parses fields, indexes, thresholds
3. **Work through each checkpoint** — provide evidence, use AI validation or manual pass/fail
4. **Generate PDF report** — download a comprehensive validation report

## Checkpoints Covered

| # | Checkpoint | Validation Method |
|---|-----------|------------------|
| 1 | Logs & Fields Availability | SPL parsing + manual |
| 2 | Rule Built as Per Objective | AI (Claude API) |
| 3 | Query Aspects (threshold, conditions, severity, frequency, lookback) | SPL parsing + manual |
| 4 | Enrichment Sources | AI (Claude API) |
| 5 | MITRE ATT&CK Mapping | AI (Claude API) |
| 6 | Alert Grouping / Correlation | AI (Claude API) |
| 7 | Historical / Simulated Testing | AI (Claude API) + manual |
| 8 | Production Trigger Validation | AI (Claude API) + manual |
| 9 | False Positive Rate < 60% | Auto-calculated |

## Architecture

```
Analyst Input (SPL, evidence, notes)
        │
        ▼
┌─────────────────────┐
│   Streamlit App     │
│  ┌───────────────┐  │
│  │ SPL Parser    │  │  ← Auto-extracts fields, indexes, thresholds
│  ├───────────────┤  │
│  │ Checkpoint UI │  │  ← 9 expandable validation sections
│  ├───────────────┤  │
│  │ Claude API    │  │  ← AI judgment for checkpoints 2,4,5,6,7,8
│  ├───────────────┤  │
│  │ PDF Generator │  │  ← ReportLab-based report output
│  └───────────────┘  │
└─────────────────────┘
        │
        ▼
   PDF Validation Report
```
