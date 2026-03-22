import streamlit as st
import json
import re
import io
import zipfile
import pandas as pd
from datetime import datetime

# --- Page Config ---
st.set_page_config(
    page_title="SIEM Use Case Validator",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- Custom CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    .stApp { font-family: 'IBM Plex Sans', sans-serif; }

    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%);
        padding: 2rem 2.5rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        border-left: 5px solid #38bdf8;
    }
    .main-header h1 { color: #f1f5f9; font-size: 1.8rem; font-weight: 700; margin: 0; letter-spacing: -0.02em; }
    .main-header p  { color: #94a3b8; font-size: 0.95rem; margin: 0.3rem 0 0 0; }

    .status-badge {
        display: inline-block;
        padding: 0.2rem 0.7rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .status-pass    { background: #dcfce7; color: #166534; }
    .status-fail    { background: #fee2e2; color: #991b1b; }
    .status-review  { background: #fef3c7; color: #92400e; }
    .status-pending { background: #f1f5f9; color: #475569; }

    .ai-assessment {
        background: #f0f9ff;
        border: 1px solid #bae6fd;
        border-radius: 8px;
        padding: 1rem;
        margin-top: 0.5rem;
        font-size: 0.9rem;
    }
    .ai-assessment-header { font-weight: 600; color: #0369a1; margin-bottom: 0.5rem; }

    .cp-card {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 0.8rem 1rem;
        margin-bottom: 0.5rem;
        border-left: 4px solid #64748b;
    }
    .cp-card.pass   { border-left-color: #22c55e; }
    .cp-card.fail   { border-left-color: #ef4444; }
    .cp-card.review { border-left-color: #f59e0b; }

    div[data-testid="stExpander"] {
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        margin-bottom: 0.6rem;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)


# =====================================================
# CONSTANTS
# =====================================================

CHECKPOINT_NAMES = {
    "cp1": "1. Logs & Fields Availability",
    "cp2": "2. Rule Built as Per Objective",
    "cp3": "3. Query Aspects Validation",
    "cp4": "4. Enrichment Sources",
    "cp5": "5. MITRE ATT&CK Mapping",
    "cp6": "6. Alert Grouping / Correlation",
    "cp7": "7. Historical / Simulated Testing",
    "cp8": "8. Production Trigger Validation",
    "cp9": "9. False Positive Rate",
}

STATUS_ICONS = {"pass": "PASS", "fail": "FAIL", "review": "REVIEW", "pending": "PENDING"}

VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}

SPLUNK_SIGNATURE_COLS    = {"title", "search", "alert.severity", "cron_schedule", "dispatch.earliest_time"}
SENTINEL_SIGNATURE_COLS  = {"displayname", "queryfrequency", "queryperiod", "tactics", "techniques"}
CHRONICLE_SIGNATURE_COLS = {"rule_name", "rule_text", "meta.description", "meta.attack_tactic"}

COLUMN_MAPS = {
    "splunk": {
        "use_case_name":    ["title"],
        "query":            ["search"],
        "description":      ["description"],
        "severity":         ["alert.severity"],
        "frequency":        ["cron_schedule"],
        "lookback":         ["dispatch.earliest_time"],
        "grouping_fields":  ["alert.suppress.fields"],
        "mitre_techniques": ["mitre_techniques", "mitre.technique"],
        "mitre_tactics":    ["mitre_tactics", "mitre.tactic"],
        "enrichment_notes": ["enrichment_notes"],
        "test_result_count":["test_result_count"],
        "total_alerts":     ["total_alerts"],
        "true_positives":   ["true_positives"],
        "use_case_id":      ["id", "savedsearch_id", "use_case_id"],
    },
    "sentinel": {
        "use_case_name":    ["displayName", "displayname", "name"],
        "query":            ["query"],
        "description":      ["description"],
        "severity":         ["severity"],
        "frequency":        ["queryFrequency", "queryfrequency"],
        "lookback":         ["queryPeriod", "queryperiod"],
        "grouping_fields":  ["groupingConfiguration", "groupingconfiguration"],
        "mitre_techniques": ["techniques"],
        "mitre_tactics":    ["tactics"],
        "enrichment_notes": ["enrichmentNotes", "enrichmentnotes", "enrichment_notes"],
        "test_result_count":["test_result_count"],
        "total_alerts":     ["total_alerts"],
        "true_positives":   ["true_positives"],
        "use_case_id":      ["id", "name", "use_case_id"],
    },
    "chronicle": {
        "use_case_name":    ["rule_name", "name"],
        "query":            ["rule_text", "query"],
        "description":      ["meta.description", "description"],
        "severity":         ["severity", "meta.severity"],
        "frequency":        ["frequency", "run_frequency"],
        "lookback":         ["lookback", "lookback_period"],
        "grouping_fields":  ["grouping_fields"],
        "mitre_techniques": ["meta.attack_technique", "techniques"],
        "mitre_tactics":    ["meta.attack_tactic", "tactics"],
        "enrichment_notes": ["enrichment_notes"],
        "test_result_count":["test_result_count"],
        "total_alerts":     ["total_alerts"],
        "true_positives":   ["true_positives"],
        "use_case_id":      ["rule_id", "id", "use_case_id"],
    },
}

SIEM_LABELS = {
    "splunk":    "Splunk",
    "sentinel":  "Microsoft Sentinel",
    "chronicle": "Google Chronicle",
    "unknown":   "Unknown",
}


# =====================================================
# SESSION STATE INITIALIZATION
# =====================================================

def init_session_state():
    defaults = {
        "page":             "upload",
        "api_key":          "",
        "siem_type":        "unknown",
        "raw_df":           None,
        "normalized_df":    None,
        "processing_done":  False,
        "results":          {},
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_session_state()


# =====================================================
# HELPER: SPL PARSING
# =====================================================

def parse_spl_fields(spl_query):
    result = {"indexes": [], "sourcetypes": [], "fields": [], "lookups": [], "timerange": ""}
    if not spl_query:
        return result
    idx_matches = re.findall(r'index\s*=\s*["\']?(\S+?)["\']?\s', spl_query + " ")
    result["indexes"] = list(set(idx_matches))
    st_matches = re.findall(r'sourcetype\s*=\s*["\']?(\S+?)["\']?\s', spl_query + " ")
    result["sourcetypes"] = list(set(st_matches))
    field_patterns = [
        r'\|\s*(?:stats|eventstats)\s+\w+\((\w+)\)',
        r'\|\s*(?:eval|where)\s+(\w+)\s*[=<>!]',
        r'\|\s*table\s+([\w\s,]+)',
        r'\|\s*fields\s+[+-]?\s*([\w\s,]+)',
        r'\|\s*rename\s+(\w+)',
        r'by\s+([\w,\s]+?)(?:\||\s*$)',
    ]
    for pattern in field_patterns:
        for m in re.findall(pattern, spl_query):
            result["fields"].extend([f.strip() for f in m.split(",") if f.strip()])
    result["fields"] = list(set(result["fields"]))
    lookup_matches = re.findall(r'(?:lookup|inputlookup|outputlookup)\s+(\S+)', spl_query)
    result["lookups"] = list(set(lookup_matches))
    time_match = re.search(r'earliest\s*=\s*(\S+)', spl_query)
    if time_match:
        result["timerange"] = time_match.group(1)
    return result


def extract_thresholds(spl_query):
    thresholds = []
    if not spl_query:
        return thresholds
    for p in [r'where\s+(\w+)\s*([><=!]+)\s*(\d+)', r'count\s*([><=!]+)\s*(\d+)']:
        for m in re.findall(p, spl_query):
            if len(m) == 3:
                thresholds.append(f"{m[0]} {m[1]} {m[2]}")
            elif len(m) == 2:
                thresholds.append(f"count {m[0]} {m[1]}")
    return thresholds


# =====================================================
# HELPER: CLAUDE AI VALIDATION
# =====================================================

def validate_with_ai(checkpoint_id, context_data, api_key):
    import urllib.request
    import ssl

    prompts = {
        "cp2": (
            "You are a SIEM security analyst. Compare this use case objective with the detection query "
            "and determine if the rule is built correctly to achieve the objective.\n\n"
            f"Use Case Objective: {context_data.get('objective', 'Not provided')}\n"
            f"Detection Query: {context_data.get('spl_query', 'Not provided')}\n"
            f"Parsed Fields: {json.dumps(context_data.get('parsed', {}), indent=2)}\n\n"
            "Evaluate:\n"
            "1. Does the query logic match the stated objective?\n"
            "2. Are there any gaps between what the objective describes and what the query detects?\n"
            "3. Are there any obvious issues with the query?\n\n"
            "Respond with:\n"
            "- STATUS: PASS / FAIL / NEEDS REVIEW\n"
            "- ASSESSMENT: 2-3 sentences explaining your evaluation\n"
            "- RECOMMENDATIONS: Any specific improvements (if applicable)"
        ),
        "cp4": (
            "You are a SIEM security analyst. Evaluate whether this use case has appropriate enrichment sources.\n\n"
            f"Use Case Name: {context_data.get('use_case_name', 'Not provided')}\n"
            f"Use Case Objective: {context_data.get('objective', 'Not provided')}\n"
            f"Detection Query: {context_data.get('spl_query', 'Not provided')}\n"
            f"Detected Lookups/Enrichments: {json.dumps(context_data.get('lookups', []))}\n"
            f"Analyst Notes on Enrichment: {context_data.get('enrichment_notes', 'Not provided')}\n\n"
            "Evaluate:\n"
            "1. Are there enrichment sources (lookups, threat intel, asset/identity) in the query?\n"
            "2. For this type of use case, what enrichments would typically be expected?\n"
            "3. Are any critical enrichments missing?\n\n"
            "Respond with:\n"
            "- STATUS: PASS / FAIL / NEEDS REVIEW / NOT APPLICABLE\n"
            "- ASSESSMENT: 2-3 sentences\n"
            "- RECOMMENDATIONS: Specific enrichment suggestions if missing"
        ),
        "cp5": (
            "You are a SIEM security analyst expert in MITRE ATT&CK framework. "
            "Validate the MITRE mapping for this use case.\n\n"
            f"Use Case Name: {context_data.get('use_case_name', 'Not provided')}\n"
            f"Use Case Objective: {context_data.get('objective', 'Not provided')}\n"
            f"Detection Query: {context_data.get('spl_query', 'Not provided')}\n"
            f"Mapped MITRE Techniques: {context_data.get('mitre_techniques', 'Not provided')}\n\n"
            "Evaluate:\n"
            "1. Do the mapped MITRE ATT&CK techniques correctly align with what this rule detects?\n"
            "2. Are there any techniques that should be mapped but are not?\n"
            "3. Are any of the current mappings incorrect or a stretch?\n\n"
            "Respond with:\n"
            "- STATUS: PASS / FAIL / NEEDS REVIEW\n"
            "- ASSESSMENT: 2-3 sentences\n"
            "- RECOMMENDATIONS: Correct technique IDs if mapping is wrong"
        ),
        "cp6": (
            "You are a SIEM security analyst. Evaluate the alert grouping and correlation settings.\n\n"
            f"Use Case Name: {context_data.get('use_case_name', 'Not provided')}\n"
            f"Use Case Objective: {context_data.get('objective', 'Not provided')}\n"
            f"Grouping Fields: {context_data.get('grouping_fields', 'Not provided')}\n"
            f"Correlation Settings: {context_data.get('correlation_settings', 'Not provided')}\n\n"
            "Evaluate:\n"
            "1. Are the grouping fields appropriate for this type of use case?\n"
            "2. Will the grouping reduce alert fatigue effectively?\n"
            "3. Could the grouping cause important alerts to be suppressed?\n\n"
            "Respond with:\n"
            "- STATUS: PASS / FAIL / NEEDS REVIEW\n"
            "- ASSESSMENT: 2-3 sentences\n"
            "- RECOMMENDATIONS: Better grouping strategy if needed"
        ),
        "cp7": (
            "You are a SIEM security analyst. Evaluate the historical/simulated test results for this rule.\n\n"
            f"Use Case Name: {context_data.get('use_case_name', 'Not provided')}\n"
            f"Use Case Objective: {context_data.get('objective', 'Not provided')}\n"
            f"Test Results Summary: {context_data.get('test_results', 'Not provided')}\n"
            f"Number of Results: {context_data.get('result_count', 'Not provided')}\n\n"
            "Evaluate:\n"
            "1. Do the test results show the rule is detecting what it is supposed to?\n"
            "2. Are the results consistent with expected behavior?\n"
            "3. Are there any red flags in the test output?\n\n"
            "Respond with:\n"
            "- STATUS: PASS / FAIL / NEEDS REVIEW\n"
            "- ASSESSMENT: 2-3 sentences\n"
            "- RECOMMENDATIONS: Additional testing suggestions if needed"
        ),
        "cp8": (
            "You are a SIEM security analyst. Evaluate whether this rule triggers correctly on production data.\n\n"
            f"Use Case Name: {context_data.get('use_case_name', 'Not provided')}\n"
            f"Use Case Objective: {context_data.get('objective', 'Not provided')}\n"
            f"Production Alert Samples: {context_data.get('prod_results', 'Not provided')}\n"
            f"Number of Alerts in Production: {context_data.get('alert_count', 'Not provided')}\n\n"
            "Evaluate:\n"
            "1. Is the rule triggering on production data as expected?\n"
            "2. Do the alert samples look like genuine detections?\n"
            "3. Any concerns about the production behavior?\n\n"
            "Respond with:\n"
            "- STATUS: PASS / FAIL / NEEDS REVIEW\n"
            "- ASSESSMENT: 2-3 sentences\n"
            "- RECOMMENDATIONS: Any adjustments needed"
        ),
    }

    if checkpoint_id not in prompts:
        return None

    try:
        data = json.dumps({
            "model": "claude-sonnet-4-5",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompts[checkpoint_id]}]
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            }
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
            text = result["content"][0]["text"]
            status = "review"
            if "STATUS: PASS" in text.upper():
                status = "pass"
            elif "STATUS: FAIL" in text.upper():
                status = "fail"
            elif "NOT APPLICABLE" in text.upper():
                status = "pass"
            return {"status": status, "assessment": text}
    except Exception as e:
        return {"status": "review", "assessment": f"AI validation could not be completed: {str(e)}. Please review manually."}


# =====================================================
# SIEM DETECTION & NORMALIZATION
# =====================================================

def detect_siem_type(df):
    cols_lower = {c.lower().strip() for c in df.columns}
    scores = {
        "splunk":    len(SPLUNK_SIGNATURE_COLS    & cols_lower),
        "sentinel":  len(SENTINEL_SIGNATURE_COLS  & cols_lower),
        "chronicle": len(CHRONICLE_SIGNATURE_COLS & cols_lower),
    }
    best = max(scores, key=scores.get)
    return best if scores[best] >= 2 else "unknown"


def normalize_row(row, siem_type, df_columns):
    col_map    = COLUMN_MAPS.get(siem_type, COLUMN_MAPS["splunk"])
    cols_lower = {c.lower().strip(): c for c in df_columns}
    norm = {}
    for field, candidates in col_map.items():
        norm[field] = ""
        for candidate in candidates:
            actual = cols_lower.get(candidate.lower().strip())
            if actual and actual in row.index:
                val = row[actual]
                if pd.notna(val) and str(val).strip():
                    norm[field] = str(val).strip()
                    break
    if not norm.get("use_case_id"):
        norm["use_case_id"] = f"UC-{int(row.name) + 1:03d}"
    if not norm.get("use_case_name"):
        norm["use_case_name"] = f"Use Case {int(row.name) + 1}"
    norm["siem_type"] = siem_type
    return norm


# =====================================================
# CHECKPOINT RUNNERS
# =====================================================

def run_cp1(norm, siem_type):
    query = norm.get("query", "")
    if siem_type == "splunk":
        parsed = parse_spl_fields(query)
        if parsed["indexes"] or parsed["sourcetypes"]:
            status = "pass"
            assessment = (
                "Detected indexes: " + (", ".join(parsed["indexes"]) or "none") +
                "; sourcetypes: " + (", ".join(parsed["sourcetypes"]) or "none") + "."
            )
        elif query.strip():
            status = "review"
            assessment = "Query present but no explicit index/sourcetype found. Manual verification needed."
        else:
            status = "fail"
            assessment = "No query found. Cannot assess log/field availability."
        evidence = {
            "parsed_indexes":     ", ".join(parsed["indexes"]) or "none",
            "parsed_sourcetypes": ", ".join(parsed["sourcetypes"]) or "none",
            "parsed_fields":      ", ".join(parsed["fields"][:10]) or "none",
        }
    else:
        if query.strip():
            status = "pass"
            assessment = (
                "Detection query is present (" + SIEM_LABELS.get(siem_type, siem_type) +
                " syntax). Data source is embedded in the query."
            )
        else:
            status = "fail"
            assessment = "No detection query found. Cannot assess log/field availability."
        evidence = {"query_present": "Yes" if query.strip() else "No", "siem_type": siem_type}
    return {"status": status, "evidence": evidence, "assessment": assessment}


def run_cp3(norm, siem_type):
    score = 0
    notes = []

    sev = norm.get("severity", "").lower().strip()
    if sev in VALID_SEVERITIES:
        score += 1
        notes.append("Severity '" + norm["severity"] + "' is valid")
    elif sev:
        notes.append("Severity '" + norm["severity"] + "' is unrecognized")
    else:
        notes.append("Severity: missing")

    freq = norm.get("frequency", "").strip()
    if freq:
        score += 1
        notes.append("Frequency: " + freq)
    else:
        notes.append("Frequency: missing")

    lookback = norm.get("lookback", "").strip()
    if lookback:
        score += 1
        notes.append("Lookback: " + lookback)
    else:
        notes.append("Lookback: missing")

    query = norm.get("query", "")
    thresholds = extract_thresholds(query) if siem_type == "splunk" else re.findall(r'[><=!]+\s*\d+', query)
    if thresholds:
        score += 1
        notes.append("Thresholds detected: " + str(thresholds[:3]))
    else:
        notes.append("Thresholds: none detected")

    status = "pass" if score >= 4 else "review" if score >= 2 else "fail"
    assessment = "Score " + str(score) + "/4. " + "; ".join(notes) + "."
    evidence = {
        "severity":           norm.get("severity", ""),
        "frequency":          norm.get("frequency", ""),
        "lookback":           norm.get("lookback", ""),
        "thresholds_detected":str(thresholds[:3]) if thresholds else "none",
        "score":              str(score) + "/4",
    }
    return {"status": status, "evidence": evidence, "assessment": assessment}


def run_cp9(norm):
    def safe_int(val):
        try:
            return int(float(val or 0))
        except (ValueError, TypeError):
            return 0

    total = safe_int(norm.get("total_alerts", ""))
    tp    = safe_int(norm.get("true_positives", ""))

    if total <= 0:
        total = safe_int(norm.get("test_result_count", ""))

    if total <= 0:
        return {
            "status": "review",
            "evidence": {
                "total_alerts":   norm.get("total_alerts", ""),
                "true_positives": norm.get("true_positives", ""),
            },
            "assessment": "No alert count data in CSV. FP rate cannot be calculated. Manual review needed.",
        }

    tp       = min(tp, total)
    fp_count = total - tp
    fp_rate  = (fp_count / total) * 100
    status   = "pass" if fp_rate < 60 else "fail"
    assessment = (
        "FP rate: " + str(round(fp_rate, 1)) + "% (" + str(fp_count) + " FP out of " +
        str(total) + " total alerts). " +
        ("Below" if fp_rate < 60 else "Exceeds") + " the 60% threshold."
    )
    return {
        "status": status,
        "evidence": {
            "total_alerts":   total,
            "true_positives": tp,
            "fp_count":       fp_count,
            "fp_rate":        str(round(fp_rate, 1)) + "%",
        },
        "assessment": assessment,
    }


def run_ai_checkpoints(norm, siem_type, api_key):
    results = {}
    if not api_key or not api_key.strip():
        for cp in ("cp2", "cp4", "cp5", "cp6", "cp7", "cp8"):
            results[cp] = {
                "status": "review", "evidence": {},
                "assessment": "No API key provided. Manual review required.",
            }
        return results

    query  = norm.get("query", "")
    parsed = parse_spl_fields(query) if siem_type == "splunk" else {}

    contexts = {
        "cp2": {
            "objective": norm.get("description", ""),
            "spl_query": query,
            "parsed":    parsed,
        },
        "cp4": {
            "use_case_name":    norm.get("use_case_name", ""),
            "objective":        norm.get("description", ""),
            "spl_query":        query,
            "lookups":          parsed.get("lookups", []),
            "enrichment_notes": norm.get("enrichment_notes", ""),
        },
        "cp5": {
            "use_case_name":    norm.get("use_case_name", ""),
            "objective":        norm.get("description", ""),
            "spl_query":        query,
            "mitre_techniques": (
                norm.get("mitre_techniques", "Not provided") +
                " | Tactics: " + norm.get("mitre_tactics", "Not provided")
            ),
        },
        "cp6": {
            "use_case_name":       norm.get("use_case_name", ""),
            "objective":           norm.get("description", ""),
            "grouping_fields":     norm.get("grouping_fields", "Not provided"),
            "correlation_settings":"Derived from CSV export",
        },
        "cp7": {
            "use_case_name": norm.get("use_case_name", ""),
            "objective":     norm.get("description", ""),
            "test_results":  "Test result count: " + norm.get("test_result_count", "Not provided"),
            "result_count":  norm.get("test_result_count", "Not provided"),
        },
        "cp8": {
            "use_case_name": norm.get("use_case_name", ""),
            "objective":     norm.get("description", ""),
            "prod_results":  (
                "Total alerts: " + norm.get("total_alerts", "Not provided") +
                ", True positives: " + norm.get("true_positives", "Not provided")
            ),
            "alert_count":   norm.get("total_alerts", "Not provided"),
        },
    }

    for cp_id, ctx in contexts.items():
        try:
            ai_result = validate_with_ai(cp_id, ctx, api_key)
            evidence  = {k: str(v)[:200] for k, v in ctx.items() if k != "parsed"}
            results[cp_id] = {
                "status":     ai_result["status"] if ai_result else "review",
                "evidence":   evidence,
                "assessment": ai_result["assessment"] if ai_result else "No response.",
            }
        except Exception as e:
            results[cp_id] = {"status": "review", "evidence": {}, "assessment": "Error: " + str(e)}

    return results


def compute_overall_status(checkpoints):
    statuses = [cp.get("status", "pending") for cp in checkpoints.values()]
    if "fail"    in statuses: return "FAIL"
    if "review"  in statuses: return "NEEDS REVIEW"
    if "pending" in statuses: return "NEEDS REVIEW"
    return "PASS"


def process_all_rows(norm_df, siem_type, api_key, progress_bar, status_text):
    total = len(norm_df)
    for i in range(total):
        row     = norm_df.iloc[i]
        norm    = dict(row)
        uc_name = norm.get("use_case_name", "Row " + str(i + 1))
        status_text.markdown("**Processing " + str(i + 1) + "/" + str(total) + ":** " + uc_name)
        progress_bar.progress(i / total)

        result = {
            "use_case_id":   norm.get("use_case_id", "UC-" + str(i + 1).zfill(3)),
            "use_case_name": uc_name,
            "siem_type":     siem_type,
            "checkpoints":   {},
            "overall":       "NEEDS REVIEW",
            "error":         None,
        }

        try:
            result["checkpoints"]["cp1"] = run_cp1(norm, siem_type)
            result["checkpoints"]["cp3"] = run_cp3(norm, siem_type)
            result["checkpoints"]["cp9"] = run_cp9(norm)
            ai = run_ai_checkpoints(norm, siem_type, api_key)
            for cp_key in ("cp2", "cp4", "cp5", "cp6", "cp7", "cp8"):
                result["checkpoints"][cp_key] = ai.get(
                    cp_key, {"status": "review", "evidence": {}, "assessment": "Not run."})
            result["overall"] = compute_overall_status(result["checkpoints"])
        except Exception as e:
            result["error"] = str(e)
            for cp_key in CHECKPOINT_NAMES:
                if cp_key not in result["checkpoints"]:
                    result["checkpoints"][cp_key] = {
                        "status": "review", "evidence": {},
                        "assessment": "Processing error: " + str(e)}
            result["overall"] = "NEEDS REVIEW"

        st.session_state.results[i] = result

    progress_bar.progress(1.0)
    status_text.markdown("**Done!** Processed " + str(total) + " use cases.")
    st.session_state.processing_done = True
    st.session_state.page = "results"
    st.rerun()


# =====================================================
# PDF GENERATION
# =====================================================

def _get_pdf_styles():
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle", parent=styles["Title"],
        fontSize=22, spaceAfter=6,
        textColor=colors.HexColor("#0f172a"), fontName="Helvetica-Bold")
    subtitle_style = ParagraphStyle(
        "CustomSubtitle", parent=styles["Normal"],
        fontSize=11, textColor=colors.HexColor("#64748b"), spaceAfter=20)
    heading_style = ParagraphStyle(
        "CustomHeading", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#0f172a"),
        spaceBefore=16, spaceAfter=8, fontName="Helvetica-Bold")
    body_style = ParagraphStyle(
        "CustomBody", parent=styles["Normal"],
        fontSize=10, leading=14, textColor=colors.HexColor("#334155"))
    status_pass = ParagraphStyle(
        "StatusPass", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#166534"), fontName="Helvetica-Bold")
    status_fail = ParagraphStyle(
        "StatusFail", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#991b1b"), fontName="Helvetica-Bold")
    status_review = ParagraphStyle(
        "StatusReview", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#92400e"), fontName="Helvetica-Bold")
    footer_style = ParagraphStyle(
        "Footer", parent=styles["Normal"],
        fontSize=8, textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER)
    return styles, title_style, subtitle_style, heading_style, body_style, status_pass, status_fail, status_review, footer_style


def _xml_esc(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_use_case_story(row_data, result, styles, body_style, heading_style, sp, sf, sr):
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle

    story = []

    info_data = [
        ["Use Case Name",  result.get("use_case_name", "N/A")],
        ["Use Case ID",    result.get("use_case_id",   "N/A")],
        ["SIEM Type",      SIEM_LABELS.get(result.get("siem_type", "unknown"), "Unknown")],
        ["Overall Result", result.get("overall", "NEEDS REVIEW")],
        ["Validation Date",datetime.now().strftime("%Y-%m-%d")],
    ]
    info_table = Table(info_data, colWidths=[120, 380])
    info_table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("TEXTCOLOR",     (0, 0), (0, -1), colors.HexColor("#475569")),
        ("TEXTCOLOR",     (1, 0), (1, -1), colors.HexColor("#0f172a")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 10))

    desc = str(row_data.get("description", "") or "")
    if desc:
        story.append(Paragraph("<b>Objective:</b>", body_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(_xml_esc(desc), body_style))
        story.append(Spacer(1, 8))

    query = str(row_data.get("query", "") or "")
    if query:
        siem_label = SIEM_LABELS.get(result.get("siem_type", ""), "Detection")
        story.append(Paragraph("<b>" + siem_label + " Query:</b>", body_style))
        story.append(Spacer(1, 4))
        mono_style = ParagraphStyle(
            "Mono", parent=body_style,
            fontSize=8, leading=11, fontName="Courier",
            textColor=colors.HexColor("#334155"))
        story.append(Paragraph(_xml_esc(query[:800]), mono_style))
        story.append(Spacer(1, 12))

    story.append(Paragraph("Checkpoint Results", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 8))

    for cp_key, cp_name in CHECKPOINT_NAMES.items():
        cp = result["checkpoints"].get(cp_key, {"status": "pending", "evidence": {}, "assessment": ""})
        status_label = cp.get("status", "pending").upper()
        if status_label == "REVIEW":
            status_label = "NEEDS REVIEW"
        s_style = sp if cp.get("status") == "pass" else sf if cp.get("status") == "fail" else sr

        story.append(Paragraph("<b>" + cp_name + "</b>", body_style))
        story.append(Paragraph("Status: " + status_label, s_style))
        story.append(Spacer(1, 4))

        for ek, ev in (cp.get("evidence") or {}).items():
            if ev and str(ev).strip():
                label   = ek.replace("_", " ").title()
                val_str = _xml_esc(str(ev)[:300])
                story.append(Paragraph("<b>" + label + ":</b> " + val_str, body_style))

        if cp.get("assessment"):
            story.append(Spacer(1, 3))
            story.append(Paragraph(
                "<b>Assessment:</b> " + _xml_esc(cp["assessment"][:500]), body_style))

        story.append(Spacer(1, 6))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 6))

    return story


def generate_pdf_report(row_data, result):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable

    styles, ts, subs, hs, bs, sp, sf, sr, fs = _get_pdf_styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=25*mm, leftMargin=25*mm,
                            topMargin=25*mm, bottomMargin=25*mm)
    story = []
    story.append(Spacer(1, 20))
    story.append(Paragraph("SIEM Use Case Validation Report", ts))
    story.append(Paragraph("Generated on " + datetime.now().strftime("%B %d, %Y at %H:%M"), subs))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#38bdf8")))
    story.append(Spacer(1, 16))
    story.extend(_build_use_case_story(row_data, result, styles, bs, hs, sp, sf, sr))
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "This report was generated by the SIEM Use Case Validation Agent. "
        "AI-powered assessments should be reviewed by a qualified security analyst.", fs))
    doc.build(story)
    buffer.seek(0)
    return buffer.read()


def generate_consolidated_pdf(results, norm_df):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable, PageBreak)
    from reportlab.lib.styles import ParagraphStyle

    styles, ts, subs, hs, bs, sp, sf, sr, fs = _get_pdf_styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=25*mm, leftMargin=25*mm,
                            topMargin=25*mm, bottomMargin=25*mm)
    story = []

    story.append(Spacer(1, 20))
    story.append(Paragraph("SIEM Use Case Validation - Batch Report", ts))
    story.append(Paragraph("Generated on " + datetime.now().strftime("%B %d, %Y at %H:%M"), subs))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#38bdf8")))
    story.append(Spacer(1, 16))

    total    = len(results)
    pass_c   = sum(1 for r in results.values() if r["overall"] == "PASS")
    fail_c   = sum(1 for r in results.values() if r["overall"] == "FAIL")
    review_c = total - pass_c - fail_c

    sum_data = [["Total", "PASS", "FAIL", "NEEDS REVIEW"],
                [str(total), str(pass_c), str(fail_c), str(review_c)]]
    sum_table = Table(sum_data, colWidths=[125, 125, 125, 125])
    sum_table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR",     (1, 1), (1, 1), colors.HexColor("#166534")),
        ("TEXTCOLOR",     (2, 1), (2, 1), colors.HexColor("#991b1b")),
        ("TEXTCOLOR",     (3, 1), (3, 1), colors.HexColor("#92400e")),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 16))

    qr_data = [["ID", "Use Case", "Overall"] + ["CP" + str(i) for i in range(1, 10)]]
    for i, res in sorted(results.items()):
        name_trunc = res["use_case_name"][:32] + "..." if len(res["use_case_name"]) > 32 else res["use_case_name"]
        row_entry  = [res["use_case_id"], name_trunc, res["overall"]]
        for cp_key in CHECKPOINT_NAMES:
            s = res["checkpoints"].get(cp_key, {}).get("status", "pending")
            row_entry.append({"pass": "P", "fail": "F", "review": "R", "pending": "-"}.get(s, "-"))
        qr_data.append(row_entry)

    qr_table = Table(qr_data, colWidths=[45, 155, 70] + [28]*9)
    qr_cmds = [
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7),
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("ALIGN",         (2, 0), (-1, -1), "CENTER"),
    ]
    for i, res in sorted(results.items()):
        row_idx = i + 1
        col = (colors.HexColor("#166534") if res["overall"] == "PASS" else
               colors.HexColor("#991b1b") if res["overall"] == "FAIL" else
               colors.HexColor("#92400e"))
        qr_cmds.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), col))
    qr_table.setStyle(TableStyle(qr_cmds))
    story.append(qr_table)
    story.append(PageBreak())

    for i, res in sorted(results.items()):
        row_data = norm_df.iloc[i].to_dict() if i < len(norm_df) else {}
        story.append(Paragraph(res["use_case_id"] + " - " + res["use_case_name"], hs))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#38bdf8")))
        story.append(Spacer(1, 10))
        if res.get("error"):
            err_sty = ParagraphStyle("ErrSty", parent=bs, textColor=colors.HexColor("#991b1b"))
            story.append(Paragraph("Processing error: " + _xml_esc(res["error"]), err_sty))
            story.append(Spacer(1, 8))
        story.extend(_build_use_case_story(row_data, res, styles, bs, hs, sp, sf, sr))
        story.append(PageBreak())

    story.append(Paragraph(
        "This report was generated by the SIEM Use Case Validation Agent. "
        "AI-powered assessments should be reviewed by a qualified security analyst.", fs))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()


def generate_zip(results, norm_df):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i, res in sorted(results.items()):
            try:
                row_data  = norm_df.iloc[i].to_dict() if i < len(norm_df) else {}
                pdf_bytes = generate_pdf_report(row_data, res)
                uc_id    = re.sub(r'[^\w\-]', '_', res["use_case_id"])
                uc_name  = re.sub(r'[^\w\-]', '_', res["use_case_name"][:30])
                zf.writestr(uc_id + "_" + uc_name + ".pdf", pdf_bytes)
            except Exception as e:
                zf.writestr(
                    "ERROR_" + res["use_case_id"] + ".txt",
                    "PDF generation failed for " + res["use_case_name"] + ": " + str(e))
    zip_buffer.seek(0)
    return zip_buffer.read()


# =====================================================
# RESULTS TABLE BUILDER
# =====================================================

def build_results_dataframe(results):
    rows = []
    for i, res in sorted(results.items()):
        name = res["use_case_name"]
        row = {
            "ID":       res["use_case_id"],
            "Use Case": name[:38] + "..." if len(name) > 38 else name,
        }
        for cp_key in CHECKPOINT_NAMES:
            status = res["checkpoints"].get(cp_key, {}).get("status", "pending")
            icon = {"pass": "PASS", "fail": "FAIL", "review": "REVIEW", "pending": "-"}.get(status, "-")
            row[cp_key.upper()] = icon
        row["Overall"] = res["overall"]
        rows.append(row)
    return pd.DataFrame(rows)


def render_status_badge(status):
    css   = {"pass": "status-pass", "fail": "status-fail",
             "review": "status-review", "pending": "status-pending"}.get(status, "status-pending")
    label = status.upper().replace("REVIEW", "NEEDS REVIEW")
    return '<span class="status-badge ' + css + '">' + label + '</span>'


# =====================================================
# PAGE: UPLOAD
# =====================================================

def render_upload_page():
    st.markdown("""
    <div class="main-header">
        <h1>SIEM Use Case Validation Agent</h1>
        <p>Automated batch validation - Splunk, Microsoft Sentinel, Google Chronicle</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Step 1 - Upload your CSV export")
    uploaded_file = st.file_uploader(
        "Upload a CSV file exported from your SIEM",
        type=["csv"],
        help="Supports Splunk saved-search exports, Microsoft Sentinel analytics rule exports, and Google Chronicle rule exports."
    )

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file, encoding_errors="replace")
            df = df.loc[:, ~df.columns.duplicated()]
            df = df.dropna(how="all").reset_index(drop=True)
        except Exception as e:
            st.error("Could not parse CSV: " + str(e))
            return

        if len(df) == 0:
            st.error("The uploaded CSV is empty.")
            return
        if len(df) > 500:
            st.error("CSV has " + str(len(df)) + " rows. Maximum supported is 500. Please split your file.")
            return
        if len(df) > 50:
            est_secs = len(df) * 6
            st.warning("Warning: " + str(len(df)) + " use cases detected. With AI validation this will take approximately " + str(est_secs) + " seconds.")

        detected = detect_siem_type(df)

        st.markdown("---")
        st.markdown("### Step 2 - Confirm SIEM type")

        siem_options = ["Splunk", "Microsoft Sentinel", "Google Chronicle"]
        siem_keys    = ["splunk", "sentinel", "chronicle"]
        detected_label = SIEM_LABELS.get(detected, "Splunk")
        default_idx = siem_options.index(detected_label) if detected_label in siem_options else 0

        if detected != "unknown":
            st.success("Auto-detected: **" + detected_label + "**")
        else:
            st.warning("Could not auto-detect SIEM type. Please select manually.")

        selected_label = st.radio("SIEM Platform", siem_options, index=default_idx, horizontal=True)
        siem_type = siem_keys[siem_options.index(selected_label)]

        col_map    = COLUMN_MAPS[siem_type]
        df_cols_lc = {c.lower().strip(): c for c in df.columns}
        mapping_rows = []
        for field, candidates in col_map.items():
            matched = next((c for c in candidates if c.lower().strip() in df_cols_lc), None)
            mapping_rows.append({
                "Normalized Field": field,
                "Maps From":        matched if matched else "not found",
                "Status":           "Mapped" if matched else "Missing",
            })
        with st.expander("Column mapping preview", expanded=False):
            st.dataframe(pd.DataFrame(mapping_rows), use_container_width=True, hide_index=True)

        st.markdown("---")
        st.markdown("### Step 3 - Configure AI validation")
        _secret_key = st.secrets.get("ANTHROPIC_API_KEY", "") if hasattr(st, "secrets") else ""
        api_key = st.text_input(
            "Claude API Key",
            value=_secret_key,
            type="password",
            help="Required for AI validation on checkpoints 2, 4, 5, 6, 7, 8."
        )
        if not api_key:
            st.info("No API key - checkpoints 2, 4, 5, 6, 7, 8 will be marked NEEDS REVIEW.")

        st.markdown("---")
        st.markdown("### Step 4 - Preview and Run")
        st.markdown("**" + str(len(df)) + " use cases** ready to validate.")
        with st.expander("Preview first 5 rows", expanded=False):
            st.dataframe(df.head(), use_container_width=True)

        if st.button("Run Validation", type="primary", use_container_width=True):
            norm_rows = [normalize_row(df.iloc[i], siem_type, list(df.columns)) for i in range(len(df))]
            st.session_state.normalized_df   = pd.DataFrame(norm_rows)
            st.session_state.raw_df          = df
            st.session_state.siem_type       = siem_type
            st.session_state.api_key         = api_key
            st.session_state.results         = {}
            st.session_state.processing_done = False
            st.session_state.page            = "processing"
            st.rerun()

    else:
        st.info("Upload a CSV file to begin.")
        with st.expander("What columns should my CSV have?"):
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("**Splunk** (saved search export)")
                st.code("title\nsearch\ndescription\nalert.severity\ncron_schedule\ndispatch.earliest_time\nalert.suppress.fields\nmitre_techniques (opt)\nmitre_tactics (opt)\ntotal_alerts (opt)\ntrue_positives (opt)")
            with c2:
                st.markdown("**Microsoft Sentinel**")
                st.code("displayName\nquery\ndescription\nseverity\nqueryFrequency\nqueryPeriod\ntactics\ntechniques\ngroupingConfiguration\ntotal_alerts (opt)\ntrue_positives (opt)")
            with c3:
                st.markdown("**Google Chronicle**")
                st.code("rule_name\nrule_text\nmeta.description\nseverity\nmeta.attack_tactic\nmeta.attack_technique\nfrequency (opt)\ntotal_alerts (opt)\ntrue_positives (opt)")


# =====================================================
# PAGE: PROCESSING
# =====================================================

def render_processing_page():
    st.markdown("""
    <div class="main-header">
        <h1>SIEM Use Case Validation Agent</h1>
        <p>Running automated validation across all use cases...</p>
    </div>
    """, unsafe_allow_html=True)

    norm_df   = st.session_state.normalized_df
    siem_type = st.session_state.siem_type
    api_key   = st.session_state.api_key
    total     = len(norm_df)

    st.markdown("### Processing " + str(total) + " use case" + ("s" if total != 1 else ""))
    st.markdown(
        "SIEM: **" + SIEM_LABELS.get(siem_type, siem_type) + "** | " +
        "AI validation: **" + ("Enabled" if api_key else "Disabled") + "**"
    )

    progress_bar = st.progress(0)
    status_text  = st.empty()

    _, cancel_col = st.columns([5, 1])
    with cancel_col:
        if st.button("Cancel"):
            st.session_state.page = "upload"
            st.rerun()

    process_all_rows(norm_df, siem_type, api_key, progress_bar, status_text)


# =====================================================
# PAGE: RESULTS
# =====================================================

def render_results_page():
    st.markdown("""
    <div class="main-header">
        <h1>SIEM Use Case Validation Agent</h1>
        <p>Validation complete - review results and download reports</p>
    </div>
    """, unsafe_allow_html=True)

    results  = st.session_state.results
    norm_df  = st.session_state.normalized_df
    total    = len(results)
    pass_c   = sum(1 for r in results.values() if r["overall"] == "PASS")
    fail_c   = sum(1 for r in results.values() if r["overall"] == "FAIL")
    review_c = total - pass_c - fail_c

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Use Cases",  total)
    c2.metric("PASS",             pass_c)
    c3.metric("FAIL",             fail_c)
    c4.metric("Needs Review",     review_c)

    st.markdown("---")
    st.markdown("### Validation Summary")

    df_display = build_results_dataframe(results)

    def style_overall(val):
        if val == "PASS":    return "color: #166534; font-weight: 600"
        elif val == "FAIL":  return "color: #991b1b; font-weight: 600"
        else:                return "color: #92400e; font-weight: 600"

    styled = df_display.style.map(style_overall, subset=["Overall"])
    st.dataframe(styled, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("### Download Reports")

    dl1, dl2 = st.columns(2)
    with dl1:
        st.markdown("**Individual PDFs (ZIP)**")
        st.caption("One PDF per use case, bundled into a ZIP.")
        if st.button("Generate ZIP", use_container_width=True, type="primary", key="gen_zip"):
            with st.spinner("Building ZIP..."):
                try:
                    zip_bytes = generate_zip(results, norm_df)
                    st.download_button(
                        "Download ZIP",
                        zip_bytes,
                        file_name="siem_validation_" + datetime.now().strftime("%Y%m%d_%H%M") + ".zip",
                        mime="application/zip",
                        use_container_width=True,
                        key="dl_zip",
                    )
                except Exception as e:
                    st.error("ZIP generation failed: " + str(e))

    with dl2:
        st.markdown("**Consolidated PDF**")
        st.caption("All use cases in one PDF with a cover summary.")
        if st.button("Generate Consolidated PDF", use_container_width=True, type="primary", key="gen_pdf"):
            with st.spinner("Building PDF..."):
                try:
                    pdf_bytes = generate_consolidated_pdf(results, norm_df)
                    st.download_button(
                        "Download PDF",
                        pdf_bytes,
                        file_name="siem_validation_consolidated_" + datetime.now().strftime("%Y%m%d_%H%M") + ".pdf",
                        mime="application/pdf",
                        use_container_width=True,
                        key="dl_pdf",
                    )
                except Exception as e:
                    st.error("PDF generation failed: " + str(e))

    st.markdown("---")
    st.markdown("### Detailed Results")

    for i, res in sorted(results.items()):
        overall_icon = "[PASS]" if res["overall"] == "PASS" else "[FAIL]" if res["overall"] == "FAIL" else "[REVIEW]"
        with st.expander(overall_icon + " [" + res["use_case_id"] + "] " + res["use_case_name"] + " - " + res["overall"]):
            if res.get("error"):
                st.error("Processing error: " + res["error"])

            cp_cols = st.columns(3)
            for j, (cp_key, cp_name) in enumerate(CHECKPOINT_NAMES.items()):
                cp     = res["checkpoints"].get(cp_key, {"status": "pending"})
                status = cp.get("status", "pending")
                card_c = {"pass": "pass", "fail": "fail", "review": "review"}.get(status, "")
                icon   = {"pass": "[P]", "fail": "[F]", "review": "[R]", "pending": "[-]"}.get(status, "[-]")
                with cp_cols[j % 3]:
                    st.markdown(
                        '<div class="cp-card ' + card_c + '">' +
                        '<b>' + icon + ' ' + cp_name + '</b><br>' +
                        render_status_badge(status) +
                        '</div>',
                        unsafe_allow_html=True,
                    )

            ai_cps = ["cp2", "cp4", "cp5", "cp6", "cp7", "cp8"]
            assessments = [
                (cp_key, res["checkpoints"].get(cp_key, {}))
                for cp_key in ai_cps
                if res["checkpoints"].get(cp_key, {}).get("assessment")
            ]
            if assessments:
                st.markdown("**AI Assessments:**")
                for cp_key, cp in assessments:
                    a = cp["assessment"].replace("<", "&lt;").replace(">", "&gt;")
                    st.markdown(
                        '<div class="ai-assessment">'
                        '<div class="ai-assessment-header">' + CHECKPOINT_NAMES[cp_key] + '</div>' +
                        a + '</div>',
                        unsafe_allow_html=True,
                    )

    st.markdown("---")
    if st.button("Start New Validation", use_container_width=True):
        for k in ["page", "results", "raw_df", "normalized_df",
                  "processing_done", "siem_type", "api_key"]:
            st.session_state.pop(k, None)
        st.rerun()

    st.markdown("""
    <div style="text-align:center;color:#94a3b8;font-size:0.8rem;padding:1rem 0;">
        SIEM Use Case Validation Agent - AI assessments should be reviewed by a qualified security analyst
    </div>
    """, unsafe_allow_html=True)


# =====================================================
# PAGE ROUTER
# =====================================================

page = st.session_state.get("page", "upload")
if page == "upload":
    render_upload_page()
elif page == "processing":
    render_processing_page()
elif page == "results":
    render_results_page()
else:
    st.session_state.page = "upload"
    st.rerun()
