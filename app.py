import streamlit as st
import json
import re
import math
import io
from datetime import datetime

# --- Page Config ---
st.set_page_config(
    page_title="SIEM Use Case Validator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    .stApp {
        font-family: 'IBM Plex Sans', sans-serif;
    }
    
    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%);
        padding: 2rem 2.5rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        border-left: 5px solid #38bdf8;
    }
    .main-header h1 {
        color: #f1f5f9;
        font-size: 1.8rem;
        font-weight: 700;
        margin: 0;
        letter-spacing: -0.02em;
    }
    .main-header p {
        color: #94a3b8;
        font-size: 0.95rem;
        margin: 0.3rem 0 0 0;
    }
    
    .checkpoint-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        border-left: 4px solid #64748b;
        transition: border-left-color 0.3s;
    }
    .checkpoint-card.pass { border-left-color: #22c55e; }
    .checkpoint-card.fail { border-left-color: #ef4444; }
    .checkpoint-card.review { border-left-color: #f59e0b; }
    
    .status-badge {
        display: inline-block;
        padding: 0.2rem 0.7rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .status-pass { background: #dcfce7; color: #166534; }
    .status-fail { background: #fee2e2; color: #991b1b; }
    .status-review { background: #fef3c7; color: #92400e; }
    .status-pending { background: #f1f5f9; color: #475569; }
    
    .sidebar-status {
        padding: 0.5rem 0.8rem;
        margin: 0.3rem 0;
        border-radius: 8px;
        font-size: 0.85rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .metric-box {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
    }
    .metric-box .number {
        font-size: 2rem;
        font-weight: 700;
        color: #0f172a;
    }
    .metric-box .label {
        font-size: 0.8rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    div[data-testid="stExpander"] {
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        margin-bottom: 0.8rem;
        overflow: hidden;
    }
    
    .ai-assessment {
        background: #f0f9ff;
        border: 1px solid #bae6fd;
        border-radius: 8px;
        padding: 1rem;
        margin-top: 0.5rem;
        font-size: 0.9rem;
    }
    .ai-assessment-header {
        font-weight: 600;
        color: #0369a1;
        margin-bottom: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)


# --- Session State Initialization ---
if "checkpoints" not in st.session_state:
    st.session_state.checkpoints = {
        "cp1": {"status": "pending", "assessment": "", "evidence": {}},
        "cp2": {"status": "pending", "assessment": "", "evidence": {}},
        "cp3": {"status": "pending", "assessment": "", "evidence": {}},
        "cp4": {"status": "pending", "assessment": "", "evidence": {}},
        "cp5": {"status": "pending", "assessment": "", "evidence": {}},
        "cp6": {"status": "pending", "assessment": "", "evidence": {}},
        "cp7": {"status": "pending", "assessment": "", "evidence": {}},
        "cp8": {"status": "pending", "assessment": "", "evidence": {}},
        "cp9": {"status": "pending", "assessment": "", "evidence": {}},
    }

if "use_case_info" not in st.session_state:
    st.session_state.use_case_info = {
        "name": "",
        "id": "",
        "description": "",
        "analyst": "",
        "date": datetime.now().strftime("%Y-%m-%d")
    }

CHECKPOINT_NAMES = {
    "cp1": "1. Logs & Fields Availability",
    "cp2": "2. Rule Built as Per Objective",
    "cp3": "3. Query Aspects Validation",
    "cp4": "4. Enrichment Sources",
    "cp5": "5. MITRE ATT&CK Mapping",
    "cp6": "6. Alert Grouping / Correlation",
    "cp7": "7. Historical / Simulated Testing",
    "cp8": "8. Production Trigger Validation",
    "cp9": "9. False Positive Rate"
}

STATUS_ICONS = {
    "pass": "✅",
    "fail": "❌",
    "review": "⚠️",
    "pending": "⏳"
}


# --- Helper Functions ---

def parse_spl_fields(spl_query):
    """Extract fields, indexes, sourcetypes from SPL query."""
    result = {"indexes": [], "sourcetypes": [], "fields": [], "lookups": [], "timerange": ""}
    if not spl_query:
        return result
    
    # Extract indexes
    idx_matches = re.findall(r'index\s*=\s*["\']?(\S+?)["\']?\s', spl_query + " ")
    result["indexes"] = list(set(idx_matches))
    
    # Extract sourcetypes
    st_matches = re.findall(r'sourcetype\s*=\s*["\']?(\S+?)["\']?\s', spl_query + " ")
    result["sourcetypes"] = list(set(st_matches))
    
    # Extract fields (from eval, stats, where, table, fields commands)
    field_patterns = [
        r'\|\s*(?:stats|eventstats)\s+\w+\((\w+)\)',
        r'\|\s*(?:eval|where)\s+(\w+)\s*[=<>!]',
        r'\|\s*table\s+([\w\s,]+)',
        r'\|\s*fields\s+[+-]?\s*([\w\s,]+)',
        r'\|\s*rename\s+(\w+)',
        r'by\s+([\w,\s]+?)(?:\||\s*$)',
    ]
    for pattern in field_patterns:
        matches = re.findall(pattern, spl_query)
        for m in matches:
            fields = [f.strip() for f in m.split(",") if f.strip()]
            result["fields"].extend(fields)
    result["fields"] = list(set(result["fields"]))
    
    # Extract lookups
    lookup_matches = re.findall(r'(?:lookup|inputlookup|outputlookup)\s+(\S+)', spl_query)
    result["lookups"] = list(set(lookup_matches))
    
    # Extract time range
    time_match = re.search(r'earliest\s*=\s*(\S+)', spl_query)
    if time_match:
        result["timerange"] = time_match.group(1)
    
    return result


def extract_thresholds(spl_query):
    """Extract threshold values from SPL."""
    thresholds = []
    if not spl_query:
        return thresholds
    patterns = [
        r'where\s+(\w+)\s*([><=!]+)\s*(\d+)',
        r'count\s*([><=!]+)\s*(\d+)',
    ]
    for p in patterns:
        matches = re.findall(p, spl_query)
        for m in matches:
            if len(m) == 3:
                thresholds.append(f"{m[0]} {m[1]} {m[2]}")
            elif len(m) == 2:
                thresholds.append(f"count {m[0]} {m[1]}")
    return thresholds


def validate_with_ai(checkpoint_id, context_data, api_key):
    """Call Claude API for judgment-based validation."""
    import urllib.request
    import ssl
    
    prompts = {
        "cp2": f"""You are a SIEM security analyst. Compare this use case objective with the SPL query and determine if the rule is built correctly to achieve the objective.

Use Case Objective: {context_data.get('objective', 'Not provided')}
SPL Query: {context_data.get('spl_query', 'Not provided')}
Parsed Fields: {json.dumps(context_data.get('parsed', {}), indent=2)}

Evaluate:
1. Does the query logic match the stated objective?
2. Are there any gaps between what the objective describes and what the query detects?
3. Are there any obvious issues with the query?

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW
- ASSESSMENT: 2-3 sentences explaining your evaluation
- RECOMMENDATIONS: Any specific improvements (if applicable)""",

        "cp4": f"""You are a SIEM security analyst. Evaluate whether this use case has appropriate enrichment sources.

Use Case Name: {context_data.get('use_case_name', 'Not provided')}
Use Case Objective: {context_data.get('objective', 'Not provided')}
SPL Query: {context_data.get('spl_query', 'Not provided')}
Detected Lookups/Enrichments: {json.dumps(context_data.get('lookups', []))}
Analyst Notes on Enrichment: {context_data.get('enrichment_notes', 'Not provided')}

Evaluate:
1. Are there enrichment sources (lookups, threat intel, asset/identity) in the query?
2. For this type of use case, what enrichments would typically be expected?
3. Are any critical enrichments missing?

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW / NOT APPLICABLE
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Specific enrichment suggestions if missing""",

        "cp5": f"""You are a SIEM security analyst expert in MITRE ATT&CK framework. Validate the MITRE mapping for this use case.

Use Case Name: {context_data.get('use_case_name', 'Not provided')}
Use Case Objective: {context_data.get('objective', 'Not provided')}
SPL Query: {context_data.get('spl_query', 'Not provided')}
Mapped MITRE Techniques: {context_data.get('mitre_techniques', 'Not provided')}

Evaluate:
1. Do the mapped MITRE ATT&CK techniques correctly align with what this rule detects?
2. Are there any techniques that should be mapped but aren't?
3. Are any of the current mappings incorrect or a stretch?

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Correct technique IDs if mapping is wrong""",

        "cp6": f"""You are a SIEM security analyst. Evaluate the alert grouping and correlation settings.

Use Case Name: {context_data.get('use_case_name', 'Not provided')}
Use Case Objective: {context_data.get('objective', 'Not provided')}
Grouping Fields: {context_data.get('grouping_fields', 'Not provided')}
Correlation Settings: {context_data.get('correlation_settings', 'Not provided')}
Analyst Notes: {context_data.get('grouping_notes', 'Not provided')}

Evaluate:
1. Are the grouping fields appropriate for this type of use case?
2. Will the grouping reduce alert fatigue effectively?
3. Could the grouping cause important alerts to be suppressed?

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Better grouping strategy if needed""",

        "cp7": f"""You are a SIEM security analyst. Evaluate the historical/simulated test results for this rule.

Use Case Name: {context_data.get('use_case_name', 'Not provided')}
Use Case Objective: {context_data.get('objective', 'Not provided')}
Test Results Summary: {context_data.get('test_results', 'Not provided')}
Number of Results: {context_data.get('result_count', 'Not provided')}
Analyst Notes: {context_data.get('test_notes', 'Not provided')}

Evaluate:
1. Do the test results show the rule is detecting what it's supposed to?
2. Are the results consistent with expected behavior?
3. Are there any red flags in the test output?

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Additional testing suggestions if needed""",

        "cp8": f"""You are a SIEM security analyst. Evaluate whether this rule triggers correctly on production data.

Use Case Name: {context_data.get('use_case_name', 'Not provided')}
Use Case Objective: {context_data.get('objective', 'Not provided')}
Production Alert Samples: {context_data.get('prod_results', 'Not provided')}
Number of Alerts in Production: {context_data.get('alert_count', 'Not provided')}
Analyst Notes: {context_data.get('prod_notes', 'Not provided')}

Evaluate:
1. Is the rule triggering on production data as expected?
2. Do the alert samples look like genuine detections?
3. Any concerns about the production behavior?

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Any adjustments needed"""
    }
    
    if checkpoint_id not in prompts:
        return None
    
    try:
        data = json.dumps({
            "model": "claude-sonnet-4-5",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompts[checkpoint_id]}]
        }).encode('utf-8')
        
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
            result = json.loads(response.read().decode('utf-8'))
            text = result["content"][0]["text"]
            
            # Parse status from response
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


def generate_pdf_report():
    """Generate a PDF validation report."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=25*mm,
        leftMargin=25*mm,
        topMargin=25*mm,
        bottomMargin=25*mm
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle', parent=styles['Title'],
        fontSize=22, spaceAfter=6, textColor=colors.HexColor('#0f172a'),
        fontName='Helvetica-Bold'
    )
    subtitle_style = ParagraphStyle(
        'CustomSubtitle', parent=styles['Normal'],
        fontSize=11, textColor=colors.HexColor('#64748b'),
        spaceAfter=20
    )
    heading_style = ParagraphStyle(
        'CustomHeading', parent=styles['Heading2'],
        fontSize=13, textColor=colors.HexColor('#0f172a'),
        spaceBefore=16, spaceAfter=8,
        fontName='Helvetica-Bold'
    )
    body_style = ParagraphStyle(
        'CustomBody', parent=styles['Normal'],
        fontSize=10, leading=14, textColor=colors.HexColor('#334155')
    )
    status_pass = ParagraphStyle(
        'StatusPass', parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#166534'),
        fontName='Helvetica-Bold'
    )
    status_fail = ParagraphStyle(
        'StatusFail', parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#991b1b'),
        fontName='Helvetica-Bold'
    )
    status_review = ParagraphStyle(
        'StatusReview', parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#92400e'),
        fontName='Helvetica-Bold'
    )
    
    story = []
    info = st.session_state.use_case_info
    cps = st.session_state.checkpoints
    
    # --- Cover Section ---
    story.append(Spacer(1, 30))
    story.append(Paragraph("SIEM Use Case Validation Report", title_style))
    story.append(Paragraph(
        f"Generated on {datetime.now().strftime('%B %d, %Y at %H:%M')}",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#38bdf8')))
    story.append(Spacer(1, 16))
    
    # Use case info table
    info_data = [
        ["Use Case Name", info.get("name", "N/A")],
        ["Use Case ID", info.get("id", "N/A")],
        ["Analyst", info.get("analyst", "N/A")],
        ["Validation Date", info.get("date", "N/A")],
    ]
    info_table = Table(info_data, colWidths=[120, 380])
    info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#475569')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#0f172a')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 10))
    
    # Description
    if info.get("description"):
        story.append(Paragraph("<b>Use Case Description:</b>", body_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(info["description"], body_style))
        story.append(Spacer(1, 10))

    # SPL Query
    spl = st.session_state.get("shared_spl", "") or ""
    if not spl:
        # Try to recover from CP1 evidence if available
        spl = cps.get("cp1", {}).get("evidence", {}).get("spl_query", "")
    if spl:
        story.append(Paragraph("<b>SPL Query:</b>", body_style))
        story.append(Spacer(1, 4))
        mono_style = ParagraphStyle(
            'Mono', parent=styles['Normal'],
            fontSize=8, leading=11, fontName='Courier',
            textColor=colors.HexColor('#334155'),
            backColor=colors.HexColor('#f8fafc'),
            borderPadding=(4, 4, 4, 4),
        )
        spl_escaped = spl.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        story.append(Paragraph(spl_escaped, mono_style))

    story.append(Spacer(1, 20))
    
    # --- Summary Section ---
    story.append(Paragraph("Validation Summary", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1, 10))
    
    pass_count = sum(1 for cp in cps.values() if cp["status"] == "pass")
    fail_count = sum(1 for cp in cps.values() if cp["status"] == "fail")
    review_count = sum(1 for cp in cps.values() if cp["status"] == "review")
    pending_count = sum(1 for cp in cps.values() if cp["status"] == "pending")
    
    overall = "PASS" if fail_count == 0 and pending_count == 0 and review_count == 0 else \
              "FAIL" if fail_count > 0 else "NEEDS REVIEW"
    
    summary_data = [
        ["Overall Result", "Passed", "Failed", "Needs Review", "Pending"],
        [overall, str(pass_count), str(fail_count), str(review_count), str(pending_count)]
    ]
    summary_table = Table(summary_data, colWidths=[100, 100, 100, 100, 100])
    
    overall_color = colors.HexColor('#166534') if overall == "PASS" else \
                    colors.HexColor('#991b1b') if overall == "FAIL" else \
                    colors.HexColor('#92400e')
    
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('TEXTCOLOR', (0, 1), (0, 1), overall_color),
        ('FONTNAME', (0, 1), (0, 1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor('#166534')),
        ('TEXTCOLOR', (2, 1), (2, 1), colors.HexColor('#991b1b')),
        ('TEXTCOLOR', (3, 1), (3, 1), colors.HexColor('#92400e')),
        ('TEXTCOLOR', (4, 1), (4, 1), colors.HexColor('#475569')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))
    
    # --- Checkpoint quick reference ---
    story.append(Spacer(1, 10))
    cp_summary_data = [["#", "Checkpoint", "Status"]]
    for key, name in CHECKPOINT_NAMES.items():
        status = cps[key]["status"].upper().replace("REVIEW", "NEEDS REVIEW").replace("PENDING", "PENDING")
        cp_summary_data.append([key.replace("cp", ""), name.replace(f"{key.replace('cp','')}. ", ""), status])
    
    cp_summary_table = Table(cp_summary_data, colWidths=[30, 370, 100])
    cp_style_commands = [
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('ALIGN', (0, 0), (0, -1), 'CENTER'),
        ('ALIGN', (2, 0), (2, -1), 'CENTER'),
    ]
    # Color code status cells
    for i, key in enumerate(CHECKPOINT_NAMES.keys(), 1):
        s = cps[key]["status"]
        if s == "pass":
            cp_style_commands.append(('TEXTCOLOR', (2, i), (2, i), colors.HexColor('#166534')))
        elif s == "fail":
            cp_style_commands.append(('TEXTCOLOR', (2, i), (2, i), colors.HexColor('#991b1b')))
        elif s == "review":
            cp_style_commands.append(('TEXTCOLOR', (2, i), (2, i), colors.HexColor('#92400e')))
    
    cp_summary_table.setStyle(TableStyle(cp_style_commands))
    story.append(cp_summary_table)
    
    story.append(PageBreak())
    
    # --- Detailed Checkpoint Results ---
    story.append(Paragraph("Detailed Checkpoint Results", heading_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#38bdf8')))
    story.append(Spacer(1, 12))
    
    for key, name in CHECKPOINT_NAMES.items():
        cp = cps[key]
        
        # Status styling
        status_text = cp["status"].upper()
        if status_text == "REVIEW":
            status_text = "NEEDS REVIEW"
        
        s_style = status_pass if cp["status"] == "pass" else \
                  status_fail if cp["status"] == "fail" else status_review
        
        story.append(Paragraph(f"<b>{name}</b>", heading_style))
        story.append(Paragraph(f"Status: {status_text}", s_style))
        story.append(Spacer(1, 6))
        
        # Evidence
        if cp.get("evidence"):
            for ev_key, ev_val in cp["evidence"].items():
                if ev_val and str(ev_val).strip():
                    label = ev_key.replace("_", " ").title()
                    # Truncate very long values
                    val_str = str(ev_val)
                    if len(val_str) > 500:
                        val_str = val_str[:500] + "..."
                    # Escape XML special chars
                    val_str = val_str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    story.append(Paragraph(f"<b>{label}:</b> {val_str}", body_style))
                    story.append(Spacer(1, 3))
        
        # AI Assessment
        if cp.get("assessment"):
            assessment_text = cp["assessment"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>AI Assessment:</b>", body_style))
            story.append(Paragraph(assessment_text, body_style))
        
        story.append(Spacer(1, 6))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 8))
    
    # --- Footer ---
    story.append(Spacer(1, 20))
    footer_style = ParagraphStyle(
        'Footer', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER
    )
    story.append(Paragraph(
        "This report was generated by the SIEM Use Case Validation Agent. "
        "AI-powered assessments should be reviewed by a qualified security analyst.",
        footer_style
    ))
    
    doc.build(story)
    buffer.seek(0)
    return buffer.read()


# =====================================================
# SIDEBAR
# =====================================================
with st.sidebar:
    st.markdown("### 🛡️ Validation Status")
    st.markdown("---")

    # Counts first so progress bar can use them
    cps = st.session_state.checkpoints
    p = sum(1 for c in cps.values() if c["status"] == "pass")
    f = sum(1 for c in cps.values() if c["status"] == "fail")
    r = sum(1 for c in cps.values() if c["status"] == "review")
    completed = p + f + r
    total = len(cps)

    # Progress bar
    st.progress(completed / total, text=f"{completed}/{total} checkpoints reviewed")
    st.markdown("")

    for key, name in CHECKPOINT_NAMES.items():
        status = st.session_state.checkpoints[key]["status"]
        icon = STATUS_ICONS[status]
        short_name = name.split(". ", 1)[1] if ". " in name else name
        st.markdown(f"{icon} **{short_name}**")

    st.markdown("---")

    col1, col2, col3 = st.columns(3)
    col1.metric("Pass", p)
    col2.metric("Fail", f)
    col3.metric("Review", r)

    st.markdown("---")
    if st.button("🔄 Reset / New Validation", use_container_width=True):
        for key in st.session_state.checkpoints:
            st.session_state.checkpoints[key] = {"status": "pending", "assessment": "", "evidence": {}}
        st.session_state.use_case_info = {
            "name": "", "id": "", "description": "", "analyst": "",
            "date": datetime.now().strftime("%Y-%m-%d")
        }
        st.rerun()
    
    st.markdown("---")
    st.markdown("### ⚙️ Settings")
    _secret_key = st.secrets.get("ANTHROPIC_API_KEY", "") if hasattr(st, "secrets") else ""
    api_key = st.text_input(
        "Claude API Key",
        value=_secret_key,
        type="password",
        help="Required for AI-powered validation (CPs 2,4,5,6,7,8). Set ANTHROPIC_API_KEY in Streamlit secrets to pre-fill."
    )
    
    st.markdown("---")
    st.markdown("### 📄 Generate Report")
    if st.button("📥 Generate PDF Report", use_container_width=True, type="primary"):
        with st.spinner("Generating report..."):
            try:
                pdf_bytes = generate_pdf_report()
                st.download_button(
                    "⬇️ Download Report",
                    pdf_bytes,
                    file_name=f"validation_report_{st.session_state.use_case_info.get('id', 'draft')}_{datetime.now().strftime('%Y%m%d')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
                st.success("Report generated!")
            except Exception as e:
                st.error(f"Error generating report: {e}")


# =====================================================
# MAIN CONTENT
# =====================================================

# Header
st.markdown("""
<div class="main-header">
    <h1>🛡️ SIEM Use Case Validation Agent</h1>
    <p>Guided validation of SIEM detection rules against acceptance checkpoints</p>
</div>
""", unsafe_allow_html=True)

# --- Use Case Information ---
with st.expander("📋 Use Case Information", expanded=True):
    col1, col2 = st.columns(2)
    with col1:
        st.session_state.use_case_info["name"] = st.text_input(
            "Use Case Name",
            value=st.session_state.use_case_info["name"],
            placeholder="e.g., Brute Force Detection on VPN"
        )
        st.session_state.use_case_info["id"] = st.text_input(
            "Use Case ID",
            value=st.session_state.use_case_info["id"],
            placeholder="e.g., UC-001"
        )
    with col2:
        st.session_state.use_case_info["analyst"] = st.text_input(
            "Analyst Name",
            value=st.session_state.use_case_info["analyst"],
            placeholder="Your name"
        )
        st.session_state.use_case_info["date"] = st.text_input(
            "Validation Date",
            value=st.session_state.use_case_info["date"]
        )
    
    st.session_state.use_case_info["description"] = st.text_area(
        "Use Case Objective / Description",
        value=st.session_state.use_case_info["description"],
        placeholder="Describe what this use case is designed to detect...",
        height=100
    )

st.markdown("---")

# Shared SPL input (used across multiple checkpoints)
with st.expander("🔍 SPL Query (shared across checkpoints)", expanded=True):
    spl_query = st.text_area(
        "Paste the SPL query for this use case",
        height=150,
        placeholder="index=security sourcetype=vpn_logs | stats count by src_ip | where count > 10",
        key="shared_spl"
    )
    
    if spl_query:
        parsed = parse_spl_fields(spl_query)
        thresholds = extract_thresholds(spl_query)
        
        st.markdown("**Parsed from SPL:**")
        pcol1, pcol2, pcol3 = st.columns(3)
        with pcol1:
            st.markdown(f"**Indexes:** {', '.join(parsed['indexes']) if parsed['indexes'] else 'None detected'}")
            st.markdown(f"**Sourcetypes:** {', '.join(parsed['sourcetypes']) if parsed['sourcetypes'] else 'None detected'}")
        with pcol2:
            st.markdown(f"**Fields:** {', '.join(parsed['fields']) if parsed['fields'] else 'None detected'}")
            st.markdown(f"**Lookups:** {', '.join(parsed['lookups']) if parsed['lookups'] else 'None'}")
        with pcol3:
            st.markdown(f"**Time Range:** {parsed['timerange'] if parsed['timerange'] else 'Not specified'}")
            st.markdown(f"**Thresholds:** {', '.join(thresholds) if thresholds else 'None detected'}")
    else:
        parsed = {}
        thresholds = []

st.markdown("---")
st.markdown("## Validation Checkpoints")

# =====================================================
# CHECKPOINT 1: Logs & Fields Availability
# =====================================================
with st.expander(f"{STATUS_ICONS[st.session_state.checkpoints['cp1']['status']]} **Checkpoint 1: Are the necessary logs and fields available to trigger the rule?**"):
    st.markdown("Verify that all required data sources, indexes, and fields referenced in the SPL are available and populated.")
    
    cp1_sample = st.text_area(
        "Paste sample search results (CSV or raw) or describe field availability",
        height=120,
        key="cp1_sample",
        placeholder="Paste sample output from the SPL query, or describe which fields are available..."
    )
    
    cp1_notes = st.text_area("Analyst notes", height=60, key="cp1_notes", placeholder="Any additional context...")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("✅ Pass", key="cp1_pass", use_container_width=True):
            st.session_state.checkpoints["cp1"]["status"] = "pass"
            st.session_state.checkpoints["cp1"]["evidence"] = {"sample_data": cp1_sample, "analyst_notes": cp1_notes, "spl_query": spl_query, "parsed_fields": json.dumps(parsed) if parsed else ""}
            st.rerun()
    with col2:
        if st.button("❌ Fail", key="cp1_fail", use_container_width=True):
            st.session_state.checkpoints["cp1"]["status"] = "fail"
            st.session_state.checkpoints["cp1"]["evidence"] = {"sample_data": cp1_sample, "analyst_notes": cp1_notes, "spl_query": spl_query, "parsed_fields": json.dumps(parsed) if parsed else ""}
            st.rerun()
    with col3:
        if st.button("⚠️ Needs Review", key="cp1_review", use_container_width=True):
            st.session_state.checkpoints["cp1"]["status"] = "review"
            st.session_state.checkpoints["cp1"]["evidence"] = {"sample_data": cp1_sample, "analyst_notes": cp1_notes, "spl_query": spl_query, "parsed_fields": json.dumps(parsed) if parsed else ""}
            st.rerun()
    
    if st.session_state.checkpoints["cp1"]["assessment"]:
        st.markdown(f"""<div class="ai-assessment"><div class="ai-assessment-header">AI Assessment</div>{st.session_state.checkpoints["cp1"]["assessment"]}</div>""", unsafe_allow_html=True)


# =====================================================
# CHECKPOINT 2: Rule Built as Per Objective
# =====================================================
with st.expander(f"{STATUS_ICONS[st.session_state.checkpoints['cp2']['status']]} **Checkpoint 2: Is rule built as per objective?**"):
    st.markdown("Compare the use case objective against the actual SPL implementation to identify gaps.")
    
    cp2_objective = st.session_state.use_case_info.get("description", "")
    if not cp2_objective:
        st.warning("Please fill in the Use Case Objective in the Use Case Information section above.")
    
    cp2_notes = st.text_area("Additional context or notes", height=60, key="cp2_notes")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🤖 Validate with AI", key="cp2_ai", use_container_width=True, type="primary"):
            if not api_key:
                st.error("Please enter your Claude API Key in the sidebar.")
            elif not spl_query:
                st.error("Please enter the SPL query first.")
            elif not cp2_objective:
                st.error("Please enter the use case objective.")
            else:
                with st.spinner("AI is analyzing..."):
                    result = validate_with_ai("cp2", {
                        "objective": cp2_objective,
                        "spl_query": spl_query,
                        "parsed": parsed
                    }, api_key)
                    if result:
                        st.session_state.checkpoints["cp2"]["status"] = result["status"]
                        st.session_state.checkpoints["cp2"]["assessment"] = result["assessment"]
                        st.session_state.checkpoints["cp2"]["evidence"] = {"objective": cp2_objective, "spl_query": spl_query, "analyst_notes": cp2_notes}
                        st.rerun()
    
    with col2:
        manual_col1, manual_col2, manual_col3 = st.columns(3)
        with manual_col1:
            if st.button("✅", key="cp2_pass"):
                st.session_state.checkpoints["cp2"]["status"] = "pass"
                st.session_state.checkpoints["cp2"]["evidence"] = {"objective": cp2_objective, "spl_query": spl_query, "analyst_notes": cp2_notes}
                st.rerun()
        with manual_col2:
            if st.button("❌", key="cp2_fail"):
                st.session_state.checkpoints["cp2"]["status"] = "fail"
                st.session_state.checkpoints["cp2"]["evidence"] = {"objective": cp2_objective, "spl_query": spl_query, "analyst_notes": cp2_notes}
                st.rerun()
        with manual_col3:
            if st.button("⚠️", key="cp2_review"):
                st.session_state.checkpoints["cp2"]["status"] = "review"
                st.session_state.checkpoints["cp2"]["evidence"] = {"objective": cp2_objective, "spl_query": spl_query, "analyst_notes": cp2_notes}
                st.rerun()
    
    if st.session_state.checkpoints["cp2"]["assessment"]:
        st.markdown(f"""<div class="ai-assessment"><div class="ai-assessment-header">AI Assessment</div>{st.session_state.checkpoints["cp2"]["assessment"]}</div>""", unsafe_allow_html=True)


# =====================================================
# CHECKPOINT 3: Query Aspects Validation
# =====================================================
with st.expander(f"{STATUS_ICONS[st.session_state.checkpoints['cp3']['status']]} **Checkpoint 3: Query Aspects Validation (Thresholds, Conditions, Severity, Frequency, Lookback)**"):
    st.markdown("Validate the five query aspects: thresholds, conditions, severity, search frequency, and lookback period.")
    
    col1, col2 = st.columns(2)
    with col1:
        cp3_threshold = st.text_input(
            "Threshold Value(s)",
            value=", ".join(thresholds) if thresholds else "",
            key="cp3_threshold",
            placeholder="e.g., count > 10"
        )
        cp3_conditions = st.text_area(
            "Conditions / Filtering Logic",
            height=60, key="cp3_conditions",
            placeholder="Describe the key conditions in the query..."
        )
        cp3_severity = st.selectbox(
            "Alert Severity",
            ["-- Select --", "Informational", "Low", "Medium", "High", "Critical"],
            key="cp3_severity"
        )
    with col2:
        cp3_frequency = st.text_input(
            "Search Frequency (cron or interval)",
            key="cp3_frequency",
            placeholder="e.g., */5 * * * * (every 5 min) or every 1 hour"
        )
        cp3_lookback = st.text_input(
            "Lookback Period",
            value=parsed.get("timerange", "") if parsed else "",
            key="cp3_lookback",
            placeholder="e.g., -60m, -24h, -7d"
        )
        cp3_notes = st.text_area("Analyst Notes", height=60, key="cp3_notes")
    
    st.markdown("**Are all five aspects validated and appropriate?**")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("✅ Pass", key="cp3_pass", use_container_width=True):
            st.session_state.checkpoints["cp3"]["status"] = "pass"
            st.session_state.checkpoints["cp3"]["evidence"] = {
                "thresholds": cp3_threshold, "conditions": cp3_conditions,
                "severity": cp3_severity, "frequency": cp3_frequency,
                "lookback": cp3_lookback, "analyst_notes": cp3_notes
            }
            st.rerun()
    with col2:
        if st.button("❌ Fail", key="cp3_fail", use_container_width=True):
            st.session_state.checkpoints["cp3"]["status"] = "fail"
            st.session_state.checkpoints["cp3"]["evidence"] = {
                "thresholds": cp3_threshold, "conditions": cp3_conditions,
                "severity": cp3_severity, "frequency": cp3_frequency,
                "lookback": cp3_lookback, "analyst_notes": cp3_notes
            }
            st.rerun()
    with col3:
        if st.button("⚠️ Needs Review", key="cp3_review", use_container_width=True):
            st.session_state.checkpoints["cp3"]["status"] = "review"
            st.session_state.checkpoints["cp3"]["evidence"] = {
                "thresholds": cp3_threshold, "conditions": cp3_conditions,
                "severity": cp3_severity, "frequency": cp3_frequency,
                "lookback": cp3_lookback, "analyst_notes": cp3_notes
            }
            st.rerun()


# =====================================================
# CHECKPOINT 4: Enrichment Sources
# =====================================================
with st.expander(f"{STATUS_ICONS[st.session_state.checkpoints['cp4']['status']]} **Checkpoint 4: Are enrichment sources added (if applicable)?**"):
    st.markdown("Check if the query uses appropriate enrichment such as lookups, threat intel feeds, or asset/identity tables.")
    
    if parsed and parsed.get("lookups"):
        st.info(f"**Detected in SPL:** {', '.join(parsed['lookups'])}")
    
    cp4_notes = st.text_area(
        "Describe enrichment sources used (or explain why none are needed)",
        height=80, key="cp4_notes",
        placeholder="e.g., Uses asset_lookup for hostname enrichment, threat_intel_ip for IP reputation..."
    )
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🤖 Validate with AI", key="cp4_ai", use_container_width=True, type="primary"):
            if not api_key:
                st.error("Please enter your Claude API Key in the sidebar.")
            else:
                with st.spinner("AI is analyzing..."):
                    result = validate_with_ai("cp4", {
                        "use_case_name": st.session_state.use_case_info.get("name", ""),
                        "objective": st.session_state.use_case_info.get("description", ""),
                        "spl_query": spl_query,
                        "lookups": parsed.get("lookups", []) if parsed else [],
                        "enrichment_notes": cp4_notes
                    }, api_key)
                    if result:
                        st.session_state.checkpoints["cp4"]["status"] = result["status"]
                        st.session_state.checkpoints["cp4"]["assessment"] = result["assessment"]
                        st.session_state.checkpoints["cp4"]["evidence"] = {"enrichment_notes": cp4_notes, "detected_lookups": json.dumps(parsed.get("lookups", []) if parsed else [])}
                        st.rerun()
    with col2:
        mc1, mc2, mc3 = st.columns(3)
        with mc1:
            if st.button("✅", key="cp4_pass"):
                st.session_state.checkpoints["cp4"]["status"] = "pass"
                st.session_state.checkpoints["cp4"]["evidence"] = {"enrichment_notes": cp4_notes}
                st.rerun()
        with mc2:
            if st.button("❌", key="cp4_fail"):
                st.session_state.checkpoints["cp4"]["status"] = "fail"
                st.session_state.checkpoints["cp4"]["evidence"] = {"enrichment_notes": cp4_notes}
                st.rerun()
        with mc3:
            if st.button("⚠️", key="cp4_review"):
                st.session_state.checkpoints["cp4"]["status"] = "review"
                st.session_state.checkpoints["cp4"]["evidence"] = {"enrichment_notes": cp4_notes}
                st.rerun()
    
    if st.session_state.checkpoints["cp4"]["assessment"]:
        st.markdown(f"""<div class="ai-assessment"><div class="ai-assessment-header">AI Assessment</div>{st.session_state.checkpoints["cp4"]["assessment"]}</div>""", unsafe_allow_html=True)


# =====================================================
# CHECKPOINT 5: MITRE ATT&CK Mapping
# =====================================================
with st.expander(f"{STATUS_ICONS[st.session_state.checkpoints['cp5']['status']]} **Checkpoint 5: Is MITRE ATT&CK mapping completed and validated?**"):
    st.markdown("Verify that the use case is correctly mapped to MITRE ATT&CK techniques.")
    
    cp5_techniques = st.text_input(
        "Mapped MITRE ATT&CK Technique IDs",
        key="cp5_techniques",
        placeholder="e.g., T1110, T1110.001, T1078"
    )
    cp5_tactics = st.text_input(
        "Mapped Tactics (optional)",
        key="cp5_tactics",
        placeholder="e.g., Credential Access, Initial Access"
    )
    cp5_notes = st.text_area("Analyst notes on mapping", height=60, key="cp5_notes")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🤖 Validate with AI", key="cp5_ai", use_container_width=True, type="primary"):
            if not api_key:
                st.error("Please enter your Claude API Key in the sidebar.")
            elif not cp5_techniques:
                st.error("Please enter the MITRE technique IDs.")
            else:
                with st.spinner("AI is analyzing..."):
                    result = validate_with_ai("cp5", {
                        "use_case_name": st.session_state.use_case_info.get("name", ""),
                        "objective": st.session_state.use_case_info.get("description", ""),
                        "spl_query": spl_query,
                        "mitre_techniques": f"{cp5_techniques} | Tactics: {cp5_tactics}"
                    }, api_key)
                    if result:
                        st.session_state.checkpoints["cp5"]["status"] = result["status"]
                        st.session_state.checkpoints["cp5"]["assessment"] = result["assessment"]
                        st.session_state.checkpoints["cp5"]["evidence"] = {"mitre_techniques": cp5_techniques, "mitre_tactics": cp5_tactics, "analyst_notes": cp5_notes}
                        st.rerun()
    with col2:
        mc1, mc2, mc3 = st.columns(3)
        with mc1:
            if st.button("✅", key="cp5_pass"):
                st.session_state.checkpoints["cp5"]["status"] = "pass"
                st.session_state.checkpoints["cp5"]["evidence"] = {"mitre_techniques": cp5_techniques, "mitre_tactics": cp5_tactics, "analyst_notes": cp5_notes}
                st.rerun()
        with mc2:
            if st.button("❌", key="cp5_fail"):
                st.session_state.checkpoints["cp5"]["status"] = "fail"
                st.session_state.checkpoints["cp5"]["evidence"] = {"mitre_techniques": cp5_techniques, "mitre_tactics": cp5_tactics, "analyst_notes": cp5_notes}
                st.rerun()
        with mc3:
            if st.button("⚠️", key="cp5_review"):
                st.session_state.checkpoints["cp5"]["status"] = "review"
                st.session_state.checkpoints["cp5"]["evidence"] = {"mitre_techniques": cp5_techniques, "mitre_tactics": cp5_tactics, "analyst_notes": cp5_notes}
                st.rerun()
    
    if st.session_state.checkpoints["cp5"]["assessment"]:
        st.markdown(f"""<div class="ai-assessment"><div class="ai-assessment-header">AI Assessment</div>{st.session_state.checkpoints["cp5"]["assessment"]}</div>""", unsafe_allow_html=True)


# =====================================================
# CHECKPOINT 6: Alert Grouping / Correlation
# =====================================================
with st.expander(f"{STATUS_ICONS[st.session_state.checkpoints['cp6']['status']]} **Checkpoint 6: Are alert grouping or correlation settings configured correctly?**"):
    st.markdown("Validate that alert grouping reduces noise without suppressing critical detections.")
    
    cp6_grouping = st.text_input(
        "Grouping Fields",
        key="cp6_grouping",
        placeholder="e.g., src_ip, dest, user"
    )
    cp6_correlation = st.text_area(
        "Correlation Settings (if applicable)",
        height=60, key="cp6_correlation",
        placeholder="Describe correlation search config, throttling, etc."
    )
    cp6_notes = st.text_area("Analyst notes", height=60, key="cp6_notes")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🤖 Validate with AI", key="cp6_ai", use_container_width=True, type="primary"):
            if not api_key:
                st.error("Please enter your Claude API Key in the sidebar.")
            else:
                with st.spinner("AI is analyzing..."):
                    result = validate_with_ai("cp6", {
                        "use_case_name": st.session_state.use_case_info.get("name", ""),
                        "objective": st.session_state.use_case_info.get("description", ""),
                        "grouping_fields": cp6_grouping,
                        "correlation_settings": cp6_correlation,
                        "grouping_notes": cp6_notes
                    }, api_key)
                    if result:
                        st.session_state.checkpoints["cp6"]["status"] = result["status"]
                        st.session_state.checkpoints["cp6"]["assessment"] = result["assessment"]
                        st.session_state.checkpoints["cp6"]["evidence"] = {"grouping_fields": cp6_grouping, "correlation_settings": cp6_correlation, "analyst_notes": cp6_notes}
                        st.rerun()
    with col2:
        mc1, mc2, mc3 = st.columns(3)
        with mc1:
            if st.button("✅", key="cp6_pass"):
                st.session_state.checkpoints["cp6"]["status"] = "pass"
                st.session_state.checkpoints["cp6"]["evidence"] = {"grouping_fields": cp6_grouping, "correlation_settings": cp6_correlation, "analyst_notes": cp6_notes}
                st.rerun()
        with mc2:
            if st.button("❌", key="cp6_fail"):
                st.session_state.checkpoints["cp6"]["status"] = "fail"
                st.session_state.checkpoints["cp6"]["evidence"] = {"grouping_fields": cp6_grouping, "correlation_settings": cp6_correlation, "analyst_notes": cp6_notes}
                st.rerun()
        with mc3:
            if st.button("⚠️", key="cp6_review"):
                st.session_state.checkpoints["cp6"]["status"] = "review"
                st.session_state.checkpoints["cp6"]["evidence"] = {"grouping_fields": cp6_grouping, "correlation_settings": cp6_correlation, "analyst_notes": cp6_notes}
                st.rerun()
    
    if st.session_state.checkpoints["cp6"]["assessment"]:
        st.markdown(f"""<div class="ai-assessment"><div class="ai-assessment-header">AI Assessment</div>{st.session_state.checkpoints["cp6"]["assessment"]}</div>""", unsafe_allow_html=True)


# =====================================================
# CHECKPOINT 7: Historical / Simulated Testing
# =====================================================
with st.expander(f"{STATUS_ICONS[st.session_state.checkpoints['cp7']['status']]} **Checkpoint 7: Has the rule been validated on historical or simulated data?**"):
    st.markdown("Confirm that testing was performed and results demonstrate expected behavior.")
    
    cp7_results = st.text_area(
        "Paste test results or summary",
        height=120, key="cp7_results",
        placeholder="Paste sample test output, describe the test scenario and results..."
    )
    cp7_count = st.number_input("Number of test results/alerts generated", min_value=0, value=0, key="cp7_count")
    cp7_notes = st.text_area("Analyst notes on testing", height=60, key="cp7_notes")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🤖 Validate with AI", key="cp7_ai", use_container_width=True, type="primary"):
            if not api_key:
                st.error("Please enter your Claude API Key in the sidebar.")
            else:
                with st.spinner("AI is analyzing..."):
                    result = validate_with_ai("cp7", {
                        "use_case_name": st.session_state.use_case_info.get("name", ""),
                        "objective": st.session_state.use_case_info.get("description", ""),
                        "test_results": cp7_results,
                        "result_count": cp7_count,
                        "test_notes": cp7_notes
                    }, api_key)
                    if result:
                        st.session_state.checkpoints["cp7"]["status"] = result["status"]
                        st.session_state.checkpoints["cp7"]["assessment"] = result["assessment"]
                        st.session_state.checkpoints["cp7"]["evidence"] = {"test_results": cp7_results, "result_count": cp7_count, "analyst_notes": cp7_notes}
                        st.rerun()
    with col2:
        mc1, mc2, mc3 = st.columns(3)
        with mc1:
            if st.button("✅", key="cp7_pass"):
                st.session_state.checkpoints["cp7"]["status"] = "pass"
                st.session_state.checkpoints["cp7"]["evidence"] = {"test_results": cp7_results, "result_count": cp7_count, "analyst_notes": cp7_notes}
                st.rerun()
        with mc2:
            if st.button("❌", key="cp7_fail"):
                st.session_state.checkpoints["cp7"]["status"] = "fail"
                st.session_state.checkpoints["cp7"]["evidence"] = {"test_results": cp7_results, "result_count": cp7_count, "analyst_notes": cp7_notes}
                st.rerun()
        with mc3:
            if st.button("⚠️", key="cp7_review"):
                st.session_state.checkpoints["cp7"]["status"] = "review"
                st.session_state.checkpoints["cp7"]["evidence"] = {"test_results": cp7_results, "result_count": cp7_count, "analyst_notes": cp7_notes}
                st.rerun()
    
    if st.session_state.checkpoints["cp7"]["assessment"]:
        st.markdown(f"""<div class="ai-assessment"><div class="ai-assessment-header">AI Assessment</div>{st.session_state.checkpoints["cp7"]["assessment"]}</div>""", unsafe_allow_html=True)


# =====================================================
# CHECKPOINT 8: Production Trigger Validation
# =====================================================
with st.expander(f"{STATUS_ICONS[st.session_state.checkpoints['cp8']['status']]} **Checkpoint 8: Does the rule trigger correctly on production data/alerts?**"):
    st.markdown("Confirm the rule fires correctly in the production environment.")
    
    cp8_results = st.text_area(
        "Paste production alert samples or describe production behavior",
        height=120, key="cp8_results",
        placeholder="Paste recent production alerts or describe how the rule behaved in prod..."
    )
    cp8_count = st.number_input("Number of production alerts observed", min_value=0, value=0, key="cp8_count")
    cp8_notes = st.text_area("Analyst notes on production behavior", height=60, key="cp8_notes")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🤖 Validate with AI", key="cp8_ai", use_container_width=True, type="primary"):
            if not api_key:
                st.error("Please enter your Claude API Key in the sidebar.")
            else:
                with st.spinner("AI is analyzing..."):
                    result = validate_with_ai("cp8", {
                        "use_case_name": st.session_state.use_case_info.get("name", ""),
                        "objective": st.session_state.use_case_info.get("description", ""),
                        "prod_results": cp8_results,
                        "alert_count": cp8_count,
                        "prod_notes": cp8_notes
                    }, api_key)
                    if result:
                        st.session_state.checkpoints["cp8"]["status"] = result["status"]
                        st.session_state.checkpoints["cp8"]["assessment"] = result["assessment"]
                        st.session_state.checkpoints["cp8"]["evidence"] = {"prod_results": cp8_results, "alert_count": cp8_count, "analyst_notes": cp8_notes}
                        st.rerun()
    with col2:
        mc1, mc2, mc3 = st.columns(3)
        with mc1:
            if st.button("✅", key="cp8_pass"):
                st.session_state.checkpoints["cp8"]["status"] = "pass"
                st.session_state.checkpoints["cp8"]["evidence"] = {"prod_results": cp8_results, "alert_count": cp8_count, "analyst_notes": cp8_notes}
                st.rerun()
        with mc2:
            if st.button("❌", key="cp8_fail"):
                st.session_state.checkpoints["cp8"]["status"] = "fail"
                st.session_state.checkpoints["cp8"]["evidence"] = {"prod_results": cp8_results, "alert_count": cp8_count, "analyst_notes": cp8_notes}
                st.rerun()
        with mc3:
            if st.button("⚠️", key="cp8_review"):
                st.session_state.checkpoints["cp8"]["status"] = "review"
                st.session_state.checkpoints["cp8"]["evidence"] = {"prod_results": cp8_results, "alert_count": cp8_count, "analyst_notes": cp8_notes}
                st.rerun()
    
    if st.session_state.checkpoints["cp8"]["assessment"]:
        st.markdown(f"""<div class="ai-assessment"><div class="ai-assessment-header">AI Assessment</div>{st.session_state.checkpoints["cp8"]["assessment"]}</div>""", unsafe_allow_html=True)


# =====================================================
# CHECKPOINT 9: False Positive Rate
# =====================================================
with st.expander(f"{STATUS_ICONS[st.session_state.checkpoints['cp9']['status']]} **Checkpoint 9: Is the false-positive rate below 60%?**"):
    st.markdown("Calculate the false positive rate from alert triage data.")
    
    col1, col2 = st.columns(2)
    with col1:
        cp9_total = st.number_input("Total alerts triggered", min_value=0, value=0, key="cp9_total")
    with col2:
        cp9_tp = st.number_input("Confirmed true positives", min_value=0, value=0, key="cp9_tp")
    
    # Calculate FP rate
    if cp9_total > 0:
        fp_count = cp9_total - cp9_tp
        fp_rate = (fp_count / cp9_total) * 100
        tp_rate = (cp9_tp / cp9_total) * 100
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("False Positive Rate", f"{fp_rate:.1f}%")
        with col2:
            st.metric("True Positive Rate", f"{tp_rate:.1f}%")
        with col3:
            st.metric("False Positives", f"{fp_count}")
        
        if fp_rate < 60:
            st.success(f"✅ FP rate ({fp_rate:.1f}%) is below the 60% threshold.")
            auto_status = "pass"
        else:
            st.error(f"❌ FP rate ({fp_rate:.1f}%) exceeds the 60% threshold. Fine-tuning needed.")
            auto_status = "fail"
        
        if st.button("📊 Apply Calculated Result", key="cp9_apply", use_container_width=True, type="primary"):
            st.session_state.checkpoints["cp9"]["status"] = auto_status
            st.session_state.checkpoints["cp9"]["assessment"] = f"False positive rate: {fp_rate:.1f}% ({fp_count} FP out of {cp9_total} total alerts). {'Below' if fp_rate < 60 else 'Exceeds'} the 60% threshold."
            st.session_state.checkpoints["cp9"]["evidence"] = {"total_alerts": cp9_total, "true_positives": cp9_tp, "fp_rate": f"{fp_rate:.1f}%"}
            st.rerun()
    else:
        st.info("Enter alert counts above to calculate the false positive rate.")
    
    cp9_notes = st.text_area("Analyst notes on FP tuning", height=60, key="cp9_notes", placeholder="Describe any fine-tuning performed...")

    # Manual override
    st.markdown("**Manual override:**")
    mc1, mc2, mc3 = st.columns(3)
    with mc1:
        if st.button("✅ Pass", key="cp9_pass"):
            st.session_state.checkpoints["cp9"]["status"] = "pass"
            st.session_state.checkpoints["cp9"]["evidence"] = {"total_alerts": cp9_total, "true_positives": cp9_tp, "analyst_notes": cp9_notes}
            st.rerun()
    with mc2:
        if st.button("❌ Fail", key="cp9_fail"):
            st.session_state.checkpoints["cp9"]["status"] = "fail"
            st.session_state.checkpoints["cp9"]["evidence"] = {"total_alerts": cp9_total, "true_positives": cp9_tp, "analyst_notes": cp9_notes}
            st.rerun()
    with mc3:
        if st.button("⚠️ Review", key="cp9_review"):
            st.session_state.checkpoints["cp9"]["status"] = "review"
            st.session_state.checkpoints["cp9"]["evidence"] = {"total_alerts": cp9_total, "true_positives": cp9_tp, "analyst_notes": cp9_notes}
            st.rerun()


# =====================================================
# FOOTER
# =====================================================
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #94a3b8; font-size: 0.8rem; padding: 1rem 0;">
    SIEM Use Case Validation Agent • AI-powered assessments should be reviewed by a qualified security analyst
</div>
""", unsafe_allow_html=True)
