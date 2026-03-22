import streamlit as st
import json
import re
import io
from datetime import datetime

# --- Page Config ---
st.set_page_config(
    page_title="SIEM Use Case Validator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
    .stApp { font-family: 'IBM Plex Sans', sans-serif; }
    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%);
        padding: 2rem 2.5rem; border-radius: 12px; margin-bottom: 1.5rem;
        border-left: 5px solid #38bdf8;
    }
    .main-header h1 { color: #f1f5f9; font-size: 1.8rem; font-weight: 700; margin: 0; letter-spacing: -0.02em; }
    .main-header p  { color: #94a3b8; font-size: 0.95rem; margin: 0.3rem 0 0 0; }
    .ai-assessment {
        background: #f0f9ff; border: 1px solid #bae6fd; border-radius: 8px;
        padding: 1rem; margin-top: 0.5rem; font-size: 0.9rem;
    }
    .ai-assessment-header { font-weight: 600; color: #0369a1; margin-bottom: 0.5rem; }
    .model-info-box {
        background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;
        padding: 0.75rem 1rem; font-size: 0.82rem; color: #475569; margin-top: 0.5rem;
    }
    div[data-testid="stExpander"] {
        border: 1px solid #e2e8f0; border-radius: 10px; margin-bottom: 0.8rem; overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)

# =====================================================
# AI PROVIDER CONFIGURATION
# =====================================================
AI_PROVIDERS = {
    "Claude Sonnet 4.6 (Anthropic)": {
        "key": "claude",
        "model": "claude-sonnet-4-6",
        "label": "Claude Sonnet 4.6",
        "description": "Anthropic's latest Claude Sonnet 4.6 — best reasoning, highest quality",
        "badge_class": "provider-claude",
    },
    "Llama 3.3 70B (Groq — Free)": {
        "key": "llama",
        "model": "llama-3.3-70b-versatile",
        "label": "Llama 3.3 70B (Groq)",
        "description": "Meta's Llama 3.3 70B via Groq ultra-fast inference — free tier available at console.groq.com",
        "badge_class": "provider-llama",
    },
    "Kimi K2 Instruct (Groq — Free)": {
        "key": "kimi",
        "model": "moonshotai/kimi-k2-instruct",
        "label": "Kimi K2 Instruct (Groq)",
        "description": "Moonshot AI's 1T-param MoE via Groq — 256K context, excels at agentic reasoning & coding",
        "badge_class": "provider-kimi",
    },
}

# --- Session State ---
if "checkpoints" not in st.session_state:
    st.session_state.checkpoints = {
        f"cp{i}": {"status": "pending", "assessment": "", "evidence": {}, "provider": ""}
        for i in range(1, 10)
    }

if "use_case_info" not in st.session_state:
    st.session_state.use_case_info = {
        "name": "", "id": "", "description": "", "analyst": "",
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

STATUS_ICONS = {"pass": "✅", "fail": "❌", "review": "⚠️", "pending": "⏳"}


# --- SPL Helpers ---
def parse_spl_fields(spl_query):
    result = {"indexes": [], "sourcetypes": [], "fields": [], "lookups": [], "timerange": ""}
    if not spl_query:
        return result
    result["indexes"]     = list(set(re.findall(r'index\s*=\s*["\']?(\S+?)["\']?\s', spl_query + " ")))
    result["sourcetypes"] = list(set(re.findall(r'sourcetype\s*=\s*["\']?(\S+?)["\']?\s', spl_query + " ")))
    for pat in [r'\|\s*(?:stats|eventstats)\s+\w+\((\w+)\)', r'\|\s*(?:eval|where)\s+(\w+)\s*[=<>!]',
                r'\|\s*table\s+([\w\s,]+)', r'\|\s*fields\s+[+-]?\s*([\w\s,]+)',
                r'\|\s*rename\s+(\w+)', r'by\s+([\w,\s]+?)(?:\||\s*$)']:
        for m in re.findall(pat, spl_query):
            result["fields"].extend([f.strip() for f in m.split(",") if f.strip()])
    result["fields"]  = list(set(result["fields"]))
    result["lookups"] = list(set(re.findall(r'(?:lookup|inputlookup|outputlookup)\s+(\S+)', spl_query)))
    tm = re.search(r'earliest\s*=\s*(\S+)', spl_query)
    if tm:
        result["timerange"] = tm.group(1)
    return result

def extract_thresholds(spl_query):
    thresholds = []
    if not spl_query:
        return thresholds
    for m in re.findall(r'where\s+(\w+)\s*([><=!]+)\s*(\d+)', spl_query):
        thresholds.append(f"{m[0]} {m[1]} {m[2]}")
    for m in re.findall(r'count\s*([><=!]+)\s*(\d+)', spl_query):
        thresholds.append(f"count {m[0]} {m[1]}")
    return thresholds


# --- AI API calls ---
def call_claude_api(prompt: str, api_key: str) -> str:
    import urllib.request, ssl
    data = json.dumps({
        "model": "claude-sonnet-4-6",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=data,
        headers={"Content-Type": "application/json",
                 "x-api-key": api_key, "anthropic-version": "2023-06-01"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=45) as r:
        return json.loads(r.read().decode())["content"][0]["text"]


def call_groq_api(prompt: str, api_key: str, model: str) -> str:
    import urllib.request, ssl
    data = json.dumps({
        "model": model, "max_tokens": 1024, "temperature": 0.3,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions", data=data,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=45) as r:
        return json.loads(r.read().decode())["choices"][0]["message"]["content"]


def build_prompt(cp_id: str, ctx: dict) -> str:
    templates = {
        "cp2": f"""You are a SIEM security analyst. Compare this use case objective with the SPL query.

Use Case Objective: {ctx.get('objective','Not provided')}
SPL Query: {ctx.get('spl_query','Not provided')}
Parsed Fields: {json.dumps(ctx.get('parsed',{}), indent=2)}

Evaluate:
1. Does the query logic match the stated objective?
2. Are there any gaps between objective and query?
3. Any obvious issues with the query?

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Specific improvements if needed""",

        "cp4": f"""You are a SIEM security analyst. Evaluate enrichment sources.

Use Case: {ctx.get('use_case_name','N/A')} — {ctx.get('objective','Not provided')}
SPL: {ctx.get('spl_query','Not provided')}
Detected Lookups: {json.dumps(ctx.get('lookups',[]))}
Analyst Notes: {ctx.get('enrichment_notes','Not provided')}

Evaluate adequacy of enrichment (threat intel, asset/identity lookups, etc.).

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW / NOT APPLICABLE
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Specific enrichment suggestions if missing""",

        "cp5": f"""You are a SIEM security analyst expert in MITRE ATT&CK. Validate the MITRE mapping.

Use Case: {ctx.get('use_case_name','N/A')} — {ctx.get('objective','Not provided')}
SPL: {ctx.get('spl_query','Not provided')}
Mapped Techniques: {ctx.get('mitre_techniques','Not provided')}

Evaluate alignment of techniques with what the rule actually detects.

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Correct IDs if mapping is wrong""",

        "cp6": f"""You are a SIEM security analyst. Evaluate alert grouping and correlation.

Use Case: {ctx.get('use_case_name','N/A')} — {ctx.get('objective','Not provided')}
Grouping Fields: {ctx.get('grouping_fields','Not provided')}
Correlation Settings: {ctx.get('correlation_settings','Not provided')}
Notes: {ctx.get('grouping_notes','Not provided')}

Evaluate whether grouping reduces noise without suppressing detections.

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Better grouping strategy if needed""",

        "cp7": f"""You are a SIEM security analyst. Evaluate historical/simulated test results.

Use Case: {ctx.get('use_case_name','N/A')} — {ctx.get('objective','Not provided')}
Test Results: {ctx.get('test_results','Not provided')}
Count: {ctx.get('result_count','N/A')}
Notes: {ctx.get('test_notes','Not provided')}

Evaluate whether testing validates expected detection behavior.

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Additional testing suggestions if needed""",

        "cp8": f"""You are a SIEM security analyst. Evaluate production trigger behavior.

Use Case: {ctx.get('use_case_name','N/A')} — {ctx.get('objective','Not provided')}
Production Alerts: {ctx.get('prod_results','Not provided')}
Alert Count: {ctx.get('alert_count','N/A')}
Notes: {ctx.get('prod_notes','Not provided')}

Evaluate whether the rule fires correctly in production.

Respond with:
- STATUS: PASS / FAIL / NEEDS REVIEW
- ASSESSMENT: 2-3 sentences
- RECOMMENDATIONS: Any adjustments needed"""
    }
    return templates.get(cp_id, "")


def parse_ai_status(text: str) -> str:
    u = text.upper()
    if "STATUS: PASS" in u:  return "pass"
    if "STATUS: FAIL" in u:  return "fail"
    if "NOT APPLICABLE" in u: return "pass"
    return "review"


def validate_with_ai(cp_id: str, ctx: dict, provider_name: str, api_key: str):
    provider = AI_PROVIDERS.get(provider_name)
    if not provider:
        return None
    prompt = build_prompt(cp_id, ctx)
    if not prompt:
        return None
    try:
        if provider["key"] == "claude":
            text = call_claude_api(prompt, api_key)
        else:
            text = call_groq_api(prompt, api_key, provider["model"])
        return {"status": parse_ai_status(text), "assessment": text, "provider": provider["label"]}
    except Exception as e:
        return {"status": "review",
                "assessment": f"AI validation could not be completed ({provider['label']}): {e}. Please review manually.",
                "provider": provider["label"]}


# --- PDF Report ---
def generate_pdf_report():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, PageBreak, HRFlowable)
    from reportlab.lib.enums import TA_CENTER

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                             rightMargin=25*mm, leftMargin=25*mm,
                             topMargin=25*mm, bottomMargin=25*mm)
    styles = getSampleStyleSheet()
    title_s   = ParagraphStyle('T', parent=styles['Title'], fontSize=22, spaceAfter=6,
                                textColor=colors.HexColor('#0f172a'), fontName='Helvetica-Bold')
    sub_s     = ParagraphStyle('S', parent=styles['Normal'], fontSize=11,
                                textColor=colors.HexColor('#64748b'), spaceAfter=20)
    head_s    = ParagraphStyle('H', parent=styles['Heading2'], fontSize=13,
                                textColor=colors.HexColor('#0f172a'), spaceBefore=16,
                                spaceAfter=8, fontName='Helvetica-Bold')
    body_s    = ParagraphStyle('B', parent=styles['Normal'], fontSize=10,
                                leading=14, textColor=colors.HexColor('#334155'))
    pass_s    = ParagraphStyle('P', parent=styles['Normal'], fontSize=10,
                                textColor=colors.HexColor('#166534'), fontName='Helvetica-Bold')
    fail_s    = ParagraphStyle('F', parent=styles['Normal'], fontSize=10,
                                textColor=colors.HexColor('#991b1b'), fontName='Helvetica-Bold')
    review_s  = ParagraphStyle('R', parent=styles['Normal'], fontSize=10,
                                textColor=colors.HexColor('#92400e'), fontName='Helvetica-Bold')
    footer_s  = ParagraphStyle('Ft', parent=styles['Normal'], fontSize=8,
                                textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER)

    story = []
    info  = st.session_state.use_case_info
    cps   = st.session_state.checkpoints

    story.append(Spacer(1, 30))
    story.append(Paragraph("SIEM Use Case Validation Report", title_s))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y at %H:%M')}", sub_s))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#38bdf8')))
    story.append(Spacer(1, 16))

    it = Table([
        ["Use Case Name", info.get("name","N/A")],
        ["Use Case ID",   info.get("id","N/A")],
        ["Analyst",       info.get("analyst","N/A")],
        ["Validation Date", info.get("date","N/A")],
    ], colWidths=[120, 380])
    it.setStyle(TableStyle([
        ('FONTNAME',(0,0),(0,-1),'Helvetica-Bold'), ('FONTSIZE',(0,0),(-1,-1),10),
        ('TEXTCOLOR',(0,0),(0,-1),colors.HexColor('#475569')),
        ('TEXTCOLOR',(1,0),(1,-1),colors.HexColor('#0f172a')),
        ('BOTTOMPADDING',(0,0),(-1,-1),8), ('TOPPADDING',(0,0),(-1,-1),8),
        ('LINEBELOW',(0,0),(-1,-2),0.5,colors.HexColor('#e2e8f0')),
    ]))
    story.append(it)
    story.append(Spacer(1,10))

    if info.get("description"):
        story.append(Paragraph("<b>Description:</b>", body_s))
        story.append(Paragraph(info["description"], body_s))
        story.append(Spacer(1,10))

    spl = st.session_state.get("shared_spl","") or cps.get("cp1",{}).get("evidence",{}).get("spl_query","")
    if spl:
        story.append(Paragraph("<b>SPL Query:</b>", body_s))
        mono_s = ParagraphStyle('M', parent=styles['Normal'], fontSize=8, leading=11,
                                 fontName='Courier', textColor=colors.HexColor('#334155'),
                                 backColor=colors.HexColor('#f8fafc'), borderPadding=(4,4,4,4))
        story.append(Paragraph(spl.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"), mono_s))
    story.append(Spacer(1,20))

    # Summary
    story.append(Paragraph("Validation Summary", head_s))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1,10))
    pc = sum(1 for c in cps.values() if c["status"]=="pass")
    fc = sum(1 for c in cps.values() if c["status"]=="fail")
    rc = sum(1 for c in cps.values() if c["status"]=="review")
    nc = sum(1 for c in cps.values() if c["status"]=="pending")
    overall = "PASS" if fc==0 and nc==0 and rc==0 else "FAIL" if fc>0 else "NEEDS REVIEW"
    oc = (colors.HexColor('#166534') if overall=="PASS" else
          colors.HexColor('#991b1b') if overall=="FAIL" else colors.HexColor('#92400e'))
    st_tbl = Table([
        ["Overall Result","Passed","Failed","Needs Review","Pending"],
        [overall, str(pc), str(fc), str(rc), str(nc)]
    ], colWidths=[100,100,100,100,100])
    st_tbl.setStyle(TableStyle([
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'), ('FONTSIZE',(0,0),(-1,-1),10),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#f1f5f9')),
        ('TEXTCOLOR',(0,1),(0,1),oc), ('FONTNAME',(0,1),(0,1),'Helvetica-Bold'),
        ('TEXTCOLOR',(1,1),(1,1),colors.HexColor('#166534')),
        ('TEXTCOLOR',(2,1),(2,1),colors.HexColor('#991b1b')),
        ('TEXTCOLOR',(3,1),(3,1),colors.HexColor('#92400e')),
        ('TEXTCOLOR',(4,1),(4,1),colors.HexColor('#475569')),
        ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#e2e8f0')),
        ('BOTTOMPADDING',(0,0),(-1,-1),8), ('TOPPADDING',(0,0),(-1,-1),8),
    ]))
    story.append(st_tbl)
    story.append(Spacer(1,10))

    # Quick reference
    cp_rows = [["#","Checkpoint","Status","AI Provider"]]
    for key, name in CHECKPOINT_NAMES.items():
        s = cps[key]["status"].upper().replace("REVIEW","NEEDS REVIEW")
        prov = cps[key].get("provider","Manual") or "Manual"
        cp_rows.append([key.replace("cp",""), name.split(". ",1)[1] if ". " in name else name, s, prov])
    qr = Table(cp_rows, colWidths=[25,270,115,90])
    qr_cmds = [
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'), ('FONTSIZE',(0,0),(-1,-1),9),
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#f1f5f9')),
        ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#e2e8f0')),
        ('BOTTOMPADDING',(0,0),(-1,-1),6), ('TOPPADDING',(0,0),(-1,-1),6),
        ('ALIGN',(0,0),(0,-1),'CENTER'), ('ALIGN',(2,0),(2,-1),'CENTER'),
    ]
    for i,key in enumerate(CHECKPOINT_NAMES.keys(),1):
        s = cps[key]["status"]
        c = (colors.HexColor('#166534') if s=="pass" else
             colors.HexColor('#991b1b') if s=="fail" else colors.HexColor('#92400e'))
        qr_cmds.append(('TEXTCOLOR',(2,i),(2,i),c))
    qr.setStyle(TableStyle(qr_cmds))
    story.append(qr)
    story.append(PageBreak())

    # Detailed results
    story.append(Paragraph("Detailed Checkpoint Results", head_s))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#38bdf8')))
    story.append(Spacer(1,12))
    for key, name in CHECKPOINT_NAMES.items():
        cp = cps[key]
        st_txt = cp["status"].upper().replace("REVIEW","NEEDS REVIEW")
        ss = pass_s if cp["status"]=="pass" else fail_s if cp["status"]=="fail" else review_s
        story.append(Paragraph(f"<b>{name}</b>", head_s))
        story.append(Paragraph(f"Status: {st_txt}", ss))
        if cp.get("provider"):
            story.append(Paragraph(f"AI Provider: {cp['provider']}", body_s))
        story.append(Spacer(1,6))
        for ek, ev in (cp.get("evidence") or {}).items():
            if ev and str(ev).strip():
                vs = str(ev)[:500] + ("..." if len(str(ev))>500 else "")
                vs = vs.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                story.append(Paragraph(f"<b>{ek.replace('_',' ').title()}:</b> {vs}", body_s))
                story.append(Spacer(1,3))
        if cp.get("assessment"):
            at = cp["assessment"].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            story.append(Paragraph("<b>AI Assessment:</b>", body_s))
            story.append(Paragraph(at, body_s))
        story.append(Spacer(1,6))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1,8))

    story.append(Spacer(1,20))
    story.append(Paragraph(
        "SIEM Use Case Validation Agent — AI assessments (Claude Sonnet 4.6 / Llama 3.3 70B / Kimi K2) "
        "should be reviewed by a qualified security analyst.", footer_s))
    doc.build(story)
    buf.seek(0)
    return buf.read()


# =====================================================
# SIDEBAR
# =====================================================
with st.sidebar:
    st.markdown("### 🛡️ Validation Status")
    st.markdown("---")
    cps = st.session_state.checkpoints
    p = sum(1 for c in cps.values() if c["status"]=="pass")
    f = sum(1 for c in cps.values() if c["status"]=="fail")
    r = sum(1 for c in cps.values() if c["status"]=="review")
    completed = p + f + r
    st.progress(completed / len(cps), text=f"{completed}/{len(cps)} checkpoints reviewed")
    st.markdown("")
    for key, name in CHECKPOINT_NAMES.items():
        status = cps[key]["status"]
        short  = name.split(". ",1)[1] if ". " in name else name
        prov   = cps[key].get("provider","")
        ptag   = f" _{prov}_" if prov else ""
        st.markdown(f"{STATUS_ICONS[status]} **{short}**{ptag}")

    st.markdown("---")
    c1, c2, c3 = st.columns(3)
    c1.metric("Pass", p); c2.metric("Fail", f); c3.metric("Review", r)

    st.markdown("---")
    if st.button("🔄 Reset / New Validation", use_container_width=True):
        for key in st.session_state.checkpoints:
            st.session_state.checkpoints[key] = {
                "status":"pending","assessment":"","evidence":{},"provider":""}
        st.session_state.use_case_info = {
            "name":"","id":"","description":"","analyst":"",
            "date": datetime.now().strftime("%Y-%m-%d")}
        st.rerun()

    # AI Provider Settings
    st.markdown("---")
    st.markdown("### ⚙️ AI Provider Settings")

    selected_provider = st.selectbox(
        "Select AI Provider", options=list(AI_PROVIDERS.keys()), key="selected_provider",
        help="Choose the AI model. Groq models are FREE — get a key at console.groq.com")

    pcfg = AI_PROVIDERS[selected_provider]
    st.markdown(f"""<div class="model-info-box">
        <b>Model:</b> {pcfg['model']}<br>
        {pcfg['description']}
    </div>""", unsafe_allow_html=True)

    if pcfg["key"] == "claude":
        key_label  = "Anthropic API Key"
        key_help   = "Get yours at console.anthropic.com"
        secret_var = "ANTHROPIC_API_KEY"
    else:
        key_label  = "Groq API Key (free)"
        key_help   = "Get your FREE key at console.groq.com"
        secret_var = "GROQ_API_KEY"

    _sk = st.secrets.get(secret_var,"") if hasattr(st,"secrets") else ""
    api_key = st.text_input(key_label, value=_sk, type="password",
                             help=key_help, key="api_key_input")

    if pcfg["key"] != "claude":
        st.info("💡 **Groq is FREE** — get your key at [console.groq.com](https://console.groq.com)")

    st.markdown("---")
    st.markdown("### 📄 Generate Report")
    if st.button("📥 Generate PDF Report", use_container_width=True, type="primary"):
        with st.spinner("Generating report..."):
            try:
                pdf_bytes = generate_pdf_report()
                st.download_button(
                    "⬇️ Download Report", pdf_bytes,
                    file_name=f"validation_report_{st.session_state.use_case_info.get('id','draft')}_{datetime.now().strftime('%Y%m%d')}.pdf",
                    mime="application/pdf", use_container_width=True)
                st.success("Report generated!")
            except Exception as e:
                st.error(f"Error: {e}")


# =====================================================
# MAIN CONTENT
# =====================================================
st.markdown("""
<div class="main-header">
    <h1>🛡️ SIEM Use Case Validation Agent</h1>
    <p>Guided validation of SIEM detection rules &nbsp;·&nbsp;
       <b>Claude Sonnet 4.6</b> &nbsp;|&nbsp; <b>Llama 3.3 70B (Groq)</b> &nbsp;|&nbsp; <b>Kimi K2 (Groq)</b></p>
</div>
""", unsafe_allow_html=True)

# Use Case Info
with st.expander("📋 Use Case Information", expanded=True):
    col1, col2 = st.columns(2)
    with col1:
        st.session_state.use_case_info["name"] = st.text_input(
            "Use Case Name", value=st.session_state.use_case_info["name"],
            placeholder="e.g., Brute Force Detection on VPN")
        st.session_state.use_case_info["id"] = st.text_input(
            "Use Case ID", value=st.session_state.use_case_info["id"],
            placeholder="e.g., UC-001")
    with col2:
        st.session_state.use_case_info["analyst"] = st.text_input(
            "Analyst Name", value=st.session_state.use_case_info["analyst"],
            placeholder="Your name")
        st.session_state.use_case_info["date"] = st.text_input(
            "Validation Date", value=st.session_state.use_case_info["date"])
    st.session_state.use_case_info["description"] = st.text_area(
        "Use Case Objective / Description",
        value=st.session_state.use_case_info["description"],
        placeholder="Describe what this use case is designed to detect...", height=100)

st.markdown("---")

# Shared SPL
with st.expander("🔍 SPL Query (shared across checkpoints)", expanded=True):
    spl_query = st.text_area(
        "Paste the SPL query for this use case", height=150,
        placeholder="index=security sourcetype=vpn_logs | stats count by src_ip | where count > 10",
        key="shared_spl")
    if spl_query:
        parsed = parse_spl_fields(spl_query)
        thresholds = extract_thresholds(spl_query)
        st.markdown("**Parsed from SPL:**")
        pc1, pc2, pc3 = st.columns(3)
        with pc1:
            st.markdown(f"**Indexes:** {', '.join(parsed['indexes']) or 'None detected'}")
            st.markdown(f"**Sourcetypes:** {', '.join(parsed['sourcetypes']) or 'None detected'}")
        with pc2:
            st.markdown(f"**Fields:** {', '.join(parsed['fields']) or 'None detected'}")
            st.markdown(f"**Lookups:** {', '.join(parsed['lookups']) or 'None'}")
        with pc3:
            st.markdown(f"**Time Range:** {parsed['timerange'] or 'Not specified'}")
            st.markdown(f"**Thresholds:** {', '.join(thresholds) or 'None detected'}")
    else:
        parsed = {}; thresholds = []

st.markdown("---")
st.markdown("## Validation Checkpoints")


def ai_btn_label():
    sp = st.session_state.get("selected_provider", list(AI_PROVIDERS.keys())[0])
    cfg = AI_PROVIDERS.get(sp, {})
    icons = {"claude":"🤖", "llama":"🦙", "kimi":"🌙"}
    return f"{icons.get(cfg.get('key',''),'🤖')} Validate with AI ({cfg.get('label', sp)})"

def assessment_html(cp_key):
    cp = st.session_state.checkpoints[cp_key]
    if cp["assessment"]:
        prov = cp.get("provider","")
        ptag = f" <small style='color:#64748b'>({prov})</small>" if prov else ""
        st.markdown(
            f"""<div class="ai-assessment"><div class="ai-assessment-header">AI Assessment{ptag}</div>{cp["assessment"]}</div>""",
            unsafe_allow_html=True)

def save_cp(key, status, evidence, assessment="", provider=""):
    st.session_state.checkpoints[key].update({
        "status": status, "evidence": evidence,
        "assessment": assessment, "provider": provider})
    st.rerun()


# ── CP1 ──────────────────────────────────────────────────────────────────────
with st.expander(f"{STATUS_ICONS[cps['cp1']['status']]} **Checkpoint 1: Are the necessary logs and fields available?**"):
    st.markdown("Verify all required data sources, indexes, and fields referenced in the SPL are available and populated.")
    cp1_sample = st.text_area("Paste sample results or describe field availability", height=120, key="cp1_sample",
                               placeholder="Paste sample output from the SPL query...")
    cp1_notes  = st.text_area("Analyst notes", height=60, key="cp1_notes")
    ev1 = {"sample_data": cp1_sample, "analyst_notes": cp1_notes,
           "spl_query": spl_query, "parsed_fields": json.dumps(parsed) if parsed else ""}
    c1,c2,c3 = st.columns(3)
    with c1:
        if st.button("✅ Pass", key="cp1_pass", use_container_width=True): save_cp("cp1","pass",ev1)
    with c2:
        if st.button("❌ Fail", key="cp1_fail", use_container_width=True): save_cp("cp1","fail",ev1)
    with c3:
        if st.button("⚠️ Needs Review", key="cp1_review", use_container_width=True): save_cp("cp1","review",ev1)
    assessment_html("cp1")


# ── CP2 ──────────────────────────────────────────────────────────────────────
with st.expander(f"{STATUS_ICONS[cps['cp2']['status']]} **Checkpoint 2: Is rule built as per objective?**"):
    st.markdown("Compare the use case objective against the actual SPL implementation.")
    cp2_obj = st.session_state.use_case_info.get("description","")
    if not cp2_obj:
        st.warning("Please fill in the Use Case Objective above.")
    cp2_notes = st.text_area("Additional context or notes", height=60, key="cp2_notes")
    ev2 = {"objective": cp2_obj, "spl_query": spl_query, "analyst_notes": cp2_notes}
    col1, col2 = st.columns(2)
    with col1:
        if st.button(ai_btn_label(), key="cp2_ai", use_container_width=True, type="primary"):
            if not api_key: st.error("Please enter your API Key in the sidebar.")
            elif not spl_query: st.error("Please enter the SPL query first.")
            elif not cp2_obj: st.error("Please enter the use case objective.")
            else:
                with st.spinner("AI is analyzing..."):
                    res = validate_with_ai("cp2", {"objective":cp2_obj,"spl_query":spl_query,"parsed":parsed},
                                           st.session_state.get("selected_provider",""), api_key)
                    if res: save_cp("cp2", res["status"], ev2, res["assessment"], res.get("provider",""))
    with col2:
        m1,m2,m3 = st.columns(3)
        with m1:
            if st.button("✅", key="cp2_pass"): save_cp("cp2","pass",ev2)
        with m2:
            if st.button("❌", key="cp2_fail"): save_cp("cp2","fail",ev2)
        with m3:
            if st.button("⚠️", key="cp2_review"): save_cp("cp2","review",ev2)
    assessment_html("cp2")


# ── CP3 ──────────────────────────────────────────────────────────────────────
with st.expander(f"{STATUS_ICONS[cps['cp3']['status']]} **Checkpoint 3: Query Aspects Validation (Threshold, Conditions, Severity, Frequency, Lookback)**"):
    st.markdown("Validate the five query aspects.")
    c1,c2 = st.columns(2)
    with c1:
        cp3_thr  = st.text_input("Threshold Value(s)", value=", ".join(thresholds) if thresholds else "", key="cp3_threshold", placeholder="e.g., count > 10")
        cp3_cond = st.text_area("Conditions / Filtering Logic", height=60, key="cp3_conditions")
        cp3_sev  = st.selectbox("Alert Severity", ["-- Select --","Informational","Low","Medium","High","Critical"], key="cp3_severity")
    with c2:
        cp3_freq = st.text_input("Search Frequency", key="cp3_frequency", placeholder="e.g., */5 * * * *")
        cp3_lb   = st.text_input("Lookback Period", value=parsed.get("timerange","") if parsed else "", key="cp3_lookback")
        cp3_notes= st.text_area("Analyst Notes", height=60, key="cp3_notes")
    ev3 = {"thresholds":cp3_thr,"conditions":cp3_cond,"severity":cp3_sev,
           "frequency":cp3_freq,"lookback":cp3_lb,"analyst_notes":cp3_notes}
    b1,b2,b3 = st.columns(3)
    with b1:
        if st.button("✅ Pass", key="cp3_pass", use_container_width=True): save_cp("cp3","pass",ev3)
    with b2:
        if st.button("❌ Fail", key="cp3_fail", use_container_width=True): save_cp("cp3","fail",ev3)
    with b3:
        if st.button("⚠️ Needs Review", key="cp3_review", use_container_width=True): save_cp("cp3","review",ev3)


# ── CP4 ──────────────────────────────────────────────────────────────────────
with st.expander(f"{STATUS_ICONS[cps['cp4']['status']]} **Checkpoint 4: Are enrichment sources added (if applicable)?**"):
    st.markdown("Check for lookups, threat intel feeds, or asset/identity table usage.")
    if parsed and parsed.get("lookups"):
        st.info(f"**Detected in SPL:** {', '.join(parsed['lookups'])}")
    cp4_notes = st.text_area("Describe enrichment sources used", height=80, key="cp4_notes",
                              placeholder="e.g., asset_lookup for hostname, threat_intel_ip for reputation...")
    ev4 = {"enrichment_notes": cp4_notes,
           "detected_lookups": json.dumps(parsed.get("lookups",[]) if parsed else [])}
    col1,col2 = st.columns(2)
    with col1:
        if st.button(ai_btn_label(), key="cp4_ai", use_container_width=True, type="primary"):
            if not api_key: st.error("Please enter your API Key in the sidebar.")
            else:
                with st.spinner("AI is analyzing..."):
                    res = validate_with_ai("cp4", {
                        "use_case_name": st.session_state.use_case_info.get("name",""),
                        "objective":     st.session_state.use_case_info.get("description",""),
                        "spl_query": spl_query,
                        "lookups": parsed.get("lookups",[]) if parsed else [],
                        "enrichment_notes": cp4_notes,
                    }, st.session_state.get("selected_provider",""), api_key)
                    if res: save_cp("cp4", res["status"], ev4, res["assessment"], res.get("provider",""))
    with col2:
        m1,m2,m3 = st.columns(3)
        with m1:
            if st.button("✅", key="cp4_pass"): save_cp("cp4","pass",ev4)
        with m2:
            if st.button("❌", key="cp4_fail"): save_cp("cp4","fail",ev4)
        with m3:
            if st.button("⚠️", key="cp4_review"): save_cp("cp4","review",ev4)
    assessment_html("cp4")


# ── CP5 ──────────────────────────────────────────────────────────────────────
with st.expander(f"{STATUS_ICONS[cps['cp5']['status']]} **Checkpoint 5: Is MITRE ATT&CK mapping completed and validated?**"):
    st.markdown("Verify the use case is correctly mapped to MITRE ATT&CK techniques.")
    cp5_tech  = st.text_input("Mapped MITRE ATT&CK Technique IDs", key="cp5_techniques",
                               placeholder="e.g., T1110, T1110.001, T1078")
    cp5_tact  = st.text_input("Mapped Tactics (optional)", key="cp5_tactics",
                               placeholder="e.g., Credential Access, Initial Access")
    cp5_notes = st.text_area("Analyst notes on mapping", height=60, key="cp5_notes")
    ev5 = {"mitre_techniques": cp5_tech, "mitre_tactics": cp5_tact, "analyst_notes": cp5_notes}
    col1,col2 = st.columns(2)
    with col1:
        if st.button(ai_btn_label(), key="cp5_ai", use_container_width=True, type="primary"):
            if not api_key: st.error("Please enter your API Key in the sidebar.")
            elif not cp5_tech: st.error("Please enter the MITRE technique IDs.")
            else:
                with st.spinner("AI is analyzing..."):
                    res = validate_with_ai("cp5", {
                        "use_case_name": st.session_state.use_case_info.get("name",""),
                        "objective":     st.session_state.use_case_info.get("description",""),
                        "spl_query": spl_query,
                        "mitre_techniques": f"{cp5_tech} | Tactics: {cp5_tact}",
                    }, st.session_state.get("selected_provider",""), api_key)
                    if res: save_cp("cp5", res["status"], ev5, res["assessment"], res.get("provider",""))
    with col2:
        m1,m2,m3 = st.columns(3)
        with m1:
            if st.button("✅", key="cp5_pass"): save_cp("cp5","pass",ev5)
        with m2:
            if st.button("❌", key="cp5_fail"): save_cp("cp5","fail",ev5)
        with m3:
            if st.button("⚠️", key="cp5_review"): save_cp("cp5","review",ev5)
    assessment_html("cp5")


# ── CP6 ──────────────────────────────────────────────────────────────────────
with st.expander(f"{STATUS_ICONS[cps['cp6']['status']]} **Checkpoint 6: Are alert grouping or correlation settings configured correctly?**"):
    st.markdown("Validate alert grouping reduces noise without suppressing critical detections.")
    cp6_grp  = st.text_input("Grouping Fields", key="cp6_grouping",
                               placeholder="e.g., src_ip, dest, user")
    cp6_corr = st.text_area("Correlation Settings", height=60, key="cp6_correlation",
                              placeholder="Describe correlation search config, throttling, etc.")
    cp6_notes= st.text_area("Analyst notes", height=60, key="cp6_notes")
    ev6 = {"grouping_fields": cp6_grp, "correlation_settings": cp6_corr, "analyst_notes": cp6_notes}
    col1,col2 = st.columns(2)
    with col1:
        if st.button(ai_btn_label(), key="cp6_ai", use_container_width=True, type="primary"):
            if not api_key: st.error("Please enter your API Key in the sidebar.")
            else:
                with st.spinner("AI is analyzing..."):
                    res = validate_with_ai("cp6", {
                        "use_case_name": st.session_state.use_case_info.get("name",""),
                        "objective":     st.session_state.use_case_info.get("description",""),
                        "grouping_fields": cp6_grp, "correlation_settings": cp6_corr,
                        "grouping_notes": cp6_notes,
                    }, st.session_state.get("selected_provider",""), api_key)
                    if res: save_cp("cp6", res["status"], ev6, res["assessment"], res.get("provider",""))
    with col2:
        m1,m2,m3 = st.columns(3)
        with m1:
            if st.button("✅", key="cp6_pass"): save_cp("cp6","pass",ev6)
        with m2:
            if st.button("❌", key="cp6_fail"): save_cp("cp6","fail",ev6)
        with m3:
            if st.button("⚠️", key="cp6_review"): save_cp("cp6","review",ev6)
    assessment_html("cp6")


# ── CP7 ──────────────────────────────────────────────────────────────────────
with st.expander(f"{STATUS_ICONS[cps['cp7']['status']]} **Checkpoint 7: Has the rule been validated on historical or simulated data?**"):
    st.markdown("Confirm testing was performed and results demonstrate expected behavior.")
    cp7_res   = st.text_area("Paste test results or summary", height=120, key="cp7_results",
                               placeholder="Paste sample test output, describe the scenario and results...")
    cp7_cnt   = st.number_input("Number of test results/alerts", min_value=0, value=0, key="cp7_count")
    cp7_notes = st.text_area("Analyst notes", height=60, key="cp7_notes")
    ev7 = {"test_results": cp7_res, "result_count": cp7_cnt, "analyst_notes": cp7_notes}
    col1,col2 = st.columns(2)
    with col1:
        if st.button(ai_btn_label(), key="cp7_ai", use_container_width=True, type="primary"):
            if not api_key: st.error("Please enter your API Key in the sidebar.")
            else:
                with st.spinner("AI is analyzing..."):
                    res = validate_with_ai("cp7", {
                        "use_case_name": st.session_state.use_case_info.get("name",""),
                        "objective":     st.session_state.use_case_info.get("description",""),
                        "test_results": cp7_res, "result_count": cp7_cnt, "test_notes": cp7_notes,
                    }, st.session_state.get("selected_provider",""), api_key)
                    if res: save_cp("cp7", res["status"], ev7, res["assessment"], res.get("provider",""))
    with col2:
        m1,m2,m3 = st.columns(3)
        with m1:
            if st.button("✅", key="cp7_pass"): save_cp("cp7","pass",ev7)
        with m2:
            if st.button("❌", key="cp7_fail"): save_cp("cp7","fail",ev7)
        with m3:
            if st.button("⚠️", key="cp7_review"): save_cp("cp7","review",ev7)
    assessment_html("cp7")


# ── CP8 ──────────────────────────────────────────────────────────────────────
with st.expander(f"{STATUS_ICONS[cps['cp8']['status']]} **Checkpoint 8: Does the rule trigger correctly on production data?**"):
    st.markdown("Confirm the rule fires correctly in the production environment.")
    cp8_res   = st.text_area("Paste production alert samples or describe behavior", height=120, key="cp8_results",
                               placeholder="Paste recent production alerts or describe how the rule behaved...")
    cp8_cnt   = st.number_input("Number of production alerts observed", min_value=0, value=0, key="cp8_count")
    cp8_notes = st.text_area("Analyst notes", height=60, key="cp8_notes")
    ev8 = {"prod_results": cp8_res, "alert_count": cp8_cnt, "analyst_notes": cp8_notes}
    col1,col2 = st.columns(2)
    with col1:
        if st.button(ai_btn_label(), key="cp8_ai", use_container_width=True, type="primary"):
            if not api_key: st.error("Please enter your API Key in the sidebar.")
            else:
                with st.spinner("AI is analyzing..."):
                    res = validate_with_ai("cp8", {
                        "use_case_name": st.session_state.use_case_info.get("name",""),
                        "objective":     st.session_state.use_case_info.get("description",""),
                        "prod_results": cp8_res, "alert_count": cp8_cnt, "prod_notes": cp8_notes,
                    }, st.session_state.get("selected_provider",""), api_key)
                    if res: save_cp("cp8", res["status"], ev8, res["assessment"], res.get("provider",""))
    with col2:
        m1,m2,m3 = st.columns(3)
        with m1:
            if st.button("✅", key="cp8_pass"): save_cp("cp8","pass",ev8)
        with m2:
            if st.button("❌", key="cp8_fail"): save_cp("cp8","fail",ev8)
        with m3:
            if st.button("⚠️", key="cp8_review"): save_cp("cp8","review",ev8)
    assessment_html("cp8")


# ── CP9 ──────────────────────────────────────────────────────────────────────
with st.expander(f"{STATUS_ICONS[cps['cp9']['status']]} **Checkpoint 9: Is the false-positive rate below 60%?**"):
    st.markdown("Calculate the false positive rate from alert triage data.")
    c1,c2 = st.columns(2)
    with c1:
        cp9_total = st.number_input("Total alerts triggered", min_value=0, value=0, key="cp9_total")
    with c2:
        cp9_tp = st.number_input("Confirmed true positives", min_value=0, value=0, key="cp9_tp")
    if cp9_total > 0:
        fp_cnt  = cp9_total - cp9_tp
        fp_rate = (fp_cnt / cp9_total) * 100
        tp_rate = (cp9_tp / cp9_total) * 100
        m1,m2,m3 = st.columns(3)
        m1.metric("False Positive Rate", f"{fp_rate:.1f}%")
        m2.metric("True Positive Rate",  f"{tp_rate:.1f}%")
        m3.metric("False Positives",     str(fp_cnt))
        auto_status = "pass" if fp_rate < 60 else "fail"
        if fp_rate < 60:
            st.success(f"✅ FP rate ({fp_rate:.1f}%) is below the 60% threshold.")
        else:
            st.error(f"❌ FP rate ({fp_rate:.1f}%) exceeds the 60% threshold. Fine-tuning needed.")
        if st.button("📊 Apply Calculated Result", key="cp9_apply", use_container_width=True, type="primary"):
            save_cp("cp9", auto_status,
                    {"total_alerts": cp9_total, "true_positives": cp9_tp, "fp_rate": f"{fp_rate:.1f}%"},
                    f"FP rate: {fp_rate:.1f}% ({fp_cnt} FP / {cp9_total} total). "
                    f"{'Below' if fp_rate<60 else 'Exceeds'} the 60% threshold.")
    else:
        st.info("Enter alert counts above to calculate the false positive rate.")
    cp9_notes = st.text_area("Analyst notes on FP tuning", height=60, key="cp9_notes",
                              placeholder="Describe any fine-tuning performed...")
    st.markdown("**Manual override:**")
    b1,b2,b3 = st.columns(3)
    ev9 = {"total_alerts": cp9_total if cp9_total > 0 else 0, "analyst_notes": cp9_notes}
    with b1:
        if st.button("✅ Pass", key="cp9_pass"): save_cp("cp9","pass",ev9)
    with b2:
        if st.button("❌ Fail", key="cp9_fail"): save_cp("cp9","fail",ev9)
    with b3:
        if st.button("⚠️ Review", key="cp9_review"): save_cp("cp9","review",ev9)


# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("""
<div style="text-align:center; color:#94a3b8; font-size:0.8rem; padding:1rem 0;">
    SIEM Use Case Validation Agent &nbsp;·&nbsp;
    Powered by <b>Claude Sonnet 4.6</b> &nbsp;|&nbsp;
    <b>Llama 3.3 70B (Groq — Free)</b> &nbsp;|&nbsp;
    <b>Kimi K2 Instruct (Groq — Free)</b><br>
    AI-powered assessments should be reviewed by a qualified security analyst.
</div>
""", unsafe_allow_html=True)
