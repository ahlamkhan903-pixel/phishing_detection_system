import streamlit as st
import pandas as pd
from datetime import datetime
 
from config       import RISK_LABELS
from model_utils  import load_model, predict, build_feature_vector, model_is_trained
from url_features import extract_features, RELIABLE_FEATURES
 
# Feature groupings
CATEGORIES = {
    "🔗 URL Structure": [
        ("UsingIP",        "IP address used instead of domain name"),
        ("LongURL",        "Suspiciously long URL"),
        ("ShortURL",       "URL shortening service detected"),
        ("Symbol@",        "@ symbol found in URL"),
        ("Redirecting//",  "Double-slash redirect trick"),
        ("PrefixSuffix-",  "Hyphen found in domain name"),
        ("SubDomains",     "Too many sub-domains"),
        ("HTTPSDomainURL", "Word 'https' hidden inside domain"),
    ],
    "🔒 Security & Domain": [
        ("HTTPS",         "No HTTPS / SSL certificate"),
        ("DomainRegLen",  "Domain registered for 1 year or less"),
        ("Favicon",       "Favicon loaded from external domain"),
        ("NonStdPort",    "Non-standard port number used"),
        ("AbnormalURL",   "URL does not match registered domain"),
        ("AgeofDomain",   "Domain is newly registered"),
        ("DNSRecording",  "No DNS record found"),
    ],
    "📄 Page Content & Behaviour": [
        ("RequestURL",        "Most resources loaded from external domains"),
        ("AnchorURL",         "Most links point away from this domain"),
        ("LinksInScriptTags", "Most script/link tags are external"),
        ("ServerFormHandler", "Form submits data to a different domain"),
        ("InfoEmail",         "Form uses mailto: to collect data"),
        ("WebsiteForwarding", "Too many page redirects"),
        ("StatusBarCust",     "JavaScript changes the browser status bar"),
        ("DisableRightClick", "Right-click is disabled"),
        ("UsingPopupWindow",  "Pop-up windows with login forms"),
        ("IframeRedirection", "Hidden iframes on the page"),
    ],
    "📈 Reputation & Trust": [
        ("WebsiteTraffic",      "No web traffic history"),
        ("PageRank",            "Very low PageRank score"),
        ("GoogleIndex",         "Not indexed by Google"),
        ("LinksPointingToPage", "No backlinks to this page"),
        ("StatsReport",         "Matches known phishing patterns"),
    ],
}
 
FEATURE_LABELS = {
    "UsingIP":"IP Address in URL","LongURL":"URL Length","ShortURL":"URL Shortening Service",
    "Symbol@":"@ Symbol in URL","Redirecting//":"Double-Slash Redirect",
    "PrefixSuffix-":"Hyphen in Domain","SubDomains":"Number of Sub-Domains",
    "HTTPS":"HTTPS Certificate","DomainRegLen":"Domain Registration Length",
    "Favicon":"Favicon Source","NonStdPort":"Non-Standard Port",
    "HTTPSDomainURL":"'https' in Domain Name","RequestURL":"External Resources %",
    "AnchorURL":"Anchor Links Pointing Away","LinksInScriptTags":"External Script Tags",
    "ServerFormHandler":"Form Submission Target","InfoEmail":"mailto: in Form",
    "AbnormalURL":"Domain Identity Mismatch","WebsiteForwarding":"Number of Redirects",
    "StatusBarCust":"Status Bar Manipulation","DisableRightClick":"Right-Click Disabled",
    "UsingPopupWindow":"Pop-Up Windows with Forms","IframeRedirection":"Hidden iFrames",
    "AgeofDomain":"Domain Age","DNSRecording":"DNS Record",
    "WebsiteTraffic":"Web Traffic Rank","PageRank":"PageRank Score",
    "GoogleIndex":"Google Indexed","LinksPointingToPage":"Backlinks to Page",
    "StatsReport":"In Phishing Databases",
}
 
FEATURE_WHY = {
    "UsingIP":"Legitimate sites use domain names, not raw IP addresses.",
    "LongURL":"Phishing URLs are often very long to hide suspicious parts.",
    "ShortURL":"Short links (bit.ly etc.) hide the real destination.",
    "Symbol@":"The @ symbol tricks browsers into ignoring everything before it.",
    "Redirecting//":"Double-slash in the URL path is a known redirect trick.",
    "PrefixSuffix-":"Hyphens in domains mimic real sites (e.g. secure-paypal.com).",
    "SubDomains":"Multiple sub-domains disguise the real domain.",
    "HTTPS":"Legitimate sites encrypt connections with HTTPS.",
    "DomainRegLen":"Phishing domains are registered for short periods.",
    "Favicon":"Loading favicons from other domains copies a legitimate site.",
    "NonStdPort":"Unusual ports avoid detection by security tools.",
    "HTTPSDomainURL":"Putting 'https' in the domain name is a deception trick.",
    "RequestURL":"Most content loading from other domains = copied phishing page.",
    "AnchorURL":"Phishing pages link back to the site they are copying.",
    "LinksInScriptTags":"High external script links = copied page.",
    "ServerFormHandler":"A form sending data elsewhere = attacker collecting your info.",
    "InfoEmail":"mailto: in forms sends credentials directly to an attacker.",
    "AbnormalURL":"URL not matching the registered domain = spoofing.",
    "WebsiteForwarding":"Multiple redirects disguise the real destination.",
    "StatusBarCust":"Hiding the real URL in the status bar = deception.",
    "DisableRightClick":"Stops users from inspecting the page source.",
    "UsingPopupWindow":"Collecting credentials through pop-ups is a phishing tactic.",
    "IframeRedirection":"Hidden iframes load malicious content invisibly.",
    "AgeofDomain":"Newly registered domains are very likely to be phishing sites.",
    "DNSRecording":"Legitimate sites always have a DNS record.",
    "WebsiteTraffic":"Phishing sites have no traffic history.",
    "PageRank":"Low PageRank = site has little authority on the web.",
    "GoogleIndex":"Phishing sites are usually not indexed by Google.",
    "LinksPointingToPage":"No backlinks = site has no history.",
    "StatsReport":"Domain matches patterns in known phishing databases.",
}
 
# Page config
st.set_page_config(
    page_title="Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
 
st.markdown("""
<style>
    [data-testid="stSidebar"] { background: #f7f8fc; }
    .block-container { padding-top: 1.8rem; }
 
    /* Blue scan button — single line */
    div[data-testid="stButton"] > button {
        background: #2563eb; color: white; font-weight: 600;
        border: none; padding: 0.5rem 2rem; border-radius: 8px;
        white-space: nowrap; text-align: center;
        display: flex; align-items: center; justify-content: center;
    }
    div[data-testid="stButton"] > button:hover {
        background: #1d4ed8; color: white;
    }
 
    /* Caption next to button — black, same vertical centre */
    .scan-hint {
        color: #111827 !important;
        font-size: 0.9rem;
        display: flex;
        align-items: center;
        height: 100%;
        padding-top: 6px;
    }
</style>
""", unsafe_allow_html=True)
 
# Pill metrics
def render_pills(label, confidence, risk, risk_meta, red_count):
    risk_border = risk_meta["border"]
    risk_color  = risk_meta["color"]
    risk_emoji  = risk_meta["emoji"]
    lbl_style   = "color:#111827;font-weight:400;margin-right:3px;"
    pill        = ("display:inline-flex;align-items:center;gap:4px;"
                   "background:#f3f4f6;border:1px solid #e5e7eb;border-radius:50px;"
                   "padding:8px 20px;font-size:0.88rem;color:#111827;font-weight:500;")
    risk_pill   = (f"display:inline-flex;align-items:center;gap:4px;"
                   f"background:#f3f4f6;border:2px solid {risk_border};"
                   f"border-radius:50px;padding:8px 20px;font-size:0.88rem;"
                   f"color:{risk_color};font-weight:600;")
 
    st.markdown(
        f"<div style='display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 6px;'>"
        f"<div style='{pill}'><span style='{lbl_style}'>Prediction</span><strong>{label}</strong></div>"
        f"<div style='{pill}'><span style='{lbl_style}'>Confidence</span><strong>{confidence}%</strong></div>"
        f"<div style='{risk_pill}'><span style='color:{risk_color};opacity:.7;margin-right:3px;'>Risk</span>"
        f"{risk_emoji} <strong>{risk}</strong></div>"
        f"<div style='{pill}'><span style='{lbl_style}'>Red Flags</span><strong>{red_count} detected</strong></div>"
        f"</div>",
        unsafe_allow_html=True,
    )
  
# HTML report builder
def build_html_report(url, result, features_dict, notes_dict, real_red_flags, metadata):
    risk      = result["risk_level"]
    rmeta     = result["risk_meta"]
    label     = result["label"]
    conf      = result["confidence_pct"]
    phish_pct = round(result["phishing_prob"] * 100, 1)
    legit_pct = round(result["legit_prob"]    * 100, 1)
    scan_time = datetime.now().strftime("%d %B %Y, %I:%M %p")
    best      = metadata["best_model_name"]
    acc       = metadata["metrics"][best]["accuracy"] * 100
 
    rc = {"Safe":{"bg":"#d4edda","border":"#28a745","text":"#155724"},
          "Suspicious":{"bg":"#fff3cd","border":"#ffc107","text":"#856404"},
          "Dangerous":{"bg":"#f8d7da","border":"#dc3545","text":"#721c24"}}[risk]
 
    red_rows = ""
    for col_name, note in real_red_flags.items():
        lbl = FEATURE_LABELS.get(col_name, col_name)
        why = FEATURE_WHY.get(col_name, "")
        red_rows += (
            f"<tr><td style='padding:10px 14px;border-bottom:1px solid #fde8e8;"
            f"font-weight:600;color:#be123c;'>{lbl}</td>"
            f"<td style='padding:10px 14px;border-bottom:1px solid #fde8e8;color:#374151;'>{note}</td>"
            f"<td style='padding:10px 14px;border-bottom:1px solid #fde8e8;"
            f"color:#6b7280;font-size:0.88rem;'>{why}</td></tr>"
        )
 
    cat_rows = ""
    for cat_name, feats in CATEGORIES.items():
        total  = len(feats)
        safe   = sum(1 for c, _ in feats if features_dict.get(c, 0) == 1)
        issues = sum(1 for c, _ in feats if features_dict.get(c, 0) == -1)
        pct    = int(safe / total * 100)
        clr    = "#16a34a" if pct >= 80 else ("#d97706" if pct >= 55 else "#dc2626")
        cat_rows += (
            f"<tr><td style='padding:10px 14px;border-bottom:1px solid #f3f4f6;"
            f"font-weight:600;'>{cat_name}</td>"
            f"<td style='padding:10px 14px;border-bottom:1px solid #f3f4f6;"
            f"color:{clr};font-weight:700;'>{pct}%</td>"
            f"<td style='padding:10px 14px;border-bottom:1px solid #f3f4f6;"
            f"color:#be123c;'>{issues} issue(s)</td></tr>"
        )
 
    action = {
        "Dangerous": ("⛔ <strong>Do NOT use this website.</strong> Do not enter any passwords, "
                      "credit card numbers, or personal information. Close the page immediately."),
        "Suspicious": ("⚠️ <strong>Be careful.</strong> Verify the URL and SSL padlock before "
                       "submitting any sensitive information."),
        "Safe": ("✅ <strong>This website looks safe.</strong> No major phishing indicators found. "
                 "Always verify the URL before entering passwords or payment details."),
    }[risk]
 
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Phishing Analysis Report</title>
  <style>
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background:#f9fafb;color:#111827;margin:0;padding:30px;}}
    .wrap{{max-width:860px;margin:0 auto;}}
    h2{{font-size:1.1rem;margin:28px 0 10px;color:#1f2937;}}
    .result-box{{background:{rc['bg']};border:2px solid {rc['border']};
                 border-radius:12px;padding:22px 26px;margin:20px 0;}}
    .result-box h1{{color:{rc['text']};margin:0 0 10px;font-size:1.5rem;}}
    .result-box p{{margin:4px 0;color:#374151;}}
    .metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0;}}
    .metric{{background:white;border:1px solid #e5e7eb;border-radius:10px;
             padding:14px 18px;text-align:center;}}
    .metric .val{{font-size:1.35rem;font-weight:800;color:#111827;}}
    .metric .lbl{{font-size:0.77rem;color:#9ca3af;margin-top:2px;}}
    table{{width:100%;border-collapse:collapse;background:white;border-radius:10px;
           overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.06);}}
    th{{background:#f3f4f6;padding:10px 14px;text-align:left;font-size:0.8rem;
        color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.04em;}}
    .prog-bg{{background:#f0f0f0;border-radius:99px;height:8px;margin:6px 0;}}
    .prog-fill{{height:8px;border-radius:99px;}}
    .rec{{background:#eff6ff;border-left:4px solid #3b82f6;border-radius:8px;
          padding:14px 18px;margin:14px 0;font-size:0.93rem;line-height:1.65;color:#1e40af;}}
    .footer{{margin-top:40px;padding-top:14px;border-top:1px solid #000000;
             font-size:0.79rem;color:#000000;text-align:center;}}
  </style>
</head>
<body><div class="wrap">
  <p style="color:#9ca3af;font-size:0.86rem;margin-bottom:4px;">
    Generated: {scan_time} &nbsp;·&nbsp; Model: {best} ({acc:.1f}% accuracy)
  </p>
  <div class="result-box">
    <h1>{rmeta['emoji']} {'Phishing Website Detected' if label=='Phishing' else 'Safe Website'}</h1>
    <p><strong>URL:</strong> {url}</p>
  </div>
  <div class="metrics">
    <div class="metric"><div class="val">{label}</div><div class="lbl">Prediction</div></div>
    <div class="metric"><div class="val">{conf}%</div><div class="lbl">Confidence</div></div>
    <div class="metric"><div class="val">{rmeta['emoji']} {risk}</div><div class="lbl">Risk Level</div></div>
    <div class="metric"><div class="val">{len(real_red_flags)}/30</div><div class="lbl">Issues Found</div></div>
  </div>
  <h2>Probability</h2>
  <p> Phishing: <strong>{phish_pct}%</strong></p>
  <div class="prog-bg"><div class="prog-fill" style="width:{phish_pct}%;background:#dc2626;"></div></div>
  <p> Safe: <strong>{legit_pct}%</strong></p>
  <div class="prog-bg"><div class="prog-fill" style="width:{legit_pct}%;background:#16a34a;"></div></div>
  <h2>What Should You Do?</h2>
  <div class="rec">{action}</div>
  <h2>Security Breakdown</h2>
  <table><thead><tr><th>Category</th><th>Safety Score</th><th>Issues</th></tr></thead>
  <tbody>{cat_rows}</tbody></table>
  <h2>Phishing Indicators Detected</h2>
  {'<p style="color:#15803d;"> No phishing indicators detected.</p>' if not red_rows else
   '<table><thead><tr><th>Feature</th><th>What Was Found</th><th>Why It Matters</th></tr></thead><tbody>'
   + red_rows + '</tbody></table>'}
  <div class="footer">BSCS 7th Semester Project &nbsp;·&nbsp;
    Phishing Website Detection using Machine Learning &nbsp;·&nbsp; {scan_time}</div>
</div></body></html>"""
 
# Load model
@st.cache_resource
def get_model():
    return load_model()
  
# Sidebar 
with st.sidebar:
    st.title("🛡️ Project Information")
    st.divider()
    st.markdown("**Project:** Phishing Website Detection")
    st.markdown("**Technique:** Logistic Regression & Random Forest")
    st.markdown("**Framework:** Streamlit")
    st.markdown("**Task:** Phishing / Legitimate Classification")
    st.divider()
    st.markdown("**Features**")
    st.markdown("✓ Automatic URL scanning")
    st.markdown("✓ Confidence score")
    st.markdown("✓ Risk level classification")
    st.markdown("✓ 4-category security analysis")
    st.markdown("✓ Phishing indicators breakdown")
    st.markdown("✓ Downloadable analysis report")
 
# Guard
if not model_is_trained():
    st.error(
        "**Model not found.**\n\nRun:\n```\npython train_model.py\n```\nThen refresh."
    )
    st.stop()
 
model, scaler, metadata = get_model()
 
# Main page
st.title("🛡️ Phishing Website Detection System")
 
# Project description 
st.markdown(
    "This web application uses Machine Learning to detect whether a website is "
    "**Phishing** or **Legitimate**. It provides a confidence score, risk level, "
    "and a detailed security breakdown."
)
 
st.divider()
 
# URL input 
st.subheader("🔗 Enter Website URL")
 
url_input = st.text_input(
    label            = "url",
    placeholder      = "https://example.com",
    label_visibility = "collapsed",
) 
col_btn, col_hint = st.columns([1, 5])
with col_btn:
    scan_clicked = st.button("Scan URL")
with col_hint:
    # Black text, vertically centered with button
    st.markdown(
        "<p class='scan-hint'>Takes 5–15 seconds to visit and analyze the site.</p>",
        unsafe_allow_html=True,
    )
 
 
# Scan + Results
if scan_clicked:
 
    raw_url = url_input.strip()
    if not raw_url:
        st.warning("Please enter a URL first.")
        st.stop()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
 
    with st.spinner(f"Visiting {raw_url} — extracting security features..."):
        try:
            features_dict, notes_dict = extract_features(raw_url)
        except Exception as e:
            st.error(f"Could not analyze this URL: {e}")
            st.stop()
 
    with st.spinner("Running ML model..."):
        try:
            result = predict(model, scaler, build_feature_vector(features_dict))
        except Exception as e:
            st.error(f"Prediction failed: {e}")
            st.stop()
 
    risk     = result["risk_level"]
    rmeta    = result["risk_meta"]
    is_phish = result["label"] == "Phishing"
 
    st.divider()

    if is_phish and risk == "Dangerous":
        st.error(f"### Phishing Website Detected\n\n**URL:** {raw_url}")
    elif is_phish or risk == "Suspicious":
        st.warning(f"###  Suspicious Website\n\n**URL:** {raw_url}")
    else:
        st.success(f"###  Legitimate Website\n\n**URL:** {raw_url}")
 
    # Pill metrics
    real_red_flags = {
        col: notes_dict.get(col, col)
        for col, val in features_dict.items()
        if val == -1 and col in RELIABLE_FEATURES
    }
    render_pills(
        label      = result["label"],
        confidence = result["confidence_pct"],
        risk       = risk,
        risk_meta  = rmeta,
        red_count  = len(real_red_flags),
    )
 
    # Probability bars
    st.markdown("#### Probability")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("Phishing Probability")
        st.progress(result["phishing_prob"])
        st.caption(f"**{result['phishing_prob']*100:.1f}%**")
    with c2:
        st.markdown("Legitimate Probability")
        st.progress(result["legit_prob"])
        st.caption(f"**{result['legit_prob']*100:.1f}%**")
 
    # Recommendation 
    if risk == "Dangerous":
        st.error(
            " **Do NOT proceed.** Do not enter any passwords, credit card details, "
            "or personal information. Close this tab immediately."
        )
    elif risk == "Suspicious":
        st.warning(
            " **Proceed with caution.** Verify the URL and SSL certificate carefully "
            "before submitting any sensitive information."
        )
    else:
        st.success(
            " **Looks Legitimate.** No major phishing indicators detected. "
            "Always verify the URL before entering passwords."
        )
 
    # 4 Category Score Cards 
    st.divider()
    st.markdown("###  Security Breakdown by Category")
    st.caption(
        "All 30 features are grouped into 4 security areas. "
        "Each card shows the safety score and any issues found."
    )
 
    def category_card(col_widget, cat_name):
        feats  = CATEGORIES[cat_name]
        total  = len(feats)
        safe   = sum(1 for c, _ in feats if features_dict.get(c, 0) == 1)
        issues = [(c, lbl) for c, lbl in feats if features_dict.get(c, 0) == -1]
        pct    = int(safe / total * 100)
        dot    = "🟢" if pct >= 80 else ("🟡" if pct >= 55 else "🔴")
 
        with col_widget:
            with st.container(border=True):
                st.markdown(f"**{cat_name}**")
                # Only percentage — no "X/Y features OK"
                issue_text = f" · **{len(issues)} issue(s)**" if issues else ""
                st.markdown(f"{dot} **{pct}% safe**{issue_text}")
                st.progress(pct / 100)
                if issues:
                    for c, _ in issues:
                        note = notes_dict.get(c, FEATURE_LABELS.get(c, c))
                        st.markdown(f"⛔ {note}")
                else:
                    st.markdown("✅ All checks passed")
 
    cat_names = list(CATEGORIES.keys())
    r1 = st.columns(2, gap="medium")
    category_card(r1[0], cat_names[0])
    category_card(r1[1], cat_names[1])
    st.markdown("")
    r2 = st.columns(2, gap="medium")
    category_card(r2[0], cat_names[2])
    category_card(r2[1], cat_names[3])
 
    # Download HTML report
    html_report = build_html_report(
        url            = raw_url,
        result         = result,
        features_dict  = features_dict,
        notes_dict     = notes_dict,
        real_red_flags = real_red_flags,
        metadata       = metadata,
    )
 
    col_dl, col_note = st.columns([1, 4])
    with col_dl:
        st.download_button(
            label     = "⬇️ Download Report",
            data      = html_report.encode("utf-8"),
            file_name = "phishing_report.html",
            mime      = "text/html",
        )
    with col_note:
       with col_note:
        st.markdown("<p style='color:#111827;font-size:0.85rem;margin-top:8px;'>Downloads as an <strong>HTML file</strong> — open it in any browser. Shows the full analysis: result, risk level, all issues found, and what each issue means.</p>", unsafe_allow_html=True)
    # Footer 
    st.divider()
    st.markdown("<div style='text-align:center;color:#111827;font-size:0.82rem;margin-top:8px;'>🎓 BSCS 7th Semester Project · Phishing Detection using Machine Learning</div>", unsafe_allow_html=True)
 