import re
import socket
import urllib.parse
from datetime import datetime
 
import requests
from bs4 import BeautifulSoup
 
# Constants 
REQUEST_TIMEOUT = 10   # seconds — how long to wait for the website to respond
 
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "short.url",
    "buff.ly", "t.co", "is.gd", "cli.gs", "yfrog.com",
    "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac",
    "su.pr", "twurl.nl", "snipurl.com", "tr.im", "zip.net",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.one",
}
 
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
 
IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
 

RELIABLE_FEATURES = {
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//",
    "PrefixSuffix-", "SubDomains", "HTTPS", "HTTPSDomainURL", "NonStdPort",
    "Favicon", "RequestURL", "AnchorURL", "LinksInScriptTags",
    "ServerFormHandler", "InfoEmail", "WebsiteForwarding",
    "StatusBarCust", "DisableRightClick", "UsingPopupWindow",
    "IframeRedirection", "DNSRecording", "StatsReport",
    # WHOIS-based — only reliable when WHOIS actually returned data
    "DomainRegLen", "AbnormalURL", "AgeofDomain",
}
 
# Main entry point
def extract_features(url: str) -> tuple[dict, dict]:
    """
    Extract all 30 model features from a URL.
 
    Parameters
    ----------
    url : str — the URL entered by the user (must start with http:// or https://)
 
    Returns
    -------
    features : dict {column_name: int} — ready to feed into the model
    notes    : dict {column_name: str} — human-readable explanation of each value
               (shown in the UI so the user can see what was detected)
    """
    # ── Normalize URL ──────────────────────────────────────────────────────
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
 
    parsed  = urllib.parse.urlparse(url)
    domain  = (parsed.hostname or "").lower()
    path    = parsed.path or ""
    full_url = url
 
    features = {}
    notes    = {}   
 
    # Fetch the page 
    page_text = ""
    soup      = None
    redirects = 0
    fetch_ok  = False
 
    try:
        resp = requests.get(
            full_url,
            timeout        = REQUEST_TIMEOUT,
            allow_redirects= True,
            headers        = BROWSER_HEADERS,
            verify         = False,   # some phishing sites have bad certs — still want to scan
        )
        page_text = resp.text
        soup      = BeautifulSoup(page_text, "html.parser")
        redirects = len(resp.history)
        fetch_ok  = True
    except requests.exceptions.SSLError:
        notes["_fetch"] = "SSL error — page fetched without verification"
        try:
            resp = requests.get(full_url, timeout=REQUEST_TIMEOUT,
                                allow_redirects=True, headers=BROWSER_HEADERS, verify=False)
            page_text = resp.text
            soup      = BeautifulSoup(page_text, "html.parser")
            redirects = len(resp.history)
            fetch_ok  = True
        except Exception:
            pass
    except Exception as e:
        notes["_fetch"] = f"Could not reach site: {e}"
 
    text_lower = page_text.lower()
 
    # WHOIS data 
    whois_data       = _safe_whois(domain)
    domain_age_days  = whois_data.get("age_days")
    reg_length_years = whois_data.get("reg_years")
    whois_domain     = whois_data.get("domain", "")
 
    # Extract each feature
    # 1. UsingIP
    is_ip = bool(IP_PATTERN.match(domain))
    features["UsingIP"] = -1 if is_ip else 1
    notes["UsingIP"]    = f"IP address used: {domain}" if is_ip else f"Domain name: {domain}"
 
    # 2. LongURL
    url_len = len(full_url)
    if url_len < 54:
        features["LongURL"] = 1;  notes["LongURL"] = f"Short URL ({url_len} chars)"
    elif url_len < 75:
        features["LongURL"] = 0;  notes["LongURL"] = f"Medium URL ({url_len} chars)"
    else:
        features["LongURL"] = -1; notes["LongURL"] = f"Long URL ({url_len} chars)"
 
    # 3. ShortURL
    is_short = any(s in domain for s in SHORTENER_DOMAINS)
    features["ShortURL"] = -1 if is_short else 1
    notes["ShortURL"]    = f"Shortener detected: {domain}" if is_short else "No URL shortener"
 
    # 4. Symbol@
    has_at = "@" in full_url
    features["Symbol@"] = -1 if has_at else 1
    notes["Symbol@"]    = "@ symbol found in URL" if has_at else "No @ symbol"
 
    # 5. Redirecting//
    has_double_slash = "//" in path
    features["Redirecting//"] = -1 if has_double_slash else 1
    notes["Redirecting//"]    = "// found in URL path" if has_double_slash else "No // in path"
 
    # 6. PrefixSuffix-
    has_hyphen = "-" in domain
    features["PrefixSuffix-"] = -1 if has_hyphen else 1
    notes["PrefixSuffix-"]    = f"Hyphen in domain: {domain}" if has_hyphen else "No hyphen in domain"
 
    # 7. SubDomains
    # Remove www. and count remaining dots
    clean_domain  = re.sub(r"^www\.", "", domain)
    subdomain_cnt = clean_domain.count(".")
    if subdomain_cnt == 1:
        features["SubDomains"] = 1;  notes["SubDomains"] = "1 sub-domain (normal)"
    elif subdomain_cnt == 2:
        features["SubDomains"] = 0;  notes["SubDomains"] = "2 sub-domains (suspicious)"
    else:
        features["SubDomains"] = -1; notes["SubDomains"] = f"{subdomain_cnt} sub-domains (very suspicious)"
 
    # 8. HTTPS
    if parsed.scheme == "https":
        features["HTTPS"] = 1;  notes["HTTPS"] = "HTTPS used"
    else:
        features["HTTPS"] = -1; notes["HTTPS"] = "No HTTPS (plain HTTP)"
 
    # 9. DomainRegLen
    if reg_length_years is None:
        features["DomainRegLen"] = 0;  notes["DomainRegLen"] = "Domain registration length could not be verified"
    elif reg_length_years > 1:
        features["DomainRegLen"] = 1;  notes["DomainRegLen"] = f"Domain registered for {reg_length_years:.1f} years (long-term — good sign)"
    else:
        features["DomainRegLen"] = -1; notes["DomainRegLen"] = f"Domain registered for only {reg_length_years:.1f} year(s) — short registrations are suspicious"
 
    # 10. Favicon
    if soup is None:
        features["Favicon"] = 1; notes["Favicon"] = "Could not check favicon"
    else:
        fav_tag  = soup.find("link", rel=lambda r: r and any("icon" in x.lower() for x in (r if isinstance(r, list) else [r])))
        fav_href = fav_tag.get("href", "") if fav_tag else ""
        if fav_href and fav_href.startswith("http") and domain not in fav_href:
            features["Favicon"] = -1; notes["Favicon"] = f"Favicon from external domain: {fav_href[:60]}"
        else:
            features["Favicon"] = 1;  notes["Favicon"] = "Favicon from same domain"
 
    # 11. NonStdPort
    port = parsed.port
    std_ports = {80, 443, None}
    features["NonStdPort"] = -1 if port not in std_ports else 1
    notes["NonStdPort"]    = f"Non-standard port: {port}" if port not in std_ports else "Standard port"
 
    # 12. HTTPSDomainURL
    https_in_domain = "https" in domain
    features["HTTPSDomainURL"] = -1 if https_in_domain else 1
    notes["HTTPSDomainURL"]    = f"'https' found in domain name: {domain}" if https_in_domain else "No 'https' in domain name"
 
    # ── Content-based features (need page_text / soup) ─────────────────────
 
    # 13. RequestURL  — % of images+scripts from external domains
    if soup is None:
        features["RequestURL"] = 0; notes["RequestURL"] = "Could not fetch page"
    else:
        resources = [
            tag.get("src", "") for tag in soup.find_all(["img", "script", "video", "audio"])
            if tag.get("src")
        ]
        ext_res = [r for r in resources if r.startswith("http") and domain not in r]
        pct = (len(ext_res) / len(resources) * 100) if resources else 0
        if pct < 22:
            features["RequestURL"] = 1;  notes["RequestURL"] = f"{pct:.0f}% external resources (< 22%)"
        elif pct < 61:
            features["RequestURL"] = 0;  notes["RequestURL"] = f"{pct:.0f}% external resources (22–61%)"
        else:
            features["RequestURL"] = -1; notes["RequestURL"] = f"{pct:.0f}% external resources (> 61%)"
 
    # 14. AnchorURL — % of <a href> pointing away
    if soup is None:
        features["AnchorURL"] = 0; notes["AnchorURL"] = "Could not fetch page"
    else:
        anchors = soup.find_all("a", href=True)
        ext_a   = [a for a in anchors
                   if a["href"].startswith("http") and domain not in a["href"]]
        pct = (len(ext_a) / len(anchors) * 100) if anchors else 0
        if pct < 31:
            features["AnchorURL"] = 1;  notes["AnchorURL"] = f"{pct:.0f}% anchor links point away (< 31%)"
        elif pct < 67:
            features["AnchorURL"] = 0;  notes["AnchorURL"] = f"{pct:.0f}% anchor links point away (31–67%)"
        else:
            features["AnchorURL"] = -1; notes["AnchorURL"] = f"{pct:.0f}% anchor links point away (> 67%)"
 
    # 15. LinksInScriptTags — % of external links in meta/script/link tags
    if soup is None:
        features["LinksInScriptTags"] = 0; notes["LinksInScriptTags"] = "Could not fetch page"
    else:
        tag_links = []
        for tag in soup.find_all(["meta", "link"]):
            href = tag.get("href") or tag.get("content") or ""
            if href.startswith("http"):
                tag_links.append(href)
        ext_tag = [l for l in tag_links if domain not in l]
        pct = (len(ext_tag) / len(tag_links) * 100) if tag_links else 0
        if pct < 17:
            features["LinksInScriptTags"] = 1;  notes["LinksInScriptTags"] = f"{pct:.0f}% external (< 17%)"
        elif pct < 81:
            features["LinksInScriptTags"] = 0;  notes["LinksInScriptTags"] = f"{pct:.0f}% external (17–81%)"
        else:
            features["LinksInScriptTags"] = -1; notes["LinksInScriptTags"] = f"{pct:.0f}% external (> 81%)"
 
    # 16. ServerFormHandler — where does the form submit?
    if soup is None:
        features["ServerFormHandler"] = -1; notes["ServerFormHandler"] = "Could not fetch page"
    else:
        forms      = soup.find_all("form")
        sfh_result = 1   # default: safe
        sfh_note   = "No forms found"
        for form in forms:
            action = (form.get("action") or "").strip().lower()
            if action in ("", "about:blank", "#"):
                sfh_result = 0; sfh_note = "Form submits to empty/blank action"
            elif action.startswith("http") and domain not in action:
                sfh_result = -1; sfh_note = f"Form submits to external domain: {action[:60]}"
                break
        features["ServerFormHandler"] = sfh_result
        notes["ServerFormHandler"]    = sfh_note
 
    # 17. InfoEmail — mailto: in forms
    has_mailto = "mailto:" in text_lower
    features["InfoEmail"] = -1 if has_mailto else 1
    notes["InfoEmail"]    = "mailto: found (data sent to email)" if has_mailto else "No mailto: in forms"
 
    # 18. AbnormalURL — URL hostname vs WHOIS domain
    if not whois_domain:
        features["AbnormalURL"] = 0;  notes["AbnormalURL"] = "Domain identity could not be verified (WHOIS lookup failed)"
    else:
        clean_wh = whois_domain.lower().replace("www.", "")
        clean_dm = domain.replace("www.", "")
        match = clean_wh in clean_dm or clean_dm.endswith(clean_wh)
        features["AbnormalURL"] = 1 if match else -1
        notes["AbnormalURL"]    = "URL matches registered domain (normal)" if match else f"URL does not match WHOIS domain — possible spoofing (URL: {clean_dm}, Registered: {clean_wh})"
 
    # 19. WebsiteForwarding — number of redirects
    if redirects <= 1:
        features["WebsiteForwarding"] = 0;  notes["WebsiteForwarding"] = f"{redirects} redirect(s)"
    elif redirects == 2:
        features["WebsiteForwarding"] = 1;  notes["WebsiteForwarding"] = "2 redirects"
    else:
        features["WebsiteForwarding"] = -1; notes["WebsiteForwarding"] = f"{redirects} redirects (suspicious)"
 
    # 20. StatusBarCust — onmouseover changing status bar
    has_mouseover = "onmouseover" in text_lower
    features["StatusBarCust"] = -1 if has_mouseover else 1
    notes["StatusBarCust"]    = "onmouseover JS detected" if has_mouseover else "No status bar manipulation"
 
    # 21. DisableRightClick
    rightclick_disabled = (
        "event.button==2" in text_lower
        or "contextmenu" in text_lower
        or "preventdefault" in text_lower
    ) and "menu" in text_lower
    features["DisableRightClick"] = -1 if rightclick_disabled else 1
    notes["DisableRightClick"]    = "Right-click appears disabled" if rightclick_disabled else "Right-click enabled"
 
    # 22. UsingPopupWindow — window.open() in JS
    has_popup = "window.open" in text_lower
    features["UsingPopupWindow"] = -1 if has_popup else 1
    notes["UsingPopupWindow"]    = "window.open() found (pop-ups)" if has_popup else "No pop-up windows"
 
    # 23. IframeRedirection — hidden iframes
    if soup is None:
        features["IframeRedirection"] = 1; notes["IframeRedirection"] = "Could not fetch page"
    else:
        iframes = soup.find_all("iframe")
        hidden_iframes = [
            f for f in iframes
            if (f.get("width") in ("0", "0px") or f.get("height") in ("0", "0px")
                or "display:none" in (f.get("style") or "").replace(" ", "").lower()
                or "visibility:hidden" in (f.get("style") or "").replace(" ", "").lower())
        ]
        has_hidden = len(hidden_iframes) > 0
        features["IframeRedirection"] = -1 if has_hidden else 1
        notes["IframeRedirection"]    = f"{len(hidden_iframes)} hidden iframe(s)" if has_hidden else "No hidden iframes"
 
    # 24. AgeofDomain
    if domain_age_days is None:
        features["AgeofDomain"] = 0;  notes["AgeofDomain"] = "Domain age could not be verified"
    elif domain_age_days >= 180:
        features["AgeofDomain"] = 1;  notes["AgeofDomain"] = f"Domain is {domain_age_days} days old — established (≥ 6 months)"
    else:
        features["AgeofDomain"] = -1; notes["AgeofDomain"] = f"Domain is only {domain_age_days} days old — newly registered domains are suspicious"
 
    # 25. DNSRecording
    try:
        socket.gethostbyname(domain)
        features["DNSRecording"] = 1;  notes["DNSRecording"] = "DNS record found"
    except socket.gaierror:
        features["DNSRecording"] = -1; notes["DNSRecording"] = "No DNS record found"
 
    # 26. WebsiteTraffic — no free API; use HTTPS + DNS as heuristic
    if features["DNSRecording"] == 1 and features["HTTPS"] == 1 and not is_ip:
        features["WebsiteTraffic"] = 0;  notes["WebsiteTraffic"] = "Traffic rank not available (site has valid DNS and HTTPS)"
    else:
        features["WebsiteTraffic"] = -1; notes["WebsiteTraffic"] = "Site appears to have low or no web traffic"
 
    # 27. PageRank — deprecated API; estimate from domain age + HTTPS
    if features["AgeofDomain"] == 1 and features["HTTPS"] == 1:
        features["PageRank"] = 1;  notes["PageRank"] = "PageRank likely acceptable (established domain with HTTPS)"
    else:
        features["PageRank"] = -1; notes["PageRank"] = "PageRank likely low — domain is new or lacks HTTPS"
 
    # 28. GoogleIndex — check if site likely indexed (heuristic: HTTPS + DNS + age)
    likely_indexed = (
        features["DNSRecording"] == 1
        and features["HTTPS"] == 1
        and features["AgeofDomain"] == 1
        and not is_short
    )
    features["GoogleIndex"] = 1 if likely_indexed else -1
    notes["GoogleIndex"]    = "Site is likely indexed by Google" if likely_indexed else "Site does not appear to be indexed by Google — new or suspicious domains often aren't"
 
    # 29. LinksPointingToPage — use sub-domain count and age as proxy
    if features["AgeofDomain"] == 1 and features["DNSRecording"] == 1:
        features["LinksPointingToPage"] = 0;  notes["LinksPointingToPage"] = "Some backlinks likely exist (established domain)"
    elif features["AgeofDomain"] == -1:
        features["LinksPointingToPage"] = -1; notes["LinksPointingToPage"] = "No backlinks detected — newly registered domains have no link history"
    else:
        features["LinksPointingToPage"] = 1;  notes["LinksPointingToPage"] = "Backlinks likely exist"
 
    # 30. StatsReport — check domain against known bad patterns (heuristic)
    suspicious_patterns = [
        r"paypal.*secure", r"secure.*paypal",
        r"amazon.*login", r"login.*amazon",
        r"apple.*id",     r"microsoft.*verify",
        r"google.*account.*verify",
        r"verify.*account", r"update.*billing",
        r"confirm.*identity",
    ]
    flagged = any(re.search(p, domain) for p in suspicious_patterns)
    features["StatsReport"] = -1 if flagged else 1
    notes["StatsReport"]    = f"Domain matches suspicious pattern" if flagged else "No known phishing pattern in domain"
 
    return features, notes
 
# WHOIS helper 
def _safe_whois(domain: str) -> dict:
    result = {}
    try:
        import whois as whois_lib
        w = whois_lib.whois(domain)
 
        created = w.creation_date
        expires = w.expiration_date
 
        # WHOIS sometimes returns a list of dates — take the first one
        if isinstance(created, list): created = created[0]
        if isinstance(expires, list): expires = expires[0]
 
        now = datetime.now()
 
        if created and isinstance(created, datetime):
            result["age_days"] = (now - created).days
 
        if created and expires and isinstance(created, datetime) and isinstance(expires, datetime):
            result["reg_years"] = (expires - created).days / 365.0
 
        # Domain name from WHOIS
        wdomain = w.domain_name
        if isinstance(wdomain, list): wdomain = wdomain[0]
        if wdomain:
            result["domain"] = str(wdomain).lower()
 
    except Exception:
        pass   
 
    return result