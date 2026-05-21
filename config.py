import os

# File paths
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR    = os.path.join(BASE_DIR, "models")
MODEL_PATH    = os.path.join(MODELS_DIR, "best_model.pkl")
SCALER_PATH   = os.path.join(MODELS_DIR, "scaler.pkl")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")

# ── Dataset 
DATASET_PATH   = os.path.join(BASE_DIR, "phishing.csv")
TARGET_COLUMN  = "class"          
DROP_COLUMNS   = ["Index"]        
TEST_SIZE      = 0.20
RANDOM_STATE   = 42

# ── Risk level 
#   0%  – 40%  → Safe      
#   40% – 70%  → Suspicious  
#   70% – 100% → Dangerous   
RISK_SAFE_MAX       = 0.40
RISK_SUSPICIOUS_MAX = 0.70

RISK_LABELS = {
    "Safe":       {"emoji": "✅", "color": "#155724", "bg": "#d4edda", "border": "#28a745"},
    "Suspicious": {"emoji": "⚠️",  "color": "#856404", "bg": "#fff3cd", "border": "#ffc107"},
    "Dangerous":  {"emoji": "🚨", "color": "#721c24", "bg": "#f8d7da", "border": "#dc3545"},
}

# Feature definitions
# Values: -1 = phishing indicator, 0 = neutral, 1 = legitimate indicator
FEATURES = [
    (
        "UsingIP",
        "IP Address Used in URL?",
        [(-1, "Yes — IP address used (e.g. http://192.168.1.1/login)"),
         ( 1, "No  — Normal domain name (e.g. https://google.com)")],
        "Phishing sites often use raw IP addresses instead of domain names to avoid detection."
    ),
    (
        "LongURL",
        "URL Length",
        [( 1, "Short URL (less than 54 characters)"),
         ( 0, "Medium URL (54 to 75 characters)"),
         (-1, "Long URL (more than 75 characters)")],
        "Phishing URLs are often very long to hide the suspicious parts."
    ),
    (
        "ShortURL",
        "URL Shortening Service Used?",
        [( 1, "No  — Full URL visible"),
         (-1, "Yes — Shortened URL (e.g. bit.ly, tinyurl.com)")],
        "Shortened URLs hide the real destination and are commonly used in phishing."
    ),
    (
        "Symbol@",
        "@ Symbol in URL?",
        [( 1, "No  — No @ symbol"),
         (-1, "Yes — @ symbol present in URL")],
        "The browser ignores everything before @ in a URL, so attackers use it to disguise the real address."
    ),
    (
        "Redirecting//",
        "Double Slash (//) in URL Path?",
        [( 1, "No  — Normal URL"),
         (-1, "Yes — Contains // redirect trick")],
        "Using // in the path after the domain is a redirect trick used by phishing sites."
    ),
    (
        "PrefixSuffix-",
        "Hyphen (-) in Domain Name?",
        [( 1, "No  — No hyphen in domain"),
         (-1, "Yes — Hyphen present (e.g. secure-paypal.com)")],
        "Legitimate sites rarely use hyphens in domain names. Phishing sites do to appear real."
    ),
    (
        "SubDomains",
        "Number of Sub-Domains",
        [( 1, "One sub-domain (e.g. www.site.com)"),
         ( 0, "Two sub-domains (e.g. login.www.site.com)"),
         (-1, "Three or more sub-domains (highly suspicious)")],
        "More sub-domains make a URL look legitimate but are a common phishing trick."
    ),
    (
        "HTTPS",
        "HTTPS / SSL Certificate",
        [( 1, "Trusted certificate from a reputable authority"),
         ( 0, "Self-signed or unverified certificate"),
         (-1, "No HTTPS — plain HTTP only")],
        "Phishing sites often lack proper SSL certificates or use self-signed ones."
    ),
    (
        "DomainRegLen",
        "Domain Registration Length",
        [( 1, "Registered for more than 1 year"),
         (-1, "Registered for 1 year or less")],
        "Legitimate businesses register domains for multiple years. Phishing domains are often short-term."
    ),
    (
        "Favicon",
        "Favicon Loaded From",
        [( 1, "Same domain as the website"),
         (-1, "Loaded from an external / different domain")],
        "Loading the favicon from a different domain is a sign of a fake website copying another."
    ),
    (
        "NonStdPort",
        "Non-Standard Port Used?",
        [( 1, "No  — Standard port (80 or 443)"),
         (-1, "Yes — Unusual port number (e.g. :8080, :4444)")],
        "Phishing sites sometimes use unusual ports to avoid detection."
    ),
    (
        "HTTPSDomainURL",
        "'https' Word in Domain Name?",
        [( 1, "No  — 'https' not in domain name"),
         (-1, "Yes — Domain contains the word 'https' (deceptive trick)")],
        "A trick where the word 'https' appears inside the domain to fool users (e.g. https-paypal.com)."
    ),
    (
        "RequestURL",
        "Percentage of External Page Resources",
        [( 1, "Less than 22% come from external domains"),
         ( 0, "22% to 61% from external domains"),
         (-1, "More than 61% from external domains")],
        "If most images/scripts load from other domains, the site may be a phishing copy."
    ),
    (
        "AnchorURL",
        "Percentage of Anchor Links Pointing Away",
        [( 1, "Less than 31% point to a different domain"),
         ( 0, "31% to 67% point away"),
         (-1, "More than 67% point to a different domain")],
        "Phishing pages often have most links pointing to the real site they're copying."
    ),
    (
        "LinksInScriptTags",
        "External Links in Script / Meta / Link Tags",
        [( 1, "Less than 17% are external"),
         ( 0, "17% to 81% are external"),
         (-1, "More than 81% are external")],
        "High percentage of external resources in script tags indicates a copied phishing page."
    ),
    (
        "ServerFormHandler",
        "Where Does the Form Submit Data?",
        [( 1, "Submits to the same or a legitimate domain"),
         ( 0, "Empty or 'about:blank'"),
         (-1, "Submits to a completely different domain")],
        "Login forms that send data to a different server are a clear phishing signal."
    ),
    (
        "InfoEmail",
        "Form Uses 'mailto:' Email Submission?",
        [( 1, "No  — Form submits normally"),
         (-1, "Yes — Form uses mailto: to email data directly")],
        "Using mailto: in forms sends your credentials directly to an attacker's email."
    ),
    (
        "AbnormalURL",
        "URL Looks Abnormal / Mismatched Domain?",
        [( 1, "No  — URL matches WHOIS domain info"),
         (-1, "Yes — URL hostname doesn't match registration info")],
        "When the URL doesn't match the registered domain, it's a strong phishing indicator."
    ),
    (
        "WebsiteForwarding",
        "How Many Times Does the Site Redirect?",
        [( 0, "0 or 1 redirects (normal)"),
         ( 1, "2 redirects"),
         (-1, "3 or more redirects (suspicious)")],
        "Phishing sites often chain multiple redirects to hide their real destination."
    ),
    (
        "StatusBarCust",
        "Status Bar Changed by JavaScript?",
        [( 1, "No  — Status bar is normal"),
         (-1, "Yes — JavaScript changes what the status bar shows on hover")],
        "Hiding the real URL destination in the status bar is an old phishing trick."
    ),
    (
        "DisableRightClick",
        "Right-Click Disabled on the Page?",
        [( 1, "No  — Right-click works normally"),
         (-1, "Yes — Right-click is disabled to prevent source inspection")],
        "Phishing sites disable right-click to stop users from inspecting the page."
    ),
    (
        "UsingPopupWindow",
        "Pop-Up Windows with Forms?",
        [( 1, "No  — No suspicious pop-ups"),
         (-1, "Yes — Pop-ups appear with login or data entry forms")],
        "Collecting credentials through pop-ups instead of the main page is a phishing tactic."
    ),
    (
        "IframeRedirection",
        "Hidden iFrames Used?",
        [( 1, "No  — No hidden iframes"),
         (-1, "Yes — Invisible iframes are present")],
        "Hidden iframes can load malicious content without the user seeing it."
    ),
    (
        "AgeofDomain",
        "How Old Is the Domain?",
        [( 1, "6 months or older"),
         (-1, "Less than 6 months old")],
        "Newly registered domains are far more likely to be phishing sites."
    ),
    (
        "DNSRecording",
        "DNS Record Found for This Domain?",
        [( 1, "Yes — Valid DNS record exists"),
         (-1, "No  — No DNS record found")],
        "Legitimate websites always have DNS records. Missing records are suspicious."
    ),
    (
        "WebsiteTraffic",
        "Website Traffic Ranking",
        [( 1, "High traffic — well-known site"),
         ( 0, "Low traffic — ranked but small"),
         (-1, "No ranking — not found in traffic databases")],
        "Phishing sites have little to no web traffic since they're newly created fakes."
    ),
    (
        "PageRank",
        "Google PageRank Score",
        [( 1, "PageRank ≥ 0.2 — established site"),
         (-1, "PageRank < 0.2 — low authority site")],
        "Legitimate sites have higher PageRank scores from years of links and traffic."
    ),
    (
        "GoogleIndex",
        "Is the Site Indexed by Google?",
        [( 1, "Yes — Found in Google search results"),
         (-1, "No  — Not indexed by Google")],
        "Phishing sites are usually not indexed because they are new or get removed quickly."
    ),
    (
        "LinksPointingToPage",
        "Number of Backlinks to This Page",
        [( 1, "Many external sites link to this page"),
         ( 0, "A few backlinks"),
         (-1, "No backlinks at all")],
        "Established websites have many backlinks. Phishing pages have none."
    ),
    (
        "StatsReport",
        "Flagged in Phishing Statistical Reports?",
        [( 1, "No  — Not flagged in any report"),
         (-1, "Yes — IP or domain listed in known phishing databases")],
        "Domains that appear in phishing databases are very likely malicious."
    ),
]

# List of just the column names (for indexing into the DataFrame)
FEATURE_COLUMNS = [f[0] for f in FEATURES]
