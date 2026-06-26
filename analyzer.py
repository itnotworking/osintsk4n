"""
osintsk4n analysis engine
==========================
SOC-oriented triage for domains, URLs and email addresses. Built to sit
alongside Mimecast / CrowdStrike Falcon for spam / malware / BEC triage.

Pure stdlib + requests so it cold-starts cleanly on Render's free tier.
"""

import os
import re
import socket
import ipaddress
import datetime as dt
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import requests

VT_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")

USER_AGENT = "osintsk4n/2.0 (SOC triage)"
_executor = ThreadPoolExecutor(max_workers=10)

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# TLDs disproportionately abused for phishing / malware / BEC.
HIGH_RISK_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click",
    "country", "kim", "work", "party", "gdn", "review", "stream", "download",
    "loan", "racing", "win", "bid", "date", "faith", "science", "men",
    "cricket", "accountant", "trade", "webcam", "rest", "fit", "cam",
    "buzz", "monster", "quest", "cyou", "sbs", "lol", "live", "shop",
}

# Free / consumer mail providers — legitimate, but unusual for B2B senders
# and a common BEC pivot ("CEO" mailing from a gmail lookalike).
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net",
    "zoho.com", "yandex.com", "mail.com", "tutanota.com", "hey.com",
}

# Throwaway providers — strong abuse signal for a business sender.
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com", "trashmail.com",
    "getnada.com", "sharklasers.com", "maildrop.cc", "dispostable.com",
    "fakeinbox.com", "mintemail.com", "spamgourmet.com", "mohmal.com",
    "emailondeck.com", "burnermail.io", "mailnesia.com", "tempinbox.com",
}

# Brands most often impersonated in BEC / phishing. Used for look-alike scoring.
COMMON_TARGETS = [
    "microsoft.com", "office365.com", "outlook.com", "live.com",
    "google.com", "gmail.com", "apple.com", "icloud.com", "amazon.com",
    "paypal.com", "docusign.com", "dropbox.com", "adobe.com", "linkedin.com",
    "facebook.com", "netflix.com", "wellsfargo.com", "chase.com",
    "bankofamerica.com", "americanexpress.com", "citi.com", "fedex.com",
    "ups.com", "dhl.com", "intuit.com", "salesforce.com", "zoom.us",
    "mimecast.com", "crowdstrike.com",
]

# Common multi-label public suffixes so we can derive the registrable domain
# without dragging in tldextract (and its cold-start PSL fetch).
MULTI_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "co.nz", "com.br",
    "com.mx", "com.ar", "co.za", "co.in", "com.sg", "com.hk", "com.tw",
    "co.jp", "or.jp", "ne.jp", "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.kr", "com.tr", "com.ua", "co.il", "com.my", "com.ph", "com.vn",
}

MX_PROVIDERS = [
    ("google", "Google Workspace / Gmail"),
    ("googlemail", "Google Workspace / Gmail"),
    ("outlook.com", "Microsoft 365"),
    ("protection.outlook", "Microsoft 365 (EOP)"),
    ("pphosted", "Proofpoint"),
    ("ppe-hosted", "Proofpoint"),
    ("mimecast", "Mimecast"),
    ("messagelabs", "Broadcom / Symantec Email"),
    ("barracuda", "Barracuda"),
    ("mailgun", "Mailgun"),
    ("sendgrid", "SendGrid / Twilio"),
    ("amazonaws", "Amazon SES"),
    ("zoho", "Zoho Mail"),
    ("secureserver", "GoDaddy"),
    ("yandex", "Yandex"),
    ("qq.com", "Tencent QQ Mail"),
]

# Common DKIM selectors to probe (no enumeration is possible without these).
DKIM_SELECTORS = [
    "selector1", "selector2", "google", "default", "k1", "k2", "k3",
    "dkim", "mail", "smtp", "s1", "s2", "mandrill", "everlytickey1",
    "mxvault", "zoho", "fm1", "fm2", "fm3", "protonmail", "amazonses",
]

# --------------------------------------------------------------------------
# HTTP helper
# --------------------------------------------------------------------------

def safe_get(url, headers=None, params=None, timeout=8):
    h = {"User-Agent": USER_AGENT}
    if headers:
        h.update(headers)
    try:
        r = requests.get(url, headers=h, params=params, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None


# --------------------------------------------------------------------------
# Input parsing / hardening
# --------------------------------------------------------------------------

_DEFANG_MAP = [
    ("hxxps", "https"), ("hxxp", "http"), ("hXXps", "https"), ("hXXp", "http"),
    ("fxp", "ftp"),
    ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
    (" dot ", "."), ("[:]", ":"), ("[/]", "/"), ("\\.", "."),
    ("[at]", "@"), ("(at)", "@"), (" at ", "@"), ("[@]", "@"),
]

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@([^@\s]{1,255})$")


def refang(text):
    """Convert defanged IOCs (hxxp, [.], [at], …) back to real form."""
    out = text
    for bad, good in _DEFANG_MAP:
        out = out.replace(bad, good)
    return out.strip()


def defang(text):
    """Render an IOC safe to display / paste into a ticket."""
    if not text:
        return text
    out = str(text)
    out = out.replace("http", "hxxp").replace("HTTP", "hxxp")
    out = out.replace(".", "[.]").replace("@", "[at]")
    return out


def registrable_domain(host):
    """Best-effort eTLD+1 without the tldextract dependency."""
    if not host:
        return host
    host = host.strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in MULTI_TLDS and len(parts) >= 3:
        return last3
    return last2


def parse_target(raw):
    """
    Normalise arbitrary analyst input into a structured target.

    Returns dict: {ok, error, kind, input, normalized, domain, url, email,
                   local_part, registrable, subdomain}
    """
    result = {
        "ok": False, "error": None, "kind": None, "input": raw,
        "normalized": None, "domain": None, "url": None, "email": None,
        "local_part": None, "registrable": None, "subdomain": False,
    }
    if not raw or not isinstance(raw, str):
        result["error"] = "Empty input."
        return result

    raw = raw.strip()
    if len(raw) > 2048:
        result["error"] = "Input too long."
        return result

    value = refang(raw)

    # Reject obvious header-injection / control characters.
    if any(c in value for c in ("\r", "\n", "\0", " ")) and "@" not in value:
        value = value.split()[0] if value.split() else value
    if any(c in value for c in ("\r", "\n", "\0")):
        result["error"] = "Illegal control characters in input."
        return result

    kind = None
    domain = None
    url = None
    email = None
    local_part = None

    if "@" in value and "/" not in value.split("@")[-1]:
        m = _EMAIL_RE.match(value)
        if not m:
            result["error"] = "Looks like an email but is malformed."
            return result
        kind = "email"
        email = value.lower()
        local_part = value.split("@", 1)[0]
        domain = m.group(1).lower().strip(".")
    elif value.lower().startswith(("http://", "https://")) or "/" in value:
        if not value.lower().startswith(("http://", "https://")):
            value = "http://" + value
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        if not host:
            result["error"] = "Could not extract a host from the URL."
            return result
        kind = "url"
        url = value
        domain = host
    else:
        kind = "domain"
        domain = value.lower().strip(".")

    # Validate the extracted domain — unless it's a bare IP target.
    is_ip = False
    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except ValueError:
        pass

    if not is_ip and not _DOMAIN_RE.match(domain):
        # Allow IDN/punycode that the regex might reject; try idna encode.
        try:
            domain.encode("idna")
        except Exception:
            result["error"] = f"'{domain}' is not a valid domain."
            return result

    reg = registrable_domain(domain) if not is_ip else domain
    result.update({
        "ok": True, "kind": kind, "normalized": value, "domain": domain,
        "url": url, "email": email, "local_part": local_part,
        "registrable": reg, "subdomain": (not is_ip and domain != reg),
        "is_ip": is_ip,
    })
    return result


def is_public_ip(ip):
    """SSRF guard — reject private / loopback / reserved space."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_reserved
                or addr.is_link_local or addr.is_multicast
                or addr.is_unspecified)


# --------------------------------------------------------------------------
# Individual checks
# --------------------------------------------------------------------------

def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip if is_public_ip(ip) else None
    except Exception:
        return None


def dns_lookup(name, record_type):
    data = safe_get(f"https://dns.google/resolve?name={name}&type={record_type}")
    if data and "Answer" in data:
        return [a["data"].strip('"') for a in data["Answer"] if a.get("data")]
    return []


def dns_txt_raw(name, record_type):
    """TXT lookup that preserves quoting reassembly for SPF/DMARC parsing."""
    data = safe_get(f"https://dns.google/resolve?name={name}&type={record_type}")
    out = []
    if data and "Answer" in data:
        for a in data["Answer"]:
            d = a.get("data", "")
            d = d.replace('" "', "").strip('"')
            out.append(d)
    return out


def ip_info(ip):
    if not ip:
        return None
    return safe_get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,country,countryCode,regionName,city,isp,org,as,reverse,proxy,hosting"},
    )


def check_vt_domain(domain):
    if not VT_API_KEY:
        return None
    data = safe_get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": VT_API_KEY},
    )
    return data.get("data", {}).get("attributes") if data else None


def abuseipdb(ip):
    if not ip or not ABUSEIPDB_API_KEY:
        return None
    res = safe_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
    )
    return res.get("data") if res else None


def rdap_domain(domain):
    return safe_get(f"https://rdap.org/domain/{domain}")


def urlscan_search(domain):
    """urlscan search + verdict for the most recent scan of this domain."""
    headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else None
    data = safe_get(
        "https://urlscan.io/api/v1/search/",
        headers=headers,
        params={"q": f"domain:{domain}", "size": 5},
    )
    if not data or not data.get("results"):
        return None
    results = []
    for r in data["results"][:5]:
        page = r.get("page", {}) or {}
        task = r.get("task", {}) or {}
        results.append({
            "url": page.get("url"),
            "domain": page.get("domain"),
            "submitted": task.get("url"),
            "time": task.get("time"),
            "screenshot": r.get("screenshot"),
            "result": r.get("result"),
            "uuid": r.get("_id"),
        })

    # Pull the overall verdict for the most recent scan.
    verdict = None
    top_uuid = results[0].get("uuid") if results else None
    if top_uuid:
        detail = safe_get(
            f"https://urlscan.io/api/v1/result/{top_uuid}/", headers=headers, timeout=10
        )
        if detail and isinstance(detail.get("verdicts"), dict):
            overall = detail["verdicts"].get("overall", {})
            verdict = {
                "malicious": overall.get("malicious", False),
                "score": overall.get("score", 0),
                "brands": [b.get("name") for b in overall.get("brands", []) if b.get("name")],
                "categories": overall.get("categories", []),
            }

    # Where did the most recent scan actually land? (off-domain redirect = red flag)
    top = results[0]
    final_domain = top.get("domain")
    if not final_domain and top.get("url"):
        try:
            final_domain = urlparse(top["url"]).hostname
        except Exception:
            final_domain = None

    return {
        "count": data.get("total", len(results)),
        "results": results,
        "verdict": verdict,
        "final_url": top.get("url"),
        "final_domain": final_domain,
    }


def urlscan_submit(target_url):
    """Submit a fresh urlscan.io scan. Returns {uuid} or {error}."""
    if not URLSCAN_API_KEY:
        return {"error": "Live scan needs URLSCAN_API_KEY (not configured)."}
    try:
        r = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json",
                     "User-Agent": USER_AGENT},
            json={"url": target_url, "visibility": "unlisted"},
            timeout=15,
        )
        if r.status_code == 200:
            return {"uuid": r.json().get("uuid")}
        if r.status_code == 400:
            return {"error": "urlscan rejected the URL (blacklisted or invalid)."}
        if r.status_code == 429:
            return {"error": "urlscan rate limit hit — try again shortly."}
        return {"error": f"urlscan submit failed ({r.status_code})."}
    except Exception:
        return {"error": "Could not reach urlscan.io."}


def urlscan_result(uuid, queried_reg=None):
    """Poll a urlscan result. Returns {ready:False} until the scan finishes."""
    headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else None
    detail = safe_get(f"https://urlscan.io/api/v1/result/{uuid}/", headers=headers, timeout=10)
    if not detail:
        return {"ready": False}
    page = detail.get("page", {}) or {}
    task = detail.get("task", {}) or {}
    overall = (detail.get("verdicts", {}) or {}).get("overall", {})
    final_domain = page.get("domain")
    if not final_domain and page.get("url"):
        try:
            final_domain = urlparse(page["url"]).hostname
        except Exception:
            final_domain = None
    out = {
        "ready": True,
        "verdict": {
            "malicious": overall.get("malicious", False),
            "score": overall.get("score", 0),
            "brands": [b.get("name") for b in overall.get("brands", []) if b.get("name")],
            "categories": overall.get("categories", []),
        },
        "final_url": page.get("url"),
        "final_domain": final_domain,
        "screenshot": task.get("screenshotURL") or f"https://urlscan.io/screenshots/{uuid}.png",
        "result": task.get("reportURL") or f"https://urlscan.io/result/{uuid}/",
        "time": task.get("time"),
    }
    if final_domain and queried_reg:
        fr = registrable_domain(final_domain)
        if fr and fr != queried_reg:
            out["redirect"] = {"offsite": True, "to_host": final_domain,
                               "to_reg": fr, "final_url": page.get("url")}
    return out


def scan_url_for(raw_input):
    """Resolve arbitrary analyst input into a URL suitable for live scanning."""
    parsed = parse_target(raw_input)
    if not parsed["ok"]:
        return None, None
    if parsed["kind"] == "url":
        return parsed["url"], parsed["registrable"]
    return f"https://{parsed['domain']}", parsed["registrable"]


def crtsh(domain):
    """Subdomain / certificate enumeration via crt.sh (free, no key)."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": USER_AGENT}, timeout=12,
        )
        if r.status_code != 200:
            return None
        rows = r.json()
    except Exception:
        return None
    subs = set()
    for row in rows:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain):
                subs.add(name)
    subs.discard(domain)
    return {"count": len(subs), "subdomains": sorted(subs)[:40]}


def check_dkim(domain):
    """Probe common DKIM selectors; report which publish a key."""
    found = []
    for sel in DKIM_SELECTORS:
        recs = dns_txt_raw(f"{sel}._domainkey.{domain}", "TXT")
        if any("p=" in r or "v=DKIM1" in r for r in recs):
            found.append(sel)
        cname = dns_lookup(f"{sel}._domainkey.{domain}", "CNAME")
        if cname and sel not in found:
            found.append(sel)
    return found


# --------------------------------------------------------------------------
# Derived intelligence
# --------------------------------------------------------------------------

def domain_age(rdap):
    """Return (age_days, registration_date_str) from RDAP events."""
    if not rdap or not rdap.get("events"):
        return None, None
    reg = None
    for e in rdap["events"]:
        if e.get("eventAction") == "registration":
            reg = e.get("eventDate")
            break
    if not reg:
        return None, None
    try:
        d = reg.replace("Z", "+00:00")
        reg_dt = dt.datetime.fromisoformat(d)
        if reg_dt.tzinfo is None:
            reg_dt = reg_dt.replace(tzinfo=dt.timezone.utc)
        now = dt.datetime.now(dt.timezone.utc)
        return (now - reg_dt).days, reg
    except Exception:
        return None, reg


def rdap_events(rdap):
    if not rdap or not rdap.get("events"):
        return {}
    return {e.get("eventAction"): e.get("eventDate") for e in rdap["events"]}


def rdap_registrar(rdap):
    if not rdap:
        return None
    for ent in rdap.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            for v in ent.get("vcardArray", [[], []])[1]:
                if v and v[0] == "fn":
                    return v[3]
    return None


def parse_spf(txt_records):
    for r in txt_records:
        if r.lower().startswith("v=spf1"):
            policy = "neutral"
            if r.strip().endswith("-all"):
                policy = "hard fail (-all)"
            elif r.strip().endswith("~all"):
                policy = "soft fail (~all)"
            elif "?all" in r:
                policy = "neutral (?all)"
            elif "+all" in r:
                policy = "pass-all (+all) — dangerous"
            return {"record": r, "policy": policy}
    return None


def parse_dmarc(dmarc_records):
    for r in dmarc_records:
        if r.lower().startswith("v=dmarc1"):
            tags = {}
            for part in r.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    tags[k.strip().lower()] = v.strip()
            return {
                "record": r,
                "policy": tags.get("p", "none"),
                "subdomain_policy": tags.get("sp"),
                "pct": tags.get("pct", "100"),
                "rua": tags.get("rua"),
            }
    return None


def identify_mx_provider(mx_records):
    blob = " ".join(mx_records).lower()
    for needle, label in MX_PROVIDERS:
        if needle in blob:
            return label
    return "Unknown / self-hosted" if mx_records else None


def _levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_check(registrable):
    """Detect typosquats / homographs of common impersonation targets."""
    flags = []
    name = registrable.lower()

    # Punycode / IDN homograph
    if "xn--" in name:
        flags.append({
            "type": "punycode",
            "detail": "Internationalized (punycode) domain — homograph risk.",
            "severity": "high",
        })

    # Near-miss of a known brand (edit distance 1-2, but not an exact match)
    for target in COMMON_TARGETS:
        if name == target:
            return {"exact_brand": target, "flags": flags}
        dist = _levenshtein(name, target)
        if 0 < dist <= 2 and abs(len(name) - len(target)) <= 3:
            flags.append({
                "type": "typosquat",
                "detail": f"Edit distance {dist} from '{target}'.",
                "severity": "high",
            })
        # Brand embedded as substring but not the real domain
        brand = target.split(".")[0]
        if len(brand) >= 5 and brand in name and not name.startswith(brand + "."):
            flags.append({
                "type": "brand-in-name",
                "detail": f"Contains brand '{brand}' but is not {target}.",
                "severity": "medium",
            })
    # de-dupe
    seen = set()
    uniq = []
    for f in flags:
        key = (f["type"], f["detail"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return {"exact_brand": None, "flags": uniq}


# --------------------------------------------------------------------------
# Verdict engine
# --------------------------------------------------------------------------

def score(result):
    """Weighted risk scoring → verdict + reasons + BEC tags."""
    pts = 0
    reasons = []
    bec = []

    vt = result.get("vt")
    if vt:
        s = vt.get("last_analysis_stats", {})
        mal, susp = s.get("malicious", 0), s.get("suspicious", 0)
        if mal >= 5:
            pts += 45; reasons.append(f"VirusTotal: {mal} engines flag malicious")
        elif mal >= 1:
            pts += 22; reasons.append(f"VirusTotal: {mal} malicious / {susp} suspicious")
        elif susp > 2:
            pts += 10; reasons.append(f"VirusTotal: {susp} suspicious")

    abuse = result.get("abuse")
    if abuse:
        sc = abuse.get("abuseConfidenceScore", 0)
        if sc >= 50:
            pts += 30; reasons.append(f"AbuseIPDB confidence {sc}/100")
        elif sc >= 20:
            pts += 14; reasons.append(f"AbuseIPDB confidence {sc}/100")

    age_days = result.get("age_days")
    if age_days is not None:
        if age_days < 30:
            pts += 28
            reasons.append(f"Newly registered domain ({age_days}d old)")
            bec.append("Newly registered domain")
        elif age_days < 90:
            pts += 14
            reasons.append(f"Young domain ({age_days}d old)")
            bec.append("Young domain (<90d)")

    dmarc = result.get("dmarc_parsed")
    if dmarc is None:
        pts += 14
        reasons.append("No DMARC record — spoofable")
        bec.append("No DMARC (spoofable)")
    elif dmarc.get("policy", "none").lower() == "none":
        pts += 8
        reasons.append("DMARC p=none — not enforced")
        bec.append("DMARC not enforced (p=none)")

    if result.get("spf_parsed") is None and result.get("kind") != "url":
        pts += 6
        reasons.append("No SPF record")
        bec.append("No SPF")

    tld = result.get("registrable", "").rsplit(".", 1)[-1]
    if tld in HIGH_RISK_TLDS:
        pts += 12; reasons.append(f"High-abuse TLD (.{tld})")

    look = result.get("lookalike", {})
    for f in look.get("flags", []):
        if f["severity"] == "high":
            pts += 22; reasons.append(f["detail"]); bec.append(f["detail"])
        elif f["severity"] == "medium":
            pts += 10; reasons.append(f["detail"])

    if result.get("disposable"):
        pts += 16; reasons.append("Disposable / throwaway email domain")
        bec.append("Disposable email domain")
    elif result.get("freemail") and result.get("kind") == "email":
        pts += 4; reasons.append("Free consumer mail provider")

    us = result.get("urlscan")
    if us and us.get("redirect", {}).get("offsite"):
        pts += 28
        to_reg = us["redirect"]["to_reg"]
        reasons.append(f"Redirects off-domain to {to_reg} (not {result.get('registrable')})")
        bec.append(f"Off-domain redirect → {to_reg}")
    if us and us.get("verdict"):
        uv = us["verdict"]
        if uv.get("malicious"):
            pts += 30
            brands = ", ".join(uv.get("brands", [])) if uv.get("brands") else ""
            reasons.append("urlscan: malicious verdict" + (f" (impersonates {brands})" if brands else ""))
            if brands:
                bec.append(f"urlscan brand impersonation: {brands}")
        elif uv.get("score", 0) > 0:
            pts += 12; reasons.append(f"urlscan risk score {uv['score']}")

    info = result.get("info")
    if info and info.get("status") == "success":
        if info.get("proxy"):
            pts += 8; reasons.append("IP flagged as proxy/VPN/Tor")

    pts = min(pts, 100)
    if pts >= 60:
        verdict = "Likely Malicious"
    elif pts >= 30:
        verdict = "Suspicious"
    elif pts >= 12:
        verdict = "Low–Moderate"
    else:
        verdict = "Likely Legitimate"

    return {"score": pts, "verdict": verdict, "reasons": reasons, "bec": bec}


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

def analyze(raw_input):
    parsed = parse_target(raw_input)
    if not parsed["ok"]:
        return {"ok": False, "error": parsed["error"], "input": raw_input}

    domain = parsed["domain"]
    is_ip = parsed.get("is_ip", False)

    # Resolve first (other lookups need the IP).
    ip = domain if is_ip else resolve_ip(domain)

    futures = {
        "a":     _executor.submit(dns_lookup, domain, "A"),
        "aaaa":  _executor.submit(dns_lookup, domain, "AAAA"),
        "mx":    _executor.submit(dns_lookup, domain, "MX"),
        "ns":    _executor.submit(dns_lookup, domain, "NS"),
        "cname": _executor.submit(dns_lookup, domain, "CNAME"),
        "soa":   _executor.submit(dns_lookup, domain, "SOA"),
        "txt":   _executor.submit(dns_txt_raw, domain, "TXT"),
        "dmarc": _executor.submit(dns_txt_raw, f"_dmarc.{domain}", "TXT"),
        "vt":    _executor.submit(check_vt_domain, domain),
        "rdap":  _executor.submit(rdap_domain, parsed["registrable"]),
        "info":  _executor.submit(ip_info, ip),
        "abuse": _executor.submit(abuseipdb, ip),
        "urlscan": _executor.submit(urlscan_search, domain),
        "crtsh": _executor.submit(crtsh, parsed["registrable"]),
        "dkim":  _executor.submit(check_dkim, domain),
    }
    res = {k: f.result() for k, f in futures.items()}

    age_days, reg_date = domain_age(res["rdap"])
    spf = parse_spf(res["txt"])
    dmarc = parse_dmarc(res["dmarc"])
    look = lookalike_check(parsed["registrable"])
    reg_dom = parsed["registrable"]

    # Off-domain redirect detection: did the scanned page land on an unrelated domain?
    us = res["urlscan"]
    if us and us.get("final_domain"):
        final_reg = registrable_domain(us["final_domain"])
        if final_reg and final_reg != reg_dom:
            us["redirect"] = {
                "offsite": True,
                "to_host": us["final_domain"],
                "to_reg": final_reg,
                "final_url": us.get("final_url"),
            }

    result = {
        "ok": True,
        "kind": parsed["kind"],
        "input": raw_input,
        "domain": domain,
        "registrable": reg_dom,
        "email": parsed["email"],
        "url": parsed["url"],
        "ip": ip,
        "is_ip": is_ip,
        "defanged": defang(parsed["normalized"]),
        # raw data
        "a": res["a"], "aaaa": res["aaaa"], "mx": res["mx"],
        "ns": res["ns"], "cname": res["cname"], "soa": res["soa"],
        "txt": res["txt"], "dmarc": res["dmarc"],
        "vt": res["vt"], "rdap_events": rdap_events(res["rdap"]),
        "registrar": rdap_registrar(res["rdap"]),
        "info": res["info"], "abuse": res["abuse"],
        "urlscan": res["urlscan"], "crtsh": res["crtsh"],
        "dkim": res["dkim"],
        # derived
        "age_days": age_days, "registered": reg_date,
        "spf_parsed": spf, "dmarc_parsed": dmarc,
        "mx_provider": identify_mx_provider(res["mx"]),
        "lookalike": look,
        "high_risk_tld": reg_dom.rsplit(".", 1)[-1] in HIGH_RISK_TLDS,
        "freemail": reg_dom in FREEMAIL_DOMAINS,
        "disposable": reg_dom in DISPOSABLE_DOMAINS,
    }

    result.update(score(result))
    result["ticket_summary"] = build_summary(result)
    return result


def build_summary(r):
    """Analyst-ready, copy-paste block (defanged) for case notes."""
    lines = []
    lines.append(f"IOC:      {r['defanged']}  ({r['kind']})")
    lines.append(f"Verdict:  {r['verdict']}  (risk {r['score']}/100)")
    if r.get("ip"):
        loc = r.get("info") or {}
        where = f"{loc.get('country','?')} · {loc.get('org') or loc.get('isp','?')}"
        lines.append(f"Hosting:  {defang(r['ip'])}  [{where}]")
    if r.get("registered"):
        age = r.get("age_days")
        lines.append(f"Domain:   registered {r['registered'][:10]}"
                     + (f" ({age}d old)" if age is not None else ""))
    if r.get("mx_provider"):
        lines.append(f"Mail:     {r['mx_provider']}")
    dmarc = r.get("dmarc_parsed")
    lines.append(f"DMARC:    {('p=' + dmarc['policy']) if dmarc else 'MISSING'}"
                 f"  |  SPF: {'present' if r.get('spf_parsed') else 'MISSING'}"
                 f"  |  DKIM: {', '.join(r['dkim']) if r.get('dkim') else 'none found'}")
    if r.get("bec"):
        lines.append("BEC flags: " + "; ".join(r["bec"]))
    if r.get("reasons"):
        lines.append("Signals:  " + " | ".join(r["reasons"]))
    return "\n".join(lines)
