"""
osintsk4n analysis engine
==========================
SOC-oriented triage for domains, URLs and email addresses. Built to sit
alongside Mimecast / CrowdStrike Falcon for spam / malware / BEC triage.

Pure stdlib + requests so it cold-starts cleanly on Render's free tier.
"""

import os
import re
import html
import time
import socket
import ipaddress
import datetime as dt
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor

import requests

VT_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
ABUSECH_API_KEY = os.environ.get("ABUSECH_API_KEY", "")
GSB_API_KEY = os.environ.get("GSB_API_KEY", "")
EMAILREP_API_KEY = os.environ.get("EMAILREP_API_KEY", "")
IPQS_API_KEY = os.environ.get("IPQS_API_KEY", "")

USER_AGENT = "osintsk4n/2.0 (SOC triage)"
_executor = ThreadPoolExecutor(max_workers=16)

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


ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def abuseipdb(ip, verbose=False):
    """AbuseIPDB /check. verbose=True also returns recent report detail so we can
    surface the top abuse categories the IP has been reported for."""
    if not ip or not ABUSEIPDB_API_KEY:
        return None
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    if verbose:
        params["verbose"] = ""
    res = safe_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params=params,
    )
    data = res.get("data") if res else None
    if not data:
        return None
    if verbose and data.get("reports"):
        counts = {}
        for rep in data["reports"]:
            for cid in (rep.get("categories") or []):
                counts[cid] = counts.get(cid, 0) + 1
        top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:6]
        data["top_categories"] = [ABUSE_CATEGORIES.get(c, f"cat{c}") for c, _ in top]
        data.pop("reports", None)   # drop the bulky raw array; we keep the summary
    return data


def check_vt_ip(ip):
    """VirusTotal IP-address endpoint — reputation, ASN/owner, country, network."""
    if not ip or not VT_API_KEY:
        return None
    data = safe_get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VT_API_KEY},
    )
    a = data.get("data", {}).get("attributes") if data else None
    if not a:
        return None
    return {
        "last_analysis_stats": a.get("last_analysis_stats", {}),
        "reputation": a.get("reputation"),
        "as_owner": a.get("as_owner"),
        "asn": a.get("asn"),
        "country": a.get("country"),
        "network": a.get("network"),
        "tags": a.get("tags") or [],
    }


def rdap_domain(domain):
    return safe_get(f"https://rdap.org/domain/{domain}")


def urlscan_search(domain):
    """urlscan search + verdict for the most recent scan of this domain."""
    headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else None
    # task.domain = the domain actually SUBMITTED for scanning (not every domain the
    # page merely contacted) — avoids matching unrelated scans that just loaded our
    # domain as a third-party resource, which produced bogus "redirect" findings.
    data = safe_get(
        "https://urlscan.io/api/v1/search/",
        headers=headers,
        params={"q": f"task.domain:{domain}", "size": 5},
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


# --------------------------------------------------------------------------
# Threat-intel enrichment (history + actor correlation)
# --------------------------------------------------------------------------

def otx_lookup(domain):
    """AlienVault OTX — community 'pulses' tying an indicator to campaigns/actors/malware."""
    if not domain:
        return None
    headers = {"User-Agent": USER_AGENT}
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY
    data = safe_get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
        headers=headers, timeout=10,
    )
    if not data:
        return None
    pi = data.get("pulse_info") or {}
    pulses = pi.get("pulses") or []
    families, adversaries, tags, names = set(), set(), set(), []
    for p in pulses[:25]:
        if p.get("name"):
            names.append(p["name"])
        for mf in (p.get("malware_families") or []):
            nm = (mf.get("display_name") or mf.get("id")) if isinstance(mf, dict) else mf
            if nm:
                families.add(nm)
        if p.get("adversary"):
            adversaries.add(p["adversary"])
        for t in (p.get("tags") or []):
            tags.add(t)
    return {
        "pulse_count": pi.get("count", len(pulses)),
        "pulses": names[:6],
        "malware_families": sorted(families)[:8],
        "adversaries": sorted(adversaries)[:6],
        "tags": sorted(tags)[:10],
    }


def otx_ip(ip):
    """OTX IPv4 — threat pulses (actors/malware). (passive DNS comes from VT — more reliable)"""
    if not ip:
        return None
    headers = {"User-Agent": USER_AGENT}
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY
    gen = safe_get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers=headers, timeout=9,
    )
    if not gen:
        return None
    families, adversaries, tags, names = set(), set(), set(), []
    pi = gen.get("pulse_info") or {}
    for p in (pi.get("pulses") or [])[:25]:
        if p.get("name"):
            names.append(p["name"])
        for mf in (p.get("malware_families") or []):
            nm = (mf.get("display_name") or mf.get("id")) if isinstance(mf, dict) else mf
            if nm:
                families.add(nm)
        if p.get("adversary"):
            adversaries.add(p["adversary"])
        for t in (p.get("tags") or []):
            tags.add(t)
    return {
        "pulse_count": pi.get("count", 0),
        "pulses": names[:6],
        "malware_families": sorted(families)[:8],
        "adversaries": sorted(adversaries)[:6],
        "tags": sorted(tags)[:10],
    }


def _epoch_to_date(ts):
    try:
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return ""


def vt_ip_resolutions(ip):
    """Passive DNS via VirusTotal — domains that have resolved to this IP (uses VT key)."""
    if not ip or not VT_API_KEY:
        return None
    data = safe_get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions",
        headers={"x-apikey": VT_API_KEY}, params={"limit": 40},
    )
    if not data or not data.get("data"):
        return None
    recs = []
    for item in data["data"]:
        a = item.get("attributes") or {}
        h = a.get("host_name")
        if h:
            recs.append({"hostname": h, "date": _epoch_to_date(a.get("date"))})
    if not recs:
        return None
    return {"count": data.get("meta", {}).get("count", len(recs)), "records": recs}


def rdap_ip(ip):
    """RDAP for an IP — network allocation, CIDR, org, abuse contact."""
    data = safe_get(f"https://rdap.org/ip/{ip}", timeout=10)
    if not data:
        return None
    cidr = None
    for c in (data.get("cidr0_cidrs") or []):
        pfx = c.get("v4prefix") or c.get("v6prefix")
        if pfx:
            cidr = f"{pfx}/{c.get('length')}"
            break
    org, abuse = None, None
    for ent in (data.get("entities") or []):
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray", [[], []])
        fn = None
        for v in (vcard[1] if len(vcard) > 1 else []):
            if v and v[0] == "fn":
                fn = v[3]
            if v and v[0] == "email" and "abuse" in str(v[3]).lower():
                abuse = v[3]
        if fn and ("registrant" in roles or "administrative" in roles) and not org:
            org = fn
        # nested abuse contact
        for sub in (ent.get("entities") or []):
            if "abuse" in sub.get("roles", []):
                for v in (sub.get("vcardArray", [[], []])[1] if len(sub.get("vcardArray", [])) > 1 else []):
                    if v and v[0] == "email":
                        abuse = v[3]
    return {
        "name": data.get("name"),
        "handle": data.get("handle"),
        "cidr": cidr,
        "range": f"{data.get('startAddress','?')} – {data.get('endAddress','?')}",
        "country": data.get("country"),
        "org": org,
        "abuse_contact": abuse,
    }


def reverse_dns(ip):
    """PTR (reverse DNS) lookup for an IP via DoH."""
    if not ip:
        return None
    try:
        octets = ip.split(".")
        if len(octets) == 4:
            name = ".".join(reversed(octets)) + ".in-addr.arpa"
            recs = dns_lookup(name, "PTR")
            return recs[0].rstrip(".") if recs else None
    except Exception:
        return None
    return None


def _ioc_host(value):
    """Extract the host from a ThreatFox IOC value (url, domain, ip:port)."""
    if not value:
        return ""
    v = value.lower().strip()
    if "://" in v:
        v = urlparse(v).hostname or v
    v = v.split("/")[0]   # strip any path
    v = v.split(":")[0]   # strip any port
    return v


def threatfox_lookup(ioc, registrable=None):
    """abuse.ch ThreatFox — is this EXACT host a known malware/C2 IOC?
    ThreatFox search is substring-ish, so we filter to exact-host matches to avoid
    false-flagging legitimate infra that malware merely abuses (e.g. drive.google.com)."""
    if not ioc:
        return None
    headers = {"User-Agent": USER_AGENT}
    if ABUSECH_API_KEY:
        headers["Auth-Key"] = ABUSECH_API_KEY
    try:
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                          json={"query": "search_ioc", "search_term": ioc},
                          headers=headers, timeout=10)
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None
    if d.get("query_status") != "ok" or not d.get("data"):
        return {"found": False}

    target = (ioc or "").lower()
    reg = (registrable or "").lower()
    rows = [row for row in d["data"]
            if _ioc_host(row.get("ioc")) in (target, reg) and (target or reg)]
    if not rows:
        return {"found": False}

    fams, tags, first = set(), set(), None
    for row in rows[:10]:
        if row.get("malware_printable"):
            fams.add(row["malware_printable"])
        for t in (row.get("tags") or []):
            tags.add(t)
        if row.get("first_seen") and not first:
            first = row["first_seen"]
    return {"found": True, "count": len(rows), "malware": sorted(fams)[:6],
            "tags": sorted(tags)[:8], "first_seen": first,
            "confidence": rows[0].get("confidence_level")}


def urlhaus_host(host):
    """abuse.ch URLhaus — known malware-distribution host lookup."""
    if not host:
        return None
    headers = {"User-Agent": USER_AGENT}
    if ABUSECH_API_KEY:
        headers["Auth-Key"] = ABUSECH_API_KEY
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                          data={"host": host}, headers=headers, timeout=10)
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None
    qs = d.get("query_status")
    if qs == "no_results":
        return {"found": False}
    if qs != "ok":
        return None
    urls = d.get("urls") or []
    return {"found": True, "url_count": d.get("url_count") or len(urls),
            "threats": sorted({u.get("threat") for u in urls if u.get("threat")}),
            "urls": [u.get("url") for u in urls[:5] if u.get("url")]}


def shodan_internetdb(ip):
    """Shodan InternetDB (free, no key) — open ports, CVEs, tags for an IP."""
    if not ip:
        return None
    data = safe_get(f"https://internetdb.shodan.io/{ip}", timeout=8)
    if not data:
        return None
    return {"ports": data.get("ports") or [], "vulns": data.get("vulns") or [],
            "tags": data.get("tags") or [], "hostnames": data.get("hostnames") or [],
            "cpes": data.get("cpes") or []}


def greynoise_lookup(ip):
    """GreyNoise Community (free) — benign scanner vs malicious noise classification.
    Note: returns HTTP 404 (with a useful JSON body) when an IP hasn't been observed."""
    if not ip:
        return None
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}",
                         headers={"User-Agent": USER_AGENT, "Accept": "application/json"}, timeout=8)
        if r.status_code not in (200, 404):
            return None
        data = r.json()
    except Exception:
        return None
    if not data:
        return None
    if data.get("classification"):
        return {"observed": True, "noise": data.get("noise"), "riot": data.get("riot"),
                "classification": data.get("classification"), "name": data.get("name"),
                "last_seen": data.get("last_seen")}
    return {"observed": False, "message": data.get("message")}


def safebrowsing(url):
    """Google Safe Browsing — authoritative malware/phishing verdict for a URL."""
    if not GSB_API_KEY or not url:
        return None
    body = {
        "client": {"clientId": "sc4n", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
            json=body, headers={"User-Agent": USER_AGENT}, timeout=10)
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None
    matches = d.get("matches") or []
    if not matches:
        return {"flagged": False}
    return {"flagged": True, "threats": sorted({m.get("threatType") for m in matches if m.get("threatType")})}


def ipqs_email(email):
    """IPQualityScore — email fraud/reputation (fraud score, abuse, breach leak, disposable…)."""
    if not email or not IPQS_API_KEY:
        return None
    data = safe_get(
        f"https://www.ipqualityscore.com/api/json/email/{IPQS_API_KEY}/{quote(email)}",
        params={"timeout": 7, "fast": "true"}, timeout=12,
    )
    if not data or data.get("success") is False:
        return None

    def _human(v):
        return v.get("human") if isinstance(v, dict) else v

    return {
        "fraud_score": data.get("fraud_score"),
        "deliverability": data.get("deliverability"),
        "valid": data.get("valid"),
        "disposable": data.get("disposable"),
        "recent_abuse": data.get("recent_abuse"),
        "leaked": data.get("leaked"),
        "honeypot": data.get("honeypot"),
        "spam_trap_score": data.get("spam_trap_score"),
        "frequent_complainer": data.get("frequent_complainer"),
        "suspect": data.get("suspect"),
        "catch_all": data.get("catch_all"),
        "dns_valid": data.get("dns_valid"),
        "domain_age": _human(data.get("domain_age")),
        "first_seen": _human(data.get("first_seen")),
    }


def disify_email(email):
    """Disify (free, no key, no signup) — email validity, disposable, MX/DNS, freemail, role."""
    if not email:
        return None
    data = safe_get(f"https://disify.com/api/email/{quote(email)}", timeout=8)
    if not data:
        return None
    return {
        "format": data.get("format"),
        "disposable": data.get("disposable"),
        "dns": data.get("dns"),
        "free": data.get("free"),
        "role": data.get("role"),
        "whitelist": data.get("whitelist"),
        "confidence": data.get("confidence"),
        "signals": data.get("signals") or [],
        "mx_info": data.get("mx_info") or [],
    }


def emailrep_lookup(email):
    """EmailRep.io — reputation of an email address (suspicious/malicious, breaches, profiles)."""
    if not email:
        return None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if EMAILREP_API_KEY:
        headers["Key"] = EMAILREP_API_KEY
    data = safe_get(f"https://emailrep.io/{email}", headers=headers, timeout=10)
    if not data or "reputation" not in data:
        return None
    det = data.get("details") or {}
    return {
        "reputation": data.get("reputation"),
        "suspicious": data.get("suspicious"),
        "references": data.get("references"),
        "blacklisted": det.get("blacklisted"),
        "malicious_activity": det.get("malicious_activity"),
        "credentials_leaked": det.get("credentials_leaked"),
        "data_breach": det.get("data_breach"),
        "spam": det.get("spam"),
        "first_seen": det.get("first_seen"),
        "last_seen": det.get("last_seen"),
        "profiles": det.get("profiles") or [],
    }


# --------------------------------------------------------------------------
# Threat news feed (header ticker) — KEV + security news, no keys
# --------------------------------------------------------------------------

_feed_cache = {"ts": 0.0, "items": []}


def _clean_text(s):
    if not s:
        return ""
    s = s.strip()
    m = re.match(r"^<!\[CDATA\[(.*?)\]\]>$", s, re.S)
    if m:
        s = m.group(1)
    s = re.sub(r"<[^>]+>", "", s)        # strip any tags
    s = html.unescape(s)                  # decode all HTML entities
    return s.strip()


def _rss_items(url, limit=4):
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0 (SC4N threat feed)"}, timeout=10)
        if r.status_code != 200:
            return []
        xml = r.text
    except Exception:
        return []
    out = []
    for block in re.findall(r"<item[ >].*?</item>", xml, re.S):
        t = re.search(r"<title>(.*?)</title>", block, re.S)
        l = re.search(r"<link>(.*?)</link>", block, re.S)
        p = re.search(r"<pubDate>(.*?)</pubDate>", block, re.S)
        title = _clean_text(t.group(1)) if t else None
        link = _clean_text(l.group(1)) if l else None
        if title and link and link.startswith("http"):
            out.append({"title": title, "url": link, "date": _clean_text(p.group(1)) if p else ""})
        if len(out) >= limit:
            break
    return out


def _kev_items(limit=4):
    data = safe_get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout=12,
    )
    if not data or not data.get("vulnerabilities"):
        return []
    vulns = sorted(data["vulnerabilities"], key=lambda x: x.get("dateAdded", ""), reverse=True)[:limit]
    out = []
    for v in vulns:
        title = f"{v.get('vendorProject','')} {v.get('product','')}: {v.get('vulnerabilityName','')}".strip()
        out.append({
            "kind": "kev", "cve": v.get("cveID"), "title": title,
            "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
            "date": v.get("dateAdded", ""), "source": "CISA KEV",
        })
    return out


def threat_news():
    """Aggregated SOC morning brief: actively-exploited CVEs + breaking news.
    Cached 30 min so page loads never wait on or hammer the upstreams."""
    now = time.time()
    if _feed_cache["items"] and (now - _feed_cache["ts"] < 1800):
        return _feed_cache["items"]
    fk = _executor.submit(_kev_items, 4)
    ft = _executor.submit(_rss_items, "https://feeds.feedburner.com/TheHackersNews", 3)
    fr = _executor.submit(_rss_items, "https://krebsonsecurity.com/feed/", 2)
    kev = fk.result()
    thn = [{**i, "kind": "news", "source": "The Hacker News"} for i in ft.result()]
    krebs = [{**i, "kind": "news", "source": "Krebs on Security"} for i in fr.result()]
    # interleave KEV first (most actionable), then news
    items = kev + thn + krebs
    if items:
        _feed_cache["ts"] = now
        _feed_cache["items"] = items
    return items


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

def _verdict_from(pts):
    pts = min(pts, 100)
    if pts >= 60:
        return pts, "Likely Malicious"
    if pts >= 30:
        return pts, "Suspicious"
    if pts >= 12:
        return pts, "Low–Moderate"
    return pts, "Likely Legitimate"


def score_ip(result):
    """IP-specific scoring — reputation/threat signals only, no domain/email concepts."""
    pts, reasons = 0, []
    abuse = result.get("abuse")
    if abuse:
        sc = abuse.get("abuseConfidenceScore", 0)
        if sc >= 50:
            pts += 35; reasons.append(f"AbuseIPDB confidence {sc}/100")
        elif sc >= 20:
            pts += 16; reasons.append(f"AbuseIPDB confidence {sc}/100")
        if abuse.get("isTor"):
            pts += 5; reasons.append("Tor exit node")
        cats = abuse.get("top_categories") or []
        if cats:
            reasons.append("AbuseIPDB reports: " + ", ".join(cats[:3]))
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
    tf = result.get("threatfox")
    if tf and tf.get("found"):
        fam = ", ".join(tf.get("malware") or [])
        pts += 35; reasons.append("ThreatFox: known malicious IOC" + (f" ({fam})" if fam else ""))
    uh = result.get("urlhaus")
    if uh and uh.get("found"):
        pts += 30; reasons.append(f"URLhaus: hosts known malware ({uh.get('url_count','?')} URLs)")
    otx = result.get("otx")
    if otx and otx.get("pulse_count", 0) > 0:
        named = (otx.get("malware_families") or []) + (otx.get("adversaries") or [])
        if named:
            pts += 20; reasons.append(f"AlienVault OTX: {otx['pulse_count']} reports ({', '.join(named[:3])})")
        else:
            pts += 8; reasons.append(f"AlienVault OTX: {otx['pulse_count']} community reports")
    gn = result.get("greynoise")
    if gn and gn.get("observed") and gn.get("classification") == "malicious":
        pts += 15; reasons.append("GreyNoise: classified malicious")
    info = result.get("info")
    if info and info.get("status") == "success" and info.get("proxy"):
        pts += 8; reasons.append("Flagged as proxy / VPN / Tor")
    pts, verdict = _verdict_from(pts)
    return {"score": pts, "verdict": verdict, "reasons": reasons, "bec": []}


def score(result):
    """Weighted risk scoring → verdict + reasons + BEC tags."""
    if result.get("is_ip"):
        return score_ip(result)
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

    gsb = result.get("gsb")
    if gsb and gsb.get("flagged"):
        pts += 40
        reasons.append("Google Safe Browsing: " + ", ".join(gsb.get("threats") or ["flagged"]))
        bec.append("Google Safe Browsing hit")

    tf = result.get("threatfox")
    if tf and tf.get("found"):
        pts += 35
        fam = ", ".join(tf.get("malware") or [])
        reasons.append("ThreatFox: known malicious IOC" + (f" ({fam})" if fam else ""))
        bec.append("ThreatFox known IOC")

    uh = result.get("urlhaus")
    if uh and uh.get("found"):
        pts += 35
        reasons.append(f"URLhaus: known malware host ({uh.get('url_count', '?')} URLs)")
        bec.append("URLhaus malware host")

    otx = result.get("otx")
    if otx and otx.get("pulse_count", 0) > 0:
        named = (otx.get("malware_families") or []) + (otx.get("adversaries") or [])
        if named:
            pts += 20
            reasons.append(f"AlienVault OTX: {otx['pulse_count']} reports ({', '.join(named[:3])})")
            bec.append("OTX threat reports")
        else:
            pts += 10
            reasons.append(f"AlienVault OTX: {otx['pulse_count']} community threat reports")

    gn = result.get("greynoise")
    if gn and gn.get("observed") and gn.get("classification") == "malicious":
        pts += 15
        reasons.append("GreyNoise: source IP classified malicious")

    dis = result.get("disify")
    if dis:
        sig = dis.get("signals") or []
        if dis.get("disposable") and not result.get("disposable"):
            pts += 12; reasons.append("Disposable/temporary email domain (Disify)"); bec.append("Disposable email domain")
        if dis.get("dns") is False:
            pts += 8; reasons.append("Email domain has no MX records (cannot receive mail)")
        if "high_entropy" in sig:
            pts += 8; reasons.append("Email domain looks algorithmically generated (high entropy)")

    iq = result.get("ipqs")
    if iq:
        fs = iq.get("fraud_score") or 0
        if iq.get("recent_abuse") or fs >= 85:
            pts += 25
            reasons.append(f"IPQS: recent abuse / high fraud score ({fs})")
            bec.append("IPQS high fraud/abuse")
        elif fs >= 60:
            pts += 14; reasons.append(f"IPQS fraud score {fs}")
        if iq.get("honeypot") or iq.get("spam_trap_score") in ("high", "medium"):
            pts += 10; reasons.append("IPQS: spam-trap / honeypot indicators")
        if iq.get("disposable") and not result.get("disposable"):
            pts += 12; reasons.append("IPQS: disposable/temporary email")
        if iq.get("leaked"):
            reasons.append("IPQS: address found in data breaches")

    er = result.get("emailrep")
    if er:
        if er.get("malicious_activity"):
            pts += 25; reasons.append("EmailRep: known malicious activity"); bec.append("EmailRep malicious activity")
        elif er.get("suspicious"):
            pts += 14; reasons.append("EmailRep: flagged suspicious")
        if er.get("credentials_leaked") or er.get("data_breach"):
            reasons.append("EmailRep: address appears in breaches/credential leaks")

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
    ip = domain if is_ip else resolve_ip(domain)

    result = _analyze_ip(parsed, ip, raw_input) if is_ip \
        else _analyze_domain(parsed, domain, ip, raw_input)

    result.update(score(result))
    result["ticket_summary"] = build_summary(result)
    return result


def _analyze_ip(parsed, ip, raw_input):
    """Dedicated IP path — correct IP endpoints, no domain/email checks."""
    futures = {
        "vt":        _executor.submit(check_vt_ip, ip),
        "passive":   _executor.submit(vt_ip_resolutions, ip),
        "abuse":     _executor.submit(abuseipdb, ip, True),
        "otx":       _executor.submit(otx_ip, ip),
        "rdap_ip":   _executor.submit(rdap_ip, ip),
        "info":      _executor.submit(ip_info, ip),
        "shodan":    _executor.submit(shodan_internetdb, ip),
        "greynoise": _executor.submit(greynoise_lookup, ip),
        "threatfox": _executor.submit(threatfox_lookup, ip, ip),
        "urlhaus":   _executor.submit(urlhaus_host, ip),
        "ptr":       _executor.submit(reverse_dns, ip),
    }
    res = {k: f.result() for k, f in futures.items()}
    return {
        "ok": True, "kind": "ip", "input": raw_input,
        "domain": ip, "registrable": ip, "ip": ip, "is_ip": True,
        "email": None, "url": None,
        "defanged": defang(parsed["normalized"]),
        "vt": res["vt"], "abuse": res["abuse"], "otx": res["otx"],
        "rdap_ip": res["rdap_ip"], "info": res["info"],
        "shodan": res["shodan"], "greynoise": res["greynoise"],
        "threatfox": res["threatfox"], "urlhaus": res["urlhaus"],
        "ptr": res["ptr"], "passive_dns": res["passive"],
    }


def _analyze_domain(parsed, domain, ip, raw_input):
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
        "otx":   _executor.submit(otx_lookup, parsed["registrable"]),
        "threatfox": _executor.submit(threatfox_lookup, domain, parsed["registrable"]),
        "urlhaus": _executor.submit(urlhaus_host, domain),
        "shodan": _executor.submit(shodan_internetdb, ip),
        "greynoise": _executor.submit(greynoise_lookup, ip),
        "gsb":   _executor.submit(safebrowsing, parsed["url"] or f"https://{domain}"),
        "emailrep": _executor.submit(emailrep_lookup, parsed["email"]),
        "ipqs":  _executor.submit(ipqs_email, parsed["email"]),
        "disify": _executor.submit(disify_email, parsed["email"]),
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
        "is_ip": False,
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
        "otx": res["otx"], "threatfox": res["threatfox"],
        "urlhaus": res["urlhaus"], "shodan": res["shodan"],
        "greynoise": res["greynoise"], "gsb": res["gsb"],
        "emailrep": res["emailrep"], "ipqs": res["ipqs"], "disify": res["disify"],
        # derived
        "age_days": age_days, "registered": reg_date,
        "spf_parsed": spf, "dmarc_parsed": dmarc,
        "mx_provider": identify_mx_provider(res["mx"]),
        "lookalike": look,
        "high_risk_tld": reg_dom.rsplit(".", 1)[-1] in HIGH_RISK_TLDS,
        "freemail": reg_dom in FREEMAIL_DOMAINS,
        "disposable": reg_dom in DISPOSABLE_DOMAINS,
    }
    return result


def build_summary(r):
    """Analyst-ready, copy-paste block (defanged) for case notes."""
    if r.get("is_ip"):
        return build_ip_summary(r)
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


def build_ip_summary(r):
    lines = []
    info = r.get("info") or {}
    ab = r.get("abuse") or {}
    lines.append(f"IOC:      {r['defanged']}  (ip)")
    lines.append(f"Verdict:  {r['verdict']}  (risk {r['score']}/100)")
    lines.append(f"Network:  {info.get('as','?')}  ·  {info.get('country','?')}"
                 f"  ·  {info.get('org') or info.get('isp','?')}")
    rip = r.get("rdap_ip") or {}
    if rip.get("cidr") or rip.get("name"):
        lines.append(f"Alloc:    {rip.get('name','?')}  {rip.get('cidr') or ''}".rstrip())
    if r.get("ptr"):
        lines.append(f"rDNS:     {r['ptr']}")
    if ab:
        extra = " · Tor" if ab.get("isTor") else ""
        lines.append(f"AbuseIPDB: {ab.get('abuseConfidenceScore',0)}/100"
                     f"  ·  {ab.get('usageType','?')}{extra}"
                     f"  ·  {ab.get('totalReports',0)} reports")
        if ab.get("top_categories"):
            lines.append("Reported: " + ", ".join(ab["top_categories"]))
    pdns = r.get("passive_dns") or {}
    if pdns.get("count"):
        lines.append(f"Passive DNS: {pdns['count']} domains have resolved here")
    if r.get("reasons"):
        lines.append("Signals:  " + " | ".join(r["reasons"]))
    return "\n".join(lines)
