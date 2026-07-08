"""
osintsk4n analysis engine
==========================
SOC-oriented triage for domains, URLs and email addresses. Built to sit
alongside Mimecast / CrowdStrike Falcon for spam / malware / BEC triage.

Pure stdlib + requests so it cold-starts cleanly on Render's free tier.
"""

import os
import re
import json
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
HYBRID_API_KEY = os.environ.get("HYBRID_API_KEY", "")
TRIAGE_API_KEY = os.environ.get("TRIAGE_API_KEY", "")

USER_AGENT = "osintsk4n/2.0 (SOC triage)"
_executor = ThreadPoolExecutor(max_workers=16)

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# TLDs commonly abused for phishing / malware
HIGH_RISK_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click",
    "country", "kim", "work", "party", "gdn", "review", "stream", "download",
    "loan", "racing", "win", "bid", "date", "faith", "science", "men",
    "cricket", "accountant", "trade", "webcam", "rest", "fit", "cam",
    "buzz", "monster", "quest", "cyou", "sbs", "lol", "live", "shop",
}

# Free / consumer mail providers — legit but unusual for a business sender
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net",
    "zoho.com", "yandex.com", "mail.com", "tutanota.com", "hey.com",
}

# Throwaway providers — strong abuse signal
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com", "trashmail.com",
    "getnada.com", "sharklasers.com", "maildrop.cc", "dispostable.com",
    "fakeinbox.com", "mintemail.com", "spamgourmet.com", "mohmal.com",
    "emailondeck.com", "burnermail.io", "mailnesia.com", "tempinbox.com",
}

# Big hosting / CDN / user-content platforms attackers abuse to host malware.
# A feed match on the bare domain shouldn't flip the verdict — judge the URL.
HOSTING_PLATFORMS = {
    # code / repos
    "github.com", "githubusercontent.com", "github.io", "gitlab.com", "bitbucket.org", "sourceforge.net",
    # cloud storage / CDN
    "amazonaws.com", "cloudfront.net", "googleapis.com", "googleusercontent.com", "gstatic.com",
    "azureedge.net", "windows.net", "azurewebsites.net", "cloudflare.com", "workers.dev", "pages.dev",
    "r2.dev", "fastly.net", "akamaihd.net", "digitaloceanspaces.com", "backblazeb2.com", "wasabisys.com",
    # file sharing / paste
    "dropbox.com", "dropboxusercontent.com", "box.com", "mediafire.com", "mega.nz", "wetransfer.com",
    "pastebin.com", "paste.ee", "gofile.io", "file.io", "anonfiles.com",
    # chat / social CDNs
    "discord.com", "discordapp.com", "discordapp.net", "telegram.org", "t.me", "telegra.ph",
    # app hosting / site builders / tunnels
    "herokuapp.com", "netlify.app", "vercel.app", "glitch.me", "repl.co", "replit.dev", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "web.app", "firebaseapp.com", "blogspot.com", "wordpress.com",
    "weebly.com", "wixsite.com", "google.com", "sharepoint.com", "1drv.ms",
}

# Commonly impersonated brands, for look-alike scoring
COMMON_TARGETS = [
    "microsoft.com", "office365.com", "outlook.com", "live.com",
    "google.com", "gmail.com", "apple.com", "icloud.com", "amazon.com",
    "paypal.com", "docusign.com", "dropbox.com", "adobe.com", "linkedin.com",
    "facebook.com", "netflix.com", "wellsfargo.com", "chase.com",
    "bankofamerica.com", "americanexpress.com", "citi.com", "fedex.com",
    "ups.com", "dhl.com", "intuit.com", "salesforce.com", "zoom.us",
    "mimecast.com", "crowdstrike.com",
]

# Multi-label public suffixes, so we can skip the tldextract dependency
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

# DKIM selectors to probe
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

    # File hash — check before domain validation
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        htype = {32: "MD5", 40: "SHA1", 64: "SHA256"}[len(value)]
        h = value.lower()
        result.update({
            "ok": True, "kind": "hash", "normalized": h,
            "domain": h, "registrable": h, "url": None, "email": None,
            "local_part": None, "hash": h, "hash_type": htype,
            "subdomain": False, "is_ip": False,
        })
        return result

    # CIDR range — check before URL parsing (both use "/")
    if re.match(r"^[0-9a-fA-F:.]+/\d{1,3}$", value):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if net.num_addresses > 256:
                result["error"] = (
                    f"CIDR range too large: /{net.prefixlen} covers {net.num_addresses:,} "
                    f"addresses. Maximum is 256 (IPv4 /24 or smaller, IPv6 /120 or smaller)."
                )
                return result
            result.update({
                "ok": True, "kind": "cidr", "normalized": str(net),
                "domain": str(net.network_address), "registrable": str(net.network_address),
                "url": None, "email": None, "local_part": None,
                "cidr": str(net), "network_addr": str(net.network_address),
                "subdomain": False, "is_ip": False,
            })
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

    # Strip a leading 'www.' so it triages the same as the apex (keep a real domain behind it)
    if domain and domain.startswith("www.") and domain.count(".") >= 2:
        domain = domain[4:]
        if kind == "domain":
            value = domain

    # Validate the extracted domain — unless it's a bare IP target.
    is_ip = False
    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except ValueError:
        pass

    if not is_ip and not _DOMAIN_RE.match(domain):
        # Allow IDN/punycode the regex rejects, but require a TLD dot
        try:
            domain.encode("idna")
            if "." not in domain:
                raise ValueError("no TLD")
        except Exception:
            result["error"] = f"'{domain}' is not a valid {kind}."
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
        data.pop("reports", None)   # drop the raw array, keep the summary
    return data


_drop_cache = {"ts": 0.0, "nets": []}


def _spamhaus_drop_nets():
    """Spamhaus DROP + EDROP — netblocks known to be controlled by criminals (free). Cached 6h."""
    now = time.time()
    if _drop_cache["nets"] and (now - _drop_cache["ts"] < 21600):
        return _drop_cache["nets"]
    nets = []
    try:
        r = requests.get("https://www.spamhaus.org/drop/drop_v4.json",
                         headers={"User-Agent": USER_AGENT}, timeout=12)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    c = obj.get("cidr")
                    if c:
                        nets.append((ipaddress.ip_network(c, strict=False), obj.get("sblid")))
                except Exception:
                    pass
    except Exception:
        pass
    if nets:
        _drop_cache["nets"] = nets
        _drop_cache["ts"] = now
    return nets or _drop_cache["nets"]


def spamhaus_drop_check(cidr):
    """Is this range on the Spamhaus DROP list (known criminal/hijacked netblock)?"""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return None
    nets = _spamhaus_drop_nets()
    if not nets:
        return None
    for d, sbl in nets:
        if net.version == d.version and net.overlaps(d):
            return {"listed": True, "entry": str(d), "sblid": sbl}
    return {"listed": False}


def abuseipdb_block(cidr):
    """AbuseIPDB /check-block — aggregate abuse across a network range (up to /24)."""
    if not cidr or not ABUSEIPDB_API_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check-block",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"network": cidr, "maxAgeInDays": 90},
            timeout=15,
        )
    except Exception:
        return {"error": "Could not reach AbuseIPDB."}
    if r.status_code in (402, 403):
        return {"error": "AbuseIPDB check-block isn't available on this API plan (paid feature)."}
    if r.status_code == 422:
        return {"error": "AbuseIPDB rejected this network (size or format)."}
    if r.status_code == 429:
        return {"error": "AbuseIPDB rate limit reached — try again shortly."}
    if r.status_code != 200:
        return {"error": f"AbuseIPDB check-block failed ({r.status_code})."}
    try:
        data = r.json().get("data")
    except Exception:
        data = None
    if not data:
        return None
    reported = data.get("reportedAddress") or []
    reported.sort(key=lambda x: x.get("abuseConfidenceScore", 0), reverse=True)
    return {
        "network": data.get("networkAddress"),
        "netmask": data.get("netmask"),
        "min": data.get("minAddress"),
        "max": data.get("maxAddress"),
        "num_hosts": data.get("numPossibleHosts"),
        "space_desc": data.get("addressSpaceDesc"),
        "reported_count": len(reported),
        "reported": [{
            "ip": r.get("ipAddress"), "score": r.get("abuseConfidenceScore", 0),
            "reports": r.get("numReports", 0), "last": (r.get("mostRecentReport") or "")[:10],
            "cc": r.get("countryCode"),
        } for r in reported[:40]],
    }


def check_vt_file(file_hash):
    """VirusTotal file endpoint — detection ratio, malware family, type, names, first seen."""
    if not file_hash or not VT_API_KEY:
        return None
    data = safe_get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": VT_API_KEY},
    )
    a = data.get("data", {}).get("attributes") if data else None
    if not a:
        return {"found": False}
    ptc = a.get("popular_threat_classification") or {}
    family = ptc.get("suggested_threat_label")
    labels = [c.get("value") for c in (ptc.get("popular_threat_category") or []) if c.get("value")]
    names = a.get("names") or []
    return {
        "found": True,
        "last_analysis_stats": a.get("last_analysis_stats", {}),
        "reputation": a.get("reputation"),
        "family": family,
        "categories": labels,
        "type": a.get("type_description") or a.get("type_tag"),
        "size": a.get("size"),
        "meaningful_name": a.get("meaningful_name") or (names[0] if names else None),
        "names": names[:6],
        "first_seen": _epoch_to_date(a.get("first_submission_date")),
        "last_seen": _epoch_to_date(a.get("last_analysis_date")),
        "times_submitted": a.get("times_submitted"),
        "tags": a.get("tags") or [],
        "sha256": a.get("sha256"), "md5": a.get("md5"), "sha1": a.get("sha1"),
    }


def hybrid_analysis(file_hash):
    """Hybrid Analysis (Falcon Sandbox) — sandbox verdict/threat score/family for a hash."""
    if not file_hash or not HYBRID_API_KEY:
        return None
    # /overview only accepts SHA256; VT + MalwareBazaar cover MD5/SHA1
    if len(file_hash) != 64:
        return {"found": False, "note": "Hybrid Analysis lookup needs a SHA256 hash."}
    headers = {"api-key": HYBRID_API_KEY, "User-Agent": "Falcon Sandbox", "accept": "application/json"}
    try:
        r = requests.get(
            "https://hybrid-analysis.com/api/v2/overview/" + file_hash, headers=headers, timeout=15,
        )
        if r.status_code == 404:
            return {"found": False}
        if r.status_code != 200:
            msg = ""
            try:
                msg = (r.json() or {}).get("message") or ""
            except Exception:
                pass
            return {"error": msg or ("HTTP " + str(r.status_code))}
        ov = r.json()
    except Exception:
        return {"error": "request failed"}
    if not ov:
        return {"found": False}
    # overview "tags" is HA's whole taxonomy, not this sample's — omit it
    ftype = ov.get("type") or ov.get("type_short")
    if isinstance(ftype, list):
        ftype = ", ".join(str(x) for x in ftype)
    if ftype and len(ftype) > 60:
        ftype = ftype[:60].rstrip(" ,") + "…"
    return {
        "found": True,
        "verdict": ov.get("verdict"),
        "threat_score": ov.get("threat_score"),
        "av_detect": ov.get("multiscan_result"),
        "family": ov.get("vx_family"),
        "type": ftype,
        "filename": ov.get("last_file_name"),
        "analysis_time": (ov.get("analysis_start_time") or ov.get("submitted_at") or "")[:10],
    }


def triage_lookup(file_hash):
    """Hatching Triage (tria.ge) — sandbox score/family/tags for a hash."""
    if not file_hash or not TRIAGE_API_KEY:
        return None
    headers = {"Authorization": "Bearer " + TRIAGE_API_KEY, "User-Agent": USER_AGENT}
    data = safe_get("https://tria.ge/api/v0/search", headers=headers,
                    params={"query": file_hash}, timeout=12)
    samples = (data or {}).get("data") or []
    if not samples:
        return {"found": False}
    sid = samples[0].get("id")
    if not sid:
        return {"found": False}
    ov = safe_get(f"https://tria.ge/api/v0/samples/{sid}/overview.json",
                  headers=headers, timeout=12)
    analysis = (ov or {}).get("analysis") or {}
    fam = analysis.get("family") or []
    if not fam:
        for tgt in ((ov or {}).get("targets") or []):
            fam += (tgt.get("family") or [])
    return {
        "found": True, "id": sid,
        "score": analysis.get("score"),
        "family": sorted(set(fam))[:6],
        "tags": (analysis.get("tags") or [])[:8],
        "url": f"https://tria.ge/{sid}",
    }


def malwarebazaar(file_hash):
    """abuse.ch MalwareBazaar — known malware sample lookup (family, tags, delivery)."""
    if not file_hash:
        return None
    headers = {"User-Agent": USER_AGENT}
    if ABUSECH_API_KEY:
        headers["Auth-Key"] = ABUSECH_API_KEY
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
                          data={"query": "get_info", "hash": file_hash},
                          headers=headers, timeout=12)
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None
    if d.get("query_status") != "ok" or not d.get("data"):
        return {"found": False}
    s = d["data"][0]
    return {
        "found": True,
        "file_name": s.get("file_name"),
        "file_type": s.get("file_type"),
        "file_size": s.get("file_size"),
        "signature": s.get("signature"),       # malware family
        "tags": s.get("tags") or [],
        "delivery_method": s.get("delivery_method"),
        "first_seen": (s.get("first_seen") or "")[:10],
        "reporter": s.get("reporter"),
    }


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
    # match on task.domain (the submitted domain), not every domain the page contacted
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

    # where the most recent scan landed (off-domain redirect = red flag)
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
        headers=headers, timeout=16,
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
        headers=headers, timeout=16,   # OTX IP general is slow
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
    v = v.split("/")[0]
    v = v.split(":")[0]
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


def hudsonrock_email(email):
    """Hudson Rock Cavalier (free, no key, no signup) — is this exact address in infostealer malware
    logs? A hit means a machine that used this address was infected and its saved credentials were
    stolen — a strong, actionable account-takeover signal for SOC triage."""
    if not email:
        return None
    data = safe_get(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
        params={"email": email}, timeout=14,
    )
    if not data:
        return None
    stealers = data.get("stealers") or []
    if not stealers:
        return {"compromised": False}
    dates = sorted([s.get("date_compromised") for s in stealers if s.get("date_compromised")], reverse=True)
    return {
        "compromised": True,
        "count": len(stealers),
        "last_date": (dates[0][:10] if dates else None),
        "corporate_services": data.get("total_corporate_services")
            or sum((s.get("total_corporate_services") or 0) for s in stealers),
        "user_services": data.get("total_user_services")
            or sum((s.get("total_user_services") or 0) for s in stealers),
        "os": stealers[0].get("operating_system"),
    }


def xposedornot_email(email):
    """XposedOrNot (free, no key, no signup) — which known data breaches this address appears in.
    Exposure ≠ malicious (most real, long-lived addresses appear in some breach), so this is reported
    as reputation CONTEXT, not scored as a risk on its own."""
    if not email:
        return None
    data = safe_get("https://api.xposedornot.com/v1/check-email/" + quote(email), timeout=12)
    if not data or data.get("Error"):
        return {"found": False}
    breaches = data.get("breaches") or []
    names = breaches[0] if (breaches and isinstance(breaches[0], list)) else breaches
    names = [n for n in names if isinstance(n, str)]
    return {"found": bool(names), "count": len(names), "breaches": names[:12]}


def emailrep_lookup(email):
    """EmailRep.io — reputation of an email address (suspicious/malicious, breaches, profiles)."""
    if not email:
        return None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if EMAILREP_API_KEY:
        headers["Key"] = EMAILREP_API_KEY
    data = safe_get(f"https://emailrep.io/{quote(email)}", headers=headers, timeout=10)
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
    s = re.sub(r"<[^>]+>", "", s)
    s = html.unescape(s)
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
    # KEV first (most actionable), then news
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

    # Near-miss of a known brand (edit distance 1-2)
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
        # brand as substring but not the real domain
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
    return {"score": pts, "verdict": verdict, "reasons": reasons, "flags": []}


def score_cidr(result):
    """Network-block scoring — Spamhaus DROP membership + share of range reported."""
    pts, reasons = 0, []
    drop = result.get("drop")
    if drop and drop.get("listed"):
        pts += 65
        reasons.append(f"Listed on Spamhaus DROP — known criminal/hijacked netblock ({drop.get('sblid')})")
    block = result.get("block")
    if block and not block.get("error"):
        rc = block.get("reported_count", 0)
        hosts = block.get("num_hosts") or 256
        pct = (rc / hosts * 100) if hosts else 0
        high = [r for r in (block.get("reported") or []) if r.get("score", 0) >= 50]
        if rc:
            reasons.append(f"{rc} of {hosts} addresses reported for abuse ({pct:.0f}% of the block)")
            if high:
                reasons.append(f"{len(high)} address(es) at 50+ abuse confidence")
            if len(high) >= 5 or pct >= 25:
                pts += 45
            elif len(high) >= 1 or pct >= 8:
                pts += 24
            else:
                pts += 8
        else:
            reasons.append("No addresses in this block have recent abuse reports")
    pts, verdict = _verdict_from(pts)
    return {"score": pts, "verdict": verdict, "reasons": reasons, "flags": []}


def score_hash(result):
    """File-hash scoring — VT detections + MalwareBazaar/ThreatFox known-malware match."""
    pts, reasons = 0, []
    vt = result.get("vt_file")
    if vt and vt.get("found"):
        s = vt.get("last_analysis_stats", {})
        mal, susp = s.get("malicious", 0), s.get("suspicious", 0)
        if mal >= 5:
            pts += 65
            reasons.append(f"VirusTotal: {mal} engines detect this file as malicious"
                           + (f" ({vt.get('family')})" if vt.get("family") else ""))
        elif mal >= 1:
            pts += 30; reasons.append(f"VirusTotal: {mal} malicious / {susp} suspicious")
        elif susp > 0:
            pts += 12; reasons.append(f"VirusTotal: {susp} suspicious")
    mb = result.get("mb")
    if mb and mb.get("found"):
        pts += 40
        sig = mb.get("signature")
        reasons.append("MalwareBazaar: known malware sample" + (f" ({sig})" if sig else ""))
    tf = result.get("threatfox")
    if tf and tf.get("found"):
        pts += 30
        fam = ", ".join(tf.get("malware") or [])
        reasons.append("ThreatFox: known malicious IOC" + (f" ({fam})" if fam else ""))
    hy = result.get("hybrid")
    if hy and hy.get("found"):
        ts = hy.get("threat_score") or 0
        v = (hy.get("verdict") or "").lower()
        if v == "malicious" or ts >= 70:
            pts += 45
            reasons.append("Hybrid Analysis: malicious" + (f" ({hy.get('family')})" if hy.get("family") else "") + (f", threat score {ts}" if ts else ""))
        elif v == "suspicious" or ts >= 30:
            pts += 22
            reasons.append(f"Hybrid Analysis: suspicious (threat score {ts})")
    tr = result.get("triage")
    if tr and tr.get("found"):
        sc = tr.get("score") or 0
        if sc >= 8:
            pts += 45
            fam = ", ".join(tr.get("family") or [])
            reasons.append("Hatching Triage: malicious" + (f" ({fam})" if fam else "") + f", score {sc}/10")
        elif sc >= 5:
            pts += 22
            reasons.append(f"Hatching Triage: suspicious (score {sc}/10)")
    pts, verdict = _verdict_from(pts)
    return {"score": pts, "verdict": verdict, "reasons": reasons, "flags": []}


def score(result):
    """Weighted risk scoring → verdict + reasons + BEC tags."""
    if result.get("kind") == "hash":
        return score_hash(result)
    if result.get("kind") == "cidr":
        return score_cidr(result)
    if result.get("is_ip"):
        return score_ip(result)
    pts = 0
    reasons = []
    # risk-flag chips: {"cat": <category>, "detail": <specific>}
    flags = []

    # For a freemail provider queried by address, domain-level feeds describe the
    # provider not the sender — let only address-level signals drive the score.
    provider = bool(result.get("is_provider"))

    # not in DNS → doesn't exist; don't score it like a real domain
    if result.get("unresolved"):
        return {
            "score": 0, "verdict": "No DNS Record", "flags": [],
            "reasons": ["Domain has no DNS records (no A / MX / NS) and no registration — it does not "
                        "resolve and appears unregistered or inactive."],
        }

    vt = result.get("vt")
    if vt and not provider:
        s = vt.get("last_analysis_stats", {})
        mal, susp = s.get("malicious", 0), s.get("suspicious", 0)
        if mal >= 5:
            pts += 45; reasons.append(f"VirusTotal: {mal} engines flag malicious")
        elif mal >= 1:
            pts += 22; reasons.append(f"VirusTotal: {mal} malicious / {susp} suspicious")
        elif susp > 2:
            pts += 10; reasons.append(f"VirusTotal: {susp} suspicious")

    abuse = result.get("abuse")
    if abuse and not provider:
        sc = abuse.get("abuseConfidenceScore", 0)
        if sc >= 50:
            pts += 30; reasons.append(f"AbuseIPDB confidence {sc}/100")
        elif sc >= 20:
            pts += 14; reasons.append(f"AbuseIPDB confidence {sc}/100")

    age_days = result.get("age_days")
    if age_days is not None and not provider:
        if age_days < 30:
            pts += 28
            reasons.append(f"Newly registered domain ({age_days}d old)")
            flags.append({"cat": "New domain", "detail": f"registered {age_days}d ago"})
        elif age_days < 90:
            pts += 14
            reasons.append(f"Young domain ({age_days}d old)")
            flags.append({"cat": "New domain", "detail": f"{age_days}d old"})

    dmarc = result.get("dmarc_parsed")
    if provider:
        pass  # provider SPF/DMARC says nothing about the mailbox
    elif dmarc is None:
        pts += 14
        reasons.append("No DMARC record — spoofable")
        flags.append({"cat": "Spoofable", "detail": "no DMARC record"})
    elif dmarc.get("policy", "none").lower() == "none":
        pts += 8
        reasons.append("DMARC p=none — not enforced")
        flags.append({"cat": "Spoofable", "detail": "DMARC not enforced (p=none)"})

    if result.get("spf_parsed") is None and result.get("kind") != "url" and not provider:
        pts += 6
        reasons.append("No SPF record")
        flags.append({"cat": "Spoofable", "detail": "no SPF record"})

    tld = result.get("registrable", "").rsplit(".", 1)[-1]
    if tld in HIGH_RISK_TLDS:
        pts += 12; reasons.append(f"High-abuse TLD (.{tld})")

    look = result.get("lookalike", {})
    for f in look.get("flags", []):
        if f["severity"] == "high":
            pts += 22; reasons.append(f["detail"]); flags.append({"cat": "Impersonation", "detail": f["detail"]})
        elif f["severity"] == "medium":
            pts += 10; reasons.append(f["detail"])

    if result.get("disposable"):
        pts += 16; reasons.append("Disposable / throwaway email domain")
        flags.append({"cat": "Disposable", "detail": "throwaway email domain"})
    elif result.get("freemail") and result.get("kind") == "email":
        pts += 4; reasons.append("Free consumer mail provider")

    us = result.get("urlscan")
    if us and us.get("redirect", {}).get("offsite"):
        pts += 28
        to_reg = us["redirect"]["to_reg"]
        reasons.append(f"Redirects off-domain to {to_reg} (not {result.get('registrable')})")
        flags.append({"cat": "Redirect", "detail": f"→ {to_reg}"})
    if us and us.get("verdict"):
        uv = us["verdict"]
        if uv.get("malicious"):
            pts += 30
            brands = ", ".join(uv.get("brands", [])) if uv.get("brands") else ""
            reasons.append("urlscan: malicious verdict" + (f" (impersonates {brands})" if brands else ""))
            if brands:
                flags.append({"cat": "Impersonation", "detail": f"impersonates {brands}"})
        elif uv.get("score", 0) > 0:
            pts += 12; reasons.append(f"urlscan risk score {uv['score']}")

    gsb = result.get("gsb")
    if gsb and gsb.get("flagged") and not provider:
        pts += 40
        reasons.append("Google Safe Browsing: " + ", ".join(gsb.get("threats") or ["flagged"]))
        flags.append({"cat": "Known bad", "detail": "Google Safe Browsing hit"})

    # hosting/CDN platforms show up in URLhaus/ThreatFox because malware is hosted
    # on them — surface as context, don't let it flip the verdict
    platform = bool(result.get("is_platform"))

    tf = result.get("threatfox")
    if tf and tf.get("found") and not provider and not platform:
        pts += 35
        fam = ", ".join(tf.get("malware") or [])
        reasons.append("ThreatFox: known malicious IOC" + (f" ({fam})" if fam else ""))
        flags.append({"cat": "Known bad", "detail": "ThreatFox IOC" + (f" ({fam})" if fam else "")})

    uh = result.get("urlhaus")
    if uh and uh.get("found") and not provider and not platform:
        pts += 35
        reasons.append(f"URLhaus: known malware host ({uh.get('url_count', '?')} URLs)")
        flags.append({"cat": "Known bad", "detail": "URLhaus malware host"})

    if platform and ((tf and tf.get("found")) or (uh and uh.get("found"))):
        n = (uh or {}).get("url_count")
        reasons.append("Malware has been hosted on this platform by third parties"
                       + (f" ({n} URLs in URLhaus)" if n else "")
                       + " — expected for a large hosting service; assess the specific URL, not the domain.")

    otx = result.get("otx")
    if otx and otx.get("pulse_count", 0) > 0 and not provider and not platform:
        named = (otx.get("malware_families") or []) + (otx.get("adversaries") or [])
        if named:
            pts += 20
            reasons.append(f"AlienVault OTX: {otx['pulse_count']} reports ({', '.join(named[:3])})")
            flags.append({"cat": "Known bad", "detail": "OTX threat reports"})
        else:
            pts += 10
            reasons.append(f"AlienVault OTX: {otx['pulse_count']} community threat reports")

    gn = result.get("greynoise")
    if gn and gn.get("observed") and gn.get("classification") == "malicious":
        pts += 15
        reasons.append("GreyNoise: source IP classified malicious")

    # infostealer exposure applies to any address (provider or not) — it's per-mailbox
    hr = result.get("hudsonrock")
    if hr and hr.get("compromised"):
        pts += 20
        reasons.append(
            f"Hudson Rock: address found in infostealer logs ({hr.get('count')} infection(s)"
            + (f", last {hr.get('last_date')}" if hr.get("last_date") else "") + ")"
        )
        flags.append({"cat": "Compromised", "detail": "in infostealer logs"})

    dis = result.get("disify")
    if dis:
        sig = dis.get("signals") or []
        if dis.get("disposable") and not result.get("disposable"):
            pts += 12; reasons.append("Disposable/temporary email domain (Disify)"); flags.append({"cat": "Disposable", "detail": "throwaway email domain"})
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
            flags.append({"cat": "Fraud", "detail": f"IPQS high fraud/abuse ({fs})"})
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
            pts += 25; reasons.append("EmailRep: known malicious activity"); flags.append({"cat": "Fraud", "detail": "EmailRep: known malicious activity"})
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

    return {"score": pts, "verdict": verdict, "reasons": reasons, "flags": flags}


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

def analyze(raw_input):
    parsed = parse_target(raw_input)
    if not parsed["ok"]:
        return {"ok": False, "error": parsed["error"], "input": raw_input}

    domain = parsed["domain"]
    is_ip = parsed.get("is_ip", False)

    # Refuse private/loopback/reserved IPs — nothing to triage against public sources, and it keeps
    # internal addresses out of the pipeline entirely.
    if is_ip and not is_public_ip(domain):
        return {"ok": False, "input": raw_input,
                "error": "That is a private, loopback, or reserved IP — there is nothing to triage "
                         "against public threat-intelligence sources."}

    ip = domain if is_ip else resolve_ip(domain)

    if parsed["kind"] == "hash":
        result = _analyze_hash(parsed, raw_input)
    elif parsed["kind"] == "cidr":
        result = _analyze_cidr(parsed, raw_input)
    elif is_ip:
        result = _analyze_ip(parsed, ip, raw_input)
    else:
        result = _analyze_domain(parsed, domain, ip, raw_input)

    result.update(score(result))
    result["ticket_summary"] = build_summary(result)
    result["keys"] = {
        "vt": bool(VT_API_KEY), "abuseipdb": bool(ABUSEIPDB_API_KEY),
        "otx": bool(OTX_API_KEY), "urlscan": bool(URLSCAN_API_KEY),
        "gsb": bool(GSB_API_KEY), "abusech": bool(ABUSECH_API_KEY),
        "hybrid": bool(HYBRID_API_KEY), "triage": bool(TRIAGE_API_KEY),
    }
    return result


def _analyze_hash(parsed, raw_input):
    """File-hash path — VirusTotal + MalwareBazaar + ThreatFox (uses existing keys)."""
    h = parsed["hash"]
    futures = {
        "vt_file":   _executor.submit(check_vt_file, h),
        "mb":        _executor.submit(malwarebazaar, h),
        "threatfox": _executor.submit(threatfox_lookup, h, h),
        "hybrid":    _executor.submit(hybrid_analysis, h),
        "triage":    _executor.submit(triage_lookup, h),
    }
    res = {k: f.result() for k, f in futures.items()}
    return {
        "ok": True, "kind": "hash", "input": raw_input,
        "domain": h, "registrable": h, "ip": None, "is_ip": False,
        "email": None, "url": None,
        "hash": h, "hash_type": parsed.get("hash_type"),
        "defanged": h,
        "vt_file": res["vt_file"], "mb": res["mb"], "threatfox": res["threatfox"],
        "hybrid": res["hybrid"], "triage": res["triage"],
    }


def _analyze_cidr(parsed, raw_input):
    """Network-block path — aggregate abuse (AbuseIPDB check-block) + RDAP allocation."""
    cidr = parsed["cidr"]
    net_addr = parsed["network_addr"]
    futures = {
        "block":   _executor.submit(abuseipdb_block, cidr),
        "rdap_ip": _executor.submit(rdap_ip, net_addr),
        "drop":    _executor.submit(spamhaus_drop_check, cidr),
    }
    res = {k: f.result() for k, f in futures.items()}
    return {
        "ok": True, "kind": "cidr", "input": raw_input,
        "domain": cidr, "registrable": cidr, "ip": None, "is_ip": False,
        "cidr": cidr, "email": None, "url": None,
        "defanged": defang(cidr),
        "block": res["block"], "rdap_ip": res["rdap_ip"], "drop": res["drop"],
    }


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
    is_email = parsed["kind"] == "email"
    reg_dom = parsed["registrable"]

    # Phase 1 — fast DNS presence probe. No records of any kind → bail early
    # with "No DNS Record" instead of running the slow sources.
    dns_fut = {
        "a":    _executor.submit(dns_lookup, domain, "A"),
        "aaaa": _executor.submit(dns_lookup, domain, "AAAA"),
        "mx":   _executor.submit(dns_lookup, domain, "MX"),
        "ns":   _executor.submit(dns_lookup, domain, "NS"),
    }
    dns = {k: f.result() for k, f in dns_fut.items()}
    if not (dns["a"] or dns["aaaa"] or dns["mx"] or dns["ns"]):
        return {
            "ok": True, "kind": parsed["kind"], "input": raw_input,
            "domain": domain, "registrable": reg_dom,
            "email": parsed["email"], "url": parsed["url"],
            "ip": None, "is_ip": False, "defanged": defang(parsed["normalized"]),
            "a": [], "aaaa": [], "mx": [], "ns": [], "cname": [], "soa": [], "txt": [], "dmarc": [],
            "dkim": [], "rdap_events": {}, "lookalike": {"exact_brand": None, "flags": []},
            "spf_parsed": None, "dmarc_parsed": None, "age_days": None, "registered": None,
            "mx_provider": None, "high_risk_tld": False,
            "unresolved": True,
            "freemail": reg_dom in FREEMAIL_DOMAINS, "disposable": reg_dom in DISPOSABLE_DOMAINS,
            "is_provider": False, "provider_note": None,
            "is_platform": False, "platform_note": None,
        }

    # Phase 2 — full pipeline (reuse the DNS already fetched); skip urlscan for email
    futures = {
        "cname": _executor.submit(dns_lookup, domain, "CNAME"),
        "soa":   _executor.submit(dns_lookup, domain, "SOA"),
        "txt":   _executor.submit(dns_txt_raw, domain, "TXT"),
        "dmarc": _executor.submit(dns_txt_raw, f"_dmarc.{domain}", "TXT"),
        "vt":    _executor.submit(check_vt_domain, domain),
        "rdap":  _executor.submit(rdap_domain, parsed["registrable"]),
        "info":  _executor.submit(ip_info, ip),
        "abuse": _executor.submit(abuseipdb, ip),
        "urlscan": _executor.submit(lambda: None) if is_email else _executor.submit(urlscan_search, domain),
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
        # address-level reputation — only meaningful for an email query
        "hudsonrock": _executor.submit(hudsonrock_email, parsed["email"]),
        "xon":   _executor.submit(xposedornot_email, parsed["email"]),
    }
    res = {k: f.result() for k, f in futures.items()}
    res.update(dns)   # fold in the phase-1 DNS results

    age_days, reg_date = domain_age(res["rdap"])
    spf = parse_spf(res["txt"])
    dmarc = parse_dmarc(res["dmarc"])
    look = lookalike_check(parsed["registrable"])
    reg_dom = parsed["registrable"]

    # off-domain redirect: did the scan land on an unrelated domain?
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
        "hudsonrock": res["hudsonrock"], "xon": res["xon"],
        # derived
        "age_days": age_days, "registered": reg_date,
        "spf_parsed": spf, "dmarc_parsed": dmarc,
        "mx_provider": identify_mx_provider(res["mx"]),
        "lookalike": look,
        "high_risk_tld": reg_dom.rsplit(".", 1)[-1] in HIGH_RISK_TLDS,
        "freemail": reg_dom in FREEMAIL_DOMAINS,
        "disposable": reg_dom in DISPOSABLE_DOMAINS,
    }
    # no DNS records and no registration = unregistered / doesn't exist
    result["unresolved"] = (not (res["a"] or res["aaaa"] or res["mx"] or res["ns"])) and reg_date is None

    # freemail provider: domain intel describes the provider, not the mailbox
    result["is_provider"] = bool(is_email and result["freemail"])
    result["provider_note"] = (
        f"{reg_dom} is a major consumer mail provider, so the domain data below describes the provider's "
        f"mail infrastructure — not this specific mailbox. The sender itself is assessed by the Email "
        f"Reputation checks (breach & infostealer exposure), which look up the exact address."
    ) if result["is_provider"] else None

    # hosting/CDN platform: feed hits reflect third-party abuse, not the platform itself
    result["is_platform"] = bool(parsed["kind"] in ("domain", "url") and reg_dom in HOSTING_PLATFORMS)
    result["platform_note"] = (
        f"{reg_dom} is a major hosting / content platform. Threat feeds (URLhaus, ThreatFox) list malware "
        f"that third parties have hosted on it — this reflects abuse of the platform, not that {reg_dom} "
        f"itself is malicious. Judge the specific URL or path, not the bare domain."
    ) if result["is_platform"] else None
    return result


def build_summary(r):
    """Analyst-ready, copy-paste block (defanged) for case notes."""
    if r.get("kind") == "hash":
        return build_hash_summary(r)
    if r.get("kind") == "cidr":
        return build_cidr_summary(r)
    if r.get("is_ip"):
        return build_ip_summary(r)
    lines = []
    lines.append(f"IOC:      {r['defanged']}  ({r['kind']})")
    if r.get("unresolved"):
        lines.append(f"Verdict:  {r['verdict']} — does not resolve")
        lines.append("DNS:      no A / MX / NS records; appears unregistered or inactive")
        return "\n".join(lines)
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
    if r.get("kind") == "email":
        hr, xon = r.get("hudsonrock") or {}, r.get("xon") or {}
        rep = []
        if hr.get("compromised"):
            rep.append(f"infostealer logs ({hr.get('count')} infection(s)"
                       + (f", last {hr.get('last_date')}" if hr.get("last_date") else "") + ")")
        elif hr:
            rep.append("no infostealer exposure")
        if xon.get("found"):
            rep.append(f"{xon.get('count')} known breach(es)")
        elif xon:
            rep.append("no known breaches")
        if rep:
            lines.append("Address:  " + " | ".join(rep))
    dmarc = r.get("dmarc_parsed")
    lines.append(f"DMARC:    {('p=' + dmarc['policy']) if dmarc else 'MISSING'}"
                 f"  |  SPF: {'present' if r.get('spf_parsed') else 'MISSING'}"
                 f"  |  DKIM: {', '.join(r['dkim']) if r.get('dkim') else 'none found'}")
    if r.get("flags"):
        lines.append("Risk flags: " + "; ".join(f"{x['cat']} ({x['detail']})" for x in r["flags"]))
    if r.get("reasons"):
        lines.append("Signals:  " + " | ".join(r["reasons"]))
    return "\n".join(lines)


def build_hash_summary(r):
    lines = []
    vt = r.get("vt_file") or {}
    mb = r.get("mb") or {}
    lines.append(f"IOC:      {r['hash']}  ({r.get('hash_type','hash')})")
    lines.append(f"Verdict:  {r['verdict']}  (risk {r['score']}/100)")
    if vt.get("found"):
        s = vt.get("last_analysis_stats", {})
        lines.append(f"VirusTotal: {s.get('malicious',0)}/{sum(s.values()) or '?'} engines malicious"
                     + (f"  ·  {vt.get('family')}" if vt.get("family") else ""))
        if vt.get("type"):
            lines.append(f"File:     {vt.get('type')}"
                         + (f"  ·  {vt['size']} bytes" if vt.get("size") else "")
                         + (f"  ·  \"{vt['meaningful_name']}\"" if vt.get("meaningful_name") else ""))
        if vt.get("first_seen"):
            lines.append(f"First seen: {vt['first_seen']}")
    elif vt:
        lines.append("VirusTotal: file not found in VT (unknown sample)")
    if mb.get("found"):
        lines.append(f"MalwareBazaar: known sample" + (f"  ·  {mb.get('signature')}" if mb.get("signature") else "")
                     + (f"  ·  delivery: {mb['delivery_method']}" if mb.get("delivery_method") else ""))
    hy = r.get("hybrid") or {}
    if hy.get("found"):
        lines.append(f"Hybrid Analysis: {hy.get('verdict','?')}"
                     + (f"  ·  {hy.get('family')}" if hy.get("family") else "")
                     + (f"  ·  threat {hy.get('threat_score')}/100" if hy.get("threat_score") is not None else ""))
    tr = r.get("triage") or {}
    if tr.get("found") and tr.get("score") is not None:
        fam = ", ".join(tr.get("family") or [])
        lines.append(f"Hatching Triage: score {tr.get('score')}/10" + (f"  ·  {fam}" if fam else ""))
    if r.get("reasons"):
        lines.append("Signals:  " + " | ".join(r["reasons"]))
    return "\n".join(lines)


def build_cidr_summary(r):
    lines = []
    b = r.get("block") or {}
    rip = r.get("rdap_ip") or {}
    lines.append(f"IOC:      {r['defanged']}  (network block)")
    lines.append(f"Verdict:  {r['verdict']}  (risk {r['score']}/100)")
    drop = r.get("drop") or {}
    if drop.get("listed"):
        lines.append(f"Spamhaus: DROP-LISTED (criminal netblock, {drop.get('sblid')})")
    elif drop:
        lines.append("Spamhaus: not on DROP list")
    if b and not b.get("error"):
        lines.append(f"Block:    {b.get('min','?')} – {b.get('max','?')}  ·  {b.get('num_hosts','?')} hosts")
        if b.get("space_desc"):
            lines.append(f"Space:    {b['space_desc']}")
        lines.append(f"Abuse:    {b.get('reported_count',0)} reported address(es) in range")
    if rip.get("name") or rip.get("org"):
        lines.append(f"Owner:    {rip.get('name') or rip.get('org')}"
                     + (f"  ·  abuse: {rip['abuse_contact']}" if rip.get("abuse_contact") else ""))
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
