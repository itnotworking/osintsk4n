from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import requests, socket, os, asyncio
from concurrent.futures import ThreadPoolExecutor

app = FastAPI(title="OSINT Domain Analyzer")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

VT_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

executor = ThreadPoolExecutor(max_workers=8)

# ---------- helpers ----------
def safe_get(url, headers=None, params=None, timeout=8):
    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except:
        return None
    return None

def check_vt(domain):
    if not VT_API_KEY:
        return None
    data = safe_get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": VT_API_KEY},
    )
    return data.get("data", {}).get("attributes") if data else None

def dns_lookup(domain, record_type):
    data = safe_get(f"https://dns.google/resolve?name={domain}&type={record_type}")
    if data and "Answer" in data:
        return [a["data"] for a in data["Answer"]]
    return []

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def ip_info(ip):
    if not ip:
        return None
    return safe_get(f"http://ip-api.com/json/{ip}")

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

# ---------- routes ----------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "result": None})

@app.post("/analyze", response_class=JSONResponse)
async def analyze(domain: str = Form(...)):
    loop = asyncio.get_event_loop()

    ip = await loop.run_in_executor(executor, resolve_ip, domain)

    tasks = {
        "a":    loop.run_in_executor(executor, dns_lookup, domain, "A"),
        "mx":   loop.run_in_executor(executor, dns_lookup, domain, "MX"),
        "ns":   loop.run_in_executor(executor, dns_lookup, domain, "NS"),
        "txt":  loop.run_in_executor(executor, dns_lookup, domain, "TXT"),
        "dmarc":loop.run_in_executor(executor, dns_lookup, f"_dmarc.{domain}", "TXT"),
        "vt":   loop.run_in_executor(executor, check_vt, domain),
        "rdap": loop.run_in_executor(executor, rdap_domain, domain),
        "info": loop.run_in_executor(executor, ip_info, ip),
        "abuse":loop.run_in_executor(executor, abuseipdb, ip),
    }

    results = {k: await v for k, v in tasks.items()}
    results["ip"] = ip
    results["domain"] = domain

    # Risk scoring
    risk = "low"
    reasons = []
    vt = results["vt"]
    if vt:
        stats = vt.get("last_analysis_stats", {})
        mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
        if mal >= 5:
            risk = "high"; reasons.append(f"VT mal={mal}")
        elif mal > 0 or susp > 2:
            risk = "medium"; reasons.append(f"VT mal={mal}, susp={susp}")
    if results["abuse"] and results["abuse"].get("abuseConfidenceScore", 0) >= 50:
        risk = "high"
        reasons.append(f"AbuseIPDB={results['abuse']['abuseConfidenceScore']}")

    results["risk"] = risk
    results["reasons"] = reasons
    return results
