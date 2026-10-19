"""
osintsk4n — FastAPI front door.
Thin routing layer; all intelligence lives in analyzer.py.
"""

import os
import re
import time
import asyncio
from collections import defaultdict, deque

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import analyzer

app = FastAPI(title="osintsk4n — SOC Triage", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
# changes with every deploy, so browsers fetch the new stylesheet instead of a cached old one
CSS_VERSION = str(int(os.path.getmtime("static/style.css")))
# SEO: one canonical site. sc4n.app served a full duplicate copy, which splits search ranking.
CANONICAL_HOST = "sc4n.lol"
ALIAS_HOSTS = {"sc4n.app", "www.sc4n.app"}
# Google Search Console HTML-tag verification code, set in Render; no code change needed to verify
GOOGLE_SITE_VERIFICATION = os.environ.get("GOOGLE_SITE_VERIFICATION", "").strip().strip('"')
PAGE_UPDATED = __import__("datetime").date.fromtimestamp(os.path.getmtime("templates/index.html")).isoformat()

# --- simple in-memory rate limit (per client IP) ---------------------------
RATE_LIMIT = 20          # requests
RATE_WINDOW = 60         # seconds
_hits = defaultdict(deque)


def _client_ip(request: Request) -> str:
    # Render is a single trusted proxy that appends the real client IP as the LAST X-Forwarded-For
    # entry. Use that — the leftmost values are client-supplied and can be spoofed to dodge the limiter.
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        parts = [p.strip() for p in fwd.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.client.host if request.client else "unknown"


def _rate_ok(ip: str) -> bool:
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return False
    q.append(now)
    return True


@app.middleware("http")
async def canonical_host(request: Request, call_next):
    host = (request.headers.get("host") or "").split(":")[0].lower()
    if host in ALIAS_HOSTS:
        url = f"https://{CANONICAL_HOST}{request.url.path}" + (f"?{request.url.query}" if request.url.query else "")
        # 301 for pages; 308 keeps the method and body for anything posted to the old host
        return RedirectResponse(url, status_code=301 if request.method in ("GET", "HEAD") else 308)
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), usb=(), payment=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' https: data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'; "
        "object-src 'none'; frame-ancestors 'none'"
    )
    return resp


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "css_v": CSS_VERSION,
                                                     "gsv": GOOGLE_SITE_VERIFICATION})


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    # index the page; keep crawlers off the lookup endpoints, which cost API quota
    return ("User-agent: *\nAllow: /\nDisallow: /analyze\nDisallow: /precheck\nDisallow: /urlscan/\n"
            "Disallow: /health\n\nSitemap: https://sc4n.lol/sitemap.xml\n")


@app.get("/sitemap.xml")
async def sitemap():
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
           f'  <url><loc>https://sc4n.lol/</loc><lastmod>{PAGE_UPDATED}</lastmod></url>\n'
           '</urlset>\n')
    return Response(xml, media_type="application/xml")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "vt": bool(analyzer.VT_API_KEY),
        "abuseipdb": bool(analyzer.ABUSEIPDB_API_KEY),
        "urlscan": bool(analyzer.URLSCAN_API_KEY),
    }


@app.get("/precheck", response_class=JSONResponse)
async def precheck(target: str = ""):
    """Instant, local-only check so the UI can warn before a known-slow lookup (Tor exits run ~25s)."""
    parsed = analyzer.parse_target(target[:256]) if target else {}
    ip = parsed.get("domain") if parsed.get("ok") and parsed.get("is_ip") else None
    if not ip or not analyzer.is_public_ip(ip):
        return {"tor_exit": False}
    bl = await asyncio.to_thread(analyzer.blocklist_lookup, ip)
    return {"tor_exit": bool((bl or {}).get("tor_exit"))}


@app.post("/analyze", response_class=JSONResponse)
async def analyze(request: Request, target: str = Form(...), fresh: str = Form("")):
    ip = _client_ip(request)
    if not _rate_ok(ip):
        return JSONResponse(
            {"ok": False, "error": "Rate limit exceeded — slow down."},
            status_code=429,
        )
    if not target or len(target) > 2048:
        return JSONResponse({"ok": False, "error": "Invalid input."}, status_code=400)

    try:
        result = await asyncio.to_thread(analyzer.analyze, target, fresh == "1")
    except Exception:
        # keep errors as JSON so the UI can render them
        return JSONResponse(
            {"ok": False, "error": "The analysis engine hit an unexpected error on this input. "
                                   "Please try again, or try a different format."},
            status_code=500,
        )
    status = 200 if result.get("ok") else 400
    return JSONResponse(result, status_code=status)


@app.post("/urlscan/submit", response_class=JSONResponse)
async def urlscan_submit(request: Request, target: str = Form(...), auto: str = Form("")):
    ip = _client_ip(request)
    if not _rate_ok(ip):
        return JSONResponse({"error": "Rate limit exceeded — slow down."}, status_code=429)
    if not target or len(target) > 2048:
        return JSONResponse({"error": "Invalid input."}, status_code=400)
    scan_url, reg = await asyncio.to_thread(analyzer.scan_url_for, target)
    if not scan_url:
        return JSONResponse({"error": "Could not derive a URL to scan."}, status_code=400)
    res = await asyncio.to_thread(analyzer.urlscan_submit, scan_url, auto == "1")
    res["reg"] = reg
    res["scan_url"] = scan_url
    return JSONResponse(res, status_code=200 if res.get("uuid") else 502)


@app.get("/urlscan/result/{uuid}", response_class=JSONResponse)
async def urlscan_result(uuid: str, reg: str = ""):
    if not re.fullmatch(r"[0-9a-fA-F-]{16,64}", uuid or ""):
        return JSONResponse({"error": "Bad scan id."}, status_code=400)
    reg = reg[:255] if reg else None
    res = await asyncio.to_thread(analyzer.urlscan_result, uuid, reg)
    return JSONResponse(res)
