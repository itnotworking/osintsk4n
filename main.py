"""
osintsk4n — FastAPI front door.
Thin routing layer; all intelligence lives in analyzer.py.
"""

import time
import asyncio
from collections import defaultdict, deque

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import analyzer

app = FastAPI(title="osintsk4n — SOC Triage", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- simple in-memory rate limit (per client IP) ---------------------------
RATE_LIMIT = 20          # requests
RATE_WINDOW = 60         # seconds
_hits = defaultdict(deque)


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
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
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' https: data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'"
    )
    return resp


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "vt": bool(analyzer.VT_API_KEY),
        "abuseipdb": bool(analyzer.ABUSEIPDB_API_KEY),
        "urlscan": bool(analyzer.URLSCAN_API_KEY),
    }


@app.post("/analyze", response_class=JSONResponse)
async def analyze(request: Request, target: str = Form(...)):
    ip = _client_ip(request)
    if not _rate_ok(ip):
        return JSONResponse(
            {"ok": False, "error": "Rate limit exceeded — slow down."},
            status_code=429,
        )
    if not target or len(target) > 2048:
        return JSONResponse({"ok": False, "error": "Invalid input."}, status_code=400)

    result = await asyncio.to_thread(analyzer.analyze, target)
    status = 200 if result.get("ok") else 400
    return JSONResponse(result, status_code=status)
