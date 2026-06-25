import streamlit as st
import requests
import socket

st.set_page_config(page_title="OSINT Domain Analyzer", layout="wide")

# ---------------- SAFE SECRETS ----------------
try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
except Exception:
    VT_API_KEY = ""

try:
    ABUSEIPDB_API_KEY = st.secrets["ABUSEIPDB_API_KEY"]
except Exception:
    ABUSEIPDB_API_KEY = ""

# ---------------- HELPERS ----------------
def safe_get(url, headers=None, params=None, timeout=8):
    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None

def check_vt(domain):
    if not VT_API_KEY:
        return None
    data = safe_get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": VT_API_KEY},
    )
    if data:
        return data.get("data", {}).get("attributes", {})
    return None

def dns_lookup(domain, record_type):
    data = safe_get(f"https://dns.google/resolve?name={domain}&type={record_type}")
    if data and "Answer" in data:
        return [a["data"] for a in data["Answer"]]
    return []

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def ip_info(ip):
    if not ip:
        return None
    return safe_get(f"http://ip-api.com/json/{ip}")

def abuseipdb(ip):
    if not ip or not ABUSEIPDB_API_KEY:
        return None
    return safe_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
    )

def rdap_domain(domain):
    return safe_get(f"https://rdap.org/domain/{domain}")

# ---------------- UI ----------------
st.title("🔍 OSINT Domain Analyzer")
st.caption("Threat intelligence + infrastructure analysis dashboard")

col1, col2 = st.columns([4, 1])
with col1:
    domain = st.text_input("Enter domain", placeholder="example.com")
with col2:
    analyze = st.button("Analyze", use_container_width=True)

if analyze and domain:
    with st.spinner("Running OSINT analysis..."):
        ip = resolve_ip(domain)
        a_records = dns_lookup(domain, "A")
        mx_records = dns_lookup(domain, "MX")
        ns_records = dns_lookup(domain, "NS")
        txt_records = dns_lookup(domain, "TXT")
        dmarc = dns_lookup(f"_dmarc.{domain}", "TXT")
        vt = check_vt(domain)
        info = ip_info(ip)
        abuse_raw = abuseipdb(ip)
        abuse = abuse_raw.get("data") if abuse_raw else None
        rdap = rdap_domain(domain)

    # Risk Score
    risk = "🟢 Low"
    reasons = []
    if vt:
        stats = vt.get("last_analysis_stats", {})
        mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
        if mal >= 5:
            risk = "🔴 High"; reasons.append(f"VT mal={mal}")
        elif mal > 0 or susp > 2:
            risk = "🟡 Medium"; reasons.append(f"VT mal={mal}, susp={susp}")
    if abuse and abuse.get("abuseConfidenceScore", 0) >= 50:
        risk = "🔴 High"; reasons.append(f"AbuseIPDB={abuse['abuseConfidenceScore']}")

    st.markdown(f"### Risk: {risk}")
    if reasons:
        st.write(" • ".join(reasons))

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["🌐 Infrastructure", "📨 DNS", "🛡️ VirusTotal", "🚨 Reputation", "🔗 Links"]
    )

    with tab1:
        st.subheader("IP & Hosting")
        st.write(f"**Resolved IP:** {ip or 'N/A'}")
        if info and info.get("status") == "success":
            st.write(f"**Country:** {info.get('country')} ({info.get('countryCode')})")
            st.write(f"**Region/City:** {info.get('regionName')} / {info.get('city')}")
            st.write(f"**ISP:** {info.get('isp')}")
            st.write(f"**Org:** {info.get('org')}")
            st.write(f"**ASN:** {info.get('as')}")
        else:
            st.info("IP info not available")

        if rdap:
            st.subheader("WHOIS / RDAP")
            events = {e.get("eventAction"): e.get("eventDate") for e in rdap.get("events", [])}
            st.write(f"**Registered:** {events.get('registration','?')}")
            st.write(f"**Last Updated:** {events.get('last changed','?')}")
            st.write(f"**Expires:** {events.get('expiration','?')}")
        else:
            st.info("No RDAP info available")

    with tab2:
        st.subheader("DNS Records")
        st.write("**A**"); st.write(a_records or "None")
        st.write("**MX**"); st.write(mx_records or "None")
        st.write("**NS**"); st.write(ns_records or "None")

        spf = [t for t in txt_records if "spf" in t.lower()]
        verifications = [t for t in txt_records if "verification" in t.lower()]

        st.subheader("Mail / Auth")
        st.write("**SPF**"); st.write(spf or "None")
        st.write("**DMARC**"); st.write(dmarc or "None")

        st.subheader("Verifications")
        st.write(verifications or "None")

    with tab3:
        if vt:
            stats = vt.get("last_analysis_stats", {})
            st.metric("Malicious", stats.get("malicious", 0))
            st.metric("Suspicious", stats.get("suspicious", 0))
            st.metric("Harmless", stats.get("harmless", 0))
            st.metric("Undetected", stats.get("undetected", 0))
        else:
            st.warning("No VT data (missing key or no record)")

    with tab4:
        st.subheader("AbuseIPDB")
        if abuse:
            st.write(f"**Score:** {abuse.get('abuseConfidenceScore')}/100")
            st.write(f"**Reports:** {abuse.get('totalReports')}")
            st.write(f"**Last Reported:** {abuse.get('lastReportedAt')}")
            st.write(f"**Country:** {abuse.get('countryCode')}")
            st.write(f"**Usage:** {abuse.get('usageType')}")
        elif not ABUSEIPDB_API_KEY:
            st.info("Add ABUSEIPDB_API_KEY in Secrets to enable.")
        else:
            st.write("No data")

    with tab5:
        st.subheader("Quick Lookups")
        st.markdown(f"https://www.virustotal.com/gui/domain/{domain}")
        st.markdown(f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}")
        st.markdown(f"https://urlscan.io/domain/{domain}")
        st.markdown(f"https://www.abuseipdb.com/check/{ip}")
        st.markdown(f"https://talosintelligence.com/reputation_center/lookup?search={domain}")
        st.markdown(f"https://search.censys.io/search?q={domain}")
        st.markdown(f"https://www.shodan.io/search?query={domain}")
