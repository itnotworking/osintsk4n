import streamlit as st
import requests
import socket

VT_API_KEY = st.secrets["VT_API_KEY"]
ABUSEIPDB_API_KEY = st.secrets.get("ABUSEIPDB_API_KEY", "")

st.set_page_config(page_title="OSINT Domain Analyzer", layout="wide")

# ---------------- API CALLS ----------------
def check_vt(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            return r.json()["data"]["attributes"]
    except:
        return None
    return None

def dns_lookup(domain, record_type):
    try:
        r = requests.get(f"https://dns.google/resolve?name={domain}&type={record_type}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            return [a["data"] for a in data.get("Answer", [])]
    except:
        return []
    return []

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def ip_info(ip):
    if not ip:
        return None
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if r.status_code == 200:
            return r.json()
    except:
        return None
    return None

def abuseipdb(ip):
    if not ip or not ABUSEIPDB_API_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("data")
    except:
        return None
    return None

def rdap_domain(domain):
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=15)
        if r.status_code == 200:
            return r.json()
    except:
        return None
    return None

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
        vt = check_vt(domain)
        info = ip_info(ip)
        abuse = abuseipdb(ip)
        rdap = rdap_domain(domain)

    # ---------- Risk Summary ----------
    risk_level = "🟢 Low"
    risk_reason = []

    if vt:
        stats = vt.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        if mal >= 5:
            risk_level = "🔴 High"
            risk_reason.append(f"VT malicious={mal}")
        elif mal > 0 or susp > 2:
            risk_level = "🟡 Medium"
            risk_reason.append(f"VT detections (mal={mal}, susp={susp})")

    if abuse and abuse.get("abuseConfidenceScore", 0) >= 50:
        risk_level = "🔴 High"
        risk_reason.append(f"AbuseIPDB score={abuse['abuseConfidenceScore']}")

    st.markdown(f"### Risk: {risk_level}")
    if risk_reason:
        st.write(" • ".join(risk_reason))

    # ---------- TABS ----------
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["🌐 Infrastructure", "📨 DNS", "🛡️ VirusTotal", "🚨 Reputation", "🔗 Links"]
    )

    # --- Infrastructure ---
    with tab1:
        st.subheader("IP & Hosting")
        st.write(f"**Resolved IP:** {ip or 'N/A'}")
        if info and info.get("status") == "success":
            st.write(f"**Country:** {info.get('country')} ({info.get('countryCode')})")
            st.write(f"**Region/City:** {info.get('regionName')} / {info.get('city')}")
            st.write(f"**ISP:** {info.get('isp')}")
            st.write(f"**Org:** {info.get('org')}")
            st.write(f"**ASN:** {info.get('as')}")
            st.write(f"**Reverse DNS:** {info.get('reverse', 'N/A')}")
        else:
            st.warning("IP info not available")

        if rdap:
            st.subheader("WHOIS / RDAP")
            try:
                events = {e["eventAction"]: e["eventDate"] for e in rdap.get("events", [])}
                st.write(f"**Registered:** {events.get('registration','?')}")
                st.write(f"**Last Updated:** {events.get('last changed','?')}")
                st.write(f"**Expires:** {events.get('expiration','?')}")
                if "entities" in rdap:
                    for ent in rdap["entities"]:
                        roles = ", ".join(ent.get("roles", []))
                        handle = ent.get("handle", "")
                        st.write(f"- {roles}: {handle}")
            except:
                st.write("RDAP parse error")
        else:
            st.info("No RDAP info available")

    # --- DNS ---
    with tab2:
        st.subheader("DNS Records")
        st.write("**A records**")
        st.write(a_records or "None")
        st.write("**MX records**")
        st.write(mx_records or "None")
        st.write("**NS records**")
        st.write(ns_records or "None")

        spf = [t for t in txt_records if "spf" in t.lower()]
        dmarc = dns_lookup(f"_dmarc.{domain}", "TXT")
        verifications = [t for t in txt_records if "verification" in t.lower()]

        st.subheader("Mail / Auth Records")
        st.write("**SPF**")
        st.write(spf or "None")
        st.write("**DMARC**")
        st.write(dmarc or "None")

        st.subheader("Domain Verifications")
        st.write(verifications or "None")

    # --- VirusTotal ---
    with tab3:
        if vt:
            stats = vt.get("last_analysis_stats", {})
            st.metric("Malicious", stats.get("malicious", 0))
            st.metric("Suspicious", stats.get("suspicious", 0))
            st.metric("Harmless", stats.get("harmless", 0))
            st.metric("Undetected", stats.get("undetected", 0))

            cats = vt.get("categories", {})
            if cats:
                st.subheader("Categories")
                st.json(cats)
        else:
            st.warning("No VirusTotal data")

    # --- Reputation ---
    with tab4:
        st.subheader("AbuseIPDB")
        if abuse:
            st.write(f"**Abuse Score:** {abuse.get('abuseConfidenceScore')}/100")
            st.write(f"**Total Reports:** {abuse.get('totalReports')}")
            st.write(f"**Last Reported:** {abuse.get('lastReportedAt')}")
            st.write(f"**Country:** {abuse.get('countryCode')}")
            st.write(f"**Usage Type:** {abuse.get('usageType')}")
        elif not ABUSEIPDB_API_KEY:
            st.info("Add ABUSEIPDB_API_KEY in Secrets to enable.")
        else:
            st.write("No data")

    # --- Quick Links ---
    with tab5:
        st.subheader("External Lookups")
        st.markdown(f"https://www.virustotal.com/gui/domain/{domain}")
        st.markdown(f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}")
        st.markdown(f"https://urlscan.io/domain/{domain}")
        st.markdown(f"https://www.abuseipdb.com/check/{ip}")
        st.markdown(f"https://talosintelligence.com/reputation_center/lookup?search={domain}")
        st.markdown(f"https://search.censys.io/search?q={domain}")
        st.markdown(f"https://www.shodan.io/search?query={domain}")
