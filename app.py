import streamlit as st
import requests
import socket

VT_API_KEY = st.secrets["VT_API_KEY"]

# ---------- VirusTotal ----------
def check_vt(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            return "ok", r.json()["data"]["attributes"]["last_analysis_stats"]
        elif r.status_code == 404:
            return "not_found", None
        elif r.status_code == 401:
            return "auth_error", None
        elif r.status_code == 429:
            return "rate_limit", None
        else:
            return f"http_{r.status_code}", None
    except Exception as e:
        return f"error: {e}", None

# ---------- DNS ----------
def dns_lookup(domain, record_type):
    url = f"https://dns.google/resolve?name={domain}&type={record_type}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if "Answer" in data:
                return [a["data"] for a in data["Answer"]]
        return []
    except:
        return []

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "N/A"

# ---------- IP Geolocation + ASN ----------
def ip_info(ip):
    if not ip or ip == "N/A":
        return None
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "IP": ip,
                "Country": data.get("country_name", "Unknown"),
                "Region": data.get("region", "Unknown"),
                "City": data.get("city", "Unknown"),
                "ASN": data.get("asn", "Unknown"),
                "Org": data.get("org", "Unknown"),
                "Hostname": data.get("hostname", "Unknown"),
            }
    except:
        return None
    return None

# ---------- UI ----------
st.title("🔍 OSINT Domain Analyzer")

domain = st.text_input("Enter domain")

if st.button("Analyze"):
    st.write("Running analysis...")

    # --- Infrastructure ---
    ip = resolve_ip(domain)
    a_records = dns_lookup(domain, "A")
    mx_records = dns_lookup(domain, "MX")
    ns_records = dns_lookup(domain, "NS")
    txt_records = dns_lookup(domain, "TXT")

    st.subheader("🌐 Infrastructure")
    st.write(f"**Resolved IP:** {ip}")
    st.write(f"**A records:** {a_records or 'None'}")
    st.write(f"**MX records:** {mx_records or 'None'}")
    st.write(f"**NS records:** {ns_records or 'None'}")
    st.write(f"**TXT records:** {txt_records or 'None'}")

    # --- IP Geolocation / ASN ---
    st.subheader("🛰️ IP Geolocation & ASN")
    info = ip_info(ip)
    if info:
        st.write(f"**Country:** {info['Country']}")
        st.write(f"**Region/City:** {info['Region']} / {info['City']}")
        st.write(f"**ASN:** {info['ASN']}")
        st.write(f"**Organization / Hosting:** {info['Org']}")
        st.write(f"**Hostname:** {info['Hostname']}")
    else:
        st.write("No IP info available.")

    # --- VirusTotal ---
    status, vt = check_vt(domain)

    st.subheader("🛡️ VirusTotal")
    if status == "ok":
        st.write(f"**Malicious:** {vt.get('malicious', 0)}")
        st.write(f"**Suspicious:** {vt.get('suspicious', 0)}")
        st.write(f"**Harmless:** {vt.get('harmless', 0)}")
        st.write(f"**Undetected:** {vt.get('undetected', 0)}")
    elif status == "not_found":
        st.warning("VirusTotal has no record for this domain.")
    elif status == "auth_error":
        st.error("API key missing or invalid.")
    elif status == "rate_limit":
        st.error("Rate limit hit. Try again in 60 seconds.")
    else:
        st.error(f"VT request failed: {status}")

    st.markdown(f"https://www.virustotal.com/gui/domain/{domain}")
