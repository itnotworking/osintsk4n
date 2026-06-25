import streamlit as st
import requests
import socket

VT_API_KEY = st.secrets["VT_API_KEY"]

def check_vt(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            return data["data"]["attributes"]["last_analysis_stats"]
    except:
        return None

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "N/A"

st.title("🔍 OSINT Domain Analyzer")

domain = st.text_input("Enter domain")

if st.button("Analyze"):
    st.write("Running analysis...")

    vt = check_vt(domain)
    ip = resolve_ip(domain)

    if vt:
        st.write("### VirusTotal")
        st.write(vt)
        st.write("### IP Address")
        st.write(ip)
    else:
        st.error("Failed to retrieve data")
