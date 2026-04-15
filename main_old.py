import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.tls.handshake import TLSClientHello
from collections import Counter
import threading
import time

# --- CONFIGURATION ---
TARGET_INTERFACE = "Wi-Fi"  # Change this to your actual interface
REFRESH_RATE = 1  # seconds

# --- STREAMLIT SETUP ---
st.set_page_config(page_title="Live NetViz Demo", page_icon="📡", layout="wide")
st.title("📡 Live Network Traffic Visualizer")
st.markdown("### Live Demo: Protocols, IPs & Visited Domains")

# --- STATE ---
@st.cache_resource
def get_counters():
    return Counter(), Counter(), Counter()  # proto, ip, domains

proto_counts, ip_counts, domain_counts = get_counters()

PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}

# --- PACKET PROCESSING ---
def process_packet(pkt):
    # Protocol + IP tracking
    if pkt.haslayer(IP):
        proto_num = pkt[IP].proto
        proto_name = PROTO_MAP.get(proto_num, f"Other ({proto_num})")
        proto_counts[proto_name] += 1

        src_ip = pkt[IP].src
        ip_counts[src_ip] += 1

    # --- DNS (Domain detection) ---
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            domain = pkt[DNSQR].qname.decode(errors="ignore")
            domain_counts[domain] += 1
        except:
            pass

    # --- TLS SNI (HTTPS domain detection) ---
    if pkt.haslayer(TLSClientHello):
        try:
            for ext in pkt[TLSClientHello].ext:
                if hasattr(ext, "servernames"):
                    for server in ext.servernames:
                        domain = server.servername.decode()
                        domain_counts[domain] += 1
        except:
            pass

# --- START SNIFFER THREAD ---
@st.cache_resource
def start_sniffing():
    sniff_thread = threading.Thread(
        target=sniff,
        kwargs={
            "iface": TARGET_INTERFACE,
            "prn": process_packet,
            "store": 0
        },
        daemon=True
    )
    sniff_thread.start()
    return sniff_thread

start_sniffing()

# --- UI LAYOUT ---
col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("Protocol Distribution")
    proto_chart_placeholder = st.empty()

with col2:
    st.subheader("Top Talkers (Source IPs)")
    ip_chart_placeholder = st.empty()

with col3:
    st.subheader("Visited Domains")
    domain_chart_placeholder = st.empty()

st.divider()
total_pkts_placeholder = st.empty()

# --- RENDER DASHBOARD (NO while loop) ---

# Protocol Chart
if proto_counts:
    df_proto = pd.DataFrame(list(proto_counts.items()), columns=["Protocol", "Count"])
    fig_proto = px.pie(df_proto, values="Count", names="Protocol", hole=0.4)
    proto_chart_placeholder.plotly_chart(fig_proto, use_container_width=True)

# IP Chart
if ip_counts:
    top_ips = ip_counts.most_common(10)
    df_ip = pd.DataFrame(top_ips, columns=["Source IP", "Packet Count"])
    fig_ip = px.bar(df_ip, x="Source IP", y="Packet Count", color="Packet Count")
    ip_chart_placeholder.plotly_chart(fig_ip, use_container_width=True)

# Domain Chart
if domain_counts:
    top_domains = domain_counts.most_common(10)
    df_domains = pd.DataFrame(top_domains, columns=["Domain", "Requests"])
    fig_domains = px.bar(df_domains, x="Domain", y="Requests", color="Requests")
    domain_chart_placeholder.plotly_chart(fig_domains, use_container_width=True)

# Metrics
total_pkts = sum(proto_counts.values())
total_pkts_placeholder.metric("Total Packets Captured", f"{total_pkts:,}")

# Empty state
if total_pkts == 0:
    st.info("Waiting for network traffic...")

# --- AUTO REFRESH ---
time.sleep(REFRESH_RATE)
st.rerun()