import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, get_if_list
# For better names of interfaces
try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None
from datetime import datetime
import threading
import time
import logging
import ctypes

#logging setup, Minimum level set to INFO
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Admin check, used later
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# Packet Processing
class PacketProcessor:
    def __init__(self):
        self.packet_data = []
        self.start_time = datetime.now()
        self.lock = threading.Lock()

    def process_packet(self, packet):
        try:
            if IP in packet:
                with self.lock:
                    info = {
                        "timestamp": datetime.now(),
                        "source": packet[IP].src,
                        "destination": packet[IP].dst,
                        "protocol": (
                            "TCP" if TCP in packet else
                            "UDP" if UDP in packet else
                            "OTHER"
                        ),
                        "size": len(packet)
                    }

                    if TCP in packet:
                        info["src_port"] = packet[TCP].sport
                        info["dst_port"] = packet[TCP].dport
                    elif UDP in packet:
                        info["src_port"] = packet[UDP].sport
                        info["dst_port"] = packet[UDP].dport

                    self.packet_data.append(info)

                    if len(self.packet_data) > 5000:
                        self.packet_data.pop(0)

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def dataframe(self):
        with self.lock:
            return pd.DataFrame(self.packet_data)


# Packet Capturing
def start_sniffer(iface):
    processor = PacketProcessor()

    def sniff_packets():
        try:
            sniff(
                iface=iface,
                prn=processor.process_packet,
                store=False,
                filter=None
            )
        except Exception as e:
            logger.error(f"Sniffer failed: {e}")

    thread = threading.Thread(target=sniff_packets, daemon=True)
    thread.start()
    return processor


# Main App itself
def main():
    st.set_page_config("Network Traffic Dashboard", layout="wide")
    st.title("📡 Real-Time Network Traffic Dashboard")

    if not is_admin():
        st.error("⚠️ STRICT WARNING: You are not running as Administrator. Packet capturing will likely fail.")

    # --- Interface Selection ---
    if get_windows_if_list:
        win_ifaces = get_windows_if_list()
        iface_map = {f"{i['description']} ({i['name']})": i['name'] for i in win_ifaces}
        sorted_names = sorted(list(iface_map.keys()))
        selected_name = st.selectbox("Select network interface", sorted_names)
        iface = iface_map[selected_name] if selected_name else None
    else:
        interfaces = get_if_list()
        iface = st.selectbox("Select network interface", interfaces)
        
    if "processor" not in st.session_state or st.session_state.get("iface") != iface:
        if iface:
            st.session_state.processor = start_sniffer(iface)
            st.session_state.iface = iface
            st.session_state.start = time.time()
            st.success(f"Started capturing on {iface[:20]}...")

    if "processor" in st.session_state:
        df = st.session_state.processor.dataframe()
    else:
        df = pd.DataFrame()

    col1, col2 = st.columns(2)
    col1.metric("Total Packets", len(df))
    uptime = time.time() - st.session_state.start if "start" in st.session_state else 0
    col2.metric("Uptime (s)", f"{uptime:.1f}")

    if df.empty:
        st.warning("No packets captured yet... (Waiting for traffic)")
        time.sleep(1)
        st.rerun()
        return
    
    protocol_counts = df["protocol"].value_counts()
    st.plotly_chart(
        px.pie(values=protocol_counts.values, names=protocol_counts.index, title="Protocol Distribution"),
        use_container_width=True
    )

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    timeline = df.groupby(df["timestamp"].dt.floor("s")).size()

    st.plotly_chart(
        px.line(x=timeline.index, y=timeline.values, title="Packets per Second"),
        use_container_width=True
    )

    if "source" in df.columns:
        top_sources = df["source"].value_counts().head(10)
        st.plotly_chart(
            px.bar(x=top_sources.index, y=top_sources.values, title="Top Source IPs"),
            use_container_width=True
        )

    st.subheader("Recent Packets")
    st.dataframe(df.tail(15), use_container_width=True)
    time.sleep(1)
    st.rerun()
    

if __name__ == "__main__":
    main()
