import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from datetime import datetime
import threading
import time
import logging

# Logging, Minimum level set to INFO
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Packet Proccesing Class
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
            logger.error(e)

    def dataframe(self):
        with self.lock:
            return pd.DataFrame(self.packet_data)

# Capturing Packets in Background
def start_sniffer(iface):
    processor = PacketProcessor()

    def sniff_packets():
        sniff(
            iface=iface,
            prn=processor.process_packet,
            store=False,
            filter="ip"
        )

    thread = threading.Thread(target=sniff_packets, daemon=True)
    thread.start()
    return processor

# Streamlit Usuerint
def main():
    st.set_page_config("Network Traffic Dashboard", layout="wide")
    st.title("📡 Real-Time Network Traffic Dashboard")

    interfaces = get_if_list()
    iface = st.selectbox("Select network interface", interfaces)

    if "processor" not in st.session_state or st.session_state.get("iface") != iface:
        st.session_state.processor = start_sniffer(iface)
        st.session_state.iface = iface
        st.session_state.start = time.time()

    df = st.session_state.processor.dataframe()

    col1, col2 = st.columns(2)
    col1.metric("Total Packets", len(df))
    col2.metric("Uptime (s)", f"{time.time() - st.session_state.start:.1f}")

    if df.empty:
        st.warning("No packets captured yet...")
        return

    protocol_counts = df["protocol"].value_counts()
    st.plotly_chart(
        px.pie(values=protocol_counts.values, names=protocol_counts.index,
               title="Protocol Distribution"),
        use_container_width=True
    )

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    timeline = df.groupby(df["timestamp"].dt.floor("S")).size()
    st.plotly_chart(
        px.line(x=timeline.index, y=timeline.values,
                title="Packets per Second"),
        use_container_width=True
    )

    top_sources = df["source"].value_counts().head(10)
    st.plotly_chart(
        px.bar(x=top_sources.index, y=top_sources.values,
               title="Top Source IPs"),
        use_container_width=True
    )

    st.subheader("Recent Packets")
    st.dataframe(df.tail(15), use_container_width=True)

    st.caption("Auto-updates every interaction (Streamlit native rerun)")

if __name__ == "__main__":
    main()
