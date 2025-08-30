
from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy.all import (
    AsyncSniffer, get_if_list, get_if_addr, get_if_hwaddr,
    Ether, IP, IPv6, TCP, UDP, ICMP, ARP
)
from mac_vendor_lookup import MacLookup
from datetime import datetime
from threading import Lock

app = Flask(__name__)
CORS(app)


sniffer = None
sniffer_iface = None
sniff_lock = Lock()
captured = []          
MAX_STORE = 2000        
vendor_cache = {}
mac_lookup = MacLookup()  

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

def now_iso():
    return datetime.now().isoformat(timespec="seconds")

def protocol_name(pkt):
    if ARP in pkt: return "ARP"
    if TCP in pkt: return "TCP"
    if UDP in pkt: return "UDP"
    if ICMP in pkt: return "ICMP"
    if IPv6 in pkt: return "IPv6"
    if IP in pkt:
        return PROTO_MAP.get(pkt[IP].proto, f"IP-{pkt[IP].proto}")
    return "OTHER"

def safe_lookup_vendor(mac, ip_hint=None):
   
    if ip_hint and (ip_hint == "127.0.0.1" or ip_hint.startswith("127.")):
        return "Localhost"
    if not mac:
        return "Unknown"
    m = mac.lower()
    if m in vendor_cache:
        return vendor_cache[m]
    try:
        vendor = mac_lookup.lookup(m)
        if not vendor: vendor = "Unknown"
    except Exception:
        vendor = "Unknown"
    vendor_cache[m] = vendor
    return vendor

def extract_packet(pkt, iface_my_ip=None, iface_my_mac=None):
    info = {
        "time_iso": now_iso(),
        "src_ip": "",
        "dst_ip": "",
        "src_port": None,
        "dst_port": None,
        "src_mac": "",
        "dst_mac": "",
        "src_vendor": "Unknown",
        "dst_vendor": "Unknown",
        "protocol": protocol_name(pkt),
        "size_bytes": len(pkt),
        "summary": pkt.summary(),
        "meant_for_me": False
    }

    try:
        if Ether in pkt:
            info["src_mac"] = pkt[Ether].src
            info["dst_mac"] = pkt[Ether].dst

       
        if IP in pkt:
            info["src_ip"] = pkt[IP].src
            info["dst_ip"] = pkt[IP].dst
        elif IPv6 in pkt:
            info["src_ip"] = pkt[IPv6].src
            info["dst_ip"] = pkt[IPv6].dst

        
        if TCP in pkt:
            info["src_port"] = pkt[TCP].sport
            info["dst_port"] = pkt[TCP].dport
        elif UDP in pkt:
            info["src_port"] = pkt[UDP].sport
            info["dst_port"] = pkt[UDP].dport

        
        info["src_vendor"] = safe_lookup_vendor(info["src_mac"], info["src_ip"])
        info["dst_vendor"] = safe_lookup_vendor(info["dst_mac"], info["dst_ip"])

       
        if iface_my_mac and info["dst_mac"] and info["dst_mac"].lower() == iface_my_mac.lower():
            info["meant_for_me"] = True
        elif iface_my_ip and info["dst_ip"] and info["dst_ip"] == iface_my_ip:
            info["meant_for_me"] = True
        elif iface_my_ip and info["dst_ip"] and info["dst_ip"].startswith("127.") and iface_my_ip.startswith("127."):
           
            info["meant_for_me"] = True

    except Exception as e:
        
        info["summary"] += f" [parse_err:{e}]"

    return info


def start_sniff(interface):
    global sniffer, sniffer_iface
    with sniff_lock:
        if sniffer and sniffer.running:
            return False, "already running"
        
        try:
            my_ip = get_if_addr(interface)
        except Exception:
            my_ip = None
        try:
            my_mac = get_if_hwaddr(interface)
        except Exception:
            my_mac = None

        
        def on_packet(pkt):
            info = extract_packet(pkt, iface_my_ip=my_ip, iface_my_mac=my_mac)
            with sniff_lock:
                captured.append(info)
                if len(captured) > MAX_STORE:
                    captured.pop(0)

        sniffer = AsyncSniffer(iface=interface, store=False, prn=on_packet)
        sniffer.start()
        sniffer_iface = interface
        return True, "started"

def stop_sniff():
    global sniffer, sniffer_iface
    with sniff_lock:
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass
            sniffer = None
            sniffer_iface = None
    return True, "stopped"

# --- Flask routes ---
@app.route("/interfaces", methods=["GET"])
def route_interfaces():
    try:
        lst = get_if_list()
        # prefer non-loopback first
        lst = [i for i in lst if i != "lo"] + (["lo"] if "lo" in get_if_list() else [])
        return jsonify(lst)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/start", methods=["POST"])
def route_start():
    data = request.get_json(force=True, silent=True) or {}
    iface = data.get("interface")
    if not iface:
        return jsonify({"error": "interface missing"}), 400
    ok, msg = start_sniff(iface)
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"status": "started", "interface": iface})

@app.route("/stop", methods=["POST"])
def route_stop():
    ok, msg = stop_sniff()
    return jsonify({"status": msg})

@app.route("/clear", methods=["POST"])
def route_clear():
    with sniff_lock:
        captured.clear()
    return jsonify({"status": "cleared"})

@app.route("/packets", methods=["GET"])
def route_packets():
    
    with sniff_lock:
        return jsonify(captured)


if __name__ == "__main__":
    # run as root: sudo python3 app.py
    app.run(host="0.0.0.0", port=5000, debug=False)
