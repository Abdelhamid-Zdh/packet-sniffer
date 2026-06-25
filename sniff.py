from scapy.all import sniff, IP, TCP, UDP, conf
import argparse
import datetime
import time


FLAGS = {
    'F': "FIN",
    'S': "SYN",
    'R': "RST",
    'P': "PSH",
    'A': "ACK",
    'U': "URG",
    'E': "ECE",
    'C': "CWR",
    'N': "NS"
}

ROUTER_IP = conf.route.route("0.0.0.0")[2]

def getFlags(flags):
    r = ''
    for f in flags:
        r += FLAGS.get(f, f) + ' / '
    return r[:-2]

def log(s):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = now + '  ' + s
    filename = 'record.log'
    with open(filename, "a") as file:
        file.write(line)
    

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        msg = ''
        if TCP in packet:
            msg = f"[ TCP ] {src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport} | Flags: {getFlags(packet[TCP].flags)}"
            if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                msg += "\n[ Alert ] Unencrypted HTTP traffic"
        elif UDP in packet:
            msg = f"[ UDP ] {src}:{packet[UDP].sport} -> {dst}:{packet[UDP].dport}"
            if (packet[UDP].dport == 53 or packet[UDP].sport == 53) and dst != ROUTER_IP and src != ROUTER_IP:
                msg = f"[ Alert ] Suspicious DNS traffic: {src} -> {dst}"
        else:
            msg = f"[ OTHER ] {src} -> {dst}"
        msg += '\n'
        print(msg, end='')
        log(msg)

scan_tracker = {}
def scan_detection(packet):
    if IP in packet and TCP in packet and packet[TCP].flags in ('S', 'SA', 'A'):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        now = time.time()

        if src_ip not in scan_tracker:
            scan_tracker[src_ip] = {"ports": set(), "first_seen": now}
        
        scan_tracker[src_ip]["ports"].add(dst_port)

        time_window = now - scan_tracker[src_ip]["first_seen"]
        port_count = len(scan_tracker[src_ip]["ports"])

        if port_count > 10 and time_window < 1.1:
            msg = f"[ALERT] Port scan detected from {src_ip} — {port_count} ports in {time_window:.1f}s"
            scan_tracker[src_ip]["alerted"] = True
            log(msg)


def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("--filter", type=str, default=None, help="BPF filter string")
    parser.add_argument("--count", type=int, default=0, help="Number of packets (0 = infinite)")
    parser.add_argument("--scan-detection", type=bool, default=False, help="Detect port scans using SYN packets")
    args = parser.parse_args()

    if args.scan_detection:
        print("Scan detection ..., Monitoring for SYN packets...")
        sniff(prn=scan_detection)
        return  

    print(f"Starting capture... filter={args.filter or 'none'}")
    packets = sniff(filter=args.filter, count=args.count, prn=process_packet)

    if not packets:
        print("No packets captured.")
        return
    print("Done")


if __name__ == "__main__":
    main()