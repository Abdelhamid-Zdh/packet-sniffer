from scapy.all import sniff, IP, TCP, UDP
import argparse

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        if TCP in packet:
            print(f"[ TCP ] {src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport}")

        elif UDP in packet:
            print(f"[ UDP ] {src}:{packet[UDP].sport} -> {dst}:{packet[UDP].dport}")
        else:
            # [OTHER] src -> dst, no ports
            print(f"[ OTHER ] {src} -> {dst}")




def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("--filter", type=str, default=None, help="BPF filter string")
    parser.add_argument("--count", type=int, default=0, help="Number of packets (0 = infinite)")
    args = parser.parse_args()

    print(f"Starting capture... filter={args.filter or 'none'}")
    packets = sniff(filter=args.filter, count=args.count, prn=process_packet)

    if not packets:
        print("No packets captured.")
        return
    print("Done")


if __name__ == "__main__":
    main()