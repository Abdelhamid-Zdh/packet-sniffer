from scapy.all import sniff, IP, TCP, UDP

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
    print("Capturing packets (count=20, timeout=10s)...")
    packets = sniff(count=20, timeout=10, prn=process_packet)

    if not packets:
        print("No packets were captured.")
        return

    print('Done')


if __name__ == "__main__":
    main()