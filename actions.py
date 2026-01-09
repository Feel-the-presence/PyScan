from scapy.all import IP, TCP, sr1


def scan_ports(ports, target):
    for x in ports:
        packet = IP(dst=target) / TCP(dport=x, flags="S")
        response = sr1(packet, timeout=2, verbose=0)

        if response is None:
            print(f"Port [{x}] is filtered or host didn't respond")
            continue

        if response.haslayer(TCP):
            flags = response.getlayer(TCP).flags

            if flags == 0x12:
                print(f"[+] Port [{x}] is open")
            elif flags == 0x14:
                print(f"[-] Port [{x}] isn't open")
            else:
                print(f"[?] Port [{x}] returned unexpected TCP flags: {flags}")


def analyze_response():
    return 0
