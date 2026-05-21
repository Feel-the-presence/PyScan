from scapy.all import *
import socket

class NetworkScanner:
    def __init__(
        self, 
        target_ip: str, 
        ports_to_scan: list[int], 
        interface = None, 
        local_ip = None, 
        gateway_ip = None
    ) -> None:

        auto_iface, auto_local_ip, auto_gateway = conf.route.route(target_ip)

        self.interface = interface or auto_iface
        self.local_ip = local_ip or auto_local_ip
        self.gateway_ip = gateway_ip or auto_gateway

        self.target_ip: str = target_ip
        self.ports_to_scan: list[int] = ports_to_scan
        self.open_ports: list[int] = []
        """
            target_ip (str): IPv4-адрес цели для сканирования.
            ports_to_scan (list[int]): Список портов для проверки.
        """

    def arp_scan(self) -> dict:

        network_prefix = self.gateway_ip.rsplit('.', 1)[0]
        target_network = f"{network_prefix}.0/24"

        arp_frame = Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = target_network)
        answered, unanswered = srp(arp_frame, iface = self.interface, retry = 5, timeout = 3, verbose = False)   
        self.route_tab = {}

        for sent, received in answered:
            if received.psrc != self.local_ip:
                self.route_tab[received.psrc] = received.hwsrc
        
        return self.route_tab
        


    def scan_ports(self) -> None:

        self.open_ports = []

        if not self.ports_to_scan:
            return

        packet = IP(dst = self.target_ip)/TCP(dport = self.ports_to_scan, flags = "S")
        answered, unanswered = sr(packet, timeout = 2, verbose = False)

        for info, received_packet in answered:
            if received_packet.haslayer(TCP):
                if received_packet.getlayer(TCP).flags == "SA":
                    open_port = info[TCP].dport
                    if open_port not in self.open_ports:
                        self.open_ports.append(open_port)

                        rst_packet = IP(dst = self.target_ip)/TCP(dport = open_port, flags = "R")
                        send(rst_packet, verbose = 0)

    def grab_banner(self, port: int) -> str:

        #----------------------------
        #Забить на метод(временно) или позже доработать для исключений (FTP, HTTP, etc.)
        #----------------------------

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)

        try:
            s.connect((self.target_ip, port))
            probe = b"SERVER\r\n\r\n"
            s.send(probe)

            response_bytes = s.recv(1024)

            banner = response_bytes.decode("utf-8", errors="ignore").strip()
            return banner if banner else "No banner"

        except socket.timeout:
            return "Timed-out"
        except Exception as e:
            return f"Connection error: {e}"
        finally:
            s.close()

