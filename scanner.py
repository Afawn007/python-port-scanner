import socket  # network baat-cheet khatir. TCP connection chu ye banawaan.
import concurrent.futures  # ye che threading
import argparse  # te chu tto take input
import sys  # ye chu to exit program
import ssl  # ye chu for tls handshake and banner grabbing https banner
from scapy.all import sr1, RandShort, send, srp, \
    ARP  # ye chu for stealth scan s means send r means recieve and 1 means only 1
from scapy.layers.inet import IP, TCP, Ether  # dk why i was unable to import them in scapy.all
from scapy.all import ICMP
from scapy.layers.inet import UDP
import os  # ye chu to check root previlidges
import errno  # te chu deal kran for filtered errors in dropped packets
import ipaddress # for arp scanning

RED = "\033[91m"  # yim che colour
GREEN = "\033[92m"
RESET = "\033[0m"


def probe_http(sock, host):  # ye chu to get banners from http services
    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent:FastPortScanner (+https://github.com/Afawn007/python-port-scanner)\r\n"
        f"Connection: close\r\n\r\n"
    )
    try:
        sock.sendall(request.encode())
        return sock.recv(4096).decode(errors="ignore").strip()  # ye ker return value into banner
    except (socket.timeout, OSError):
        return ""


def arp_scan(cidr):
     try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print(f"[!] Invalid CIDR: {cidr}")
        sys.exit(1)
    arp_request = ARP(pdst=cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answer = srp(packet, timeout=1, verbose=False)[0]
    clients = []
    for sent, received in answer:
        ip = received.psrc
        clients.append(ip)
    return clients


def probe_https(sock, host):  # ye chu to get banners for https services
    # HTTPS manz chu pehlay TLS handshake zaroori
    context = ssl.create_default_context()  # TLS context banao . Like es kyah rules ker set
    context.check_hostname = False  # Certificate verification band (scanner behavior)
    context.verify_mode = ssl.CERT_NONE
    sock_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_2.settimeout(2)
    secure_socket = None
    try:
        sock_2.connect((host, 443))
        secure_socket = context.wrap_socket(sock_2, server_hostname=host)  # TCP socket keriv TLS manz wrap
        request = ("HEAD / HTTP/1.1\r\n"
                   f"Host: {host}\r\n"
                   "User-Agent: FastPortScanner\r\n"
                   "Connection: close\r\n"
                   "\r\n")
        secure_socket.sendall(request.encode())
        secure_socket.settimeout(2)
        response = b''
        while True:
            data = secure_socket.recv(4096)
            if not data:
                break
            response += data
        return response.decode(errors="ignore").strip()
    except (ssl.SSLError, socket.timeout):
        return ""
    finally:
        if secure_socket:
            secure_socket.close()

def get_banner(sock):
    sock.settimeout(1)
    try:
        return sock.recv(1024).decode(errors="ignore").strip()
    except (socket.timeout, OSError):
        return ""


def udp_scan(target, port):
    """
    UDP scan using Scapy.
    open|filtered  — no response (UDP is stateless; silence ≠ closed)
    closed         — ICMP port-unreachable received
    Requires root.
    """
    pkt = IP(dst=target) / UDP(dport=port) # Es che packet banawan
    res = sr1(pkt, timeout=2, verbose=False)# s mean send and r1  means wait for first response

    if res is None:
        return port, "unknown", "", "open|filtered"

    if res.haslayer(ICMP):
        icmp = res[ICMP]
        # type 3 code 3 = port unreachable
        if int(icmp.type) == 3 and int(icmp.code) == 3:
            return port, "", "", "closed"
        # other ICMP unreachables → administratively filtered
        if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 9, 10, 13):
            return port, "", "", "filtered"

    if res.haslayer(UDP):
        try:
            service = socket.getservbyport(port, "udp")
        except OSError:
            service = "unknown"
        return port, service, "", "open"

    return port, "", "", "open|filtered"

def sleath_scan(target, port):  # ye chu stealth scan function
    src_port = RandShort()  # ye chu bcz aes chhu karun random port select as cource
    syn = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")  # aes banov packet to send . S flag mean SYN
    res = sr1(syn, timeout=1, verbose=False)  # response abd send together . syn means only listen to first response
    if res and res.haslayer(TCP) and res[TCP].flags == 0x12:
        # first we check res cha ti kin na . Then we check res manz cha tcp response and at last we check response in syn ack . In binary it is 0x12
        rst = IP(dst=target) / TCP(sport=src_port, dport=port, flags="R")  # this is end connection ack packet
        send(rst, verbose=False)  # we send close connection
        service = socket.getservbyport(port, "tcp")
        return port, service, "", "open"  # if port is open return open
    elif res and res.haslayer(TCP) and res[TCP].flags in (0x14, 0x04):
        return port, "", "", "closed"
    return port, "", "", "filtered"  # return closed if port is closed


def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((target, port))
        if result == 0:  # port cha open
            try:
                service = socket.getservbyport(port, "tcp")
            except:
                service = "unknown"
            try:
                if port in (80, 8080):
                    banner = probe_http(sock, target)
                elif port == 443:
                    banner = probe_https(sock, target)
                else:
                    banner = get_banner(sock)
            except Exception:
                banner = ''
            return port, service, banner, "open"
        elif result == errno.ECONNREFUSED:
            return port, "", "", "closed"
        elif result in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
            return port, "", "", "filtered"
        else:
            return port, "", "", "filtered"
    except socket.error:
        return port, '', '', "filtered"
    finally:
        sock.close()


def scan(target, start_port, end_port, max_workers , sleath=False, udp=False, output=None):
    if sleath:
        scan_fn = lambda p: sleath_scan(target, p)
    elif udp:
        scan_fn = lambda p: udp_scan(target, p)
    else:
        scan_fn = lambda p: scan_port(target, p)
    print(f"Scanning {target}")
    results = []
    total = end_port - start_port + 1
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(scan_fn ,p)
                for p in range(start_port, end_port + 1)]
            # Iterate over futures jim gasen complete (not in submission order)
            # enumerate dee es id in 1 , 2 ,3
            # as_completed() yields futures the moment each thread finishes.
            closes = 0
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                results.append(future.result())
                sys.stdout.write(f"\r[*] Progress: {i}/{total}")
                sys.stdout.flush()
            sys.stdout.write("\n")
        sys.stdout.write("\n")
    except KeyboardInterrupt:
        sys.stdout.write("\n[!] Scan interrupted.\n")
        sys.exit()
    open_ports = [r for r in results if r[-1] == "open"]
    closed_ports = [r for r in results if r[-1] == "closed"]
    filtered_ports = [r for r in results if r[-1] in ("filtered", "open|filtered")]

    print(f"  Open:     {len(open_ports)}")
    print(f"  Closed:   {len(closed_ports)}")
    print(f"  Filtered: {len(filtered_ports)}")
    print(format_port_results(results))
    if output:
        output_file(results, output)


def format_port_results(results):  # ye chu for looks
    header = f"{'Port':<9}{'Service':<15}{'State':<12}\n"
    header += "-" * 60 + "\n"
    body = ""
    for port, service, banner, state in sorted(results, key=lambda x: x[0]):
        if state == "open":
            body += f"{RED}{port:<9}{service:<15}{'Open':<12}{RESET}\n"
            if banner:
                for line in banner.split("\n"):
                    body += f"{GREEN}         {line}{RESET}\n"
        elif state == "open|filtered":
            body += f"{port:<9}{service:<15}{'Open|Filtered':<12}\n"
    return header + body


def output_file(results, output):
    with open(output, "w") as f:
        f.write("Port Scanning Results:\n")
        f.write("-" * 85 + "\n")
        for port, service, banner, state in sorted(results, key=lambda x: x[0]):
            if state in ("open", "open|filtered"):
                f.write(f"{port:<9}{service:<15}{state}\n")
                if banner:
                    for line in banner.split("\n"):
                        f.write(f"         {line}\n")
    print(f"[+] Results saved to {output}")

def parser_ok():
    p = argparse.ArgumentParser(
        description="FastPortScanner — TCP/SYN/UDP port scanner"
    )
    p.add_argument("target_input", nargs="?", help="Host or IP to scan")
    p.add_argument("--start_port", type=int, default=1, help="First port (default 1)")
    p.add_argument("--end_port", type=int, default=1024, help="Last port (default 1024)")
    p.add_argument("--max_workers", type=int, default=100, help="Thread count (default 100)")
    p.add_argument("-p", action="store_true", help="Scan all 65535 ports")
    p.add_argument("--output", help="Save results to file")
    p.add_argument("-S", action="store_true", help="SYN stealth scan (root only)")
    p.add_argument("-U", action="store_true", help="UDP scan (root only)")
    p.add_argument("--subnet", help="ARP scan a subnet (e.g. 192.168.1.0/24)")
    p.add_argument("--about", action="store_true", help=argparse.SUPPRESS)
    return p
def main():
    parser = parser_ok()
    args = parser.parse_args()
    if args.about:
        print("Built to understand networks, not just scan them. — AK")
        sys.exit(0)
    if (args.S or args.U or args.subnet) and os.geteuid() != 0:  # we see if user running is sudo
        print("You must have root privileges for slealth scan")
        sys.exit(1)  # 1 means error occured and exit code
    target = None

    if not args.subnet and not args.target_input:
        print(" You must provide a target host or use --subnet")
        sys.exit(1)
    if args.target_input:
        try:
                target = socket.gethostbyname(args.target_input)
        except socket.gaierror:
                print("Hostname could not be resolved")
                sys.exit(1)
    if args.p:
        start_port = 1
        end_port = 65535
    else:
        start_port = args.start_port
        end_port = args.end_port
    max_workers = args.max_workers
    if start_port > end_port:
        print("Start port must be smaller than end port")
        sys.exit()
    if start_port < 1 or end_port > 65535:
        print("Ports must be between 1 and 65535")
        sys.exit()

    if args.subnet:
        cidr = args.subnet
        clients = arp_scan(cidr)
        if not clients:
            print(" No live hosts found.")
            sys.exit(0)
        print(f"[+] Found {len(clients)} live host(s): {', '.join(clients)}")
        for target in clients:
            scan(target, start_port, end_port, max_workers, sleath=args.S, udp=args.U, output=args.output)
    else:
        scan(target, start_port, end_port, max_workers,sleath=args.S, udp=args.U, output=args.output)

if __name__ == "__main__":
    main()
