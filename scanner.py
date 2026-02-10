import socket #network baat-cheet khatir. TCP connection chu ye banawaan.
import concurrent.futures # ye che threading
import argparse #te chu tto take input
import sys #ye chu to exit program
import ssl # ye chu for tls handshake and banner grabbing https banner
from scapy.all import  sr1, RandShort, send ,srp, ARP# ye chu for stealth scan s means send r means recieve and 1 means only 1
from scapy.layers.inet import IP, TCP , Ether# dk why i was unable to import them in scapy.all
import os # ye chu to check root previlidges
import errno #te chu deal kran for filtered errors in dropped packets

RED = "\033[91m"  # yim che colour
GREEN = "\033[92m"
RESET = "\033[0m"
def probe_http(sock, host): # ye chu to get banners from http services
    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent:FastPortScanner (+https://github.com/Afawn007/python-port-scanner)\r\n"
        f"Connection: close\r\n\r\n"
    )
    sock.sendall(request.encode())
    return sock.recv(4096).decode(errors="ignore").strip() # ye ker return value into banner
def arp_scan(cidr):
    arp_request = ARP(pdst=cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answer = srp(packet, timeout=1, verbose=False)[0]
    clients=[]
    for sent,received in answer:
        ip=received.psrc
        clients.append(ip)
    return clients
def probe_https(sock, host): # ye chu to get banners for https services
    # HTTPS manz chu pehlay TLS handshake zaroori
    context = ssl.create_default_context() # TLS context banao . Like es kyah rules ker set
    context.check_hostname= False # Certificate verification band (scanner behavior)
    context.verify_mode = ssl.CERT_NONE
    sock.settimeout(2)
    secure_socket=context.wrap_socket(sock, server_hostname=host)# TCP socket keriv TLS manz wrap
    request = ("HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: FastPortScanner\r\n"
        "Connection: close\r\n"
        "\r\n")
    secure_socket.sendall(request.encode())
    secure_socket.settimeout(2)
    response=b''
    while True:
        data = secure_socket.recv(4096)
        if not data:
            break
        response += data
    return response.decode(errors="ignore").strip()
def get_banner(sock):
    sock.settimeout(1)
    banner =sock.recv(1024).decode().strip()
    return banner
def sleath_scan(target,port):# ye chu stealth scan function
    src_port=RandShort()#  ye chu bcz aes chhu karun random port select as cource
    syn= IP(dst=target)/TCP(sport=src_port,dport=port,flags="S")# aes banov packet to send . S flag mean SYN
    res=sr1(syn,timeout=1,verbose=False)# response abd send together . syn means only listen to first response
    if res and res.haslayer(TCP) and res[TCP].flags ==0x12:
        # first we check res cha ti kin na . Then we check res manz cha tcp response and at last we check response in syn ack . In binary it is 0x12
        rst=IP(dst=target)/TCP(sport=src_port,dport=port,flags="R")# this is end connection ack packet
        send(rst,verbose=False)# we send close connection
        return port, "", "", "open"# if port is open return open
    elif res and res.haslayer(TCP) and res[TCP].flags in (0x14, 0x04):
        return port, "", "", "closed" 
    return port, "", "", "filtered"# return closed if port is closed
def scan_port(target,port):
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result=sock.connect_ex((target,port))
        if result==0:# port cha open
                try:
                    service=socket.getservbyport(port,"tcp")
                except :
                    service="unknown"
                try:
                    if port in (80, 8080):
                        banner = probe_http(sock, target)
                    elif port == 443:
                        banner = probe_https(sock, target)
                    else:
                        banner =get_banner(sock)
                except :
                    banner=''
                return port,service,banner,"open"
        elif result == errno.ECONNREFUSED:
            return port, "", "", "closed"
        elif result in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
            return port, "", "", "filtered"
        else:
            return port, "", "", "filtered"    
    except socket.error:
        return port,'','',"filtered"
    finally:
        sock.close()

def scan(target,start_port,end_port,max_workers):
    try:
        print(f"Scanning {target}")
        results=[]
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit( sleath_scan if args.S else scan_port, target, port)
                for port in range(start_port, end_port + 1)]
            total_ports=end_port-start_port+1
            # Iterate over futures jim gasen complete (not in submission order)
            #enumerate dee es id in 1 , 2 ,3
            # as_completed() yields futures the moment each thread finishes.
            closes=0
            for i,future in enumerate(concurrent.futures.as_completed(futures),start=1):
                # Get the result jim ker return scan_port()
                # This waits until THIS thread is done
                port,service,banner,success = future.result()
                # Save the result so we can print everything later
                results.append([port,service,banner,success])
                # Show scan progress on the same line
                # '\r' moves cursor back to start of the line
                sys.stdout.write(f"\r Progress: {i}/{total_ports}")
                # Force the progress text to show immediately
                sys.stdout.flush()
                # Move to a new line after progress is complete
        sys.stdout.write("\n")
        if args.output:
            print("Saving results to file")
            output_file(results,args.output)
        else:
            print(format_port_results(results))
            count=0
            for j in results:
                if j[3]=="closed" :
                    count +=1
            print(f"{count} ports are closed")
            filtered=0
            for i in results:
                if i[3]=="filtered":
                    filtered+=1
            print(f"{filtered} ports are filtered")
    except KeyboardInterrupt:
        sys.exit()
def format_port_results(results):# ye chu for looks
    print("Port Scanning Results:\n")
    formatted_results="Port Scanning Results:\n"
    formatted_results+="{:<9} {:<15} {:<10}{:<8}\n".format("Port","Service","Banner","Success")
    formatted_results+= '-' *85+"\n"
    # Sort results by port number
    results.sort(key=lambda x: x[0])
    for port,service,banner,success in results:
        if success == "open":
            formatted_results+=f"{RED} {port:<8} {service:<15} {'Open':<8}{RESET} \n"
            if banner:
                banner_lines = banner.split('\n')
                for line in banner_lines:
                    formatted_results += f"{GREEN}{'':<8}{line}{RESET}\n"
    return formatted_results
def output_file(results,output):
    with open(output,"w") as f:
        f.write("Port Scanning Results:\n")
        f.write("-"*85+"\n")
        for port,service,banner,success in results:
            if success =="open":
                f.write(f"{port} {service} Open\n")
                if banner:
                    for line in banner.split('\n'):
                        f.write(f"    {line}\n")

parser = argparse.ArgumentParser()
parser.add_argument("target_input",nargs="?",help="The target to scan")
parser.add_argument("--start_port",type=int,default=1,help="The starting port to scan")
parser.add_argument("--end_port",type=int,default=65535,help="The ending port to scan")
parser.add_argument("--max_workers",type=int,default=100,help="The maximum number of threads to use")
parser.add_argument("-p",type=int,default=0,help="Scanning all ports")
parser.add_argument("--output",   help="Save scan results to a file (txt or json)")
parser.add_argument("--S",action="store_true",help="Sleath Scan")
parser.add_argument("--subnet",help="Scan whole subnet")
parser.add_argument("--about", action="store_true", help=argparse.SUPPRESS)
parser.add_argument("--own",help="Ye chu banovmut by Afawn")
args = parser.parse_args()
target = None

if not args.subnet:
    if not args.target_input:
        print("You must provide a target host or use --subnet")
        sys.exit(1)

    try:
        target = socket.gethostbyname(args.target_input)
    except socket.gaierror:
        print("Hostname could not be resolved")
        sys.exit(1)
if args.p:
    start_port=1
    end_port=65535
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
if (args.S or args.subnet) and os.geteuid()!= 0:# we see if user running is sudo
    print("You must have root privileges for slealth scan")
    sys.exit(1)# 1 means error occured and exit code

if args.subnet:
    cidr=args.subnet
    clients=arp_scan(cidr)
    for target in clients:
        scan(target,start_port,end_port,max_workers)
else:
    scan(target, start_port, end_port, max_workers)
if args.about:
    print("Built to understand networks, not just scan them. — AK")
    sys.exit(0)    
    

