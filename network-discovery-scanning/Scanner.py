import socket
import argparse
import datetime
import icmplib


def is_host_alive(ip):
    is_alive = icmplib.ping(str(ip), count=3, interval=0.1).is_alive
    return is_alive


def scan_ip_range(start_ip, end_ip):
    active_ips = []
    for ip in range(int(start_ip.split('.')[-1]), int(end_ip.split('.')[-1]) + 1):
        current_ip = ".".join(start_ip.split('.')[:-1]) + '.' + str(ip)
        if is_host_alive(current_ip):
            active_ips.append(current_ip)
    return active_ips


def scan_tcp_ports(ip, start_port, end_port):
    open_tcp_ports = []
    for port in range(start_port, end_port + 1):
        if is_port_open(ip, port, socket.SOCK_STREAM):
            open_tcp_ports.append(port)
    return open_tcp_ports


def is_port_open_udp(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            return True

    except (socket.timeout, socket.error):
        return False


def scan_udp_ports(ip, start_port, end_port):
    open_udp_ports = []
    for port in range(start_port, end_port + 1):
        if is_port_open_udp(ip, port):
            open_udp_ports.append(port)
    return open_udp_ports


def is_port_open(ip, port, sock_type):
    try:
        with socket.socket(socket.AF_INET, sock_type) as s:
            s.settimeout(1)
            s.connect((ip, port))
        return True
    except (socket.timeout, socket.error):
        return False


def save_report(filename, content):
    with open(filename, 'a') as file:
        file.write(content)


def generate_report(ip_range, active_ips, open_tcp_ports, open_udp_ports):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_content = f"Scan Report - {timestamp}\n"
    report_content += f"IP Range: {ip_range}\n\n"

    if active_ips:
        report_content += "Active IP Addresses:\n"
        for ip in active_ips:
            report_content += f"- {ip}\n"
        report_content += "\n"

    if open_tcp_ports:
        report_content += "Open TCP Ports:\n"
        for port in open_tcp_ports:
            report_content += f"- Port {port} is open\n"
        report_content += "\n"

    if open_udp_ports:
        report_content += "Open UDP Ports:\n"
        for port in open_udp_ports:
            report_content += f"- Port {port} is open\n"
        report_content += "\n"

    return report_content


def main():
    parser = argparse.ArgumentParser(description="Network Scanning Tool")
    parser.add_argument('--ipscan', action='store_true', help='Scan IP range')
    parser.add_argument('--portscan', action='store_true', help='Scan ports')
    parser.add_argument('--tcp', nargs=2, type=int, help='Specify TCP port range')
    parser.add_argument('--udp', nargs=2, type=int, help='Specify UDP port range')
    parser.add_argument('-m', '--subnet-mask', type=int, help='Subnet mask for IP scan')
    parser.add_argument('-ip', '--ip-range', nargs=2, help='IP range for scan')

    args = parser.parse_args()

    active_ips, open_tcp_ports, open_udp_ports = [], [], []

    if args.ipscan:
        start_ip, end_ip = args.ip_range
        active_ips = scan_ip_range(start_ip, end_ip)
        print("Active IP addresses:", active_ips)

    elif args.portscan:
        if args.tcp:
            start_port, end_port = args.tcp
            start_ip, end_ip = args.ip_range
            active_ips = scan_ip_range(start_ip, end_ip)
            for ip in active_ips:
                open_tcp_ports.extend(scan_tcp_ports(ip, start_port, end_port))
                print(f"Open TCP ports on {ip}: {open_tcp_ports}")

        elif args.udp:
            start_port, end_port = args.udp
            start_ip, end_ip = args.ip_range
            active_ips = scan_ip_range(start_ip, end_ip)
            for ip in active_ips:
                open_udp_ports.extend(scan_udp_ports(ip, start_port, end_port))
                print(f"Open UDP ports on {ip}: {open_udp_ports}")

    report_content = generate_report(args.ip_range, active_ips, open_tcp_ports, open_udp_ports)
    save_report('scan_report.txt', report_content)


if __name__ == "__main__":
    main()
