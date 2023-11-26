import os
import socket
import subprocess
import configparser
import time

def load_config():
    config = configparser.ConfigParser()
    config.read('guard.conf')
    return config

def parse_port_range(port_range):
    start, end = map(int, port_range.split('-'))
    return set(range(start, end + 1))

def scan_ports(port_range):
    config = load_config()
    ignored_ports = set(map(int, config['General']['ignored_ports'].split(',')))
    scan_timeout = int(config['General']['scan_timeout'])

    open_ports = []

    for port in port_range:
        if port not in ignored_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(scan_timeout)
                try:
                    start_time = time.time()
                    result = sock.connect_ex(('localhost', port))
                    elapsed_time = time.time() - start_time

                    if result == 0:
                        open_ports.append((port, elapsed_time))
                except Exception as e:
                    print(f"Error checking port {port}: {e}")

    return open_ports

def show_unused_ports():
    # Your logic to find unused ports goes here
    pass

def close_unused_ports(ports):
    for port in ports:
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'])
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP'])

def get_open_ports():
    # Your logic to get open ports and their protocols goes here
    pass

def main():
    config = load_config()
    tcp_port_range = parse_port_range(config['General']['tcp_port_range'])
    udp_port_range = parse_port_range(config['General']['udp_port_range'])

    open_tcp_ports = scan_ports(tcp_port_range)
    open_udp_ports = scan_ports(udp_port_range)

    print("Open TCP Ports:", open_tcp_ports)
    print("Open UDP Ports:", open_udp_ports)

    unused_ports = show_unused_ports()
    print("Unused Ports:", unused_ports)

    close_unused_ports(unused_ports)

    open_ports = get_open_ports()
    print("Open Ports in use:", open_ports)

if __name__ == "__main__":
    main()
