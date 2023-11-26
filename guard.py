import os
import socket
import subprocess
import configparser
import socketserver
import time
import smtplib
from email.mime.text import MIMEText
import logging
import datetime

def setup_logging():
    current_datetime = datetime.datetime.now()
    log_timestamp = current_datetime.strftime("%Y-%m-%d_%H:%M")
    log_filename = f"/home/guardlog/{log_timestamp}.txt"

    log_format = "%(asctime)s - %(levelname)s - %(message)s"

    logging.basicConfig(filename=log_filename, level=logging.INFO, format=log_format)

    # Log to console as well
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(log_format)
    console_handler.setFormatter(formatter)
    logging.getLogger('').addHandler(console_handler)

    logging.info("Logging started.")

# Add this line at the beginning of your main() function or __main__ block
setup_logging()

def log_suspicious_activity(source_ip, port):
    config = load_config()
    log_message = f"Suspicious activity from {source_ip} on port {port}"

    with open(config['General']['log_file'], 'a') as log_file:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"{timestamp} - {log_message}\n")
        print(log_message)

    if config.getboolean('Email', 'send_notification', fallback=True):
        send_email(log_message)

def send_email(message):
    config = load_config()
    smtp_server = config['Email']['smtp_server']
    smtp_port = config['Email']['smtp_port']
    smtp_username = config['Email']['smtp_username']
    smtp_password = config['Email']['smtp_password']
    admin_email = config['Email']['admin_email']

    subject = 'Suspicious Activity Detected'
    body = f"Subject: {subject}\n\n{message}"

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_username, admin_email, body)


class OpenPortChecker(socketserver.BaseRequestHandler):
    def handle(self):
        pass  # Do nothing, just want to check if the port is open

def load_config():
    config = configparser.ConfigParser()
    config.read('guard.conf')
    return config

def parse_port_range(port_range):
    start, end = map(int, port_range.split('-'))
    return set(range(start, end + 1))

def is_port_open(port):
    try:
        with socketserver.TCPServer(('localhost', port), OpenPortChecker) as server:
            return True
    except OSError:
        return False

def log_suspicious_activity(source_ip, port):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} - Suspicious activity from {source_ip} on port {port}\n"
    with open('suspicious_activity.log', 'a') as log_file:
        log_file.write(log_message)
    print(log_message)

def block_ip(source_ip):
    subprocess.run(['iptables', '-A', 'INPUT', '-s', source_ip, '-j', 'DROP'])
    print(f"Blocked IP: {source_ip}")

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
                    result = sock.connect_ex(('localhost', port))

                    if result == 0:
                        open_ports.append(port)
                        log_suspicious_activity('localhost', port)
                except Exception as e:
                    print(f"Error checking port {port}: {e}")

    return open_ports

def show_unused_ports():
    # Your logic to find unused ports goes here
    pass

def block_suspicious_ips():
    # Your logic to block suspicious IPs goes here
    pass

def get_open_ports():
    # Your logic to get open ports and their protocols goes here
    pass

def main():
    config = load_config()
    tcp_port_range = parse_port_range(config['General']['tcp_port_range'])
    udp_port_range = parse_port_range(config['General']['udp_port_range'])

    open_tcp_ports = scan_ports(tcp_port_range)
    open_udp_ports = scan_ports(udp_port_range)

    logging.info("Open TCP Ports: %s", open_tcp_ports)
    logging.info("Open UDP Ports: %s", open_udp_ports)


    unused_ports = show_unused_ports()
    print("Unused Ports:", unused_ports)

    if config.getboolean('General', 'block_suspicious_ips', fallback=False):
        block_suspicious_ips()

    open_ports = get_open_ports()
    print("Open Ports in use:", open_ports)

if __name__ == "__main__":
    main()
