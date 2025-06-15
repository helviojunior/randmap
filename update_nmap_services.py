#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''
Author : Helvio Junior (M4v3r1cK)
'''

import requests
import re

URL = "https://raw.githubusercontent.com/nmap/nmap/refs/heads/master/nmap-services"
GO_FILE = "pkg/models/nmap_services.go"

def fetch_nmap_services():
    print("[*] Downloading nmap-services...")
    response = requests.get(URL)
    response.raise_for_status()
    return response.text.splitlines()

def parse_services(lines):
    services = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        parts = re.split(r'\s+', line)
        if len(parts) < 3:
            continue

        name = parts[0]
        port_proto = parts[1]
        frequency = parts[2]

        # Extract port and protocol
        if '/' not in port_proto:
            continue
        port_str, proto = port_proto.split('/')
        try:
            port = int(port_str)
            open_freq = float(frequency)
        except ValueError:
            continue

        services.append({
            "name": name,
            "port": port,
            "protocol": proto.lower(),
            "frequency": open_freq
        })

    return services

def generate_go_file(services):
    with open(GO_FILE, 'w') as f:
        f.write("package models\n\n")

        f.write("var nmap_services = []Service{\n")
        for svc in services:
            f.write("    {\n")
            f.write(f'        Name: "{svc["name"]}",\n')
            f.write(f'        Port: {svc["port"]},\n')
            f.write(f'        Protocol: "{svc["protocol"]}",\n')
            f.write(f'        OpenFrequency: {svc["frequency"]:.6f},\n')
            f.write("    },\n")
        f.write("}\n")

    print(f"[+] Generated {GO_FILE} with {len(services)} services.")

if __name__ == "__main__":
    lines = fetch_nmap_services()
    services = parse_services(lines)
    if len(services) < 100:
        print("[!] Error: Fail to update services")
    generate_go_file(services)