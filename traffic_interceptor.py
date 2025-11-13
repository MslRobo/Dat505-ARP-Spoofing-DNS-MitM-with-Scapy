import argparse
import os
import csv
import json
from collections import Counter
import scapy.all as scapy
from datetime import datetime
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSQR

#sudo python3 traffic_interceptor.py -i eth0 -o traffic_sniffing -d 20

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest = "interface", required=True, help='Network interface to capture on')
    parser.add_argument('-o', '--output', dest = "output", required=True, help='Output PCAP file')
    parser.add_argument('-d', '--duration', dest = "duration", type=int, help='Capture duration in seconds')
    options = parser.parse_args()
    if not options.interface:
        parser.error("Please specify an interface")
    elif not options.output:
        parser.error("Please specify an output dir")
    return options

def packet_handler(packet):
    packets.append(packet)
    statistics['packet_count'] += 1

    if scapy.IP in packet:
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        statistics['top_talkers'][f"{src_ip} to {dst_ip}"] += 1

        if scapy.TCP in packet:
            if packet[scapy.TCP].dport == 80 or packet[scapy.TCP].sport == 80:
                statistics['protocols']['HTTP'] += 1
            elif packet[scapy.TCP].dport == 443 or packet[scapy.TCP].sport == 443:
                statistics['protocols']['HTTPS'] += 1
            elif packet[scapy.TCP].dport == 22 or packet[scapy.TCP].sport == 22:
                statistics['protocols']['SSH'] += 1
            elif packet[scapy.TCP].dport == 21 or packet[scapy.TCP].sport == 21:
                statistics['protocols']['FTP'] += 1
            else:
                statistics['protocols']['TCP'] += 1
        elif scapy.UDP in packet:
            if packet[scapy.UDP].dport == 53 or packet[scapy.UDP].sport == 53:
                statistics['protocols']['DNS'] += 1
            else:
                statistics['protocols']['UDP'] += 1
        elif scapy.ICMP in packet:
            statistics['protocols']['ICMP'] += 1
        else:
            statistics['protocols']['Other'] += 1

    if HTTPRequest in packet:
        try:
            host = packet[HTTPRequest].Host.decode() if packet[HTTPRequest].Host else "Unknown"
            statistics['http_requests'].append({
                'timestamp': datetime.now().isoformat(),
                'method': packet[HTTPRequest].Method.decode() if packet[HTTPRequest].Method else "GET",
                'url': f"http://{packet[HTTPRequest].Host.decode() if packet[HTTPRequest].Host else 'Unknown'}{packet[HTTPRequest].Path.decode() if packet[HTTPRequest].Path else '/'}",
                'host': packet[HTTPRequest].Host.decode() if packet[HTTPRequest].Host else "Unknown",
                'src_ip': packet[scapy.IP].src,
                'dst_ip': packet[scapy.IP].dst
            })
        except Exception as e:
            pass
    
    if DNS in packet and DNSQR in packet:
        try:
            statistics['dns_queries'].append({
                'timestamp': datetime.now().isoformat(),
                'query': packet[DNSQR].qname.decode().rstrip('.'),
                'type': packet[DNSQR].qtype,
                'src_ip': packet[scapy.IP].src,
                'dst_ip': packet[scapy.IP].dst
            })
        except:
            pass

def save_analysis():
    try:
        scapy.wrpcap(output, packets)
        print(f"Packets saved to {output}")
    except Exception as e:
        print(f"Failed to save pcap, {e}")
    
    output_name = os.path.splitext(output)[0]
    http_file = f"{output_name}_http.csv"
    dns_file = f"{output_name}_dns.csv"
    statistics_file = f"{output_name}_statistics.json"

    statistics_short = {
        'top_talkers': dict(statistics['top_talkers'].most_common(5)),
        'dns_query_count': len(statistics['dns_queries']),
        'http_request_count': len(statistics['http_requests']),
    }

    try:
        with open(http_file, 'w') as f:
            if statistics['http_requests']:
                writer = csv.DictWriter(f, fieldnames=statistics['http_requests'][0].keys())
                writer.writeheader()
                writer.writerows(statistics['http_requests'])
    except Exception as e:
        print(f"Error saving http file, {e}")

    try:
        with open(dns_file, 'w') as f:
            if statistics['dns_queries']:
                writer = csv.DictWriter(f, fieldnames=statistics['dns_queries'][0].keys())
                writer.writeheader()
                writer.writerows(statistics['dns_queries'])
    except Exception as e:
        print(f"Error saving dns file, {e}")

    try:
        with open(statistics_file, 'w') as f:
            json.dump(statistics_short, f)
    except Exception as e:
        print(f"Error saving statistics, {e}")

def run_capture():
    print(f"Starting capture on {interface}")

    if duration:
        print(f"Duartion of capture: {duration} seconds")

    try:
        scapy.sniff(iface=interface, prn=packet_handler, timeout=duration, store=False)
    except Exception as e:
        print(f"Error capturing packets: {e}")

def main():
    output_dir = os.path.dirname(options.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        run_capture()
    except KeyboardInterrupt:
        pass
    finally:
        save_analysis()

options = get_args()
output = options.output
interface = options.interface
duration = options.duration
packets = []

statistics = {
    'packet_count': 0,
    'dns_queries': [],
    'http_requests': [],
    'top_talkers': Counter(),
    'protocols': Counter(),
}

main()