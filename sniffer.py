# sniffer.py
from scapy.all import sniff, UDP, DNS, DNSQR, DNSRR, IP, IPv6
import threading
import time
import collections
import queue # Import queue

# We will no longer directly call show_alert from here.
# Instead, we send messages to the GUI via a queue.
from alert import log_event
from resolver import get_trusted_ips, TRUSTED_DNS_SERVERS as GLOBAL_TRUSTED_DNS_SERVERS # Ensure get_trusted_ips is imported

# Global set to store domains that we've already alerted on to avoid spamming
ALERTED_DOMAINS = set()
ALERT_COOLDOWN_SECONDS = 300 # 5 minutes

# --- ADDED FOR GRACEFUL SHUTDOWN ---
stop_sniffer_event = threading.Event()

def should_stop_sniffer(packet):
    """
    Callback function for sniff's stop_filter.
    Returns True if the stop_sniffer_event is set, signaling sniff to stop.
    """
    return stop_sniffer_event.is_set()
# --- END ADDITION ---

# --- TRANSACTION ID MATCHING IMPLEMENTATION ---
# Stores { (client_ip, client_port, dns_id): (domain_name, timestamp) }
pending_queries = {}
# Max time a query is considered valid/pending (e.g., 5 seconds)
QUERY_TIMEOUT_SECONDS = 5
# Lock for thread-safe access to pending_queries
queries_lock = threading.Lock()

# Function to clean up old queries from pending_queries
def cleanup_pending_queries():
    current_time = time.time()
    with queries_lock:
        keys_to_remove = [
            (client_ip, client_port, dns_id)
            for (client_ip, client_port, dns_id), (domain, timestamp) in pending_queries.items()
            if (current_time - timestamp) > QUERY_TIMEOUT_SECONDS
        ]
        for key in keys_to_remove:
            # print(f"[DEBUG] Cleaning up expired query ID: {key[2]} for {pending_queries[key][0]}")
            del pending_queries[key]
    # Schedule next cleanup
    threading.Timer(QUERY_TIMEOUT_SECONDS, cleanup_pending_queries).start()

cleanup_thread_started = False # Flag to ensure cleanup thread starts only once
# --- END TRANSACTION ID MATCHING ---

# --- BASIC DNS SERVER SOURCE VALIDATION IMPLEMENTATION ---
# Add the IPs of your actual configured DNS servers (e.g., your router's IP if it's a DNS relay, or your ISP's DNS)
# You can find these by running 'ipconfig /all' on Windows or 'cat /etc/resolv.conf' on Linux.
# Example: If your router is 192.168.1.1 and it acts as DNS, add that.
# Or if you manually set Google DNS on your client, add 8.8.8.8.
# If this list is empty, this check will be skipped.
TRUSTED_LOCAL_DNS_SERVERS = ['192.168.1.1', '192.168.0.1'] # <--- IMPORTANT: CONFIGURE THIS FOR YOUR NETWORK!
TRUSTED_LOCAL_DNS_SERVERS.extend(GLOBAL_TRUSTED_DNS_SERVERS) # Add global trusted DNS servers from resolver
TRUSTED_LOCAL_DNS_SERVERS = list(set(TRUSTED_LOCAL_DNS_SERVERS)) # Remove duplicates
# --- END DNS SERVER SOURCE VALIDATION ---

# Global queue variable to be set by start_sniffer
gui_message_queue = None 

def process_dns_packet(packet):
    """
    Processes a captured packet to check for DNS spoofing.
    Handles both DNS queries (QR=0) and responses (QR=1).
    Sends alerts to the GUI queue.
    """
    global cleanup_thread_started
    global gui_message_queue # Access the global queue

    if not cleanup_thread_started:
        cleanup_pending_queries() # Start the cleanup timer
        cleanup_thread_started = True

    if packet.haslayer(DNS):
        try:
            queried_domain = None
            if packet.haslayer(DNSQR):
                queried_domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')

            dns_id = packet[DNS].id
            client_ip = None
            if packet.haslayer(IP):
                client_ip = packet[IP].src
            elif packet.haslayer(IPv6):
                client_ip = packet[IPv6].src
            
            client_port = packet[UDP].sport # Source port of the UDP packet (client's port)
            dns_server_ip = None
            if packet.haslayer(IP):
                dns_server_ip = packet[IP].dst if packet[DNS].qr == 0 else packet[IP].src
            elif packet.haslayer(IPv6):
                dns_server_ip = packet[IPv6].dst if packet[DNS].qr == 0 else packet[IPv6].src

            # DNS Query (QR=0)
            if packet[DNS].qr == 0:
                if queried_domain:
                    # --- TRANSACTION ID MATCHING IMPLEMENTATION ---
                    with queries_lock:
                        # Store the query details with timestamp
                        # Key: (client_ip, client_port, dns_id) - to identify unique queries from a client
                        # Value: (domain_name, timestamp)
                        pending_queries[(client_ip, client_port, dns_id)] = (queried_domain, time.time())
                    # --- END TRANSACTION ID MATCHING ---
                    # You might send query info to GUI for a "Live Traffic" view
                    # if gui_message_queue: gui_message_queue.put(f"[INFO] Query: {queried_domain} from {client_ip}", "info")

            # DNS Response (QR=1)
            elif packet[DNS].qr == 1 and packet.haslayer(DNSRR):
                # print(f"[DEBUG] Captured DNS response: {queried_domain} ID: {dns_id}") # For internal debugging only

                # --- BASIC DNS SERVER SOURCE VALIDATION IMPLEMENTATION ---
                if TRUSTED_LOCAL_DNS_SERVERS and dns_server_ip not in TRUSTED_LOCAL_DNS_SERVERS:
                    message = (
                        f"DNS Spoofing Suspect: Response from unexpected DNS server!\n"
                        f"  Domain     : {queried_domain}\n"
                        f"  Source IP  : {dns_server_ip} (NOT IN TRUSTED LIST)\n"
                        f"  Expected   : {', '.join(TRUSTED_LOCAL_DNS_SERVERS)}"
                    )
                    if queried_domain not in ALERTED_DOMAINS: # Apply cooldown
                         if gui_message_queue: gui_message_queue.put((message, "alert"))
                         ALERTED_DOMAINS.add(queried_domain)
                         threading.Timer(ALERT_COOLDOWN_SECONDS, lambda: ALERTED_DOMAINS.discard(queried_domain)).start()
                    # Continue to check other spoofing signs, as it might be both
                # --- END BASIC DNS SERVER SOURCE VALIDATION ---

                # --- TRANSACTION ID MATCHING IMPLEMENTATION ---
                query_key = (client_ip, packet[UDP].dport, dns_id) # dport for response is client's sport for query
                matched_query_domain = None
                with queries_lock:
                    if query_key in pending_queries:
                        matched_query_domain, _ = pending_queries.pop(query_key) # Remove once matched
                    # else:
                        # This means we received a DNS response without seeing a corresponding query.
                        # This could be legitimate (e.g., query before sniffer started),
                        # but also suspicious (e.g., unsolicited response, attacker response injection).
                        # We'll alert if the domain matches something we're tracking, but prioritize query match.
                        # For now, if no query matched, we'll use the domain from the response.

                if not matched_query_domain:
                    if queried_domain not in ALERTED_DOMAINS:
                        message = (
                            f"DNS Spoofing Suspect: Unsolicited or Mismatched Transaction ID!\n"
                            f"  Domain     : {queried_domain}\n"
                            f"  Transaction ID: {hex(dns_id)} (No matching query or expired)\n"
                            f"  Source DNS : {dns_server_ip}"
                        )
                        if gui_message_queue: gui_message_queue.put((message, "alert"))
                        ALERTED_DOMAINS.add(queried_domain)
                        threading.Timer(ALERT_COOLDOWN_SECONDS, lambda: ALERTED_DOMAINS.discard(queried_domain)).start()
                    matched_query_domain = queried_domain # Use the domain from the response itself
                # --- END TRANSACTION ID MATCHING ---

                # 3. Extract all returned A and AAAA IPs
                returned_ips = {'A': [], 'AAAA': []}
                if packet[DNS].an: # Check if there are any answer records in the 'an' (answer) section
                    for rr in packet[DNS].an: # Iterate directly over answer records
                        if rr.type == 1: # A record
                            returned_ips['A'].append(rr.rdata)
                        elif rr.type == 28: # AAAA record
                            returned_ips['AAAA'].append(rr.rdata)
                
                # Check against trusted IPs (from resolver)
                if matched_query_domain and (returned_ips['A'] or returned_ips['AAAA']):
                    # Get trusted IPs for both A and AAAA
                    trusted_ips_dict = get_trusted_ips(matched_query_domain, ['A', 'AAAA'])
                    
                    # --- NEGATIVE CACHING DETECTION (from resolver's perspective) ---
                    if trusted_ips_dict.get('NXDOMAIN', False):
                        if (returned_ips['A'] or returned_ips['AAAA']) and matched_query_domain not in ALERTED_DOMAINS:
                            message = (
                                f"DNS Spoofing Detected: NXDOMAIN Spoofing!\n"
                                f"  Domain     : {matched_query_domain} (Trusted: Non-existent)\n"
                                f"  Reported IPs: A={returned_ips['A']}, AAAA={returned_ips['AAAA']}\n"
                                f"  Source DNS : {dns_server_ip}"
                            )
                            if gui_message_queue: gui_message_queue.put((message, "alert"))
                            ALERTED_DOMAINS.add(matched_query_domain)
                            threading.Timer(ALERT_COOLDOWN_SECONDS, lambda: ALERTED_DOMAINS.discard(matched_query_domain)).start()
                        return # Stop processing if it's an NXDOMAIN spoof, don't check IP mismatches
                    # --- END NEGATIVE CACHING DETECTION ---

                    # Compare A records
                    spoofed_a = False
                    if trusted_ips_dict.get('A') and returned_ips['A']:
                        # If trusted has A and we received A, check if the received A is one of the trusted ones
                        if not any(ip in returned_ips['A'] for ip in [trusted_ips_dict['A']]): # Assuming resolver returns only one trusted A for simplicity for now
                            spoofed_a = True
                    # elif trusted_ips_dict.get('A') and not returned_ips['A']:
                        # Trusted has A, but response didn't provide it (could be benign or spoofed omission)
                        # For now, don't flag as spoof if just missing, focus on mismatch

                    # Compare AAAA records
                    spoofed_aaaa = False
                    if trusted_ips_dict.get('AAAA') and returned_ips['AAAA']:
                        if not any(ip in returned_ips['AAAA'] for ip in [trusted_ips_dict['AAAA']]):
                            spoofed_aaaa = True
                    # elif trusted_ips_dict.get('AAAA') and not returned_ips['AAAA']:
                        # Trusted has AAAA, but response didn't provide it

                    # If either A or AAAA is spoofed, or trusted has no record but we got IPs (e.g. for NXDOMAIN already caught above)
                    if (spoofed_a or spoofed_aaaa) and matched_query_domain not in ALERTED_DOMAINS:
                        message = (
                            f"DNS Spoofing Detected: IP Mismatch!\n"
                            f"  Domain     : {matched_query_domain}\n"
                            f"  Reported IPs: A={returned_ips['A']}, AAAA={returned_ips['AAAA']}\n"
                            f"  Trusted IPs : A={trusted_ips_dict.get('A')}, AAAA={trusted_ips_dict.get('AAAA')}\n"
                            f"  Source DNS : {dns_server_ip}"
                        )
                        if gui_message_queue: gui_message_queue.put((message, "alert"))
                        ALERTED_DOMAINS.add(matched_query_domain)
                        threading.Timer(ALERT_COOLDOWN_SECONDS, lambda: ALERTED_DOMAINS.discard(matched_query_domain)).start()

        except Exception as e:
            # Send errors to GUI as well
            error_message = f"[-] Error processing DNS packet ({packet.summary()}): {e}"
            if gui_message_queue: gui_message_queue.put((error_message, "error"))
            log_event(f"ERROR: Packet processing error: {e} - Packet: {packet.summary()}")
            pass


def start_sniffer(q: queue.Queue):
    """
    Starts the network sniffer to capture DNS UDP packets on port 53.
    Messages (including alerts) are sent to the provided queue.
    """
    global gui_message_queue
    gui_message_queue = q # Store the queue passed from GUI
    
    q.put((f"Starting SpoofSniff DNS monitoring...", "info"))
    q.put((f"Configured Trusted Local DNS Servers: {TRUSTED_LOCAL_DNS_SERVERS if TRUSTED_LOCAL_DNS_SERVERS else 'None (DNS server source validation skipped)'}", "info"))
    q.put(("Waiting for DNS queries and responses on UDP port 53...", "info"))
    log_event("SpoofSniff started monitoring DNS traffic (via GUI).")
    try:
        sniff(filter="udp and port 53", prn=process_dns_packet, store=0, stop_filter=should_stop_sniffer)
        q.put(("\nSpoofSniff stopped gracefully.", "info"))
        log_event("SpoofSniff stopped gracefully (via GUI).")
    except OSError as e:
        error_msg = f"\n[!!! ERROR !!!] Permission denied or network interface issue: {e}"
        q.put((error_msg, "error"))
        q.put(("Please ensure you run this script with sufficient privileges (e.g., sudo on Linux).", "error"))
        q.put(("Also, check if your network interface is up and running.", "error"))
        log_event(f"ERROR: Sniffer failed to start due to OSError: {e}")
    except Exception as e:
        error_msg = f"\n[!!! ERROR !!!] An unexpected error occurred while sniffing: {e}"
        q.put((error_msg, "error"))
        log_event(f"ERROR: Sniffer failed to start due to unexpected error: {e}")

# This __name__ == "__main__" block is for direct testing (won't use the queue).
# The main application flow runs via main.py -> gui.py
if __name__ == "__main__":
    print("Running sniffer.py directly (for testing without GUI)...")
    print("This will not exit until you press Ctrl+C.")
    # Create a dummy queue for direct testing
    dummy_q = queue.Queue()
    start_sniffer(dummy_q)