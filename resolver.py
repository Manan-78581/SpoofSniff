import dns.resolver
import dns.exception
import json
import time
import os

TRUSTED_DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '9.9.9.9'] # Google DNS, Cloudflare DNS, Quad9

CACHE_FILE = 'cache.json'
POSITIVE_CACHE_TTL_SECONDS = 3600  # 1 hour for valid IP mappings
NEGATIVE_CACHE_TTL_SECONDS = 300   # 5 minutes for non-existent domains

dns_cache = {} # Global cache dictionary

def load_dns_cache():
    """
    Loads the DNS cache from the CACHE_FILE.
    """
    global dns_cache
    if os.path.exists(CACHE_FILE) and os.path.getsize(CACHE_FILE) > 0:
        try:
            with open(CACHE_FILE, 'r') as f:
                dns_cache = json.load(f)
            print(f"[CACHE] Loaded {len(dns_cache)} entries from {CACHE_FILE}")
        except json.JSONDecodeError as e:
            print(f"[CACHE] Error loading cache from {CACHE_FILE}: {e}. Starting with empty cache.")
            dns_cache = {}
    else:
        print(f"[CACHE] {CACHE_FILE} not found or empty. Starting with empty cache.")
        dns_cache = {}

def save_dns_cache():
    """
    Saves the current DNS cache to the CACHE_FILE.
    Removes expired entries before saving.
    """
    global dns_cache
    try:
        current_time = time.time()
        # Create a new dictionary for valid entries to save
        cleaned_cache = {}
        for domain, data in dns_cache.items():
            cache_type = data.get('type') # 'positive' or 'negative'
            timestamp = data.get('timestamp', 0)
            
            if cache_type == 'positive' and (current_time - timestamp) < POSITIVE_CACHE_TTL_SECONDS:
                cleaned_cache[domain] = data
            elif cache_type == 'negative' and (current_time - timestamp) < NEGATIVE_CACHE_TTL_SECONDS:
                cleaned_cache[domain] = data
            # else: entry is expired or malformed, don't add to cleaned_cache

        dns_cache = cleaned_cache # Update global cache with cleaned version
        
        with open(CACHE_FILE, 'w') as f:
            json.dump(dns_cache, f, indent=4)
        print(f"[CACHE] Saved {len(dns_cache)} entries to {CACHE_FILE}")
    except Exception as e:
        print(f"[CACHE] Error saving cache to {CACHE_FILE}: {e}")

def get_trusted_ips(domain_name, record_types=['A', 'AAAA']):
    """
    Performs DNS lookups for the given domain and record types using trusted DNS servers
    or retrieves it from cache. Returns a dictionary of {record_type: ip_address}.
    Handles negative caching for NXDOMAIN.
    """
    if isinstance(domain_name, bytes):
        try:
            domain_str = domain_name.decode('utf-8').rstrip('.')
        except UnicodeDecodeError:
            print(f"[-] Could not decode domain name: {domain_name}")
            return {}
    else:
        domain_str = domain_name.rstrip('.')

    if not domain_str:
        return {}

    resolved_ips = {}
    current_time = time.time()
    
    # 1. Check cache first
    if domain_str in dns_cache:
        cached_data = dns_cache[domain_str]
        cache_timestamp = cached_data.get('timestamp', 0)
        cache_type = cached_data.get('type')

        # --- NEGATIVE CACHING IMPLEMENTATION ---
        if cache_type == 'negative' and (current_time - cache_timestamp) < NEGATIVE_CACHE_TTL_SECONDS:
            # print(f"[CACHE] Returning cached NXDOMAIN for {domain_str}")
            return {'NXDOMAIN': True} # Indicate it's a known non-existent domain
        # --- END NEGATIVE CACHING ---
        
        if cache_type == 'positive':
            # Check if all requested record types are present and not expired
            all_cached_and_valid = True
            for rtype in record_types:
                if rtype not in cached_data.get('ips', {}) or \
                   (current_time - cache_timestamp) >= POSITIVE_CACHE_TTL_SECONDS:
                    all_cached_and_valid = False
                    break
            
            if all_cached_and_valid:
                # print(f"[CACHE] Returning cached IPs for {domain_str}: {cached_data['ips']}")
                return cached_data['ips']

    # 2. If not in cache or expired, perform live lookup
    resolver = dns.resolver.Resolver()
    resolver.nameservers = TRUSTED_DNS_SERVERS
    
    live_resolved_ips = {}
    
    for rtype in record_types:
        try:
            answer = resolver.resolve(domain_str, rtype)
            if answer:
                live_resolved_ips[rtype] = answer[0].to_text()
        except dns.resolver.NoAnswer:
            pass 
        except dns.resolver.NXDOMAIN:
            # --- NEGATIVE CACHING IMPLEMENTATION ---
            # Domain does not exist for any queried type
            # Cache as negative lookup
            dns_cache[domain_str] = {'type': 'negative', 'timestamp': current_time}
            print(f"[CACHE] Cached NXDOMAIN for {domain_str}.")
            return {'NXDOMAIN': True} # Signal non-existent domain
            # --- END NEGATIVE CACHING ---
        except dns.exception.Timeout:
            print(f"[-] Timeout resolving {domain_str} ({rtype}) via trusted DNS. Not caching.")
            return {} # Return empty if timeout
        except Exception as e:
            print(f"[-] An unexpected error occurred while resolving {domain_str} ({rtype}): {e}. Not caching.")
            return {}

    if live_resolved_ips:
        # Cache positive lookup result
        dns_cache[domain_str] = {'type': 'positive', 'ips': live_resolved_ips, 'timestamp': current_time}
        # print(f"[CACHE] Stored live IPs for {domain_str}: {live_resolved_ips}")
    
    return live_resolved_ips

if __name__ == "__main__":
    print("Testing resolver.py with advanced cache...")
    load_dns_cache()

    print("\n--- Lookup for google.com (A & AAAA) ---")
    ips_google = get_trusted_ips("google.com", ['A', 'AAAA'])
    print(f"google.com: {ips_google}")

    print("\n--- Lookup for example.com (A only) ---")
    ips_example_a = get_trusted_ips("example.com", ['A'])
    print(f"example.com (A): {ips_example_a}")

    print("\n--- Lookup for example.com (from cache, should be fast) ---")
    ips_example_cached = get_trusted_ips("example.com", ['A'])
    print(f"example.com (cached A): {ips_example_cached}")

    print("\n--- Lookup for non-existent-domain-xyz12345.com (NXDOMAIN) ---")
    ips_nx = get_trusted_ips("non-existent-domain-xyz12345.com", ['A'])
    print(f"non-existent-domain-xyz12345.com: {ips_nx}")

    print("\n--- Lookup for non-existent-domain-xyz12345.com (from negative cache) ---")
    ips_nx_cached = get_trusted_ips("non-existent-domain-xyz12345.com", ['A'])
    print(f"non-existent-domain-xyz12345.com (cached NX): {ips_nx_cached}")
    
    # Temporarily reduce TTL for testing expiry
    # POSITIVE_CACHE_TTL_SECONDS = 2
    # NEGATIVE_CACHE_TTL_SECONDS = 2
    # print(f"\n--- Simulating {NEGATIVE_CACHE_TTL_SECONDS + 1} seconds passing to expire negative cache ---")
    # time.sleep(NEGATIVE_CACHE_TTL_SECONDS + 1)
    # print("\n--- Lookup for non-existent-domain-xyz12345.com again (should be live after expiry) ---")
    # ips_nx_expired = get_trusted_ips("non-existent-domain-xyz12345.com", ['A'])
    # print(f"non-existent-domain-xyz12345.com (after expiry simulation): {ips_nx_expired}")

    save_dns_cache()
    print("\nCache testing complete.")