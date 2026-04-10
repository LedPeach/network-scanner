import asyncio
import httpx
import subprocess
import csv
import re
import sys
import ipaddress
import argparse

# ==========================================
# USER CONFIGURATION (Adjust these values)
# ==========================================
CONFIG = {
    "MAX_CONCURRENT_REQUESTS": 200,
    "TIMEOUT": 3.0,
    "OUTPUT_FILE": "scan_results.csv",
    "PROTOCOLS": ["http", "https"],
    "FOLLOW_REDIRECTS": True
}
# ==========================================

def get_ip_int(ip_str):
    """Converts an IP string to an integer for math operations."""
    try:
        return int(ipaddress.ip_address(ip_str))
    except ValueError:
        return 0

async def fetch_content(client, ip, port, csv_writer, semaphore):
    """Attempts to curl the port using HTTP and HTTPS."""
    async with semaphore:
        for proto in CONFIG["PROTOCOLS"]:
            url = f"{proto}://{ip}:{port}"
            try:
                response = await client.get(
                    url, 
                    timeout=CONFIG["TIMEOUT"], 
                    follow_redirects=CONFIG["FOLLOW_REDIRECTS"]
                )
                if response.status_code == 200:
                    content = response.text.strip().replace('\n', ' ').replace('\r', '')
                    content = (content[:100] + '...') if len(content) > 100 else content
                    
                    # We print to stdout, but since Stage 2 is fast, 
                    # it won't disrupt the Stage 1 progress bar too much.
                    print(f"\n[+] FOUND: {ip}:{port} -> {content[:30]}...")
                    csv_writer.writerow([ip, port, content])
                    return 
            except Exception:
                continue

async def scan_network(subnet_str, concurrency, timeout):
    # Override config with CLI args
    CONFIG["MAX_CONCURRENT_REQUESTS"] = concurrency
    CONFIG["TIMEOUT"] = timeout

    # 1. Calculate Subnet Bounds for Progress Bar
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
        total_ips = network.num_addresses
        start_ip_int = int(network.network_address)
    except ValueError as e:
        print(f"[!] Invalid Subnet: {e}")
        return

    print(f"[*] Target Subnet: {subnet_str} ({total_ips} addresses)")
    print(f"[*] Stage 1: Nmap scanning (this may take a while)...")

    # 2. Start Nmap as an asynchronous subprocess
    nmap_cmd = ["nmap", "-p-", "-T4", "--open", "-oG", "-", subnet_str]
    process = await asyncio.create_subprocess_exec(
        *nmap_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    found_hosts = []
    last_ip = subnet_str # Fallback
    ip_pattern = re.compile(r"Host: (\d+\.\d+\.\d+\.\d+)")
    port_pattern = re.compile(r"(\d+)/open/tcp")

    # 3. Stream Nmap output line-by-line for real-time feedback
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        
        decoded_line = line.decode().strip()
        ip_match = ip_pattern.search(decoded_line)
        
        if ip_match:
            ip = ip_match.group(1)
            last_ip = ip
            ports = port_pattern.findall(decoded_line)
            for p in ports:
                found_hosts.append((ip, p))

            # Calculate progress based on the integer value of the last IP found
            current_ip_int = get_ip_int(ip)
            progress = ((current_ip_int - start_ip_int) / total_ips) * 100
            
            # The '\r' returns the cursor to the start of the line to overwrite it
            sys.stdout.write(
                f"\r[Progress: {progress:6.2f}%] | Last IP: {ip:15} | Hosts Found: {len(found_hosts):4}"
            )
            sys.stdout.flush()

    await process.wait()
    print(f"\n[*] Stage 1 Complete. Total hosts with open ports: {len(found_hosts)}")

    if not found_hosts:
        print("[!] No open ports discovered. Exiting.")
        return

    # 4. Stage 2: Async Probing
    print(f"[*] Stage 2: Probing {len(found_hosts)} hosts via HTTP/HTTPS...")
    semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENT_REQUESTS"])

    with open(CONFIG["OUTPUT_FILE"], 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['address', 'port', 'curl_content'])

        async with httpx.AsyncClient(verify=False) as client:
            tasks = [fetch_content(client, ip, port, writer, semaphore) for ip, port in found_hosts]
            await asyncio.gather(*tasks)

    print(f"[*] All tasks finished. Results saved to {CONFIG['OUTPUT_FILE']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="High-Speed Network Service Scanner")
    parser.add_argument("subnet", help="Target subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--concurrency", type=int, default=CONFIG["MAX_CONCURRENT_REQUESTS"])
    parser.add_argument("--timeout", type=float, default=CONFIG["TIMEOUT"])
    
    args = parser.parse_args()

    try:
        asyncio.run(scan_network(args.subnet, args.concurrency, args.timeout))
    except KeyboardInterrupt:
        print("\n[!] User terminated scan.")
        sys.exit(0)
