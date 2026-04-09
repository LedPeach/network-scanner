import asyncio
import httpx
import subprocess
import csv
import re
import argparse
import sys

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

async def fetch_content(client, ip, port, csv_writer, semaphore):
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
                    
                    print(f"[+] FOUND: {ip}:{port} -> {content[:30]}...")
                    csv_writer.writerow([ip, port, content])
                    return 
            except Exception:
                continue

async def scan_network(subnet, concurrency, timeout):
    # Override config with CLI args if provided
    CONFIG["MAX_CONCURRENT_REQUESTS"] = concurrency
    CONFIG["TIMEOUT"] = timeout

    print(f"[*] Stage 1: Nmap scanning {subnet}...")
    nmap_cmd = ["nmap", "-p-", "-T4", "--open", "-oG", "-", subnet]
    
    process = await asyncio.create_subprocess_exec(
        *nmap_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        print(f"[!] Nmap Error: {stderr.decode()}")
        return

    output = stdout.decode()
    ip_pattern = re.compile(r"Host: (\d+\.\d+\.\d+\.\d+)")
    port_pattern = re.compile(r"(\d+)/open/tcp")

    tasks = []
    semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENT_REQUESTS"])

    print(f"[*] Stage 2: Probing open ports (Concurrency: {concurrency})...")
    
    with open(CONFIG["OUTPUT_FILE"], 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['address', 'port', 'curl_content'])

        async with httpx.AsyncClient(verify=False) as client:
            for line in output.splitlines():
                ip_match = ip_pattern.search(line)
                if ip_match:
                    ip = ip_match.group(1)
                    ports = port_pattern.findall(line)
                    for port in ports:
                        tasks.append(fetch_content(client, ip, port, writer, semaphore))

            if tasks:
                await asyncio.gather(*tasks)
            else:
                print("[!] No open ports discovered.")

    print(f"[*] Done. Results: {CONFIG['OUTPUT_FILE']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="High-Speed Network Service Scanner")
    parser.add_argument("subnet", help="Target subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--concurrency", type=int, default=CONFIG["MAX_CONCURRENT_REQUESTS"], help="Max simultaneous requests")
    parser.add_argument("--timeout", type=float, default=CONFIG["TIMEOUT"], help="Request timeout in seconds")
    
    args = parser.parse_args()

    try:
        asyncio.run(scan_network(args.subnet, args.concurrency, args.timeout))
    except KeyboardInterrupt:
        print("\n[!] User terminated scan.")
        sys.exit(0)
