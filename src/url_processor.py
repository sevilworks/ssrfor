import subprocess
import tempfile
import os
from typing import List
from urllib.parse import urlparse
from config import Config
from colorama import Fore, Style
import threading
import sys
import concurrent.futures

class URLProcessor:
    def __init__(self):
        self.config = Config()
    
    def extract_urls_from_subdomains(self, subdomains_file, tools=None, use_katana=False):
        """
        Extract URLs using waybackurls (optionally katana).
        Now uses threading for fast extraction on large lists.
        """
        if not tools:
            tools = ["waybackurls"]
            if use_katana:
                tools.append("katana")
        all_urls = set()
        tool_counts = {}
        with open(subdomains_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        if not subdomains:
            print(f"{Fore.RED}❌ Subdomains file is empty!{Style.RESET_ALL}")
            return []
        for tool in tools:
            urls = set()
            print(f"{Fore.YELLOW}🔎 Using {tool} to extract URLs...{Style.RESET_ALL}")
            try:
                if tool == "waybackurls":
                    def run_wayback(sub):
                        cmd = ["waybackurls", sub]
                        return self.run_tool_with_interrupt(cmd)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
                        results = list(executor.map(run_wayback, subdomains))
                    for found in results:
                        urls.update(found)
                    print(f"{Fore.GREEN}  {tool}: {len(urls)} URLs found{Style.RESET_ALL}")
                elif tool == "katana":
                    def run_katana(sub):
                        cmd = ["katana", "-u", f"http://{sub}", "-silent"]
                        try:
                            return self.run_tool_with_interrupt(cmd)
                        except FileNotFoundError:
                            print(f"{Fore.YELLOW}⚠️  {tool} not found. Skipping katana URLs.{Style.RESET_ALL}")
                            return set()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                        results = list(executor.map(run_katana, subdomains))
                    katana_total = 0
                    for found in results:
                        urls.update(found)
                        katana_total += len(found)
                    print(f"{Fore.GREEN}  {tool}: {katana_total} URLs found{Style.RESET_ALL}")
                tool_counts[tool] = len(urls)
                all_urls.update(urls)
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️  {tool} failed: {e}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}URL extraction summary:{Style.RESET_ALL}")
        for tool, count in tool_counts.items():
            print(f"  {tool}: {count} URLs")
        sorted_urls = sorted(all_urls)
        print(f"{Fore.CYAN}Total unique URLs: {len(sorted_urls)}{Style.RESET_ALL}")
        return sorted_urls
    
    def filter_urls_with_params(self, urls: List[str]) -> List[str]:
        """Filter URLs that contain parameters with values containing http/https (plain or URL-encoded)"""
        from urllib.parse import unquote
        urls_with_url_params = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    params = parsed.query.split('&')
                    for param in params:
                        key_value = param.split('=', 1)
                        if len(key_value) == 2:
                            value = key_value[1]
                            decoded_value = unquote(value)
                            if decoded_value.startswith(('http://', 'https://')):
                                urls_with_url_params.append(url)
                                break
            except Exception:
                continue
        print(f"Found {len(urls_with_url_params)} URLs with URL parameters (plain or encoded)")
        return urls_with_url_params
    
    def replace_params_with_callback(self, urls, callback_url):
        """
        Replace URL-like parameters in the given URLs with the callback URL,
        and append the original URL as a query param (?origin=...) for tracking.
        """
        from urllib.parse import quote
        modified_urls = []
        for url in urls:
            # Append ?origin=<url> to callback URL for tracking
            if '?' in callback_url:
                cb_url = f"{callback_url}&origin={quote(url)}"
            else:
                cb_url = f"{callback_url}?origin={quote(url)}"
            # For each param, replace if URL-like, else keep
            parsed = urlparse(url)
            params = parsed.query.split('&')
            new_params = []
            for param in params:
                key_value = param.split('=', 1)
                if len(key_value) == 2:
                    value = key_value[1]
                    decoded_value = value
                    if decoded_value.startswith(('http://', 'https://', 'gopher://', 'dict://', 'php://', 'jar://', 'tftp://')):
                        new_params.append(f"{key_value[0]}={cb_url}")
                    else:
                        new_params.append(param)
                else:
                    new_params.append(param)
            new_query = '&'.join(new_params)
            new_url = url.replace(parsed.query, new_query)
            modified_urls.append(new_url)
        return modified_urls
    
    def extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return "unknown"
    
    def run_tool_with_interrupt(self, cmd, stdin_file=None):
        """
        Run a tool with the ability to interrupt (Ctrl+C) and return partial output.
        Returns: set of URLs (lines)
        """
        from io import StringIO
        urls = set()
        process = None
        output = StringIO()
        print(f"{Fore.YELLOW}Press Ctrl+C to skip this tool and use found URLs so far...{Style.RESET_ALL}")
        try:
            if stdin_file:
                with open(stdin_file, 'r') as inp:
                    process = subprocess.Popen(cmd, stdin=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            else:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    output.write(line)
            except KeyboardInterrupt:
                print(f"{Fore.YELLOW}\nInterrupted! Skipping to next tool...{Style.RESET_ALL}")
                # Kill the process and use what we have so far
                process.terminate()
                process.wait(timeout=2)
            urls = set(output.getvalue().splitlines())
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️  Tool failed or interrupted: {e}{Style.RESET_ALL}")
        return urls
