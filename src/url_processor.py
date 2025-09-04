import subprocess
import tempfile
import os
from typing import List
from urllib.parse import urlparse
from config import Config
from colorama import Fore, Style
import threading
import sys

class URLProcessor:
    def __init__(self):
        self.config = Config()
    
    def extract_urls_from_subdomains(self, subdomains_file, tools=None, use_katana=False):
        """
        Extract URLs using multiple tools: gauplus, gau, waybackurls, (optionally katana).
        tools: list of tool names to use (default: gauplus, gau, waybackurls; katana only if use_katana=True)
        use_katana: if True, also use katana for crawling
        Returns: sorted list of unique URLs
        """
        if not tools:
            tools = ["gauplus", "gau", "waybackurls"]
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
                with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
                    for sub in subdomains:
                        tmp.write(sub + '\n')
                    tmp_path = tmp.name
                if tool == "gauplus":
                    cmd = [Config().GAUPLUS_PATH, "-subs", "-b", "png,jpg,gif,jpeg,swf,woff,svg,css,js,ico,pdf,zip,rar,exe,dmg,mp4,mp3,avi"]
                    urls = self.run_tool_with_interrupt(cmd, stdin_file=tmp_path)
                    print(f"{Fore.GREEN}  {tool}: {len(urls)} URLs found{Style.RESET_ALL}")
                elif tool == "gau":
                    cmd = ["gau", "--threads", "10"]
                    urls = self.run_tool_with_interrupt(cmd, stdin_file=tmp_path)
                    print(f"{Fore.GREEN}  {tool}: {len(urls)} URLs found{Style.RESET_ALL}")
                elif tool == "waybackurls":
                    cmd = ["waybackurls"]
                    urls = self.run_tool_with_interrupt(cmd, stdin_file=tmp_path)
                    print(f"{Fore.GREEN}  {tool}: {len(urls)} URLs found{Style.RESET_ALL}")
                elif tool == "katana":
                    katana_total = 0
                    for sub in subdomains:
                        cmd = ["katana", "-u", f"http://{sub}", "-silent"]
                        try:
                            found = self.run_tool_with_interrupt(cmd)
                            urls.update(found)
                            katana_total += len(found)
                        except FileNotFoundError:
                            print(f"{Fore.YELLOW}⚠️  {tool} not found. Skipping katana URLs.{Style.RESET_ALL}")
                            break
                    print(f"{Fore.GREEN}  {tool}: {katana_total} URLs found{Style.RESET_ALL}")
                tool_counts[tool] = len(urls)
                all_urls.update(urls)
                os.unlink(tmp_path)
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️  {tool} failed: {e}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}URL extraction summary:{Style.RESET_ALL}")
        for tool, count in tool_counts.items():
            print(f"  {tool}: {count} URLs")
        sorted_urls = sorted(all_urls)
        print(f"{Fore.CYAN}Total unique URLs: {len(sorted_urls)}{Style.RESET_ALL}")
        return sorted_urls
    
    def filter_urls_with_params(self, urls: List[str]) -> List[str]:
        """Filter URLs that contain parameters"""
        urls_with_params = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query and '=' in parsed.query:
                    urls_with_params.append(url)
            except Exception:
                continue
        
        print(f"Found {len(urls_with_params)} URLs with parameters")
        return urls_with_params
    
    def replace_params_with_callback(self, urls: List[str], callback_url: str) -> List[str]:
        """Replace URL parameters with callback URL using qsreplace"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as input_file:
                input_file.write('\n'.join(urls))
                input_temp = input_file.name
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as output_file:
                output_temp = output_file.name
            
            # Run qsreplace
            cmd = [self.config.QSREPLACE_PATH, callback_url]
            
            with open(input_temp, 'r') as f_in, open(output_temp, 'w') as f_out:
                process = subprocess.run(
                    cmd,
                    stdin=f_in,
                    stdout=f_out,
                    stderr=subprocess.PIPE,
                    text=True
                )
            
            if process.returncode != 0:
                print(f"Error running qsreplace: {process.stderr}")
                return []
            
            # Read results
            modified_urls = []
            with open(output_temp, 'r') as f:
                modified_urls = [line.strip() for line in f if line.strip()]
            
            # Clean up temp files
            os.unlink(input_temp)
            os.unlink(output_temp)
            
            print(f"Generated {len(modified_urls)} modified URLs")
            return modified_urls
            
        except Exception as e:
            print(f"Error replacing parameters: {e}")
            return []
    
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
