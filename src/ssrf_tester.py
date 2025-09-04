import aiohttp
import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse
import time
from tqdm import tqdm
from config import Config

class SSRFTester:
    def __init__(self):
        self.config = Config()
        self.session = None
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=self.config.MAX_CONCURRENT_REQUESTS)
        timeout = aiohttp.ClientTimeout(total=self.config.REQUEST_TIMEOUT)
        
        # Add ngrok-skip-browser-warning header to all requests
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "User-Agent": self.config.USER_AGENT,
                "ngrok-skip-browser-warning": "true"
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def test_single_url(self, url: str, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        """Test a single URL for SSRF"""
        async with semaphore:
            try:
                start_time = time.time()
                
                async with self.session.get(url, allow_redirects=True) as response:
                    end_time = time.time()
                    
                    return {
                        "url": url,
                        "status_code": response.status,
                        "response_time": end_time - start_time,
                        "content_length": len(await response.text()),
                        "headers": dict(response.headers),
                        "domain": urlparse(url).netloc,
                        "success": True
                    }
                    
            except asyncio.TimeoutError:
                return {
                    "url": url,
                    "error": "timeout",
                    "domain": urlparse(url).netloc,
                    "success": False
                }
            except Exception as e:
                return {
                    "url": url,
                    "error": str(e),
                    "domain": urlparse(url).netloc,
                    "success": False
                }
    
    async def test_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Test multiple URLs concurrently"""
        if not urls:
            return []
        
        semaphore = asyncio.Semaphore(self.config.MAX_CONCURRENT_REQUESTS)
        
        print(f"🔍 Testing {len(urls)} URLs for SSRF...")
        
        # Create tasks
        tasks = [self.test_single_url(url, semaphore) for url in urls]
        
        # Run with progress bar
        results = []
        with tqdm(total=len(tasks), desc="Testing URLs", unit="url") as pbar:
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                pbar.update(1)
                
                # Show successful requests in progress
                if result.get("success") and result.get("status_code") == 200:
                    pbar.set_postfix({"Status": f"✅ {result['status_code']}"})
        
        # Print summary
        successful = len([r for r in results if r.get("success", False)])
        failed = len(results) - successful
        status_200 = len([r for r in results if r.get("status_code") == 200])
        
        print(f"📈 Testing completed: {successful} successful, {failed} failed, {status_200} returned 200 OK")
        
        return results
