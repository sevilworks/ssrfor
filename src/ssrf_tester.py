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
    
    async def test_post_requests(self, post_requests: list, callback_url: str, ssrf_targets: list = None) -> dict:
        """
        Test POST requests for SSRF (blind and internal).
        post_requests: list of dicts with keys: url, headers, body, url_params (list of (k,v)), raw
        callback_url: the callback server URL for blind SSRF
        ssrf_targets: list of internal targets for internal SSRF (if None, only blind SSRF)
        Returns dict with 'blind' and 'internal' results.
        """
        import json as pyjson
        from urllib.parse import urlencode, parse_qs
        from difflib import SequenceMatcher
        results = {"blind": [], "internal": []}
        semaphore = asyncio.Semaphore(self.config.MAX_CONCURRENT_REQUESTS)
        # Blind SSRF: inject callback_url into each url-like param and send POST
        async def send_blind(req, param_k, orig_v):
            try:
                # Try JSON
                data = pyjson.loads(req['body'])
                data[param_k] = callback_url
                body_mod = pyjson.dumps(data)
                content_type = 'application/json'
            except Exception:
                # Fallback: form-encoded
                qs = parse_qs(req['body'])
                for k in qs:
                    qs[k] = qs[k][0] if isinstance(qs[k], list) and qs[k] else qs[k]
                qs[param_k] = callback_url
                body_mod = urlencode(qs)
                content_type = 'application/x-www-form-urlencoded'
            headers = dict(req['headers'])
            headers['Content-Type'] = content_type
            # Ensure all original headers are preserved, except Content-Type is set to match the body
            async with semaphore:
                try:
                    async with self.session.post(req['url'], data=body_mod, headers=headers, allow_redirects=False) as resp:
                        status = resp.status
                        text = await resp.text()
                        return {
                            "url": req['url'],
                            "param": param_k,
                            "status": status,
                            "body_snippet": text[:200],
                            "success": status == 200,
                            "type": "blind"
                        }
                except Exception as e:
                    return {"url": req['url'], "param": param_k, "error": str(e), "type": "blind"}
        # Internal SSRF: for each target, inject into each url-like param, send POST, compare to baseline
        async def send_internal(req, param_k, orig_v, targets):
            try:
                data = pyjson.loads(req['body'])
                body_base = pyjson.dumps(data)
                content_type = 'application/json'
            except Exception:
                qs = parse_qs(req['body'])
                for k in qs:
                    qs[k] = qs[k][0] if isinstance(qs[k], list) and qs[k] else qs[k]
                body_base = urlencode(qs)
                content_type = 'application/x-www-form-urlencoded'
            headers = dict(req['headers'])
            headers['Content-Type'] = content_type
            async with semaphore:
                try:
                    async with self.session.post(req['url'], data=body_base, headers=headers, allow_redirects=False) as resp:
                        base_status = resp.status
                        base_text = await resp.text()
                except Exception:
                    base_status = None
                    base_text = ''
            out = []
            for target in targets:
                try:
                    if content_type == 'application/json':
                        data2 = pyjson.loads(req['body'])
                        data2[param_k] = target
                        body_mod = pyjson.dumps(data2)
                    else:
                        qs2 = parse_qs(req['body'])
                        for k in qs2:
                            qs2[k] = qs2[k][0] if isinstance(qs2[k], list) and qs2[k] else qs2[k]
                        qs2[param_k] = target
                        body_mod = urlencode(qs2)
                    async with semaphore:
                        try:
                            async with self.session.post(req['url'], data=body_mod, headers=headers, allow_redirects=False) as resp2:
                                status2 = resp2.status
                                text2 = await resp2.text()
                                similarity = SequenceMatcher(None, base_text, text2).ratio()
                                is_interesting = False
                                if status2 != base_status:
                                    is_interesting = True
                                if similarity < 0.95:
                                    is_interesting = True
                                if any(x in text2.lower() for x in ["localhost", "127.0.0.1", "meta-data", "x-amz", "ec2", "internal", "root:x", "password", "admin"]):
                                    is_interesting = True
                                if status2 == 200 and is_interesting:
                                    out.append({
                                        "url": req['url'],
                                        "param": param_k,
                                        "target": target,
                                        "status": status2,
                                        "baseline_status": base_status,
                                        "similarity": similarity,
                                        "body_snippet": text2[:200],
                                        "is_interesting": is_interesting,
                                        "type": "internal"
                                    })
                        except Exception as e:
                            out.append({"url": req['url'], "param": param_k, "target": target, "error": str(e), "type": "internal"})
                except Exception as e:
                    out.append({"url": req['url'], "param": param_k, "target": target, "error": str(e), "type": "internal"})
            return out
        # Schedule all tasks
        blind_tasks = []
        internal_tasks = []
        for req in post_requests:
            url_params = req.get('url_params', [])
            for k, v in url_params:
                blind_tasks.append(send_blind(req, k, v))
                if ssrf_targets:
                    internal_tasks.append(send_internal(req, k, v, ssrf_targets))
        # Run all tasks
        blind_results = []
        if blind_tasks:
            for coro in tqdm(asyncio.as_completed(blind_tasks), total=len(blind_tasks), desc="POST Blind SSRF"):
                res = await coro
                blind_results.append(res)
        # Logger: print host and endpoint for each scanned POST request
        if blind_results:
            print("\nScanned POST requests (host + endpoint):")
            for res in blind_results:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(res['url'])
                    print(f"  Host: {parsed.netloc}  Endpoint: {parsed.path}")
                except Exception:
                    print(f"  [Error parsing URL] {res.get('url')}")
        internal_results = []
        if internal_tasks:
            for coro in tqdm(asyncio.as_completed(internal_tasks), total=len(internal_tasks), desc="POST Internal SSRF"):
                res = await coro
                if isinstance(res, list):
                    internal_results.extend(res)
                else:
                    internal_results.append(res)
        results['blind'] = blind_results
        results['internal'] = internal_results
        return results
