from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse
import uvicorn
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any
from config import Config
from .database import Database

class CallbackServer:
    def __init__(self):
        self.app = FastAPI(
            title="SSRF Detection Callback Server",
            description="Handles SSRF callbacks and logs vulnerable endpoints",
            version="1.0.0"
        )
        self.config = Config()
        self.db = Database()
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.get("/")
        async def root():
            stats = self.db.get_stats()
            ngrok_info = self.db.load_ngrok_info()
            
            return HTMLResponse(f"""
            <html>
                <head>
                    <title>SSRF Detection Server</title>
                    <meta http-equiv="refresh" content="10">
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                        .container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                        .stat {{ background: #e8f4f8; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                        .vuln {{ background: #ffe8e8; padding: 15px; margin: 10px 0; border-radius: 5px; color: #d8000c; }}
                        .success {{ background: #e8f8e8; padding: 15px; margin: 10px 0; border-radius: 5px; color: #4caf50; }}
                        .ngrok-info {{ background: #fff3cd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                        a {{ color: #007bff; text-decoration: none; }}
                        a:hover {{ text-decoration: underline; }}
                        .code {{ background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🎯 SSRF Detection Server</h1>
                        <p><strong>Status:</strong> <span class="success">✅ Online and monitoring</span></p>
                        
                        <div class="ngrok-info">
                            <h3>🌐 Ngrok Tunnel Info</h3>
                            <p><strong>Public URL:</strong> <code>{ngrok_info.get('public_url', 'Not configured')}</code></p>
                            <p><strong>Local Server:</strong> <code>http://127.0.0.1:8081</code></p>
                            <p><strong>Callback Endpoint:</strong> <code>{ngrok_info.get('public_url', 'https://your-ngrok-url')}/callback</code></p>
                        </div>
                        
                        <div class="stat">
                            <h3>📊 Statistics</h3>
                            <p><strong>Total Vulnerabilities:</strong> {stats['total_vulnerabilities']}</p>
                            <p><strong>Unique Domains:</strong> {stats['unique_domains']}</p>
                            <p><strong>Latest Discovery:</strong> {stats['latest_discovery'] or 'None yet'}</p>
                        </div>
                        
                        <h3>🔗 Quick Links</h3>
                        <p><a hr Failed to get ngrok public URLef="/stats">📈 Detailed Statistics</a></p>
                        <p><a href="/vulnerabilities">🐛 View All Vulnerabilities</a></p>
                        <p><a href="/callback">🔗 Test Callback Endpoint</a></p>
                        
                        <div class="stat">
                            <h3>🚀 Usage</h3>
                            <p>Run a scan with:</p>
                            <div class="code">python main.py scan -s subdomains.txt</div>
                        </div>
                        
                        <p><small>⟳ Page auto-refreshes every 10 seconds</small></p>
                    </div>
                </body>
            </html>
            """)
        
        @self.app.get("/callback")
        @self.app.post("/callback")
        @self.app.put("/callback")
        @self.app.delete("/callback")
        @self.app.patch("/callback")
        async def callback_handler(request: Request, background_tasks: BackgroundTasks):
            # Log the callback
            background_tasks.add_task(self.log_callback, request)
            
            return JSONResponse({
                "status": "success",
                "message": "SSRF callback received!",
                "timestamp": datetime.now().isoformat(),
                "method": request.method,
                "url": str(request.url)
            })
        
        @self.app.get("/stats")
        async def get_stats():
            stats = self.db.get_stats()
            return JSONResponse(stats)
        
        @self.app.get("/vulnerabilities")
        async def get_vulnerabilities():
            vulnerabilities = self.db.load_vulnerable_endpoints()
            return JSONResponse(vulnerabilities)
        
        @self.app.get("/health")
        async def health_check():
            return JSONResponse({"status": "healthy", "timestamp": datetime.now().isoformat()})
    
    async def log_callback(self, request: Request):
        """Log the callback and save vulnerable endpoint, extracting origin param if present"""
        try:
            client_ip = request.client.host
            user_agent = request.headers.get("user-agent", "")
            referer = request.headers.get("referer", "")
            query_params = dict(request.query_params)
            origin_url = query_params.get("origin")
            # Use origin param if present, else fallback to referer or direct_access
            vulnerable_url = origin_url if origin_url else (referer if referer else "direct_access")
            domain = urlparse(vulnerable_url).netloc if vulnerable_url else "direct"
            endpoint_data = {
                "callback_ip": client_ip,
                "user_agent": user_agent,
                "referer": referer,
                "method": request.method,
                "path": str(request.url.path),
                "query_params": query_params,
                "headers": dict(request.headers),
                "vulnerable_url": vulnerable_url,
                "domain": domain,
                "callback_received_at": datetime.now().isoformat(),
                "detection_method": "callback_server"
            }
            self.db.save_vulnerable_endpoint(endpoint_data)
            print(f"\n🎯 [SSRF VULNERABILITY DETECTED] 🎯")
            print(f"Domain: {endpoint_data['domain']}")
            print(f"Vulnerable URL: {endpoint_data['vulnerable_url']}")
            print(f"Callback IP: {client_ip}")
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 60)
        except Exception as e:
            print(f"Error logging callback: {e}")
    
    def run(self, host: str = None, port: int = None):
        """Run the callback server"""
        host = host or self.config.CALLBACK_SERVER_HOST
        port = port or self.config.CALLBACK_SERVER_PORT
        
        print(f"🚀 Starting callback server on {host}:{port}")
        print(f"📊 Dashboard: http://{host}:{port}")
        uvicorn.run(self.app, host=host, port=port, log_level="info")
