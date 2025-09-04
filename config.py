import os
from typing import Optional

class Config:
    # Server configuration
    CALLBACK_SERVER_HOST: str = "127.0.0.1"
    CALLBACK_SERVER_PORT: int = 8081
    
    # Tool paths (adjust based on your system)
    GAUPLUS_PATH: str = "gauplus"
    QSREPLACE_PATH: str = "qsreplace"
    HTTPX_PATH: str = "httpx"
    NGROK_PATH: str = "ngrok"
    
    # File paths
    DATA_DIR: str = "data"
    VULNERABLE_ENDPOINTS_FILE: str = os.path.join(DATA_DIR, "vulnerable_endpoints.json")
    NGROK_CONFIG_FILE: str = os.path.join(DATA_DIR, "ngrok_info.json")
    
    # Request settings
    REQUEST_TIMEOUT: int = 30
    MAX_CONCURRENT_REQUESTS: int = 50
    USER_AGENT: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    
    # Excluded file extensions
    EXCLUDED_EXTENSIONS: list = [
        "png", "jpg", "gif", "jpeg", "swf", "woff", "svg", "css", "js",
        "ico", "pdf", "zip", "rar", "exe", "dmg", "mp4", "mp3", "avi"
    ]
