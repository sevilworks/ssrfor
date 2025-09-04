import json
import os
from datetime import datetime
from typing import List, Dict, Any
from config import Config

class Database:
    def __init__(self):
        self.config = Config()
        self._ensure_data_dir()
    
    def _ensure_data_dir(self):
        """Ensure data directory exists"""
        if not os.path.exists(self.config.DATA_DIR):
            os.makedirs(self.config.DATA_DIR)
    
    def save_vulnerable_endpoint(self, endpoint_data: Dict[str, Any]):
        """Save vulnerable endpoint to database"""
        try:
            # Load existing data
            data = self.load_vulnerable_endpoints()
            
            # Add timestamp
            endpoint_data["discovered_at"] = datetime.now().isoformat()
            endpoint_data["id"] = len(data) + 1
            
            # Append new endpoint
            data.append(endpoint_data)
            
            # Save back to file
            with open(self.config.VULNERABLE_ENDPOINTS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
                
            return True
        except Exception as e:
            print(f"Error saving endpoint: {e}")
            return False
    
    def load_vulnerable_endpoints(self) -> List[Dict[str, Any]]:
        """Load vulnerable endpoints from database"""
        try:
            if os.path.exists(self.config.VULNERABLE_ENDPOINTS_FILE):
                with open(self.config.VULNERABLE_ENDPOINTS_FILE, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"Error loading endpoints: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about discovered vulnerabilities"""
        data = self.load_vulnerable_endpoints()
        
        stats = {
            "total_vulnerabilities": len(data),
            "unique_domains": len(set(item.get("domain", "") for item in data)),
            "latest_discovery": None,
            "endpoints_by_domain": {}
        }
        
        if data:
            # Sort by discovery time
            sorted_data = sorted(data, key=lambda x: x.get("discovered_at", ""), reverse=True)
            stats["latest_discovery"] = sorted_data[0].get("discovered_at")
            
            # Count by domain
            for item in data:
                domain = item.get("domain", "unknown")
                stats["endpoints_by_domain"][domain] = stats["endpoints_by_domain"].get(domain, 0) + 1
        
        return stats
    
    def save_ngrok_info(self, ngrok_data: Dict[str, Any]):
        """Save ngrok tunnel information"""
        try:
            with open(self.config.NGROK_CONFIG_FILE, 'w') as f:
                json.dump(ngrok_data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving ngrok info: {e}")
            return False
    
    def load_ngrok_info(self) -> Dict[str, Any]:
        """Load ngrok tunnel information"""
        try:
            if os.path.exists(self.config.NGROK_CONFIG_FILE):
                with open(self.config.NGROK_CONFIG_FILE, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Error loading ngrok info: {e}")
            return {}
