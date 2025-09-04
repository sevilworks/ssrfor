"""
# SSRF Detection Tool

A comprehensive Python tool for automated Server-Side Request Forgery (SSRF) vulnerability detection.

## Features

- **Automated URL Extraction**: Uses `gauplus` to extract URLs from subdomains
- **Parameter Detection**: Identifies URLs with parameters that could be vulnerable
- **Callback Server**: Built-in FastAPI server to receive SSRF callbacks
- **Concurrent Testing**: Asynchronous testing for improved performance
- **Database Logging**: Automatically saves discovered vulnerabilities
- **Statistics**: View statistics and discovered vulnerabilities
- **Web Interface**: Simple web interface for monitoring

## Installation

1. Clone the repository
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install required tools:
   ```bash
   # Install go tools
   go install github.com/lc/gau/v2/cmd/gau@latest
   go install github.com/bp0lr/gauplus@latest
   go install github.com/tomnomnom/qsreplace@latest
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   ```

## Usage

### 1. Start the Callback Server

First, start the callback server that will receive SSRF hits:

```bash
python main.py server --host 0.0.0.0 --port 8081
```

The server will be accessible at `http://your-ip:8081`

### 2. Run SSRF Scan

In another terminal, run the scan:

```bash
python main.py scan -s subdomains.txt -c http://your-server:8081/callback
```

### 3. View Results

Check statistics:
```bash
python main.py stats
```

List all discovered vulnerabilities:
```bash
python main.py list-vulns
```

Or visit `http://your-server:8081/stats` and `http://your-server:8081/vulnerabilities` in your browser.

## Configuration

Edit `config.py` to customize:
- Server settings
- Tool paths
- Request settings
- File extensions to exclude

## Project Structure

```
ssrf-detector/
├── main.py                 # Main CLI interface
├── config.py              # Configuration settings
├── requirements.txt       # Python dependencies
├── src/
│   ├── url_processor.py   # URL extraction and processing
│   ├── ssrf_tester.py     # Asynchronous SSRF testing
│   ├── callback_server.py # FastAPI callback server
│   └── database.py        # Data storage and retrieval
└── data/
    └── vulnerable_endpoints.json  # Discovered vulnerabilities
```

## Example Workflow

1. Prepare a file with subdomains (one per line)
2. Start the callback server
3. Run the scan with your callback URL
4. Monitor the server logs for SSRF hits
5. Check discovered vulnerabilities using CLI or web interface

## API Endpoints

- `GET /` - Main dashboard
- `GET /callback` - SSRF callback endpoint
- `GET /stats` - Vulnerability statistics
- `GET /vulnerabilities` - List all vulnerabilities

## Security Note

This tool is designed for authorized security testing only. Always ensure you have proper permission before testing any systems.
"""