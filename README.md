# FedSIG+ ThreatNet 🛡️

**Production-Ready Federated Cyber Threat Intelligence Sharing System**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Active](https://img.shields.io/badge/Status-Active-success.svg)]()

A privacy-preserving, distributed threat detection and intelligence sharing platform that enables real-time collaboration between security nodes using trust-weighted consensus and federated learning principles.

---

## 🌟 Key Features

### Core Capabilities
- **🔐 Federated Architecture** - Privacy-preserving distributed system
- **🤖 IOC Management** - 8 types of Indicators of Compromise
- **⚡ Real-time Sharing** - Instant threat intelligence via WebSockets
- **🎯 Trust Scoring** - Dynamic reputation-based validation
- **📊 YARA Integration** - Pattern-based threat detection
- **🗄️ SQLite Database** - Persistent storage with efficient querying
- **🌐 REST API** - Full API for external integrations
- **📈 Live Dashboard** - Real-time visualization with Chart.js

### Advanced Features
- **Multi-client Consensus** - Trust-weighted verification
- **Bidirectional Sync** - Client ↔ Server intelligence sharing
- **Time-based Decay** - Automatic trust score decay
- **Local IOC Caching** - Fast local threat checks
- **File Monitoring** - Watchdog-based filesystem surveillance
- **Configurable** - YAML-based configuration management

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────┐
│          Dashboard (Web Browser)                    │
│          Real-time WebSocket Updates                │
└──────────────────┬──────────────────────────────────┘
                   │ Socket.IO / HTTP
┌──────────────────┴──────────────────────────────────┐
│         Coordinator Server (Flask + SocketIO)       │
│  ┌──────────────────────────────────────────────┐  │
│  │  Trust Manager                               │  │
│  │  - Dynamic scoring with decay                │  │
│  │  - Historical tracking                       │  │
│  │  - Reputation analysis                       │  │
│  └──────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────┐  │
│  │  Intelligence Aggregator                     │  │
│  │  - IOC validation & consensus                │  │
│  │  - Multi-client verification                 │  │
│  │  - Threat deduplication                      │  │
│  └──────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────┐  │
│  │  REST API Routes                             │  │
│  │  - External integrations                     │  │
│  │  - Query endpoints                           │  │
│  └──────────────────────────────────────────────┘  │
└─────┬──────────────┬──────────────┬────────────────┘
      │              │              │
      │ WebSocket    │ WebSocket    │ WebSocket
      │              │              │
┌─────┴──────┐ ┌────┴───────┐ ┌───┴────────┐
│  Client 1  │ │  Client 2  │ │  Client N  │
│ ┌────────┐ │ │ ┌────────┐ │ │ ┌────────┐ │
│ │ YARA   │ │ │ │ YARA   │ │ │ │ YARA   │ │
│ │Scanner │ │ │ │Scanner │ │ │ │Scanner │ │
│ └────────┘ │ │ └────────┘ │ │ └────────┘ │
│ ┌────────┐ │ │ ┌────────┐ │ │ ┌────────┐ │
│ │  File  │ │ │ │  File  │ │ │ │  File  │ │
│ │Monitor │ │ │ │Monitor │ │ │ │Monitor │ │
│ └────────┘ │ │ └────────┘ │ │ └────────┘ │
│ ┌────────┐ │ │ ┌────────┐ │ │ ┌────────┐ │
│ │  IOC   │ │ │ │  IOC   │ │ │ │  IOC   │ │
│ │   DB   │ │ │ │   DB   │ │ │ │   DB   │ │
│ └────────┘ │ │ └────────┘ │ │ └────────┘ │
└────────────┘ └────────────┘ └────────────┘
```

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser

### Installation

```bash
# 1. Clone repository
git clone https://github.com/surendar004/Capstone-FedSIG-main.git
cd Capstone-FedSIG-main

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch system (automated)
python launch_fedsig_system.py
```

The launcher will:
- ✅ Check Python version & dependencies
- ✅ Verify file structure
- ✅ Create necessary directories
- ✅ Generate configurations
- ✅ Start the server
- ✅ Open dashboard in browser

### Manual Start

```bash
# Terminal 1: Start Server
python src/coordinator/integrated_server.py

# Terminal 2: Start Client
python src/client/enhanced_client.py --watch-dir /tmp/watch1

# Access Dashboard
open http://localhost:5000
```

---

## 📁 Project Structure

```
FedSIG+ ThreatNet/
├── src/
│   ├── common/                      # Shared utilities
│   │   ├── __init__.py
│   │   ├── models_enhanced.py       # Data models (IOC, ThreatIntel, etc.)
│   │   ├── config.py                # Configuration management
│   │   ├── logger.py                # Logging utilities
│   │   └── constants.py             # System constants
│   │
│   ├── coordinator/                 # Server components
│   │   ├── __init__.py
│   │   ├── integrated_server.py    # Main server (Flask + SocketIO)
│   │   ├── trust_manager.py        # Trust scoring system
│   │   ├── intel_aggregator.py     # IOC aggregation & consensus
│   │   └── api_routes.py           # REST API endpoints
│   │
│   └── client/                      # Client components
│       ├── __init__.py
│       ├── enhanced_client.py      # Main client application
│       ├── file_monitor.py         # Filesystem monitoring
│       ├── yara_scanner.py         # YARA-based scanning
│       └── ioc_database.py         # Local IOC storage
│
├── dashboard/                       # Web dashboard
│   ├── templates/
│   │   └── dashboard.html          # Real-time dashboard UI
│   └── static/
│       ├── js/                     # JavaScript (embedded in HTML)
│       └── css/                    # CSS (Tailwind CDN)
│
├── configs/                         # Configuration files
│   ├── server_config.yaml          # Server settings
│   ├── client_config.yaml          # Client settings
│   └── dashboard_config.yaml       # Dashboard settings
│
├── rules/                           # YARA rules
│   └── yara_rules.yar              # Threat detection rules
│
├── tests/                           # Test suite
│   ├── test_system.py              # Comprehensive tests
│   └── test_integration.py         # Integration tests
│
├── data/                            # Data storage (generated)
│   ├── intel/                      # Global IOC database
│   └── client/                     # Client databases
│
├── logs/                            # Application logs (generated)
│   ├── server.log
│   ├── client_*.log
│   └── trust_manager.log
│
├── launch_fedsig_system.py         # System launcher
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
└── .gitignore                       # Git ignore rules
```

---

## 🎮 Usage Examples

### Example 1: Basic Deployment

```bash
# Terminal 1: Start coordinator
python launch_fedsig_system.py

# Terminal 2: Start client 1
python src/client/enhanced_client.py --watch-dir /tmp/watch1

# Terminal 3: Start client 2
python src/client/enhanced_client.py --watch-dir /tmp/watch2

# Create test threat
echo "malware test" > /tmp/watch1/suspicious.exe
```

### Example 2: Custom Configuration

```bash
# Edit configuration
nano configs/client_config.yaml

# Start with config
python src/client/enhanced_client.py --config configs/client_config.yaml

# Or use command line
python src/client/enhanced_client.py \
  --server http://192.168.1.100:5000 \
  --watch-dir /var/log \
  --watch-dir /home/user/downloads
```

### Example 3: Testing & Validation

```bash
# Run test suite
python tests/test_system.py

# Check client statistics
python src/client/enhanced_client.py --stats

# API testing
curl http://localhost:5000/api/status | python -m json.tool
curl http://localhost:5000/api/iocs | python -m json.tool
```

---

## 🔧 Configuration

### Server Configuration

Edit `configs/server_config.yaml`:

```yaml
server:
  host: '0.0.0.0'
  port: 5000
  debug: false
  secret_key: 'change-in-production'
  
  # Database
  db_path: 'data/intel/global_iocs.db'
  
  # Trust parameters
  initial_trust: 0.5
  max_trust: 1.0
  min_trust: 0.1
  trust_decay_rate: 0.95
  
  # Consensus
  consensus_threshold: 2
  consensus_trust_avg: 0.6
```

### Client Configuration

Edit `configs/client_config.yaml`:

```yaml
client:
  server_url: 'http://localhost:5000'
  
  # Monitoring
  watch_directories:
    - '/tmp/watch1'
    - '/path/to/monitor'
  
  scan_extensions:
    - '.exe'
    - '.dll'
    - '.bat'
    - '.ps1'
  
  max_file_size_mb: 100
  
  # YARA
  yara_rules_paths:
    - 'rules/yara_rules.yar'
  enable_yara: true
  
  # Sync
  sync_interval: 300
  heartbeat_interval: 5
```

---

## 📊 Dashboard Guide

Access the dashboard at `http://localhost:5000`

### Dashboard Sections

1. **System Metrics**
   - Connected Clients (online/offline)
   - Total IOCs (verified/pending)
   - Total Detections
   - Average Trust Score

2. **Charts**
   - Detection Timeline (last 10 minutes)
   - Threat Distribution (by severity)

3. **Connected Clients Table**
   - Hostname & Client ID
   - Status indicator
   - Trust score (color-coded)

4. **IOC Intelligence Pool**
   - IOC Type & Value
   - Threat Level
   - Verification Status
   - Report Count
   - Filter: All / Verified / Pending

5. **Live Detection Feed**
   - Real-time threat events
   - File paths & hashes
   - Detection type & severity

---

## 🔌 API Reference

### GET /api/status
Get system status and statistics

```bash
curl http://localhost:5000/api/status
```

Response:
```json
{
  "status": "online",
  "data": {
    "total_clients": 3,
    "online_clients": 2,
    "total_iocs": 15,
    "verified_iocs": 12,
    "average_trust": 0.75
  }
}
```

### GET /api/clients
Get all connected clients

```bash
curl http://localhost:5000/api/clients
```

### GET /api/iocs
Get IOC intelligence (with filters)

```bash
# All IOCs
curl http://localhost:5000/api/iocs

# Verified only
curl "http://localhost:5000/api/iocs?status=verified"

# By type
curl "http://localhost:5000/api/iocs?type=file_hash"

# By threat level
curl "http://localhost:5000/api/iocs?threat_level=critical"
```

### GET /api/iocs/<ioc_id>
Get specific IOC details

```bash
curl http://localhost:5000/api/iocs/abc123def456
```

### POST /api/report_threat
Report a threat via API

```bash
curl -X POST http://localhost:5000/api/report_threat \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "client1",
    "ioc": {
      "ioc_type": "file_hash",
      "value": "abc123...",
      "threat_level": "high",
      "metadata": {"filename": "malware.exe"}
    }
  }'
```

### GET /api/sync_intel?client_id=<id>
Sync intelligence for a client

```bash
curl "http://localhost:5000/api/sync_intel?client_id=client1"
```

---

## 🧪 Testing

### Run Test Suite

```bash
# All tests
python tests/test_system.py

# With coverage
pip install pytest pytest-cov
pytest tests/ --cov=src --cov-report=html

# Specific test
pytest tests/test_system.py::TestTrustManager -v
```

### Manual Testing

```bash
# Create test directories
mkdir -p /tmp/watch1 /tmp/watch2

# Start system
python launch_fedsig_system.py

# In another terminal, create test threats
echo "test malware" > /tmp/watch1/threat1.exe
echo "test virus" > /tmp/watch2/threat2.dll

# Watch logs
tail -f logs/server.log
tail -f logs/client_*.log

# Check dashboard for detections
open http://localhost:5000
```

---

## 🐛 Troubleshooting

### Issue: Import Errors

```bash
# Ensure __init__.py files exist
ls src/__init__.py
ls src/common/__init__.py
ls src/coordinator/__init__.py
ls src/client/__init__.py

# If missing, run launcher which creates them
python launch_fedsig_system.py
```

### Issue: Port 5000 in Use

```bash
# Find process using port
lsof -i :5000  # Mac/Linux
netstat -ano | findstr :5000  # Windows

# Kill process or use different port
python src/coordinator/integrated_server.py --port 8080
```

### Issue: YARA Not Working

```bash
# Check if YARA is installed
python -c "import yara; print('YARA OK')"

# Install YARA (optional)
pip install yara-python

# Or disable in config
# Edit configs/client_config.yaml
# Set: enable_yara: false
```

### Issue: Database Errors

```bash
# Check database paths
ls -la data/intel/
ls -la data/client/

# Reset databases (WARNING: deletes all data)
rm -rf data/intel/*.db data/client/*.db

# Restart system
python launch_fedsig_system.py
```

---

## 🚀 Production Deployment

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "src/coordinator/integrated_server.py"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  fedsig-server:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    restart: unless-stopped

  fedsig-client:
    build: .
    command: python src/client/enhanced_client.py --server http://fedsig-server:5000
    depends_on:
      - fedsig-server
    volumes:
      - /tmp/watch:/tmp/watch
```

### Systemd Service

```ini
# /etc/systemd/system/fedsig.service
[Unit]
Description=FedSIG+ ThreatNet Server
After=network.target

[Service]
Type=simple
User=fedsig
WorkingDirectory=/opt/fedsig
Environment="PATH=/opt/fedsig/venv/bin"
ExecStart=/opt/fedsig/venv/bin/python src/coordinator/integrated_server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable fedsig
sudo systemctl start fedsig
sudo systemctl status fedsig
```

---

## 📈 Performance & Scaling

### Recommended Limits
- **Clients**: Up to 100 concurrent clients
- **IOCs**: 10,000+ per client database
- **File Size**: Max 100MB per file
- **Sync Interval**: 300 seconds (5 minutes)

### Optimization Tips
- Use SSD for database storage
- Increase consensus threshold for high-traffic networks
- Adjust trust decay rate based on activity level
- Enable database vacuuming regularly

---

## 🔒 Security Considerations

### Production Checklist
- [ ] Change default secret key in `server_config.yaml`
- [ ] Enable HTTPS (use nginx/Apache reverse proxy)
- [ ] Implement client authentication tokens
- [ ] Restrict server binding to specific IPs
- [ ] Enable firewall rules
- [ ] Regular database backups
- [ ] Log rotation and monitoring
- [ ] Review and update YARA rules

---

## 📚 Additional Documentation

- **API Reference**: See `/api/` endpoints above
- **Architecture**: See `ARCHITECTURE_OVERVIEW.md`
- **Deployment**: See `COMPLETE_DEPLOYMENT.md`
- **Dashboard**: See `DASHBOARD_GUIDE.md`

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

## 📄 License

MIT License - see LICENSE file for details

---

## 🙏 Acknowledgments

- Flask & Socket.IO for real-time communication
- Chart.js for data visualization
- Tailwind CSS for modern UI
- YARA for pattern matching
- Watchdog for file monitoring

---

## 📞 Support

- **Issues**: GitHub Issues
- **Documentation**: See `/docs` directory
- **Email**: support@fedsig-threatnet.example.com

---

**🎉 FedSIG+ ThreatNet - Securing the Future with Federated Intelligence**

Made with ❤️ for the cybersecurity community