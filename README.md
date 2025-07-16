# CyberAutoX 🔐
A Unified Security Toolkit for Offensive and Defensive Cybersecurity Automation

![MIT License](https://img.shields.io/badge/license-MIT-green)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)

---

## 🔥 Quick Start

### 🐳 Docker (Recommended)
```bash
git clone https://github.com/pugazh342/cyberautox.git
cd CyberAutoX-Tool
docker build -t cyberautox .
docker run cyberautox --help
```

To save reports locally:
```bash
docker run -v $(pwd)/reports:/app/reports cyberautox vulnscan --target "http://example.com" --scan-type "xss"
```

### 🖥️ Local (Without Docker)
```bash
git clone https://github.com/pugazh342/cyberautox.git
cd CyberAutoX-Tool
pip install -r requirements.txt
python cyberautox.py --help
```

---

## 📂 Project Structure

```plaintext
CyberAutoX/
│
├── core/               # Core framework components
├── modules/            # Individual security modules (vulnscan, osint, etc.)
├── utils/              # Helper functions and tools
├── config/             # Configuration files (future API keys, settings, etc.)
├── reports/            # Output reports (vulnerability, scan logs, etc.)
├── tests/              # Unit and integration tests
├── cyberautox.py       # Main CLI entry point
├── Dockerfile          # Docker container setup
├── requirements.txt    # Python dependencies
└── README.md           # This documentation
```

---

## 🚀 Available Modules & Usage

Each command module performs a specific security task. Run `--help` on any command to see its usage.

### 🔎 Vulnerability Scanner
```bash
python cyberautox.py vulnscan --target "http://example.com" --scan-type "xss"
```

### 🌐 OSINT (Open Source Intelligence)
```bash
python cyberautox.py osint --username "target_username"
```

### 🌍 Network Scanner
```bash
python cyberautox.py netscan --target "192.168.1.0/24"
```

### 🧪 Exploit Module
```bash
python cyberautox.py exploit --target "http://target.com" --exploit "sql_injection"
```

### 📶 Wireless Attacks
```bash
python cyberautox.py wireless --interface wlan0 --attack-type deauth
```

### 📜 Log Analyzer
```bash
python cyberautox.py loganalyzer --log-file "/path/to/access.log"
```

### 🧠 Threat Intelligence
```bash
python cyberautox.py threatintel --ioc "malicious.com"
```

---

## 🧪 Example Output

_Sample output (add screenshots or logs for reference):_

```plaintext
[+] Starting XSS scan on http://example.com
[!] Reflected XSS found on /search?q=<script>alert(1)</script>
[+] Report saved to reports/example.com-xss.json
```

---

## ⚙️ Docker Tips

**Mount reports volume:**
```bash
docker run -v $(pwd)/reports:/app/reports cyberautox vulnscan --target "http://site.com"
```

**Interactive Bash (for devs):**
```bash
docker run -it cyberautox bash
```

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repo
2. Create a new branch: `git checkout -b feature-name`
3. Commit your changes
4. Push to your fork and open a Pull Request

---

## ✅ To-Do / Future Features

- [ ] Web UI (dashboard)
- [ ] API key config system
- [ ] Auto-updater for modules
- [ ] Plugin support for community-made tools
- [ ] CI/CD integration with GitHub Actions

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🙌 Acknowledgements

- Inspired by tools like `Metasploit`, `recon-ng`, and `theHarvester`.
- Uses open-source libraries for scanning, parsing, and automation.

---

## 📬 Contact

Feel free to reach out for issues, collaborations, or feedback:
- GitHub Issues: [Open an issue](https://github.com/pugazh342/cyberautox/issues)
- Email: kpugazhmani21@gmail.com

---

**CyberAutoX — Because Security Should Be Automated.**
