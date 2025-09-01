# LeakMon: Real-Time Secret & PII Leak Detection

<!-- GitHub Stats -->
![GitHub repo size](https://img.shields.io/github/repo-size/RajaMuhammadAwais/LeakMoon?style=for-the-badge)
![GitHub contributors](https://img.shields.io/github/contributors/RajaMuhammadAwais/LeakMoon?style=for-the-badge)
![GitHub stars](https://img.shields.io/github/stars/RajaMuhammadAwais/LeakMoon?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/RajaMuhammadAwais/LeakMoon?style=for-the-badge)
![GitHub issues](https://img.shields.io/github/issues/RajaMuhammadAwais/LeakMoon?style=for-the-badge)
![GitHub license](https://img.shields.io/github/license/RajaMuhammadAwais/LeakMoon?style=for-the-badge)
![GitHub last commit](https://img.shields.io/github/last-commit/RajaMuhammadAwais/LeakMoon?style=for-the-badge)
<!-- Python / Dependencies -->
![Python version](https://img.shields.io/badge/python-3.11+-blue?style=for-the-badge)
<!-- Security / Analysis -->
![License](https://img.shields.io/github/license/RajaMuhammadAwais/LeakMoon?style=for-the-badge)
<!-- Activity -->
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/RajaMuhammadAwais/LeakMoon?style=for-the-badge)
![GitHub repo size](https://img.shields.io/github/repo-size/RajaMuhammadAwais/LeakMoon?style=for-the-badge)
<!-- Others -->
![Awesome Python](https://img.shields.io/badge/awesome-python-ff69b4?style=for-the-badge)
![ChatGPT Approved](https://img.shields.io/badge/chatgpt-approved-success?style=for-the-badge)



LeakMon is a powerful CLI daemon and web-based tool that monitors file changes, shell commands, and git operations in real-time to detect unintentional leaks of secrets, credentials, or sensitive data (like PII or API keys) before they're committed or exfiltrated.

## 🛡️ Features

### 🔁 Real-Time File Monitoring
- Watches files in working directory using `watchdog`
- Scans for AWS keys, JWTs, OAuth tokens, database credentials, API keys
- Detects credit card numbers, phone numbers, email addresses
- High-entropy string detection for unknown secret patterns

### 🧪 Smart Detection Engine
- Pattern-based detection using regular expressions
- Entropy analysis for detecting encoded secrets
- Confidence scoring and severity classification
- Context-aware filtering to reduce false positives

### 📊 Web Dashboard
- Real-time detection feed with WebSocket updates
- Interactive charts and statistics
- Export functionality for audit reports
- Responsive design for desktop and mobile

### 🛠️ CLI Interface
- One-time scanning mode
- Continuous monitoring mode
- Daily reports and statistics
- Rich console output with color coding

### 📦 Offline & Lightweight
- No cloud upload required
- Fast scanning via regex and entropy checks
- Configurable scan rules
- SQLite-based audit logging

## 🚀 Quick Start

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd leakmon
```

2. Set up Python virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install watchdog rich flask flask-socketio
```

### Usage

#### CLI Mode

**Start monitoring current directory:**
```bash
python main.py init
```

**Scan specific paths:**
```bash
python main.py --scan-now --paths /path/to/project
```

**Monitor multiple directories:**
```bash
python main.py --paths /path1,/path2,/path3
```

**View daily report:**
```bash
python main.py --report
```

**View statistics:**
```bash
python main.py --stats --days 30
```

#### Web Interface

**Start web dashboard:**
```bash
python main.py --web
```

Then open http://localhost:5000 in your browser.

## 🔍 Detection Types

### High Severity
- **AWS Access Keys**: `AKIA[0-9A-Z]{16}`
- **Private Keys**: `-----BEGIN PRIVATE KEY-----`
- **JWT Tokens**: `eyJ...` format tokens
- **API Keys**: OpenAI, Stripe, GitHub tokens

### Medium Severity
- **Database URLs**: Connection strings with credentials
- **Credit Card Numbers**: Luhn algorithm validated
- **Social Security Numbers**: `XXX-XX-XXXX` format
- **High Entropy Strings**: Base64-like patterns

### Low Severity
- **Email Addresses**: Standard email patterns
- **Phone Numbers**: US phone number formats
- **PII Data**: Personal identifiable information

## 📁 Project Structure

```
leakmon/
├── core/                   # Core detection and monitoring logic
│   ├── __init__.py
│   ├── secret_detector.py  # Secret detection engine
│   ├── file_watcher.py     # File monitoring system
│   └── logger.py           # Audit logging
├── web/                    # Web interface
│   ├── app.py              # Flask application
│   ├── templates/          # HTML templates
│   │   └── index.html
│   └── static/             # CSS, JS, assets
│       ├── css/style.css
│       └── js/app.js
├── test_files/             # Test files with sample secrets
├── config/                 # Configuration files
├── main.py                 # CLI entry point
└── README.md
```

## 🔧 Configuration

### Environment Variables
- `LEAKMON_LOG_DIR`: Custom log directory (default: `~/.leakmon/logs`)
- `LEAKMON_CONFIG`: Custom configuration file path

### Ignored Files and Directories
LeakMon automatically ignores:
- Binary files (`.exe`, `.dll`, `.so`, etc.)
- Archive files (`.zip`, `.tar`, `.gz`, etc.)
- Version control directories (`.git`, `.svn`, `.hg`)
- Package directories (`node_modules`, `__pycache__`, etc.)
- Large files (>10MB)

## 📊 Web Dashboard Features

### Real-time Monitoring
- Live detection feed with WebSocket updates
- Color-coded severity indicators
- File path and line number information
- Context preview for each detection

### Statistics Dashboard
- Detection count by severity level
- Detection types breakdown
- Historical trends and patterns
- Export functionality for reports

### Interactive Controls
- Start/stop monitoring
- Path configuration
- Clear detection history
- Export audit logs

## 🛡️ Security Considerations

### Data Privacy
- All processing is done locally
- No data is sent to external servers
- Detected secrets are hashed in logs
- Original secret values are not stored

### False Positive Reduction
- Context-aware filtering
- Test data exclusion
- Confidence scoring
- Whitelist support (planned)

## 🔮 Future Enhancements

### Planned Features
- Git hook integration
- Shell command monitoring
- Custom rule definitions
- Slack/email notifications
- Docker container scanning
- CI/CD pipeline integration

### Plugin System
- Custom regex patterns
- YARA rule support
- Third-party integrations
- Custom output formats

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Check the documentation
- Review existing issues and discussions

## 🏆 Acknowledgments

- Built with Python, Flask, and modern web technologies
- Inspired by GitGuardian and other security scanning tools
- Uses `watchdog` for efficient file monitoring
- Rich console output powered by the `rich` library

---

**⚠️ Important**: LeakMon is a detection tool and should be part of a comprehensive security strategy. Always review and validate detections before taking action.

