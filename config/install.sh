#!/bin/bash
# LeakMon Installation Script

set -e

echo "🛡️  Installing LeakMon - Real-Time Secret Detection"
echo "=================================================="

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Error: Python 3.8 or higher is required. Found: $python_version"
    exit 1
fi

echo "✅ Python $python_version detected"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Make main.py executable
chmod +x main.py

# Create symlink for global access (optional)
if command -v sudo &> /dev/null; then
    read -p "🔗 Create global 'leakmon' command? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo ln -sf "$(pwd)/main.py" /usr/local/bin/leakmon
        echo "✅ Global 'leakmon' command created"
    fi
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "Usage:"
echo "  ./main.py --help                 # Show help"
echo "  ./main.py init                   # Start monitoring current directory"
echo "  ./main.py --scan-now             # Scan current directory once"
echo "  ./main.py --web                  # Start web interface"
echo ""
echo "Web Dashboard: http://localhost:5000"
echo ""
echo "For more information, see README.md"

