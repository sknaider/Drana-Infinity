#!/bin/bash
# Drana-Infinity Performance Setup Script
# Optimized for: Ryzen 9 9950X + 128GB RAM + RTX 5090 + WSL2

set -e

echo "======================================================================"
echo "Drana-Infinity Performance Optimization Setup"
echo "======================================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running on WSL
if ! grep -qi microsoft /proc/version; then
    echo -e "${YELLOW}Warning: This script is optimized for WSL2${NC}"
fi

# 1. System Information
echo -e "${GREEN}[1/8] Detecting System Resources...${NC}"
CPU_CORES=$(nproc)
TOTAL_RAM=$(free -h | awk '/^Mem:/ {print $2}')
echo "  CPU Cores: $CPU_CORES"
echo "  Total RAM: $TOTAL_RAM"

# 2. Check NVIDIA GPU
echo -e "${GREEN}[2/8] Checking NVIDIA GPU...${NC}"
if command -v nvidia-smi &> /dev/null; then
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader)
    GPU_VRAM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader)
    echo "  GPU: $GPU_NAME"
    echo "  VRAM: $GPU_VRAM"
else
    echo -e "${YELLOW}  Warning: nvidia-smi not found. GPU acceleration may not work.${NC}"
    echo "  Install NVIDIA drivers and CUDA toolkit for GPU support."
fi

# 3. Setup Ollama Environment Variables
echo -e "${GREEN}[3/8] Configuring Ollama Environment Variables...${NC}"
OLLAMA_CONFIG="$HOME/.ollama_env"
cat > "$OLLAMA_CONFIG" << 'EOF'
# Ollama Performance Configuration
export OLLAMA_HOST="0.0.0.0:11434"
export OLLAMA_GPU_MEMORY="22GB"
export OLLAMA_NUM_GPU=1
export OLLAMA_NUM_THREADS=16
export CUDA_VISIBLE_DEVICES=0
export OLLAMA_MAX_LOADED_MODELS=2
export OLLAMA_KEEP_ALIVE="5m"
export OLLAMA_MAX_QUEUE=512
EOF

# Add to shell configuration if not already present
for shell_rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$shell_rc" ]; then
        if ! grep -q "source.*\.ollama_env" "$shell_rc"; then
            echo "" >> "$shell_rc"
            echo "# Ollama Performance Configuration" >> "$shell_rc"
            echo "[ -f ~/.ollama_env ] && source ~/.ollama_env" >> "$shell_rc"
            echo "  Updated: $shell_rc"
        fi
    fi
done

# 4. Python Dependencies
echo -e "${GREEN}[4/8] Checking Python Dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    if [ ! -d "venv" ]; then
        echo "  Creating virtual environment..."
        python3 -m venv venv
    fi
    source venv/bin/activate
    echo "  Installing/Updating dependencies..."
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    echo "  Dependencies installed successfully"
else
    echo -e "${RED}  Error: requirements.txt not found${NC}"
    exit 1
fi

# 5. WSL Configuration Guide
echo -e "${GREEN}[5/8] WSL2 Configuration Guidance...${NC}"
if [ -f ".wslconfig_example" ]; then
    echo "  A sample .wslconfig file has been created: .wslconfig_example"
    echo -e "${YELLOW}  ACTION REQUIRED:${NC}"
    echo "    1. Copy .wslconfig_example to C:\\Users\\YourUsername\\.wslconfig (Windows)"
    echo "    2. Adjust settings as needed"
    echo "    3. Run 'wsl --shutdown' from Windows PowerShell"
    echo "    4. Restart WSL"
fi

# 6. Optimize SQLite
echo -e "${GREEN}[6/8] Optimizing SQLite Database...${NC}"
if [ -f "chat_database.db" ]; then
    echo "  Running VACUUM to optimize database..."
    sqlite3 chat_database.db "VACUUM;"
    echo "  Running ANALYZE to update statistics..."
    sqlite3 chat_database.db "ANALYZE;"
    echo "  Database optimized"
else
    echo "  No existing database found (will be created on first run)"
fi

# 7. System Optimizations (Linux)
echo -e "${GREEN}[7/8] Applying System Optimizations...${NC}"

# Increase file descriptor limits
if ! grep -q "fs.file-max" /etc/sysctl.conf 2>/dev/null; then
    echo "  File descriptor limits (requires sudo)..."
    if command -v sudo &> /dev/null; then
        echo "fs.file-max = 2097152" | sudo tee -a /etc/sysctl.conf > /dev/null
        sudo sysctl -p > /dev/null 2>&1 || true
    else
        echo -e "${YELLOW}  Skipped: sudo not available${NC}"
    fi
fi

# 8. Verification
echo -e "${GREEN}[8/8] Verification...${NC}"

# Check Ollama
if command -v ollama &> /dev/null; then
    echo "  ✓ Ollama installed"
    # Check if Ollama is running
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "  ✓ Ollama service is running"
        # Check for drana-infinity model
        if ollama list | grep -q "drana-infinity"; then
            echo "  ✓ Drana-Infinity model found"
        else
            echo -e "${YELLOW}  ⚠ Drana-Infinity model not found${NC}"
            echo "    Run: ollama pull IHA089/drana-infinity-v1"
        fi
    else
        echo -e "${YELLOW}  ⚠ Ollama service not running${NC}"
        echo "    Run: ollama serve"
    fi
else
    echo -e "${RED}  ✗ Ollama not installed${NC}"
    echo "    Install from: https://ollama.com/download"
fi

echo ""
echo "======================================================================"
echo -e "${GREEN}Performance Optimization Setup Complete!${NC}"
echo "======================================================================"
echo ""
echo "Next Steps:"
echo "  1. Restart your shell or run: source ~/.bashrc"
echo "  2. Start Ollama: ollama serve"
echo "  3. Run Drana-Infinity: sudo python3 drana_infinity.py"
echo "  4. Monitor GPU usage: watch -n 1 nvidia-smi"
echo ""
echo "Performance Features Enabled:"
echo "  ✓ Multi-threaded request handling (${CPU_CORES} cores)"
echo "  ✓ Database connection pooling (32 connections)"
echo "  ✓ SQLite optimizations (256MB cache, WAL mode)"
echo "  ✓ GPU acceleration for AI inference"
echo "  ✓ Large buffer sizes for streaming"
echo "  ✓ Enhanced memory management"
echo ""
echo "For more information, see:"
echo "  - ollama_config.md (GPU optimization guide)"
echo "  - .wslconfig_example (WSL2 configuration)"
echo "======================================================================"
