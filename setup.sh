#!/bin/bash

#####################################################################
# Drana-Infinity - Automated Setup Script
# Version: 2.0.0
# Author: IHA089
# Description: Automated installation and configuration script
#####################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║                                                    ║"
    echo "║          🧠 DRANA-INFINITY SETUP v2.0             ║"
    echo "║       Enhanced Security Edition Installer         ║"
    echo "║                                                    ║"
    echo "║              Created by IHA089                     ║"
    echo "║                                                    ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print step
print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Print success
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

# Print error
print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Print warning
print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."

    local missing_deps=0

    # Check Python 3
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python 3 found: $PYTHON_VERSION"
    else
        print_error "Python 3 not found. Please install Python 3.10+"
        missing_deps=1
    fi

    # Check pip
    if command_exists pip3; then
        print_success "pip3 found"
    else
        print_error "pip3 not found. Please install pip3"
        missing_deps=1
    fi

    # Check git
    if command_exists git; then
        print_success "git found"
    else
        print_warning "git not found (optional for updates)"
    fi

    # Check ollama
    if command_exists ollama; then
        print_success "Ollama found"
    else
        print_warning "Ollama not found. You'll need to install it manually."
        print_warning "Download from: https://ollama.com/download"
    fi

    if [ $missing_deps -eq 1 ]; then
        print_error "Missing required dependencies. Please install them first."
        exit 1
    fi

    echo ""
}

# Create virtual environment
create_venv() {
    print_step "Creating virtual environment..."

    if [ -d "venv" ]; then
        print_warning "Virtual environment already exists. Skipping..."
    else
        python3 -m venv venv
        print_success "Virtual environment created"
    fi

    echo ""
}

# Install dependencies
install_dependencies() {
    print_step "Installing Python dependencies..."

    # Activate virtual environment
    source venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip >/dev/null 2>&1
    print_success "pip upgraded"

    # Install requirements
    pip install -r requirements.txt
    print_success "All dependencies installed"

    deactivate
    echo ""
}

# Configure environment
configure_environment() {
    print_step "Configuring environment..."

    if [ -f ".env" ]; then
        print_warning ".env file already exists. Skipping..."
    else
        cp .env.example .env
        print_success ".env file created from template"

        # Generate SECRET_KEY
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

        # Replace SECRET_KEY in .env
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
        else
            # Linux
            sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
        fi

        print_success "SECRET_KEY generated and configured"
        print_warning "Please review .env file for other settings"
    fi

    echo ""
}

# Setup Ollama model
setup_ollama() {
    print_step "Setting up Ollama model..."

    if ! command_exists ollama; then
        print_warning "Ollama not installed. Skipping model setup."
        print_warning "Install Ollama from: https://ollama.com/download"
        print_warning "Then run: ollama pull IHA089/drana-infinity-v1"
        echo ""
        return
    fi

    # Check if ollama is running
    if ! pgrep -x "ollama" > /dev/null; then
        print_warning "Ollama is not running. Starting ollama serve in background..."
        ollama serve > /dev/null 2>&1 &
        sleep 3
    fi

    # Pull the model
    print_step "Pulling IHA089/drana-infinity-v1 model (this may take a while)..."
    if ollama pull IHA089/drana-infinity-v1; then
        print_success "Ollama model downloaded successfully"
    else
        print_error "Failed to download Ollama model"
        print_warning "You can download it later with: ollama pull IHA089/drana-infinity-v1"
    fi

    echo ""
}

# Create necessary directories
create_directories() {
    print_step "Creating necessary directories..."

    mkdir -p uploads
    mkdir -p logs

    print_success "Directories created"
    echo ""
}

# Set permissions
set_permissions() {
    print_step "Setting file permissions..."

    chmod +x setup.sh
    chmod +x drana_infinity.py
    chmod +x updater.py

    print_success "Permissions set"
    echo ""
}

# Print next steps
print_next_steps() {
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║                                                    ║"
    echo "║         ✅ SETUP COMPLETED SUCCESSFULLY!          ║"
    echo "║                                                    ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${CYAN}📋 NEXT STEPS:${NC}"
    echo ""
    echo "1. Review configuration:"
    echo -e "   ${YELLOW}nano .env${NC}"
    echo ""
    echo "2. Start Ollama (if not running):"
    echo -e "   ${YELLOW}ollama serve${NC}"
    echo ""
    echo "3. Start Drana-Infinity:"
    echo -e "   ${YELLOW}source venv/bin/activate${NC}"
    echo -e "   ${YELLOW}python3 drana_infinity.py${NC}"
    echo ""
    echo "4. Open in browser:"
    echo -e "   ${YELLOW}http://127.0.0.1:80${NC}"
    echo ""
    echo -e "${CYAN}📚 DOCUMENTATION:${NC}"
    echo "   • SECURITY.md  - Security features and best practices"
    echo "   • CONFIG.md    - Configuration guide"
    echo "   • README.md    - General information"
    echo "   • CHANGELOG.md - Version history"
    echo ""
    echo -e "${GREEN}For production deployment, see SECURITY.md${NC}"
    echo ""
}

# Main installation flow
main() {
    print_banner

    check_prerequisites
    create_venv
    install_dependencies
    configure_environment
    create_directories
    set_permissions
    setup_ollama

    print_next_steps
}

# Run main
main
