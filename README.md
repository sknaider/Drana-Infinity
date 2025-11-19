# 🧠 Drana-Infinity

**Drana-Infinity v2.0 - Enhanced Security Edition**

A locally hosted advanced AI assistant designed and developed by **IHA089**.
Built specifically for **cybersecurity, ethical hacking, and bug bounty research** — empowering researchers to analyze, automate, and understand **real-world vulnerabilities**.

---

## ✨ What's New in v2.0

### 🔒 Enterprise-Grade Security Features
- ✅ **Command Injection Prevention** - Safe command execution with pattern validation
- ✅ **XSS Protection** - Server and client-side sanitization
- ✅ **CSRF Protection** - Token-based request validation
- ✅ **Rate Limiting** - Prevent abuse and DoS attacks
- ✅ **SQL Injection Prevention** - Parameterized queries throughout
- ✅ **Secure File Uploads** - Extension whitelist and size limits
- ✅ **Comprehensive Logging** - Track all security events
- ✅ **Input Validation** - Strict validation on all user inputs
- ✅ **Authorization Controls** - Resource-level access verification

### 📚 Complete Documentation
- [SECURITY.md](SECURITY.md) - Security features and deployment best practices
- [CONFIG.md](CONFIG.md) - Detailed configuration guide
- `.env.example` - Environment variable template

---

## 🌐 Overview

Drana-Infinity runs entirely **offline** and integrates directly with **Ollama** using a custom locally hosted AI model — [**IHA089/drana-infinity-v1**](https://ollama.com/IHA089/drana-infinity-v1).
It allows you to chat, execute commands, upload files, and organize research — all within a secure, private environment.

---

## ⚙️ System Requirements

To ensure smooth performance when running Drana-Infinity and your local AI model, your system should meet the following:

| Category | Minimum | Recommended |
|-----------|----------|-------------|
| **CPU** | 8-core processor | 12-core or higher |
| **RAM** | 16 GB | 32 GB or higher |
| **GPU (optional)** | NVIDIA GPU with ≥ 8 GB VRAM | RTX 3060 Ti / 4070 or higher |
| **Storage** | 15 GB free | SSD with 30 GB+ free |
| **OS** | Linux | Kali Linux |
| **Python** | 3.10+ | Latest 3.x stable version |

> 💡 Works on CPU-only systems (slower responses). GPU recommended for real-time AI streaming.

---

## 🧩 Complete Setup Guide

You can set up Drana-Infinity in two ways:

### 🚀 **Quick Setup (Recommended)**

Use the automated installation script:

```bash
git clone https://github.com/IHA089/drana-infinity.git
cd drana-infinity
chmod +x setup.sh
./setup.sh
```

The setup script will automatically:
- ✅ Check prerequisites
- ✅ Create virtual environment
- ✅ Install all dependencies
- ✅ Configure `.env` with secure SECRET_KEY
- ✅ Download Ollama model
- ✅ Set up directories and permissions

---

### 📋 **Manual Setup**

Follow these steps carefully 👇

---

### 1️⃣ Clone or Prepare the Project Folder

```bash
git clone https://github.com/IHA089/drana-infinity.git
cd drana-infinity
```

### 2️⃣ Create a Virtual Environment

```bash
python3 -m venv venv

# Activate the environment
source venv/bin/activate
```

### 3️⃣ Install All Dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Install Ollama

Download and install Ollama from the official website:

[ollama](https://ollama.com/download)

### 5️⃣ Pull the Custom Model

```bash
ollama run IHA089/drana-infinity-v1
```

Verify that it’s available:

```bash
ollama list
```

### 6️⃣ Configure Environment (NEW in v2.0)

```bash
# Copy environment template
cp .env.example .env

# Generate a strong secret key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Edit .env and paste the secret key
nano .env
```

**Important**: Set at minimum `SECRET_KEY` in `.env` for production use.

See [CONFIG.md](CONFIG.md) for complete configuration options.

### 7️⃣ Start the Ollama Backend

```bash
ollama serve
```

### 8️⃣ Run Drana-Infinity Server

```bash
python3 drana_infinity.py
```

You should see:
```
🧠 Drana-Infinity - Enhanced Security Edition
============================================================
Security features enabled:
  ✓ CSRF Protection
  ✓ Rate Limiting
  ✓ Input Sanitization
  ✓ Command Injection Prevention
  ✓ Secure File Uploads
  ✓ SQL Injection Prevention
  ✓ Comprehensive Logging
============================================================
```


<img width="1920" height="1051" alt="image" src="https://github.com/user-attachments/assets/aec3a6a6-ba11-4923-a4aa-06a8e1b2c80f" />

---

<img width="1920" height="1051" alt="image" src="https://github.com/user-attachments/assets/6f61ca41-96a6-4841-a467-351e1b80ca15" />


---


<img width="1920" height="1051" alt="image" src="https://github.com/user-attachments/assets/af36797b-b6a1-4cb4-ba62-41d57682023b" />

---

## 📊 Monitoring & Health Checks

### Health Check Endpoint

Drana-Infinity includes a comprehensive health check endpoint for monitoring:

```bash
curl http://127.0.0.1:80/health
```

**Response (healthy)**:
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "timestamp": "2025-01-18T12:00:00",
  "checks": {
    "database": {
      "status": "healthy",
      "message": "Database accessible"
    },
    "ollama": {
      "status": "healthy",
      "message": "Ollama API accessible"
    },
    "uploads": {
      "status": "healthy",
      "message": "Upload directory writable"
    }
  }
}
```

**HTTP Status Codes**:
- `200` - All systems healthy
- `503` - One or more systems unhealthy

**Use Cases**:
- Load balancer health checks
- Kubernetes liveness/readiness probes
- Monitoring systems (Prometheus, Nagios, etc.)
- CI/CD deployment verification

---

## 📖 Documentation

- **[SECURITY.md](SECURITY.md)** - Security features, best practices, deployment guides
- **[CONFIG.md](CONFIG.md)** - Complete configuration reference
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and changes
- **[LICENSE](LICENSE)** - MIT License

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**IHA089**
- Website: [https://iha089.org](https://iha089.org)
- GitHub: [@IHA089](https://github.com/IHA089)

---

## 🙏 Acknowledgments

- Built with Flask, Ollama, and modern security libraries
- Inspired by the cybersecurity community
- Designed for ethical hackers and security researchers

---

**⚠️ Disclaimer**: This tool is designed for educational and authorized security research purposes only. Always obtain proper authorization before testing on any systems you do not own.

