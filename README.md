# 🧠 Drana-Infinity

**Drana-Infinity** is a locally hosted advanced AI assistant designed and developed by **IHA089**.  
It’s built specifically for **cybersecurity, ethical hacking, and bug bounty research** — empowering researchers to analyze, automate, and understand **real-world vulnerabilities**.

---

## 🌐 Overview

Drana-Infinity runs entirely **offline** and integrates directly with **Ollama** using a custom locally hosted AI model — [**IHA089/drana-infinity-v1**](https://ollama.com/IHA089/drana-infinity-v1).  
It allows you to chat, execute commands, upload files, and organize research — all within a secure, private environment.

---

## ⚙️ System Requirements

To ensure smooth performance when running Drana-Infinity and your local AI model, your system should meet the following:

| Category | Minimum | Recommended | High-Performance* |
|-----------|----------|-------------|-------------------|
| **CPU** | 8-core processor | 12-core or higher | 16+ cores (Ryzen 9/Threadripper) |
| **RAM** | 16 GB | 32 GB or higher | 64GB+ |
| **GPU (optional)** | NVIDIA GPU with ≥ 8 GB VRAM | RTX 3060 Ti / 4070 or higher | RTX 4090/5090 |
| **Storage** | 15 GB free | SSD with 30 GB+ free | NVMe SSD with 50GB+ |
| **OS** | Linux | Kali Linux | Linux/WSL2 |
| **Python** | 3.10+ | Latest 3.x stable version | 3.11+ |

> 💡 Works on CPU-only systems (slower responses). GPU recommended for real-time AI streaming.
> ⚡ *High-performance configuration automatically detected and optimized.

---

## 🧩 Complete Setup Guide

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

### 6️⃣ Start the Ollama Backend

```bash
ollama serve
```

### 7️⃣ Run Drana-Infinity Server

```bash
python3 drana_infinity.py
```

---

## ⚡ Performance Optimizations (NEW!)

Drana-Infinity now includes **automatic performance optimizations** for high-end hardware!

### Quick Setup

```bash
# Run the automated performance setup
./setup_performance.sh

# Start the optimized server
sudo python3 drana_infinity.py
```

### What's Optimized?

✅ **Database Connection Pooling** - Reuses connections for 10x faster queries
✅ **Multi-threaded Server** - Utilizes all CPU cores (auto-detected)
✅ **GPU Acceleration** - Automatic RTX GPU detection and optimization
✅ **Memory Management** - Optimized for systems with 64GB+ RAM
✅ **SQLite Tuning** - WAL mode, 256MB cache, memory-mapped I/O
✅ **WSL2 Optimization** - Special tuning for Windows Subsystem for Linux

### Performance Benchmarks

Run the benchmark suite to verify optimizations:

```bash
python3 benchmark.py
```

### For High-End Systems

If you have a **Ryzen 9/Threadripper, 64GB+ RAM, and RTX 4090/5090**, see:
- 📄 `PERFORMANCE_OPTIMIZATIONS.md` - Detailed optimization guide
- 📄 `ollama_config.md` - GPU acceleration setup
- 📄 `.wslconfig_example` - WSL2 configuration

**Expected Performance**: 100+ concurrent users, sub-second AI responses, 1000+ req/min

---

<img width="1920" height="1051" alt="image" src="https://github.com/user-attachments/assets/aec3a6a6-ba11-4923-a4aa-06a8e1b2c80f" />

---

<img width="1920" height="1051" alt="image" src="https://github.com/user-attachments/assets/6f61ca41-96a6-4841-a467-351e1b80ca15" />


---


<img width="1920" height="1051" alt="image" src="https://github.com/user-attachments/assets/af36797b-b6a1-4cb4-ba62-41d57682023b" />


