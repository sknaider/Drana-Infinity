# Ollama GPU Optimization Guide for RTX 5090

## Environment Variables for Maximum GPU Performance

Add these to your shell configuration (~/.bashrc or ~/.zshrc):

```bash
# Ollama GPU Configuration for NVIDIA RTX 5090
export OLLAMA_HOST="0.0.0.0:11434"

# GPU Memory - RTX 5090 has 24GB VRAM, allocate most of it
export OLLAMA_GPU_MEMORY="22GB"

# Enable GPU acceleration
export OLLAMA_NUM_GPU=1

# CPU threads for Ollama (leave half for Flask/system)
export OLLAMA_NUM_THREADS=16

# Enable CUDA optimizations
export CUDA_VISIBLE_DEVICES=0

# Increase context window size (takes advantage of large VRAM)
export OLLAMA_MAX_LOADED_MODELS=2

# Performance tuning
export OLLAMA_KEEP_ALIVE="5m"
export OLLAMA_MAX_QUEUE=512

# Enable tensor cores for faster inference
export CUDA_LAUNCH_BLOCKING=0
```

## Apply Configuration

After adding to ~/.bashrc:
```bash
source ~/.bashrc
```

## Verify GPU is Being Used

Check Ollama is using GPU:
```bash
# Start Ollama
ollama serve

# In another terminal, run your model
ollama run IHA089/drana-infinity-v1

# Monitor GPU usage with nvidia-smi
watch -n 1 nvidia-smi
```

## CUDA Setup for WSL2

Ensure CUDA is properly configured in WSL2:

```bash
# Check NVIDIA driver
nvidia-smi

# If not installed, install CUDA toolkit
wget https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update
sudo apt-get -y install cuda-toolkit
```

## Expected Performance Improvements

With RTX 5090 optimization:
- **Inference Speed**: 5-10x faster than CPU
- **Concurrent Requests**: Handle multiple users simultaneously
- **Larger Models**: Support for bigger AI models
- **Lower Latency**: Sub-second response times for most queries

## Monitoring Performance

```bash
# Real-time GPU monitoring
watch -n 0.5 nvidia-smi

# Check Ollama status
curl http://localhost:11434/api/tags

# Monitor GPU utilization
nvidia-smi dmon -s u
```

## Troubleshooting

If GPU is not detected:
1. Ensure NVIDIA drivers are installed in Windows
2. WSL2 should automatically forward GPU access
3. Check `nvidia-smi` works in WSL
4. Restart Ollama service: `pkill ollama && ollama serve`

## Performance Baseline

Your RTX 5090 should achieve:
- Token generation: 100-200 tokens/second (depending on model size)
- First token latency: <100ms
- VRAM usage: Monitor with nvidia-smi, should stay under 22GB
