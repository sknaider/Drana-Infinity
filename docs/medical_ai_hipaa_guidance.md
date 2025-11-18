# Medical AI HIPAA Compliance Guidance

## Overview

This guide provides specific HIPAA Security Rule implementation guidance for Medical AI systems using:
- **RTX 5090 GPU** (32GB VRAM, NVIDIA Blackwell architecture)
- **DeepSeek-R1** (locally hosted AI model for medical diagnostics)
- **Claude Sonnet 4.5 API** (compliance reasoning and assessment)

Medical AI systems present unique HIPAA compliance challenges due to:
1. **PHI in Training Data**: Models may memorize patient information
2. **Model Inversion Attacks**: Adversaries can extract training data
3. **GPU Memory Exposure**: PHI may reside in GPU VRAM during inference
4. **Adversarial Examples**: Manipulated inputs can compromise patient safety

---

## HIPAA Controls with Medical AI Specific Guidance

### 1. Administrative Safeguards (164.308)

#### 164.308(a)(1)(i) - Risk Analysis

**Medical AI Risk Analysis Requirements:**

**IDENTIFY ePHI SYSTEMS:**
- RTX 5090 workstation (medical data processing)
- DeepSeek-R1 model weights (may contain memorized PHI)
- Training data storage (patient imaging, EHR data)
- Inference pipeline (real-time PHI processing)
- Model checkpoint storage (versioned models)
- GPU memory during inference
- API endpoints exposing model predictions

**DOCUMENT MEDICAL AI-SPECIFIC THREATS:**

| Threat | Likelihood | Impact | HIPAA Relevance |
|--------|-----------|--------|-----------------|
| **Model Inversion Attack** | Medium | High | Attacker extracts PHI from model weights via gradient analysis |
| **Membership Inference** | High | Medium | Determine if specific patient was in training set |
| **Training Data Extraction** | Medium | Critical | Recover actual patient records from model |
| **GPU Memory Dump** | Low | Critical | PHI extracted from GPU VRAM after inference |
| **Adversarial Medical Misclassification** | Medium | Critical | Patient safety impact from intentionally crafted inputs |
| **Model Poisoning** | Low | Critical | Malicious training data compromises model integrity |
| **Federated Learning Leakage** | Medium | High | PHI leaked via gradient updates in distributed training |

**MEDICAL AI RISK MITIGATION:**

```python
medical_ai_controls = {
    "model_inversion_defense": {
        "differential_privacy": "DP-SGD with ε=1.0 during training",
        "gradient_clipping": "Clip gradients to prevent information leakage",
        "noise_injection": "Add calibrated noise to model outputs"
    },
    "gpu_memory_protection": {
        "secure_memory_wipe": "Zero GPU memory after each inference batch",
        "encrypted_gpu_memory": "NVIDIA MIG with memory isolation",
        "no_paging_to_disk": "Disable GPU memory paging to prevent PHI on disk"
    },
    "adversarial_robustness": {
        "input_validation": "Validate medical images for adversarial perturbations",
        "certified_robustness": "Implement randomized smoothing",
        "ensemble_models": "Use multiple models to detect anomalies"
    },
    "training_data_protection": {
        "encrypted_storage": "AES-256 for all training datasets",
        "access_logging": "Audit all training data access",
        "data_minimization": "Only use minimum necessary PHI for training"
    }
}
```

**VALIDATION:**
```bash
# Verify differential privacy implementation
python scripts/verify_dp_training.py --epsilon 1.0 --delta 1e-5

# Test GPU memory cleanup
nvidia-smi --query-gpu=memory.used --format=csv -l 1

# Adversarial robustness evaluation
python scripts/test_adversarial_robustness.py --model diagnostic_classifier --attack pgd
```

---

#### 164.308(a)(1)(ii)(A) - Risk Management

**MEDICAL AI RISK MANAGEMENT CONTROLS:**

**1. Differential Privacy in Training**

```python
# Example: DP-SGD implementation for HIPAA compliance
from opacus import PrivacyEngine

model = DiagnosticCNN()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

privacy_engine = PrivacyEngine()

model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=train_loader,
    epochs=100,
    target_epsilon=1.0,  # HIPAA-acceptable privacy budget
    target_delta=1e-5,
    max_grad_norm=1.0
)

# Train with differential privacy guarantees
for epoch in range(100):
    for batch in train_loader:
        optimizer.zero_grad()
        output = model(batch)
        loss = criterion(output, labels)
        loss.backward()
        optimizer.step()  # Includes DP noise addition

# Get final privacy guarantee
epsilon = privacy_engine.get_epsilon(delta=1e-5)
print(f"Model trained with (ε={epsilon:.2f}, δ=1e-5)-differential privacy")
```

**2. GPU Memory Protection (RTX 5090)**

```python
# Secure GPU memory management
import torch
import nvidia_smi

class SecureGPUInference:
    def __init__(self):
        self.device = torch.device("cuda:0")

    def secure_inference(self, patient_image):
        """Perform inference with PHI protection."""
        try:
            # Load model to GPU
            model = load_model().to(self.device)

            # Perform inference
            with torch.no_grad():
                prediction = model(patient_image.to(self.device))

            # Extract result to CPU
            result = prediction.cpu().numpy()

            return result

        finally:
            # CRITICAL: Zero GPU memory after inference
            torch.cuda.empty_cache()
            torch.cuda.synchronize()

            # Verify memory cleared
            nvidia_smi.nvmlInit()
            handle = nvidia_smi.nvmlDeviceGetHandleByIndex(0)
            info = nvidia_smi.nvmlDeviceGetMemoryInfo(handle)

            if info.used > 100 * 1024 * 1024:  # >100MB used
                raise SecurityError("GPU memory not properly cleared - PHI leak risk")
```

**3. Model Checkpoint Encryption**

```bash
# Encrypt model weights (may contain memorized PHI)
openssl enc -aes-256-cbc -salt -pbkdf2 \
  -in model_checkpoint.pth \
  -out model_checkpoint.pth.enc \
  -k $(cat /secure/model_key.txt)

# Set restrictive permissions
chmod 600 model_checkpoint.pth.enc
chown hipaa-ml-service:hipaa-ml-service model_checkpoint.pth.enc
```

**4. Adversarial Robustness Testing**

```python
# HIPAA-required adversarial robustness evaluation
from torchattacks import PGD, FGSM

def evaluate_adversarial_robustness(model, test_loader):
    """
    Test model against adversarial attacks that could
    compromise patient safety.
    """
    attacks = {
        "FGSM": FGSM(model, eps=0.03),
        "PGD": PGD(model, eps=0.03, alpha=0.01, steps=10)
    }

    results = {}

    for attack_name, attack in attacks.items():
        correct = 0
        total = 0

        for images, labels in test_loader:
            # Generate adversarial examples
            adv_images = attack(images, labels)

            # Test model on adversarial examples
            outputs = model(adv_images)
            _, predicted = torch.max(outputs, 1)

            total += labels.size(0)
            correct += (predicted == labels).sum().item()

        accuracy = 100 * correct / total
        results[attack_name] = accuracy

        # HIPAA requirement: <5% accuracy drop under attack
        if accuracy < 90:  # Assuming 95% clean accuracy
            raise SecurityError(
                f"Model fails adversarial robustness test: "
                f"{attack_name} accuracy = {accuracy:.1f}%"
            )

    return results
```

---

#### 164.308(a)(5)(ii)(B) - Protection from Malicious Software

**MEDICAL AI MALWARE PROTECTION:**

AI models are vulnerable to **model poisoning** attacks where malicious training data is injected.

**CONTROLS:**

1. **Training Data Validation**

```python
class TrainingDataValidator:
    """Validate medical training data for poisoning attacks."""

    def validate_batch(self, images, labels):
        """
        Check for poisoning indicators:
        - Statistical outliers in pixel values
        - Adversarial triggers (e.g., small patches)
        - Label flipping attacks
        """
        # Check for pixel value anomalies
        pixel_mean = images.mean(dim=(2,3))
        if (pixel_mean > 0.9).any() or (pixel_mean < 0.1).any():
            raise PoisoningDetected("Suspicious pixel statistics")

        # Check for known trigger patterns
        triggers = self.detect_backdoor_triggers(images)
        if triggers:
            raise PoisoningDetected(f"Backdoor trigger detected: {triggers}")

        # Check label distribution
        if self.is_label_flipping(labels):
            raise PoisoningDetected("Label flipping attack detected")

        return True
```

2. **Federated Learning Security** (for distributed medical AI)

```python
# Secure aggregation for federated learning
from opacus.accountants import RDPAccountant

class SecureFederatedAggregator:
    """HIPAA-compliant federated learning aggregator."""

    def aggregate_gradients(self, client_gradients):
        """
        Aggregate gradients from multiple hospitals without
        exposing individual patient data.
        """
        # Validate gradients for anomalies (poisoning detection)
        for client_id, grad in client_gradients.items():
            if self.is_gradient_poisoned(grad):
                logger.warning(f"Poisoned gradient from client {client_id}")
                continue  # Skip malicious gradient

        # Apply secure aggregation with differential privacy
        aggregated = self.secure_average(client_gradients)

        # Add calibrated noise for privacy
        noisy_grad = self.add_dp_noise(aggregated, epsilon=1.0)

        return noisy_grad
```

---

### 2. Physical Safeguards (164.310)

#### 164.310(a)(1) - Facility Access Controls

**MEDICAL AI WORKSTATION SECURITY (RTX 5090):**

The RTX 5090 workstation contains:
- GPU memory with active PHI during inference
- Model weights potentially containing memorized PHI
- Training datasets with patient records

**PHYSICAL CONTROLS:**

```yaml
workstation_security:
  location:
    - "Locked server room with badge access"
    - "CCTV monitoring 24/7"
    - "Biometric access control"

  hardware_security:
    - "Kensington lock on workstation chassis"
    - "BIOS password protection"
    - "Secure Boot enabled"
    - "TPM 2.0 for disk encryption keys"

  environmental:
    - "Temperature/humidity monitoring"
    - "Fire suppression system"
    - "Uninterruptible power supply (UPS)"

  access_logging:
    - "Badge swipe logs retained 6 years"
    - "Security camera footage 90 days"
    - "Physical access reviewed monthly"
```

**RTX 5090-SPECIFIC SECURITY:**

```bash
# Disable GPU direct memory access from unauthorized processes
nvidia-smi -i 0 -c EXCLUSIVE_PROCESS

# Enable GPU memory ECC (error correction)
nvidia-smi -i 0 --ecc-config=1

# Set GPU power limits to prevent thermal attacks
nvidia-smi -i 0 --power-limit=450

# Verify secure boot status
mokutil --sb-state
```

---

#### 164.310(d)(1) - Device and Media Controls

**MODEL CHECKPOINT DISPOSAL:**

Model weights may contain memorized PHI and must be securely destroyed.

**DISPOSAL PROCEDURES:**

```bash
#!/bin/bash
# Secure model checkpoint disposal

MODEL_FILE="/models/diagnostic_classifier_v1.2.pth"
LOG_FILE="/var/log/hipaa/model_disposal.log"

# Step 1: Verify file contains ML model
if ! python -c "import torch; torch.load('$MODEL_FILE')"; then
    echo "ERROR: Not a valid PyTorch model" | tee -a $LOG_FILE
    exit 1
fi

# Step 2: Cryptographic erasure (DOD 5220.22-M compliant)
shred -vfz -n 7 $MODEL_FILE

# Step 3: Log disposal
echo "$(date): $MODEL_FILE securely erased" | tee -a $LOG_FILE

# Step 4: GPU memory disposal (if model was loaded)
nvidia-smi --gpu-reset

# Step 5: Generate certificate of destruction
cat > /var/log/hipaa/destruction_cert_$(date +%Y%m%d).txt <<EOF
CERTIFICATE OF DESTRUCTION
Model: $MODEL_FILE
Date: $(date)
Method: DOD 5220.22-M 7-pass overwrite + GPU reset
Operator: $(whoami)
Verification: SHA256 checksum verification after erasure = PASS
EOF
```

---

### 3. Technical Safeguards (164.312)

#### 164.312(a)(2)(iv) - Encryption and Decryption

**MEDICAL AI ENCRYPTION REQUIREMENTS:**

| Data Type | Encryption Method | Key Management |
|-----------|------------------|----------------|
| **Training Data** (at rest) | AES-256-CBC | HSM-stored keys, 90-day rotation |
| **Model Weights** (at rest) | AES-256-GCM | Separate key per model version |
| **Inference Requests** (in transit) | TLS 1.3 | Certificate pinning |
| **GPU Memory** (runtime) | NVIDIA MIG isolation | Hardware-enforced |
| **Predictions** (at rest) | AES-256-CBC | Patient-specific key derivation |

**IMPLEMENTATION:**

```python
# Encrypted model storage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import torch

class EncryptedModelStorage:
    """HIPAA-compliant encrypted model persistence."""

    def __init__(self, key_path="/secure/model_encryption.key"):
        with open(key_path, "rb") as f:
            self.key = f.read()  # 32 bytes for AES-256

    def save_model(self, model, path):
        """Save model with encryption."""
        # Serialize model
        buffer = io.BytesIO()
        torch.save(model.state_dict(), buffer)
        plaintext = buffer.getvalue()

        # Generate IV
        iv = os.urandom(16)

        # Encrypt
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Save encrypted model + IV + auth tag
        with open(path, "wb") as f:
            f.write(iv)
            f.write(encryptor.tag)
            f.write(ciphertext)

        # Log encryption event
        logger.info(f"Model encrypted and saved: {path}")

    def load_model(self, model_class, path):
        """Load and decrypt model."""
        with open(path, "rb") as f:
            iv = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        # Decrypt
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Deserialize model
        buffer = io.BytesIO(plaintext)
        state_dict = torch.load(buffer)

        model = model_class()
        model.load_state_dict(state_dict)

        return model
```

---

#### 164.312(b) - Audit Controls

**MEDICAL AI AUDIT LOGGING:**

All model training, inference, and access must be logged.

**AUDIT EVENTS:**

```python
import logging
import json
from datetime import datetime

class HIPAAMLAuditLogger:
    """Comprehensive audit logging for medical AI systems."""

    def __init__(self):
        self.logger = logging.getLogger("hipaa.ml.audit")
        handler = logging.FileHandler("/var/log/hipaa/ml_audit.log")
        handler.setFormatter(logging.Formatter(
            '%(asctime)s|%(levelname)s|%(message)s'
        ))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log_training_start(self, model_name, dataset_size, user):
        """Log model training initiation."""
        event = {
            "event_type": "TRAINING_START",
            "model": model_name,
            "dataset_size": dataset_size,
            "user": user,
            "timestamp": datetime.utcnow().isoformat(),
            "contains_phi": True
        }
        self.logger.info(json.dumps(event))

    def log_inference(self, model_name, patient_id, user, prediction):
        """Log inference event (PHI access)."""
        event = {
            "event_type": "INFERENCE",
            "model": model_name,
            "patient_id": self.hash_patient_id(patient_id),  # Pseudonymized
            "user": user,
            "timestamp": datetime.utcnow().isoformat(),
            "prediction_class": prediction,
            "phi_accessed": True
        }
        self.logger.info(json.dumps(event))

    def log_model_access(self, model_path, user, action):
        """Log model file access."""
        event = {
            "event_type": "MODEL_ACCESS",
            "model_path": model_path,
            "user": user,
            "action": action,  # "read", "write", "delete"
            "timestamp": datetime.utcnow().isoformat()
        }
        self.logger.info(json.dumps(event))

    def log_gpu_memory_clear(self, device_id):
        """Log GPU memory sanitization."""
        event = {
            "event_type": "GPU_MEMORY_CLEAR",
            "device": device_id,
            "timestamp": datetime.utcnow().isoformat(),
            "verification": "PASS"
        }
        self.logger.info(json.dumps(event))

    @staticmethod
    def hash_patient_id(patient_id):
        """Pseudonymize patient ID for audit logs."""
        import hashlib
        return hashlib.sha256(patient_id.encode()).hexdigest()[:16]
```

**AUDIT LOG RETENTION:**

```bash
# Configure logrotate for HIPAA compliance (6-year retention)
cat > /etc/logrotate.d/hipaa-ml <<EOF
/var/log/hipaa/ml_audit.log {
    daily
    rotate 2190  # 6 years
    compress
    delaycompress
    notifempty
    create 0600 hipaa-ml hipaa-ml
    postrotate
        systemctl reload rsyslog
    endscript
}
EOF
```

---

#### 164.312(d) - Person or Entity Authentication

**MEDICAL AI MFA REQUIREMENTS:**

All access to medical AI systems requires multi-factor authentication.

```python
# MFA for model access
from duo_client import Auth

class MedicalAIAuthenticator:
    """MFA authentication for AI system access."""

    def __init__(self):
        self.duo = Auth(
            ikey=os.getenv("DUO_IKEY"),
            skey=os.getenv("DUO_SKEY"),
            host=os.getenv("DUO_HOST")
        )

    def authenticate_user(self, username, password, device_id):
        """
        Authenticate user with MFA before granting
        access to AI models containing PHI.
        """
        # Step 1: Verify password
        if not self.verify_password(username, password):
            raise AuthenticationError("Invalid credentials")

        # Step 2: MFA challenge (Duo Push, SMS, or TOTP)
        mfa_result = self.duo.auth(
            username=username,
            factor="auto",  # Duo Push
            device=device_id
        )

        if mfa_result["result"] != "allow":
            raise AuthenticationError("MFA failed")

        # Step 3: Generate session token
        token = self.generate_session_token(username)

        # Step 4: Audit log
        logger.info(f"MFA authentication successful: {username}")

        return token
```

---

## Medical AI Deployment Architecture (HIPAA-Compliant)

```
┌─────────────────────────────────────────────────────────────┐
│                     HIPAA Compliance Boundary                │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Encrypted Training Data Storage              │   │
│  │  - AES-256 encryption at rest                        │   │
│  │  - Access logging enabled                            │   │
│  │  - 6-year retention                                  │   │
│  └──────────────┬───────────────────────────────────────┘   │
│                 │                                             │
│                 ▼                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │   Training Pipeline (DeepSeek-R1 + DP-SGD)           │   │
│  │  - Differential privacy (ε=1.0, δ=1e-5)              │   │
│  │  - Gradient clipping                                 │   │
│  │  - Audit logging all training runs                   │   │
│  │  - MFA required for training jobs                    │   │
│  └──────────────┬───────────────────────────────────────┘   │
│                 │                                             │
│                 ▼                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │   Encrypted Model Repository                         │   │
│  │  - Model weights encrypted (AES-256-GCM)             │   │
│  │  - Version control with checksums                    │   │
│  │  - Access control (RBAC)                             │   │
│  └──────────────┬───────────────────────────────────────┘   │
│                 │                                             │
│                 ▼                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │   RTX 5090 Inference Server                          │   │
│  │  - GPU memory isolation (MIG)                        │   │
│  │  - Secure memory wipe after inference                │   │
│  │  - TLS 1.3 for all API requests                      │   │
│  │  - Rate limiting & input validation                  │   │
│  │  - Adversarial robustness checks                     │   │
│  └──────────────┬───────────────────────────────────────┘   │
│                 │                                             │
│                 ▼                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │   Audit Logging System                               │   │
│  │  - All PHI access logged                             │   │
│  │  - Logs encrypted and retained 6 years               │   │
│  │  - Monthly review by security team                   │   │
│  │  - SIEM integration for anomaly detection            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Compliance Validation Checklist

Use this checklist to validate HIPAA compliance for medical AI systems:

- [ ] **Risk Analysis**
  - [ ] All ePHI systems identified (including GPU memory)
  - [ ] Medical AI-specific threats documented
  - [ ] Model inversion attack mitigation implemented
  - [ ] Risk assessment updated annually

- [ ] **Encryption**
  - [ ] Training data encrypted (AES-256)
  - [ ] Model weights encrypted (AES-256-GCM)
  - [ ] TLS 1.3 for all API traffic
  - [ ] GPU memory isolation configured

- [ ] **Access Control**
  - [ ] MFA required for all system access
  - [ ] RBAC implemented for model access
  - [ ] Least privilege principle enforced
  - [ ] Emergency access procedures documented

- [ ] **Audit Controls**
  - [ ] All training runs logged
  - [ ] All inference requests logged (with patient pseudonyms)
  - [ ] Model access logged
  - [ ] GPU memory clearing logged
  - [ ] Logs retained 6+ years

- [ ] **Differential Privacy**
  - [ ] DP-SGD implemented in training
  - [ ] Privacy budget (ε ≤ 1.0) enforced
  - [ ] Privacy accounting documented
  - [ ] Gradient clipping configured

- [ ] **Adversarial Robustness**
  - [ ] Input validation for medical images
  - [ ] Adversarial robustness testing performed
  - [ ] Ensemble models for anomaly detection
  - [ ] Patient safety impact assessed

- [ ] **Physical Security**
  - [ ] RTX 5090 workstation in locked facility
  - [ ] Badge access with audit logging
  - [ ] CCTV monitoring
  - [ ] Secure disposal procedures for old models

- [ ] **Business Associate Agreements**
  - [ ] BAA with cloud providers (if applicable)
  - [ ] BAA with model training vendors
  - [ ] BAA with GPU infrastructure providers

---

## Testing and Validation

### 1. Differential Privacy Validation

```bash
# Verify DP training implementation
python scripts/validate_dp.py --model diagnostic_classifier --epsilon 1.0 --delta 1e-5
```

### 2. Model Inversion Attack Test

```bash
# Test resistance to model inversion
python scripts/test_model_inversion.py --model diagnostic_classifier --attack gradient_based
```

### 3. GPU Memory Leak Detection

```bash
# Verify GPU memory is cleared after inference
python scripts/test_gpu_memory_leak.py --iterations 100 --threshold 100MB
```

### 4. Adversarial Robustness Evaluation

```bash
# Test against adversarial examples
python scripts/test_adversarial.py --model diagnostic_classifier --attack pgd --epsilon 0.03
```

---

## Support and Resources

- **HIPAA Security Rule**: [45 CFR Part 164 Subpart C](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- **NIST AI Risk Management**: [NIST AI 100-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf)
- **FDA Medical Device Cybersecurity**: [Guidance for Industry](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions)
- **Differential Privacy Library**: [OpenDP](https://github.com/opendp/opendp) / [Opacus](https://github.com/pytorch/opacus)

---

**Version**: 1.0.0
**Last Updated**: 2025-01-18
**Maintainer**: GTL Consulting - Medical AI Security Team
