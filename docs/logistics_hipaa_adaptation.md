# Logistics Sector HIPAA Compliance Adaptation

## Overview

This guide adapts HIPAA Security Rule controls for **logistics and supply chain companies** that handle Protected Health Information (PHI), with specific focus on:
- **Peru SUNAT** customs and tax compliance
- **EDI (Electronic Data Interchange)** security for healthcare supply chains
- **Cold chain logistics** for pharmaceuticals and medical devices
- **Medical equipment import/export** documentation

Many logistics companies are **Business Associates** under HIPAA when they:
- Transport medical records or patient specimens
- Handle pharmaceutical shipments with patient information
- Manage medical device logistics with PHI
- Process healthcare billing/claims data via EDI

---

## SUNAT Peru Compliance Integration

### Background

**SUNAT (Superintendencia Nacional de Aduanas y de Administración Tributaria)** regulates customs and tax in Peru. Logistics companies must comply with:
- **Electronic Invoice System (SEE)** - XML-based invoicing
- **Customs Declaration System (VUCE)** - Single window for foreign trade
- **EDI Integration** - X12/EDIFACT for customs clearance

When these systems handle medical shipments containing PHI, **both SUNAT and HIPAA compliance** are required.

---

## HIPAA Controls Adapted for Logistics

### 1. Administrative Safeguards (164.308)

#### 164.308(a)(1)(i) - Risk Analysis (Logistics Adaptation)

**LOGISTICS-SPECIFIC ePHI SYSTEMS:**

| System | PHI Type | HIPAA Applicability | SUNAT Relevance |
|--------|----------|---------------------|-----------------|
| **EDI Gateway** | Patient names in shipping manifests | Business Associate | Customs declarations |
| **Warehouse Management System (WMS)** | Medical device serial numbers linked to patients | Business Associate | Inventory control |
| **Transportation Management System (TMS)** | Patient specimen tracking | Business Associate | Route optimization |
| **Cold Chain Monitoring** | Pharmaceutical shipments for named patients | Business Associate | Temperature compliance |
| **Customs Broker Portal** | Medical records for customs clearance | Business Associate | SUNAT integration |

**LOGISTICS THREAT MODEL:**

```yaml
threats:
  edi_injection:
    description: "Malicious EDI messages inject SQL/XML payloads"
    likelihood: "High"
    impact: "High"
    example: "Attacker modifies X12 850 Purchase Order to extract PHI"
    mitigation:
      - "EDI schema validation"
      - "Input sanitization"
      - "Parameterized queries"

  shipment_tracking_exposure:
    description: "Patient names visible in public tracking systems"
    likelihood: "Medium"
    impact: "Critical"
    example: "Package tracking shows 'Insulin for Juan Pérez' publicly"
    mitigation:
      - "Pseudonymize patient names in tracking"
      - "Separate tracking ID from PHI"
      - "Access controls on tracking portal"

  customs_data_breach:
    description: "PHI leaked during SUNAT customs clearance"
    likelihood: "Medium"
    impact: "High"
    example: "Medical device import declaration includes patient diagnosis"
    mitigation:
      - "Minimize PHI in customs documents"
      - "Encrypt VUCE transmissions"
      - "Audit all SUNAT API calls"

  cold_chain_tampering:
    description: "Temperature sensors compromised, affecting patient safety"
    likelihood: "Low"
    impact: "Critical"
    example: "Attacker raises temperature to destroy insulin shipment"
    mitigation:
      - "IoT sensor authentication"
      - "Tamper-evident packaging"
      - "Real-time alerting"

  warehouse_access_breach:
    description: "Unauthorized access to medical shipments"
    likelihood: "Medium"
    impact: "High"
    example: "Warehouse worker photographs medical records in transit"
    mitigation:
      - "Badge access control"
      - "CCTV surveillance"
      - "No-phone policy in secure areas"
```

**VALIDATION:**

```python
# Logistics risk assessment automation
from src.compliance.frameworks.hipaa import HIPAAFramework

logistics_system_config = {
    "system_name": "Medical Logistics Platform",
    "edi_gateway": {
        "protocols": ["X12", "EDIFACT", "XML"],
        "partners": 50,
        "daily_volume": 1000
    },
    "sunat_integration": {
        "vuce_enabled": True,
        "electronic_invoice": True,
        "customs_api": "https://api.sunat.gob.pe"
    },
    "phi_types": [
        "Patient names on shipping labels",
        "Medical device serial numbers",
        "Prescription information"
    ]
}

# Assess compliance
framework = HIPAAFramework(claude_client=claude)
result = await framework.assess_compliance(
    system_config=logistics_system_config,
    system_context={"sector": "LOGISTICS", "country": "PERU"}
)
```

---

#### 164.308(a)(4)(i) - Access Authorization (Logistics)

**ROLE-BASED ACCESS CONTROL FOR LOGISTICS:**

```yaml
roles:
  warehouse_worker:
    permissions:
      - "scan_package_barcode"
      - "update_shipment_location"
    restrictions:
      - "cannot_view_patient_names"
      - "cannot_view_prescription_details"
    phi_access: "Minimal"

  customs_broker:
    permissions:
      - "submit_vuce_declaration"
      - "view_shipment_hs_code"
      - "access_commercial_invoice"
    restrictions:
      - "cannot_view_patient_diagnosis"
      - "can_view_pseudonymized_patient_id_only"
    phi_access: "Limited"

  pharmacist_logistics_coordinator:
    permissions:
      - "view_prescription_details"
      - "verify_medication_integrity"
      - "approve_cold_chain_exception"
    restrictions:
      - "audit_logged_all_phi_access"
    phi_access: "Full (with BAA)"

  driver:
    permissions:
      - "scan_delivery_confirmation"
      - "view_delivery_address"
    restrictions:
      - "cannot_view_package_contents"
      - "cannot_view_patient_names"
    phi_access: "None"
```

**IMPLEMENTATION:**

```python
# RBAC for logistics system
class LogisticsAccessControl:
    """HIPAA-compliant access control for logistics."""

    def authorize_shipment_access(self, user_role, shipment_id, action):
        """
        Authorize access to shipment data based on role
        and minimum necessary principle.
        """
        shipment = self.get_shipment(shipment_id)

        # Check if shipment contains PHI
        if shipment.contains_phi:
            # Warehouse worker cannot view PHI
            if user_role == "warehouse_worker" and action == "view_details":
                raise PermissionDenied(
                    "Warehouse workers cannot view PHI. "
                    "Use barcode scanning only."
                )

            # Customs broker can only see pseudonymized data
            if user_role == "customs_broker":
                return self.get_pseudonymized_shipment(shipment)

            # Driver cannot view package contents
            if user_role == "driver" and action == "view_contents":
                raise PermissionDenied(
                    "Drivers cannot view package contents."
                )

        # All PHI access must be logged
        if shipment.contains_phi:
            self.audit_log.log_phi_access(
                user=user,
                shipment=shipment_id,
                action=action,
                timestamp=datetime.now()
            )

        return shipment
```

---

### 2. Physical Safeguards (164.310)

#### 164.310(a)(1) - Facility Access Controls (Warehouses)

**WAREHOUSE SECURITY FOR MEDICAL SHIPMENTS:**

Logistics warehouses storing medical shipments with PHI require physical safeguards.

**CONTROLS:**

```yaml
warehouse_security:
  perimeter:
    - "Fenced compound with single entry point"
    - "24/7 security guard"
    - "Vehicle inspection at gate"

  access_control:
    - "Badge access system (HID or similar)"
    - "Biometric fingerprint for PHI storage area"
    - "Visitor log with escort requirement"
    - "Separate secure zone for medical shipments"

  surveillance:
    - "CCTV coverage of all PHI storage areas"
    - "90-day video retention"
    - "Motion sensors after hours"
    - "Panic buttons in secure areas"

  medical_shipment_zone:
    location: "Separate locked cage within warehouse"
    access: "Pharmacist coordinator + manager only"
    temperature: "Monitored 24/7 for cold chain"
    audit: "All entries/exits logged"
```

**TEMPERATURE MONITORING (Cold Chain Compliance):**

```python
# IoT cold chain monitoring with HIPAA compliance
class ColdChainMonitor:
    """
    Monitor temperature-sensitive medical shipments
    containing PHI (e.g., insulin for named patient).
    """

    def __init__(self):
        self.sensors = self.initialize_sensors()
        self.alert_thresholds = {
            "insulin": (2, 8),  # °C
            "vaccines": (2, 8),
            "blood_products": (1, 6)
        }

    def monitor_shipment(self, shipment_id, product_type):
        """Real-time temperature monitoring."""
        sensor = self.sensors[shipment_id]

        while True:
            temp = sensor.read_temperature()
            timestamp = datetime.now()

            # Log temperature
            self.audit_log.log_temperature(
                shipment=shipment_id,
                temperature=temp,
                timestamp=timestamp
            )

            # Check threshold
            min_temp, max_temp = self.alert_thresholds[product_type]

            if temp < min_temp or temp > max_temp:
                # CRITICAL: Patient safety at risk
                self.send_alert(
                    severity="CRITICAL",
                    message=f"Shipment {shipment_id} out of range: {temp}°C",
                    patient_impact=True
                )

                # HIPAA: Log patient safety incident
                self.hipaa_incident_log.log_incident(
                    type="COLD_CHAIN_BREACH",
                    shipment=shipment_id,
                    patient_safety_impact=True,
                    breach_notification_required=self.assess_breach_risk()
                )

            time.sleep(60)  # Check every minute
```

---

### 3. Technical Safeguards (164.312)

#### 164.312(a)(2)(iv) - Encryption (EDI and SUNAT Integration)

**EDI ENCRYPTION REQUIREMENTS:**

Logistics companies transmitting PHI via EDI must encrypt all messages.

**EDI PROTOCOLS AND SECURITY:**

| Protocol | Use Case | Encryption | HIPAA Compliance |
|----------|----------|------------|------------------|
| **X12 837** | Healthcare claims | TLS 1.3 + AS2 encryption | Required |
| **X12 850** | Purchase orders (medical supplies) | TLS 1.3 | Required if contains PHI |
| **EDIFACT IFTMIN** | Shipping instructions | TLS 1.3 | Required if contains PHI |
| **XML (VUCE Peru)** | Customs declarations to SUNAT | TLS 1.3 + XML encryption | Required if medical shipment has PHI |

**IMPLEMENTATION:**

```python
# Secure EDI transmission
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests

class SecureEDIGateway:
    """HIPAA-compliant EDI gateway for logistics."""

    def send_edi_message(self, message, partner_url, contains_phi=False):
        """
        Send EDI message with encryption if PHI present.
        """
        # Step 1: Validate EDI message format
        if not self.validate_edi(message):
            raise ValueError("Invalid EDI message format")

        # Step 2: Encrypt if contains PHI
        if contains_phi:
            encrypted_message = self.encrypt_edi(message)
        else:
            encrypted_message = message

        # Step 3: Send via TLS 1.3
        response = requests.post(
            partner_url,
            data=encrypted_message,
            headers={
                "Content-Type": "application/edi-x12",
                "X-PHI-Present": "true" if contains_phi else "false"
            },
            verify=True,  # Verify SSL certificate
            timeout=30
        )

        # Step 4: Audit log
        self.audit_log.log_edi_transmission(
            partner=partner_url,
            message_type=self.get_edi_type(message),
            contains_phi=contains_phi,
            status=response.status_code,
            timestamp=datetime.now()
        )

        return response

    def encrypt_edi(self, message):
        """Encrypt EDI message containing PHI."""
        # AES-256-GCM encryption
        key = self.get_partner_encryption_key()
        iv = os.urandom(12)

        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv)
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

        # Return IV + tag + ciphertext (base64 encoded)
        encrypted = base64.b64encode(iv + encryptor.tag + ciphertext)
        return encrypted
```

**SUNAT VUCE INTEGRATION (Peru Customs):**

```python
# Secure SUNAT API integration
class SUNATIntegration:
    """
    HIPAA-compliant SUNAT customs integration for
    medical device/pharmaceutical imports to Peru.
    """

    SUNAT_API_URL = "https://api.sunat.gob.pe/v1/contribuyente/vuce"

    def submit_customs_declaration(self, shipment_id, hs_code, description):
        """
        Submit customs declaration to SUNAT VUCE system.
        Minimize PHI in declaration.
        """
        shipment = self.get_shipment(shipment_id)

        # HIPAA: Minimize PHI in customs documents
        # Instead of: "Insulin for patient Juan Pérez"
        # Use: "Pharmaceutical product (HS 3004.90.99)"
        sanitized_description = self.remove_phi_from_description(description)

        declaration = {
            "ruc": os.getenv("SUNAT_RUC"),  # Company tax ID
            "numero_correlativo": shipment_id,
            "codigo_arancelario": hs_code,
            "descripcion_mercancia": sanitized_description,
            "valor_fob": shipment.value_usd,
            "peso_bruto": shipment.weight_kg
        }

        # Send to SUNAT via TLS 1.3
        response = requests.post(
            self.SUNAT_API_URL,
            json=declaration,
            headers={
                "Authorization": f"Bearer {self.get_sunat_token()}",
                "Content-Type": "application/json"
            },
            verify=True,
            cert=("/path/to/client.crt", "/path/to/client.key")  # Client cert
        )

        # Audit log SUNAT interaction
        self.audit_log.log_sunat_submission(
            shipment=shipment_id,
            declaration_number=response.json().get("numero_declaracion"),
            status=response.status_code,
            phi_minimized=True
        )

        return response.json()

    def remove_phi_from_description(self, description):
        """
        Remove patient names and diagnosis from customs description.
        HIPAA minimum necessary principle.
        """
        # Replace patient names with generic terms
        sanitized = re.sub(
            r'\b(for patient|para paciente)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b',
            'for medical use',
            description,
            flags=re.IGNORECASE
        )

        # Remove diagnosis information
        sanitized = re.sub(
            r'\b(diabetes|cancer|hypertension|COVID-19)\b',
            'medical condition',
            sanitized,
            flags=re.IGNORECASE
        )

        return sanitized
```

---

#### 164.312(b) - Audit Controls (Logistics)

**SHIPMENT TRACKING AUDIT LOGS:**

All access to shipments containing PHI must be logged.

```python
class LogisticsAuditLogger:
    """Comprehensive audit logging for logistics operations."""

    def log_shipment_scan(self, user, shipment_id, location, device_id):
        """Log warehouse scan event."""
        shipment = self.get_shipment(shipment_id)

        event = {
            "event_type": "SHIPMENT_SCAN",
            "user": user,
            "shipment_id": shipment_id,
            "contains_phi": shipment.contains_phi,
            "location": location,
            "device_id": device_id,
            "timestamp": datetime.utcnow().isoformat()
        }

        self.write_audit_log(event)

    def log_edi_message(self, message_type, partner, contains_phi, direction):
        """Log EDI transmission."""
        event = {
            "event_type": "EDI_TRANSMISSION",
            "message_type": message_type,  # e.g., "X12_850"
            "partner": partner,
            "direction": direction,  # "inbound" or "outbound"
            "contains_phi": contains_phi,
            "timestamp": datetime.utcnow().isoformat()
        }

        self.write_audit_log(event)

    def log_sunat_api_call(self, endpoint, shipment_id, response_code):
        """Log SUNAT customs API interaction."""
        event = {
            "event_type": "SUNAT_API_CALL",
            "endpoint": endpoint,
            "shipment_id": shipment_id,
            "response_code": response_code,
            "timestamp": datetime.utcnow().isoformat()
        }

        self.write_audit_log(event)

    def log_temperature_alert(self, shipment_id, temperature, threshold):
        """Log cold chain temperature alert (patient safety)."""
        event = {
            "event_type": "COLD_CHAIN_ALERT",
            "shipment_id": shipment_id,
            "temperature": temperature,
            "threshold": threshold,
            "patient_safety_impact": True,
            "timestamp": datetime.utcnow().isoformat()
        }

        self.write_audit_log(event)

        # HIPAA: Trigger breach assessment if temperature exceeded for >2 hours
        self.assess_potential_breach(shipment_id)
```

---

## Business Associate Agreement (BAA) Requirements

Logistics companies handling PHI must have BAAs with:
1. **Healthcare Providers** (hospitals, clinics shipping specimens)
2. **Pharmaceutical Manufacturers** (patient-specific medication shipments)
3. **Medical Device Companies** (implantable devices with patient data)
4. **Cloud Providers** (if using SaaS for shipment tracking)

**BAA CHECKLIST:**

```yaml
baa_requirements:
  permitted_uses:
    - "Transportation of medical devices"
    - "Warehousing of pharmaceutical shipments"
    - "Customs clearance for medical equipment"
    - "EDI transmission of healthcare claims"

  safeguards:
    - "Encryption of all PHI in transit and at rest"
    - "Access controls on warehouse zones with PHI"
    - "Audit logging of all PHI access"
    - "Background checks for employees accessing PHI"

  subcontractors:
    - "Trucking companies (require downstream BAA)"
    - "Customs brokers (require downstream BAA)"
    - "Cold chain monitoring vendors (require downstream BAA)"

  breach_notification:
    - "Notify covered entity within 48 hours of discovery"
    - "Document breach assessment"
    - "Cooperate with covered entity's breach response"

  termination:
    - "Return or destroy all PHI upon contract termination"
    - "Certify destruction of PHI"
    - "30-day notice period"
```

---

## SUNAT + HIPAA Compliance Matrix

| SUNAT Requirement | HIPAA Control | Implementation |
|-------------------|---------------|----------------|
| **Electronic Invoice (SEE)** | 164.312(e) Transmission Security | TLS 1.3 for SUNAT XML invoices |
| **VUCE Customs Declaration** | 164.502(b) Minimum Necessary | Remove patient names from customs docs |
| **RUC Taxpayer Registry** | 164.308(a)(4) Access Management | Only authorized users access SUNAT portal |
| **Digital Signature (Factura Electrónica)** | 164.312(c)(2) Integrity Authentication | Sign all SUNAT invoices with certificate |
| **Audit Trail (Libro Electrónico)** | 164.312(b) Audit Controls | Retain SUNAT transaction logs 6 years |

---

## Cold Chain Compliance (Pharmaceuticals)

**HIPAA + GDP (Good Distribution Practice) Integration:**

```yaml
cold_chain_controls:
  temperature_monitoring:
    - "IoT sensors with 1-minute logging"
    - "Real-time alerts for out-of-range temps"
    - "Audit log all temperature readings"
    - "Patient safety incident if >2°C deviation"

  packaging_integrity:
    - "Tamper-evident seals"
    - "Temperature indicator labels"
    - "Photo documentation at each checkpoint"

  transport_validation:
    - "Qualified vehicles with refrigeration"
    - "Pre-trip temperature validation"
    - "Driver training on cold chain procedures"

  patient_notification:
    - "Automated SMS if shipment delayed >4 hours"
    - "Pharmacist callback if temperature exceeded"
    - "Replacement shipment protocol"
```

---

## Sample Logistics Assessment Scenario

```python
# Example: Assess HIPAA compliance for Peru pharmaceutical logistics

from src.compliance.frameworks.hipaa import HIPAAFramework

# System configuration
logistics_config = {
    "company_name": "MedLogistics Peru SAC",
    "business_type": "Pharmaceutical cold chain logistics",
    "locations": ["Lima warehouse", "Callao port", "Arequipa distribution center"],
    "sunat_integration": {
        "ruc": "20123456789",
        "vuce_enabled": True,
        "electronic_invoice": True
    },
    "phi_handling": {
        "shipment_types": [
            "Insulin for named patients",
            "Chemotherapy drugs with patient IDs",
            "Medical devices with implant records"
        ],
        "volume": "500 shipments/month",
        "storage": "Temperature-controlled warehouse (2-8°C)"
    },
    "security_controls": {
        "warehouse_access": "Badge + biometric",
        "edi_encryption": "TLS 1.3",
        "audit_logging": "Enabled",
        "cold_chain_monitoring": "Real-time IoT sensors"
    }
}

# Evidence
evidence = {
    "HIPAA-164.310(a)(1)": [
        {
            "type": "facility_inspection",
            "date": "2024-01-15",
            "findings": "Badge access system operational, CCTV coverage 100%"
        }
    ],
    "HIPAA-164.312(e)(1)": [
        {
            "type": "network_scan",
            "date": "2024-01-20",
            "findings": "TLS 1.3 enforced on all SUNAT API calls"
        }
    ]
}

# Assess compliance
framework = HIPAAFramework(claude_client=claude)

result = await framework.assess_compliance(
    system_config=logistics_config,
    evidence=evidence,
    system_context={
        "sector": "LOGISTICS",
        "country": "PERU",
        "regulations": ["HIPAA", "SUNAT", "GDP"]
    }
)

print(f"Compliance Score: {result['summary']['compliance_score']:.1f}%")
print(f"Critical Gaps: {result['summary']['critical_gaps']}")

# Generate remediation plan
roadmap = await framework.generate_remediation_plan(
    gap_report=result['gap_report'],
    assessments=result['assessments'],
    constraints={
        "budget_usd": 75000,
        "timeline_weeks": 16,
        "team_size": 4
    }
)

print(f"Remediation Timeline: {roadmap.total_duration_days} days")
print(f"Estimated Cost: ${roadmap.total_cost:,.0f}")
```

---

## Conclusion

Logistics companies in the medical supply chain face dual compliance challenges:
1. **HIPAA Security Rule** - Protecting PHI in shipments
2. **SUNAT Regulations** - Peruvian customs and tax compliance

Key takeaways:
- **Minimize PHI** in customs declarations and tracking systems
- **Encrypt EDI** transmissions containing healthcare data
- **Secure warehouses** storing medical shipments
- **Monitor cold chain** for patient safety
- **Execute BAAs** with all healthcare partners
- **Audit all access** to shipments containing PHI

---

**Version**: 1.0.0
**Last Updated**: 2025-01-18
**Maintainer**: GTL Consulting - Logistics Security Team
