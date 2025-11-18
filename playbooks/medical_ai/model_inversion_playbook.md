# Model Inversion Attack Response Playbook

## Attack Overview

**Attack**: Model Inversion
**MITRE ATT&CK**: T1567 (Exfiltration Over Web Service)
**Severity**: CRITICAL
**Patient Safety**: Low
**Breach Risk**: HIGH

**Description**: Attacker queries medical AI model repeatedly with crafted inputs to reverse-engineer training data, potentially exposing patient PHI used in model training.

---

## Detection Indicators

### Automated Alerts
- ✓ Query rate >100/hour from single source
- ✓ Query similarity >80% (high correlation between queries)
- ✓ Systematic parameter sweeping patterns
- ✓ Unusual API usage from specific user/IP

### Manual Investigation Triggers
- User reporting suspicious activity
- Compliance audit finding
- Third-party security researcher report

---

## Response Phases

### Phase 1: DETECTION & TRIAGE (0-15 minutes)

**Actions**:
1. **Confirm Alert Validity**
   ```bash
   # Review query logs for suspected user
   grep "user_id=SUSPECT_ID" /var/log/medical_ai/api.log | tail -1000

   # Calculate query rate
   python /scripts/analyze_query_rate.py --user SUSPECT_ID --hours 1

   # Check query similarity
   python /scripts/calculate_query_similarity.py --user SUSPECT_ID
   ```

2. **Assess Severity**
   - [ ] Confirm high query rate (>100/hour)
   - [ ] Confirm high similarity (>80%)
   - [ ] Check if PHI potentially exposed in responses
   - [ ] Determine attack duration

3. **Initial Classification**
   - **Confirmed Attack**: Proceed to Phase 2
   - **False Positive**: Document and close
   - **Unclear**: Escalate to security team lead

**Stakeholders**:
- Security Operations Center (SOC)
- On-call security engineer

**Maximum Duration**: 15 minutes

---

### Phase 2: CONTAINMENT (15-30 minutes)

**Immediate Actions**:

1. **Block Attacker**
   ```bash
   # Temporarily block user account
   python /scripts/security/block_user.py --user-id SUSPECT_ID --reason "model_inversion_attack"

   # Block source IP
   sudo iptables -A INPUT -s ATTACKER_IP -j DROP

   # Update API gateway rules
   aws apigateway update-usage-plan --api-id XXX --throttle user-id=SUSPECT_ID:0
   ```

2. **Prevent Further Exfiltration**
   - [ ] Enable enhanced output perturbation (increase noise)
   - [ ] Reduce API rate limits globally (temporary)
   - [ ] Enable additional logging for all model queries

3. **Preserve Evidence**
   ```bash
   # Archive attack logs
   mkdir -p /incident_response/model_inversion_$(date +%Y%m%d_%H%M%S)
   cp /var/log/medical_ai/api.log /incident_response/model_inversion_*/
   cp /var/log/medical_ai/model_inference.log /incident_response/model_inversion_*/

   # Export database records
   pg_dump -t api_requests -t model_queries -f /incident_response/model_inversion_*/attack_data.sql
   ```

**Stakeholders**:
- SOC team
- Security engineer
- DevOps team (for infrastructure changes)

**Maximum Duration**: 15 minutes

---

### Phase 3: INVESTIGATION (30 minutes - 4 hours)

**Detailed Analysis**:

1. **Reconstruct Attack Timeline**
   ```python
   # Analyze complete attack pattern
   from src.intelligence.sectors.medical_ai_intel import MedicalAIAnomalyDetector

   detector = MedicalAIAnomalyDetector()

   # Load query history
   queries = load_user_queries(user_id="SUSPECT_ID", hours=24)

   # Analyze patterns
   alert = await detector.detect_model_inversion_attempt(
       user_id="SUSPECT_ID",
       query_history=queries,
       time_window_minutes=60
   )

   print(f"Attack indicators: {alert.indicators}")
   print(f"Confidence: {alert.confidence}")
   ```

2. **Assess PHI Exposure Risk**
   - [ ] Review model outputs for verbatim PHI
   - [ ] Check if differential privacy was enabled
   - [ ] Estimate potential data reconstruction accuracy
   - [ ] Identify affected patient records (if any)

   ```python
   # Check for PHI in responses
   responses = get_api_responses(user_id="SUSPECT_ID")

   phi_detected = []
   for response in responses:
       if contains_phi_patterns(response):
           phi_detected.append(response)

   print(f"Responses with potential PHI: {len(phi_detected)}")
   ```

3. **Determine Attack Success**
   - **Successful**: PHI likely extracted → HIPAA breach notification required
   - **Attempted**: No evidence of successful PHI extraction → No breach notification
   - **Uncertain**: Consult legal and compliance teams

4. **Identify Attack Source**
   - Geographic location
   - User account details
   - Payment information (if applicable)
   - Linked accounts or IPs

**Stakeholders**:
- Security team lead
- Compliance officer (if breach suspected)
- Legal counsel (if breach suspected)
- Clinical informatics team

**Maximum Duration**: 4 hours

---

### Phase 4: ERADICATION (4-8 hours)

**Remediation Actions**:

1. **Strengthen Model Defenses** (if attack ongoing)
   ```python
   # Enable differential privacy with stronger epsilon
   model_config = {
       "differential_privacy": True,
       "epsilon": 0.5,  # Reduce from 1.0 for stronger privacy
       "delta": 1e-5,
       "noise_multiplier": 1.5
   }

   update_model_config(model_config)
   ```

2. **Implement Additional Controls**
   - [ ] Lower API rate limits per user (e.g., 50/hour)
   - [ ] Add CAPTCHA for high-frequency users
   - [ ] Implement query cost (e.g., credits system)
   - [ ] Add output rounding (reduce precision)

   ```python
   # Update API rate limits
   new_limits = {
       "requests_per_hour": 50,
       "requests_per_day": 500,
       "burst_limit": 10
   }

   update_rate_limits(new_limits)
   ```

3. **Patch Vulnerabilities**
   - [ ] Review and update access controls
   - [ ] Fix any configuration weaknesses
   - [ ] Update anomaly detection rules

**Stakeholders**:
- Security engineering team
- ML engineering team
- DevOps team

**Maximum Duration**: 4 hours

---

### Phase 5: RECOVERY (8-24 hours)

**Service Restoration**:

1. **Verify Security Posture**
   - [ ] Confirm attacker blocked
   - [ ] Validate enhanced protections active
   - [ ] Test anomaly detection with simulated attacks
   - [ ] Review similar user accounts for coordinated attacks

2. **Resume Normal Operations**
   - [ ] Gradually restore API rate limits
   - [ ] Monitor for attack recurrence
   - [ ] Communicate status to stakeholders

3. **User Communication** (if legitimate users affected)
   ```
   Subject: Temporary Service Disruption - Security Enhancement

   We recently detected and successfully blocked a security threat
   targeting our medical AI system. As a precautionary measure, we
   temporarily reduced API access for all users.

   Service has been fully restored with enhanced security controls.
   We have confirmed no patient data was compromised.

   Thank you for your patience and understanding.
   ```

**Stakeholders**:
- Product management
- Customer support
- Communications team

**Maximum Duration**: 16 hours

---

### Phase 6: POST-INCIDENT (24-72 hours)

**Follow-up Actions**:

1. **Breach Notification Assessment**

   **If PHI Exposure Confirmed**:
   - [ ] Notify affected patients (HIPAA Breach Notification Rule)
   - [ ] Report to HHS if >500 individuals affected
   - [ ] Notify media if >500 individuals affected
   - [ ] Document breach in HIPAA breach log

   Timeline:
   - Individuals: 60 days from discovery
   - HHS: 60 days (if <500) or immediately (if >500)
   - Media: Immediately (if >500)

2. **FDA Reporting** (if patient safety impact)

   **Report via MedWatch (Form 3500A) if**:
   - Patient safety potentially compromised
   - Device functionality affected

   Timeline: 24 hours for critical, 5 days for serious

3. **Lessons Learned Meeting**

   **Agenda**:
   - Attack timeline review
   - Detection effectiveness
   - Response time analysis
   - Improvement opportunities
   - Action items assignment

   **Attendees**: Security, ML engineering, compliance, legal, clinical

4. **Prevention Improvements**
   - [ ] Update detection rules based on attack patterns
   - [ ] Enhance monitoring dashboards
   - [ ] Add automated blocking rules
   - [ ] Train SOC team on medical AI attacks
   - [ ] Update incident response playbook

5. **Documentation**
   - [ ] Complete incident report
   - [ ] Update security risk register
   - [ ] Document new controls implemented
   - [ ] Share anonymized details with industry (coordinated disclosure)

**Deliverables**:
- Incident report (PDF)
- Lessons learned document
- Updated detection rules
- Training materials

**Maximum Duration**: 48 hours

---

## Communication Templates

### Internal Alert (Slack/Email)

```
🚨 SECURITY INCIDENT: Model Inversion Attack Detected

Severity: CRITICAL
Status: Contained
Breach Risk: HIGH

Summary:
Detected model inversion attack from user [USER_ID] attempting to
extract training data from medical AI model. Attacker blocked,
investigation underway.

Actions Taken:
✓ Attacker account blocked
✓ Source IP banned
✓ Enhanced protections enabled

Next Steps:
- Assess PHI exposure risk
- Determine if HIPAA breach occurred
- Implement additional safeguards

Incident Commander: [NAME]
War Room: #incident-model-inversion-20250118
```

### Executive Summary

```
Subject: Security Incident Response Summary - Model Inversion Attack

Date: [DATE]
Incident ID: INCIDENT-MODEL-INV-001
Status: Resolved

EXECUTIVE SUMMARY:
On [DATE], we detected and successfully blocked a model inversion attack
against our medical AI diagnostic system. The attacker attempted to extract
patient data from our AI model by querying it repeatedly with crafted inputs.

IMPACT:
- No confirmed PHI exposure
- No patient safety impact
- Service availability: 99.95% maintained
- Attack duration: 4 hours before detection

RESPONSE:
- Detected via automated anomaly detection
- Attacker blocked within 15 minutes
- Enhanced security controls deployed
- No HIPAA breach notification required

PREVENTION:
- Implemented stronger differential privacy (ε=0.5)
- Reduced API rate limits
- Enhanced monitoring and alerting
- Updated incident response playbooks

RECOMMENDATION:
Continue monitoring for similar attacks. No further action required
from executive leadership at this time.

Prepared by: CISO
Approved by: CTO
```

---

## Technical Reference

### Query Similarity Calculation

```python
def calculate_query_similarity(query1: str, query2: str) -> float:
    """
    Calculate cosine similarity between two queries.

    Returns: Similarity score (0-1)
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    vectorizer = TfidfVectorizer()
    vectors = vectorizer.fit_transform([query1, query2])

    similarity = cosine_similarity(vectors[0], vectors[1])[0][0]

    return similarity
```

### Differential Privacy Parameter Tuning

```python
# Conservative (Strong Privacy)
epsilon = 0.5
delta = 1e-5
noise_multiplier = 2.0

# Balanced (HIPAA Recommended)
epsilon = 1.0
delta = 1e-5
noise_multiplier = 1.0

# Aggressive (Performance Priority)
epsilon = 2.0
delta = 1e-5
noise_multiplier = 0.5
```

---

## Checklist

### Detection Phase
- [ ] Alert validated as true positive
- [ ] Severity assessed
- [ ] Stakeholders notified

### Containment Phase
- [ ] Attacker account blocked
- [ ] Source IP banned
- [ ] Evidence preserved
- [ ] Enhanced protections enabled

### Investigation Phase
- [ ] Attack timeline reconstructed
- [ ] PHI exposure risk assessed
- [ ] Attack source identified
- [ ] Breach determination made

### Eradication Phase
- [ ] Model defenses strengthened
- [ ] Additional controls implemented
- [ ] Vulnerabilities patched

### Recovery Phase
- [ ] Security posture verified
- [ ] Normal operations resumed
- [ ] Monitoring confirmed active

### Post-Incident Phase
- [ ] Breach notification (if required)
- [ ] FDA reporting (if required)
- [ ] Lessons learned meeting
- [ ] Improvements implemented
- [ ] Documentation complete

---

## Contact Information

**Security Operations Center**:
- Email: soc@medical-ai-company.com
- Phone: +1-XXX-XXX-XXXX
- Slack: #security-operations

**Incident Commander**:
- Primary: [NAME], CISO
- Backup: [NAME], Director of Security

**Escalation Path**:
1. SOC Analyst
2. Security Engineer
3. Security Team Lead
4. CISO
5. CTO
6. CEO (if patient safety impact)

**External**:
- FBI IC3: https://www.ic3.gov
- HHS OCR: https://www.hhs.gov/ocr
- FDA MedWatch: 1-800-FDA-1088

---

**Playbook Version**: 1.0.0
**Last Updated**: 2025-01-18
**Next Review**: 2025-04-18
**Owner**: GTL Consulting - Medical AI Security Team
