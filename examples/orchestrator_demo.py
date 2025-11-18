"""
Multi-Model Orchestrator Demo

Demonstrates comprehensive usage of the Enhanced Multi-Model Orchestrator
for various security analysis scenarios.
"""

import asyncio
import json
from datetime import datetime

from src.core.multi_model_orchestrator_v2 import EnhancedMultiModelOrchestrator
from src.core.threat_analysis_models import ThreatAnalysisRequest


async def demo_critical_threat_analysis():
    """
    Demo: Critical threat analysis using all available models.

    Use Case: Production server suspected of compromise
    """
    print("\n" + "="*80)
    print("DEMO 1: Critical Threat Analysis - Suspected Server Compromise")
    print("="*80 + "\n")

    orchestrator = EnhancedMultiModelOrchestrator()

    # Check model availability
    print("Available Models:")
    for model, healthy in orchestrator.model_health.items():
        status = "✓ HEALTHY" if healthy else "✗ UNAVAILABLE"
        print(f"  - {model.upper()}: {status}")
    print()

    # Create critical priority request
    request = ThreatAnalysisRequest(
        target="prod-web-01.company.com",
        scan_type="network",
        sector="GENERAL",
        priority="critical",  # Use all models
        context={
            "alert_source": "IDS",
            "suspicious_activity": [
                "Unusual outbound traffic to 185.220.101.x",
                "Multiple failed SSH attempts",
                "Unexpected cron job modifications"
            ],
            "system_info": {
                "os": "Ubuntu 22.04",
                "services": ["nginx", "postgresql", "redis"],
                "last_patch": "2024-01-15"
            }
        },
        timeout=120
    )

    print(f"Analyzing target: {request.target}")
    print(f"Priority: {request.priority.upper()}")
    print(f"Expected models: All available\n")

    # Execute analysis
    start = datetime.now()
    result = await orchestrator.analyze_parallel(request)
    duration = (datetime.now() - start).total_seconds()

    # Display results
    print(f"\n{'─'*80}")
    print("ANALYSIS COMPLETE")
    print(f"{'─'*80}")
    print(f"Threat ID: {result.threat_id}")
    print(f"Execution Time: {result.execution_time:.2f}s")
    print(f"Models Used: {', '.join(result.models_used)}")
    print(f"Overall Confidence: {result.confidence_score:.1%}\n")

    # Findings
    print(f"FINDINGS ({len(result.findings)} total):")
    for i, finding in enumerate(result.findings[:5], 1):  # Top 5
        print(f"\n  [{i}] {finding.severity.upper()}: {finding.title}")
        print(f"      Confidence: {finding.confidence:.1%}")
        print(f"      Sources: {', '.join(finding.sources)}")
        if finding.cve_ids:
            print(f"      CVEs: {', '.join(finding.cve_ids)}")
        print(f"      Remediation: {finding.remediation[:100]}...")

    # Recommendations
    print(f"\nRECOMMENDATIONS ({len(result.recommendations)} total):")
    for i, rec in enumerate(result.recommendations[:3], 1):  # Top 3
        print(f"\n  [{i}] {rec.priority.upper()}: {rec.title}")
        print(f"      Effort: {rec.effort_hours} hours")
        print(f"      Timeline: {rec.timeline}")

    # Performance metrics
    print(f"\nPERFORMANCE METRICS:")
    metrics = orchestrator.get_metrics()
    for metric in metrics:
        status = "✓" if metric["success"] else "✗"
        print(f"  {status} {metric['model_name']}: {metric['response_time']:.2f}s")


async def demo_hipaa_compliance_analysis():
    """
    Demo: HIPAA compliance analysis for medical system.

    Use Case: Healthcare organization needs compliance audit
    """
    print("\n" + "="*80)
    print("DEMO 2: HIPAA Compliance Analysis - Medical Records System")
    print("="*80 + "\n")

    orchestrator = EnhancedMultiModelOrchestrator()

    request = ThreatAnalysisRequest(
        target="ehr-database-prod",
        scan_type="compliance",
        sector="MEDICAL_AI",
        compliance_frameworks=["HIPAA", "ISO27001"],
        priority="high",
        context={
            "system_type": "Electronic Health Records (EHR)",
            "data_classification": "Protected Health Information (PHI)",
            "current_controls": {
                "encryption_at_rest": "AES-256",
                "encryption_in_transit": "TLS 1.3",
                "access_control": "RBAC with MFA",
                "audit_logging": "Enabled",
                "backup_frequency": "Daily",
                "last_risk_assessment": "2024-01-01"
            },
            "known_gaps": [
                "Audit log review not documented",
                "No formal incident response plan",
                "Encryption keys not rotated"
            ]
        }
    )

    print(f"Analyzing: {request.target}")
    print(f"Frameworks: {', '.join(request.compliance_frameworks)}")
    print(f"Sector: {request.sector}\n")

    result = await orchestrator.analyze_parallel(request)

    print(f"\n{'─'*80}")
    print("COMPLIANCE ANALYSIS COMPLETE")
    print(f"{'─'*80}")
    print(f"Models Used: {', '.join(result.models_used)}")
    print(f"Overall Confidence: {result.confidence_score:.1%}\n")

    # Compliance Impact
    if result.compliance_impact:
        print("COMPLIANCE IMPACT:\n")
        for framework, impact in result.compliance_impact.items():
            print(f"  {framework}:")
            print(f"    Affected Controls: {len(impact.affected_controls)}")
            if impact.affected_controls:
                print(f"    Examples: {', '.join(impact.affected_controls[:3])}")
            if impact.critical_gaps:
                print(f"    Critical Gaps: {len(impact.critical_gaps)}")
                for gap in impact.critical_gaps[:3]:
                    print(f"      - {gap}")
            print()

    # Critical findings
    critical_findings = [f for f in result.findings if f.severity == "critical"]
    if critical_findings:
        print(f"CRITICAL FINDINGS ({len(critical_findings)}):")
        for finding in critical_findings:
            print(f"\n  ⚠ {finding.title}")
            print(f"    {finding.description[:150]}...")

    # Recommendations
    print(f"\nPRIORITIZED ACTIONS:")
    for i, rec in enumerate(result.recommendations[:5], 1):
        print(f"  {i}. [{rec.priority.upper()}] {rec.title}")
        print(f"     Est. {rec.effort_hours}h | Timeline: {rec.timeline}")


async def demo_medical_ai_security():
    """
    Demo: Medical AI model security analysis.

    Use Case: Hospital deploying AI-powered diagnostic system
    """
    print("\n" + "="*80)
    print("DEMO 3: Medical AI Security - Diagnostic Imaging Classifier")
    print("="*80 + "\n")

    orchestrator = EnhancedMultiModelOrchestrator()

    request = ThreatAnalysisRequest(
        target="chest-xray-classifier-v2",
        scan_type="medical_ai",
        sector="MEDICAL_AI",
        priority="high",
        context={
            "model_type": "CNN-based image classifier",
            "purpose": "Chest X-ray pneumonia detection",
            "fda_classification": "Class II Medical Device",
            "model_architecture": "ResNet-50 with custom head",
            "training_data": {
                "source": "NIH ChestX-ray14 + proprietary hospital data",
                "size": "150,000 images",
                "validation_split": "20%"
            },
            "deployment": {
                "environment": "Hospital PACS integration",
                "access": "Radiologists only",
                "output": "Probability scores + CAM visualization"
            },
            "known_risks": [
                "Model trained on limited demographic diversity",
                "No adversarial robustness testing",
                "Direct patient care impact"
            ]
        }
    )

    print(f"Analyzing: {request.target}")
    print(f"Model Type: {request.context['model_type']}")
    print(f"FDA Class: {request.context['fda_classification']}\n")

    result = await orchestrator.analyze_parallel(request)

    print(f"\n{'─'*80}")
    print("MEDICAL AI SECURITY ANALYSIS COMPLETE")
    print(f"{'─'*80}")

    # Look for DeepSeek analysis
    if "deepseek" in result.models_used:
        print("✓ DeepSeek medical AI specialist analysis included")

    # Medical AI specific findings
    ml_findings = [f for f in result.findings if any(
        keyword in f.title.lower() + f.description.lower()
        for keyword in ["adversarial", "model", "training", "bias", "poisoning", "inversion"]
    )]

    if ml_findings:
        print(f"\nMACHINE LEARNING SECURITY FINDINGS ({len(ml_findings)}):\n")
        for finding in ml_findings[:5]:
            print(f"  [{finding.severity.upper()}] {finding.title}")
            print(f"    Confidence: {finding.confidence:.1%}")
            print(f"    {finding.description[:200]}...")
            if finding.remediation:
                print(f"    → Remediation: {finding.remediation[:150]}...")
            print()

    # Patient safety recommendations
    safety_recs = [r for r in result.recommendations if any(
        keyword in r.title.lower() + r.description.lower()
        for keyword in ["patient", "safety", "clinical", "validation"]
    )]

    if safety_recs:
        print(f"PATIENT SAFETY RECOMMENDATIONS ({len(safety_recs)}):\n")
        for rec in safety_recs:
            print(f"  • {rec.title}")
            print(f"    {rec.description[:150]}...\n")


async def demo_logistics_edi_security():
    """
    Demo: EDI gateway security for logistics company.

    Use Case: Peruvian import/export company with SUNAT integration
    """
    print("\n" + "="*80)
    print("DEMO 4: Logistics EDI Security - SUNAT Integration")
    print("="*80 + "\n")

    orchestrator = EnhancedMultiModelOrchestrator()

    request = ThreatAnalysisRequest(
        target="edi-gateway.import-export.pe",
        scan_type="api_security",
        sector="LOGISTICS",
        compliance_frameworks=["SUNAT_PERU"],
        priority="high",
        context={
            "system": "EDI gateway for customs declarations",
            "protocols": ["X12 EDI", "EDIFACT", "XML"],
            "integrations": {
                "sunat": "Electronic invoice and customs API",
                "vuce": "Single window for foreign trade",
                "shipping_lines": ["Maersk", "MSC", "Hapag-Lloyd"]
            },
            "transaction_volume": "500-1000 declarations/day",
            "data_types": [
                "Commercial invoices",
                "Bill of lading",
                "Customs declarations",
                "HS codes and tariff data"
            ],
            "security_controls": {
                "authentication": "API keys + OAuth2",
                "encryption": "TLS 1.2",
                "input_validation": "Basic schema validation",
                "audit_logging": "Transaction logs only"
            }
        }
    )

    print(f"Analyzing: {request.target}")
    print(f"Sector: Logistics & Supply Chain")
    print(f"SUNAT Compliance Required\n")

    result = await orchestrator.analyze_parallel(request)

    print(f"\n{'─'*80}")
    print("LOGISTICS SECURITY ANALYSIS COMPLETE")
    print(f"{'─'*80}")

    # EDI-specific findings
    edi_findings = [f for f in result.findings if any(
        keyword in f.title.lower() + f.description.lower()
        for keyword in ["edi", "injection", "xml", "api", "sunat"]
    )]

    if edi_findings:
        print(f"\nEDI/API SECURITY FINDINGS ({len(edi_findings)}):\n")
        for finding in edi_findings:
            print(f"  [{finding.severity.upper()}] {finding.title}")
            if finding.attack_vectors:
                print(f"    Attack Vectors: {', '.join(finding.attack_vectors[:3])}")
            print(f"    {finding.description[:150]}...\n")

    # SUNAT compliance
    if "SUNAT_PERU" in result.compliance_impact:
        print("SUNAT PERU COMPLIANCE IMPACT:\n")
        impact = result.compliance_impact["SUNAT_PERU"]
        if impact.critical_gaps:
            print(f"  Critical Gaps ({len(impact.critical_gaps)}):")
            for gap in impact.critical_gaps[:3]:
                print(f"    • {gap}")

    print(f"\nHIGH PRIORITY RECOMMENDATIONS:")
    for rec in result.recommendations[:3]:
        if rec.priority in ["critical", "high"]:
            print(f"  • {rec.title}")
            print(f"    Effort: {rec.effort_hours}h | {rec.timeline}\n")


async def demo_performance_comparison():
    """
    Demo: Compare performance across different priority levels.

    Shows how routing strategy affects response time and thoroughness.
    """
    print("\n" + "="*80)
    print("DEMO 5: Performance Comparison - Priority Levels")
    print("="*80 + "\n")

    orchestrator = EnhancedMultiModelOrchestrator()

    priorities = ["low", "medium", "high", "critical"]
    results = {}

    for priority in priorities:
        print(f"Testing {priority.upper()} priority...")

        request = ThreatAnalysisRequest(
            target=f"test-server-{priority}",
            scan_type="network",
            priority=priority,
            timeout=60
        )

        result = await orchestrator.analyze_parallel(request)
        results[priority] = result

        print(f"  ✓ Complete in {result.execution_time:.2f}s using {len(result.models_used)} model(s)")

    # Comparison table
    print(f"\n{'─'*80}")
    print("PERFORMANCE COMPARISON")
    print(f"{'─'*80}")
    print(f"{'Priority':<12} {'Models':<25} {'Time (s)':<12} {'Findings':<12}")
    print(f"{'─'*80}")

    for priority in priorities:
        result = results[priority]
        models_str = ', '.join(result.models_used)
        print(f"{priority.upper():<12} {models_str:<25} {result.execution_time:<12.2f} {len(result.findings):<12}")

    print(f"{'─'*80}\n")
    print("Observations:")
    print("  • LOW priority uses fastest model (Ollama) for quick triage")
    print("  • CRITICAL priority uses all models for comprehensive analysis")
    print("  • Trade-off: Speed vs. thoroughness and confidence")


async def main():
    """Run all demos."""
    print("\n" + "="*80)
    print(" "*20 + "MULTI-MODEL ORCHESTRATOR DEMO")
    print(" "*15 + "Drana-Infinity GTL Edition")
    print("="*80)

    try:
        # Run demos
        await demo_critical_threat_analysis()
        await demo_hipaa_compliance_analysis()
        await demo_medical_ai_security()
        await demo_logistics_edi_security()
        await demo_performance_comparison()

        print("\n" + "="*80)
        print("ALL DEMOS COMPLETE")
        print("="*80 + "\n")

    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run async main
    asyncio.run(main())
