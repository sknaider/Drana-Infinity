"""
HIPAA Compliance Assessment Demo

Demonstrates comprehensive HIPAA Security Rule assessment workflow:
1. Automated control assessment using Claude AI
2. Gap analysis and prioritization
3. Remediation roadmap generation
4. Sample assessment report

This example shows both Medical AI and Logistics sector scenarios.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path

from src.compliance.frameworks.hipaa import HIPAAFramework
from src.integrations.claude_client import ClaudeClient
from src.core.config_manager import get_config


async def demo_medical_ai_assessment():
    """
    Demo: Medical AI system HIPAA assessment.

    Scenario: Hospital deploying DeepSeek-R1 diagnostic classifier
    on RTX 5090 GPU with PHI in training data.
    """
    print("\n" + "="*80)
    print("DEMO 1: Medical AI HIPAA Compliance Assessment")
    print("="*80 + "\n")

    # Initialize framework
    config = get_config()
    if not config.ai_models["claude"].enabled:
        print("⚠ Claude not configured - using mock assessment")
        return

    claude = ClaudeClient(
        api_key=config.ai_models["claude"].api_key,
        model=config.ai_models["claude"].model_name
    )

    framework = HIPAAFramework(claude_client=claude)

    # Limit to 5 controls for demo speed
    print(f"Assessing {len(framework.controls[:5])} HIPAA controls (limited for demo)...")

    # System configuration
    system_config = {
        "system_name": "Medical AI Diagnostic Platform",
        "system_type": "DeepSeek-R1 Chest X-ray Classifier",
        "deployment": {
            "gpu": "RTX 5090 (32GB VRAM)",
            "location": "Hospital data center",
            "environment": "On-premise"
        },
        "phi_exposure": {
            "training_data": "150,000 patient chest X-rays with diagnoses",
            "inference": "Real-time patient imaging analysis",
            "model_memorization_risk": "High"
        },
        "security_controls": {
            "encryption_at_rest": "AES-256",
            "encryption_in_transit": "TLS 1.3",
            "access_control": "RBAC with MFA",
            "audit_logging": True,
            "differential_privacy": "DP-SGD with ε=1.0",
            "gpu_memory_clearing": "Automated after each inference",
            "adversarial_testing": "Quarterly"
        },
        "fda_classification": "Class II Medical Device"
    }

    # Evidence provided by organization
    evidence = {
        "HIPAA-164.308(a)(1)(i)": [  # Risk Analysis
            {
                "type": "document",
                "title": "Medical AI Risk Assessment 2024",
                "date": "2024-01-15",
                "findings": [
                    "Model inversion attack risk documented",
                    "GPU memory exposure assessed",
                    "Differential privacy controls implemented"
                ]
            }
        ],
        "HIPAA-164.312(a)(2)(iv)": [  # Encryption
            {
                "type": "technical_verification",
                "tool": "encryption_audit",
                "findings": [
                    "Training data encrypted with AES-256",
                    "Model weights encrypted at rest",
                    "TLS 1.3 for all API endpoints"
                ]
            }
        ]
    }

    # System context
    system_context = {
        "sector": "MEDICAL_AI",
        "patient_population": "Adult cardiology patients",
        "clinical_impact": "High - Affects diagnostic decisions",
        "deployment_scale": "500 patients/day"
    }

    # Step 1: Assess compliance
    print("\n[1/3] Assessing HIPAA controls with Claude AI...\n")

    # Limit controls for demo
    framework.controls = framework.controls[:5]

    assessment_result = await framework.assess_compliance(
        system_config=system_config,
        evidence=evidence,
        system_context=system_context
    )

    gap_report = assessment_result["gap_report"]
    assessments = assessment_result["assessments"]
    summary = assessment_result["summary"]

    # Display results
    print(f"{'─'*80}")
    print("ASSESSMENT RESULTS")
    print(f"{'─'*80}")
    print(f"Overall Compliance Score: {summary['compliance_score']:.1f}%")
    print(f"Total Controls Assessed: {summary['total_controls']}")
    print(f"  ✓ Passed: {gap_report.controls_passed}")
    print(f"  ⚠ Partial: {gap_report.controls_partial}")
    print(f"  ✗ Failed: {gap_report.controls_failed}")
    print()
    print(f"Gap Summary:")
    print(f"  🔴 Critical: {summary['critical_gaps']}")
    print(f"  🟠 High: {summary['high_gaps']}")
    print(f"  🟡 Medium: {summary['medium_gaps']}")
    print(f"  🟢 Low: {summary['low_gaps']}")
    print()

    # Show critical gaps
    if gap_report.critical_gaps:
        print("CRITICAL GAPS REQUIRING IMMEDIATE ACTION:")
        for gap in gap_report.critical_gaps[:3]:
            print(f"\n  • {gap.description}")
            print(f"    Control: {gap.control_id}")
            if gap.patient_safety_impact:
                print(f"    ⚠ PATIENT SAFETY IMPACT")
            if gap.breach_risk:
                print(f"    ⚠ BREACH RISK")

    # Step 2: Generate remediation plan
    print(f"\n{'─'*80}")
    print("[2/3] Generating Remediation Roadmap with Claude AI...")
    print(f"{'─'*80}\n")

    constraints = {
        "budget_usd": 150000,
        "timeline_weeks": 26,  # 6 months
        "team_size": 3,
        "available_hours_per_week": 120
    }

    roadmap = await framework.generate_remediation_plan(
        gap_report=gap_report,
        assessments=assessments,
        constraints=constraints
    )

    # Display roadmap
    print(f"REMEDIATION ROADMAP:")
    print(f"  Total Duration: {roadmap.total_duration_days} days")
    print(f"  Total Effort: {roadmap.total_effort_hours} hours")
    print(f"  Estimated Cost: ${roadmap.total_cost:,.0f}")
    print()

    for phase in roadmap.phases:
        print(f"\n  Phase {phase.phase_number}: {phase.phase_name}")
        print(f"    Duration: {phase.duration_days} days")
        print(f"    Actions: {len(phase.actions)}")
        print(f"    Cost: ${phase.total_cost:,.0f}")

        for i, action in enumerate(phase.actions[:3], 1):
            print(f"\n      {i}. {action.action}")
            print(f"         Effort: {action.effort_hours}h | Cost: ${action.cost_estimate:,.0f}")
            if action.dependencies:
                print(f"         Dependencies: {', '.join(action.dependencies)}")

    # Step 3: Export report
    print(f"\n{'─'*80}")
    print("[3/3] Exporting Assessment Report...")
    print(f"{'─'*80}\n")

    report_data = {
        "assessment_metadata": {
            "report_id": gap_report.report_id,
            "target_system": gap_report.target_system,
            "assessment_date": datetime.now().isoformat(),
            "framework": "HIPAA Security Rule (45 CFR 164)",
            "sector": "Medical AI"
        },
        "executive_summary": {
            "compliance_score": summary["compliance_score"],
            "controls_assessed": summary["total_controls"],
            "critical_gaps": summary["critical_gaps"],
            "estimated_remediation_cost": roadmap.total_cost,
            "recommended_timeline": f"{roadmap.total_duration_days} days"
        },
        "assessments": [
            {
                "control_id": a.control_id,
                "status": a.status.value,
                "confidence": a.confidence_score,
                "gaps": [
                    {
                        "severity": g.severity.value,
                        "description": g.description,
                        "patient_safety": g.patient_safety_impact,
                        "breach_risk": g.breach_risk
                    }
                    for g in a.gaps
                ],
                "remediation": [
                    {
                        "action": r.action,
                        "effort_hours": r.effort_hours,
                        "cost": r.cost_estimate,
                        "priority": r.priority.value
                    }
                    for r in a.remediation_actions
                ]
            }
            for a in assessments
        ],
        "remediation_roadmap": {
            "phases": [
                {
                    "phase_number": p.phase_number,
                    "phase_name": p.phase_name,
                    "duration_days": p.duration_days,
                    "total_cost": p.total_cost,
                    "actions": [
                        {
                            "action": a.action,
                            "effort_hours": a.effort_hours,
                            "cost": a.cost_estimate
                        }
                        for a in p.actions
                    ]
                }
                for p in roadmap.phases
            ],
            "total_duration_days": roadmap.total_duration_days,
            "total_cost": roadmap.total_cost
        }
    }

    # Save report
    report_path = Path("reports") / f"hipaa_assessment_{gap_report.report_id}.json"
    report_path.parent.mkdir(exist_ok=True)

    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"✓ Assessment report saved: {report_path}")
    print()


async def demo_logistics_assessment():
    """
    Demo: Logistics company HIPAA assessment.

    Scenario: Peruvian pharmaceutical logistics company with
    SUNAT integration handling medical shipments containing PHI.
    """
    print("\n" + "="*80)
    print("DEMO 2: Logistics Sector HIPAA Compliance Assessment")
    print("="*80 + "\n")

    # Initialize framework
    config = get_config()
    if not config.ai_models["claude"].enabled:
        print("⚠ Claude not configured - using mock assessment")
        return

    claude = ClaudeClient(
        api_key=config.ai_models["claude"].api_key,
        model=config.ai_models["claude"].model_name
    )

    framework = HIPAAFramework(claude_client=claude)

    # Limit controls for demo
    framework.controls = framework.controls[:5]

    print(f"Assessing {len(framework.controls)} HIPAA controls for logistics company...")

    # System configuration
    system_config = {
        "company_name": "MedLogistics Peru SAC",
        "business_type": "Pharmaceutical cold chain logistics",
        "sunat_compliance": {
            "ruc": "20XXXXXXXXX",
            "vuce_integration": True,
            "electronic_invoice": True,
            "customs_broker_license": "ACTIVE"
        },
        "phi_handling": {
            "shipment_types": [
                "Patient-specific insulin shipments",
                "Chemotherapy drugs with patient IDs",
                "Medical devices with implant records"
            ],
            "monthly_volume": 500,
            "storage_locations": ["Lima warehouse", "Callao port"]
        },
        "security_controls": {
            "warehouse_access": "Badge + biometric for PHI zone",
            "edi_encryption": "TLS 1.3 + AS2",
            "sunat_api_encryption": "TLS 1.3 with client certificates",
            "cold_chain_monitoring": "Real-time IoT sensors",
            "audit_logging": "All PHI access logged",
            "customs_phi_minimization": "Patient names removed from declarations"
        }
    }

    # Evidence
    evidence = {
        "HIPAA-164.310(a)(1)": [  # Facility Access
            {
                "type": "facility_inspection",
                "date": "2024-01-10",
                "findings": [
                    "Badge access system operational at Lima warehouse",
                    "Biometric access for medical shipment zone",
                    "CCTV coverage 100%",
                    "Visitor logs maintained"
                ]
            }
        ],
        "HIPAA-164.312(e)(1)": [  # Transmission Security
            {
                "type": "network_scan",
                "date": "2024-01-18",
                "findings": [
                    "TLS 1.3 enforced on SUNAT API",
                    "EDI AS2 encryption configured",
                    "Certificate pinning implemented"
                ]
            }
        ]
    }

    system_context = {
        "sector": "LOGISTICS",
        "country": "PERU",
        "regulations": ["HIPAA", "SUNAT", "GDP"],
        "business_associate": True,
        "covered_entities": [
            "Hospital Nacional Guillermo Almenara",
            "Clínica Anglo Americana",
            "Pharmaceutical manufacturers"
        ]
    }

    # Assess compliance
    print("\n[1/2] Assessing HIPAA controls...\n")

    assessment_result = await framework.assess_compliance(
        system_config=system_config,
        evidence=evidence,
        system_context=system_context
    )

    gap_report = assessment_result["gap_report"]
    assessments = assessment_result["assessments"]
    summary = assessment_result["summary"]

    # Display results
    print(f"{'─'*80}")
    print("LOGISTICS HIPAA ASSESSMENT RESULTS")
    print(f"{'─'*80}")
    print(f"Company: MedLogistics Peru SAC")
    print(f"Business Associate Status: Active")
    print(f"Compliance Score: {summary['compliance_score']:.1f}%")
    print()
    print(f"Controls Assessment:")
    print(f"  ✓ Passed: {gap_report.controls_passed}")
    print(f"  ⚠ Partial: {gap_report.controls_partial}")
    print(f"  ✗ Failed: {gap_report.controls_failed}")
    print()

    # Logistics-specific findings
    print("LOGISTICS-SPECIFIC FINDINGS:")

    edi_gaps = [
        g for a in assessments for g in a.gaps
        if "EDI" in g.description or "customs" in g.description.lower()
    ]

    if edi_gaps:
        print("\n  EDI/SUNAT Integration:")
        for gap in edi_gaps:
            print(f"    • [{gap.severity.value.upper()}] {gap.description}")

    cold_chain_gaps = [
        g for a in assessments for g in a.gaps
        if "temperature" in g.description.lower() or "cold chain" in g.description.lower()
    ]

    if cold_chain_gaps:
        print("\n  Cold Chain Controls:")
        for gap in cold_chain_gaps:
            print(f"    • [{gap.severity.value.upper()}] {gap.description}")

    # Generate remediation plan
    print(f"\n{'─'*80}")
    print("[2/2] Generating Logistics Remediation Plan...")
    print(f"{'─'*80}\n")

    roadmap = await framework.generate_remediation_plan(
        gap_report=gap_report,
        assessments=assessments,
        constraints={
            "budget_usd": 75000,
            "timeline_weeks": 16,
            "team_size": 4
        }
    )

    print(f"REMEDIATION PLAN:")
    print(f"  Duration: {roadmap.total_duration_days} days")
    print(f"  Cost: ${roadmap.total_cost:,.0f}")
    print()

    for phase in roadmap.phases[:2]:  # Show first 2 phases
        print(f"\n  Phase {phase.phase_number}: {phase.phase_name}")
        for action in phase.actions[:2]:
            print(f"    • {action.action}")
            print(f"      Effort: {action.effort_hours}h | Cost: ${action.cost_estimate:,.0f}")

    print()


async def demo_quick_assessment():
    """
    Demo: Quick assessment of single control.

    Useful for testing and understanding the assessment process.
    """
    print("\n" + "="*80)
    print("DEMO 3: Quick Single Control Assessment")
    print("="*80 + "\n")

    config = get_config()
    if not config.ai_models["claude"].enabled:
        print("⚠ Claude not configured")
        return

    claude = ClaudeClient(
        api_key=config.ai_models["claude"].api_key,
        model=config.ai_models["claude"].model_name
    )

    framework = HIPAAFramework(claude_client=claude)

    # Get Risk Analysis control
    control = framework.get_control_by_id("HIPAA-164.308(a)(1)(i)")

    print(f"Assessing: {control.title} ({control.control_id})")
    print(f"Risk Level: {control.risk_level.value.upper()}")
    print()

    # Simple system config
    system_config = {
        "system_name": "Test Medical System",
        "last_risk_assessment": "2024-01-15",
        "risk_assessment_scope": "All ePHI systems"
    }

    # Assess single control
    from src.compliance.control_assessor import HIPAAControlAssessor

    assessor = HIPAAControlAssessor(claude)

    assessment = await assessor.assess_control(
        control=control,
        system_config=system_config,
        evidence_provided=[
            {
                "type": "document",
                "title": "2024 Risk Assessment",
                "date": "2024-01-15"
            }
        ]
    )

    # Display result
    print(f"Assessment Result: {assessment.status.value.upper()}")
    print(f"Confidence: {assessment.confidence_score:.0%}")
    print()

    if assessment.gaps:
        print("Gaps Identified:")
        for gap in assessment.gaps:
            print(f"  • [{gap.severity.value}] {gap.description}")
        print()

    if assessment.remediation_actions:
        print("Recommended Actions:")
        for action in assessment.remediation_actions:
            print(f"  • {action.action}")
            print(f"    Priority: {action.priority.value} | Effort: {action.effort_hours}h")
        print()


async def main():
    """Run all HIPAA assessment demos."""
    print("\n" + "="*80)
    print(" " * 20 + "HIPAA ASSESSMENT DEMO SUITE")
    print(" " * 15 + "Drana-Infinity GTL Edition")
    print("="*80)

    try:
        # Run demos
        await demo_medical_ai_assessment()
        await demo_logistics_assessment()
        await demo_quick_assessment()

        print("\n" + "="*80)
        print("ALL DEMOS COMPLETE")
        print("="*80)
        print("\nGenerated Reports:")
        print("  • reports/hipaa_assessment_*.json")
        print("\nNext Steps:")
        print("  1. Review assessment reports")
        print("  2. Prioritize critical gaps")
        print("  3. Execute remediation roadmap")
        print("  4. Re-assess compliance after remediation")
        print()

    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
