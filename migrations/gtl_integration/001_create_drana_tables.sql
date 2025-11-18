-- ================================================================
-- GTL Platform + Drana-GTL Integration Schema
-- Migration: 001_create_drana_tables
-- 
-- Creates tables to integrate Drana-GTL scanning engine with
-- existing GTL AI Security Platform database
-- ================================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ================================================================
-- DRANA SCANS TABLE
-- ================================================================
-- Stores all Drana-GTL scan executions and links to GTL scan jobs
CREATE TABLE IF NOT EXISTS drana_scans (
    scan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gtl_scan_job_id UUID NOT NULL,  -- References scans(id) in GTL platform
    
    -- Scan configuration
    target VARCHAR(500) NOT NULL,
    scan_type VARCHAR(100) NOT NULL,
    sector VARCHAR(100) NOT NULL,
    scanner_engine VARCHAR(50) DEFAULT 'drana-gtl',
    
    -- Models used for multi-model analysis
    models_used TEXT[] DEFAULT '{}',
    model_orchestrator_config JSONB,
    
    -- Timing
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    
    -- Status tracking
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    progress_percentage INTEGER DEFAULT 0,
    current_step VARCHAR(200),
    
    -- Results
    findings_count INTEGER DEFAULT 0,
    high_severity_count INTEGER DEFAULT 0,
    critical_severity_count INTEGER DEFAULT 0,
    confidence_score FLOAT,
    
    -- Compliance impact
    compliance_frameworks TEXT[],
    compliance_impact JSONB,
    
    -- Full results (stored as JSONB for flexibility)
    results JSONB,
    
    -- Metadata
    metadata JSONB,
    error_message TEXT,
    
    -- Audit fields
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(255),
    
    -- Constraints
    CONSTRAINT valid_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    CONSTRAINT valid_progress CHECK (progress_percentage BETWEEN 0 AND 100),
    CONSTRAINT valid_confidence CHECK (confidence_score IS NULL OR (confidence_score BETWEEN 0 AND 1))
);

-- Indexes for performance
CREATE INDEX idx_drana_scans_gtl_job ON drana_scans(gtl_scan_job_id);
CREATE INDEX idx_drana_scans_status ON drana_scans(status);
CREATE INDEX idx_drana_scans_target ON drana_scans(target);
CREATE INDEX idx_drana_scans_sector ON drana_scans(sector);
CREATE INDEX idx_drana_scans_started_at ON drana_scans(started_at DESC);
CREATE INDEX idx_drana_scans_compliance ON drana_scans USING GIN(compliance_frameworks);

-- ================================================================
-- DRANA FINDINGS TABLE
-- ================================================================
-- Individual security findings from Drana-GTL scans
CREATE TABLE IF NOT EXISTS drana_findings (
    finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES drana_scans(scan_id) ON DELETE CASCADE,
    gtl_incident_id UUID,  -- References incidents(id) if incident created
    
    -- Finding identification
    finding_type VARCHAR(200) NOT NULL,
    threat_category VARCHAR(100),
    attack_vector VARCHAR(200),
    
    -- Severity and confidence
    severity VARCHAR(50) NOT NULL,
    confidence FLOAT NOT NULL,
    risk_score FLOAT,
    
    -- Detection details
    detected_by VARCHAR(100),  -- Which model detected this
    detection_method VARCHAR(200),
    evidence JSONB,
    
    -- Description
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    technical_details TEXT,
    
    -- Location
    affected_component VARCHAR(500),
    affected_endpoint VARCHAR(1000),
    source_ip VARCHAR(50),
    destination_ip VARCHAR(50),
    
    -- Recommendations
    recommendations JSONB,
    mitigation_steps JSONB,
    remediation_priority VARCHAR(50),
    estimated_remediation_time VARCHAR(100),
    
    -- Compliance impact
    compliance_violations JSONB,
    regulatory_requirements JSONB,
    
    -- MITRE ATT&CK mapping
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],
    mitre_ttp VARCHAR(50),
    
    -- Patient safety (for medical AI)
    patient_safety_impact VARCHAR(50),
    patient_safety_score FLOAT,
    phi_exposure_risk BOOLEAN DEFAULT FALSE,
    
    -- Status
    status VARCHAR(50) DEFAULT 'open',
    verified BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    metadata JSONB,
    
    -- Audit fields
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(255),
    
    -- Constraints
    CONSTRAINT valid_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT valid_confidence_range CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT valid_finding_status CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive', 'accepted_risk'))
);

-- Indexes for performance
CREATE INDEX idx_drana_findings_scan ON drana_findings(scan_id);
CREATE INDEX idx_drana_findings_incident ON drana_findings(gtl_incident_id);
CREATE INDEX idx_drana_findings_severity ON drana_findings(severity);
CREATE INDEX idx_drana_findings_status ON drana_findings(status);
CREATE INDEX idx_drana_findings_type ON drana_findings(finding_type);
CREATE INDEX idx_drana_findings_created_at ON drana_findings(created_at DESC);
CREATE INDEX idx_drana_findings_mitre ON drana_findings USING GIN(mitre_techniques);
CREATE INDEX idx_drana_findings_phi_risk ON drana_findings(phi_exposure_risk) WHERE phi_exposure_risk = TRUE;

-- ================================================================
-- DRANA THREAT INDICATORS TABLE
-- ================================================================
-- Threat intelligence indicators discovered by Drana-GTL
CREATE TABLE IF NOT EXISTS drana_threat_indicators (
    indicator_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES drana_scans(scan_id) ON DELETE SET NULL,
    finding_id UUID REFERENCES drana_findings(finding_id) ON DELETE SET NULL,
    
    -- Indicator details
    indicator_type VARCHAR(100) NOT NULL,
    indicator_value TEXT NOT NULL,
    threat_actor VARCHAR(200),
    campaign VARCHAR(200),
    
    -- Classification
    severity VARCHAR(50) NOT NULL,
    confidence FLOAT NOT NULL,
    tlp_level VARCHAR(20) DEFAULT 'amber',  -- TLP: WHITE, GREEN, AMBER, RED
    
    -- Context
    description TEXT,
    context JSONB,
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    occurrences INTEGER DEFAULT 1,
    
    -- Threat intel correlation
    ioc_hash VARCHAR(64),
    external_references JSONB,
    related_indicators UUID[],
    
    -- Sector-specific
    sector_tags TEXT[],
    target_industries TEXT[],
    
    -- Metadata
    metadata JSONB,
    
    -- Audit fields
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT valid_tlp CHECK (tlp_level IN ('white', 'green', 'amber', 'red')),
    CONSTRAINT valid_indicator_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

-- Indexes
CREATE INDEX idx_threat_indicators_scan ON drana_threat_indicators(scan_id);
CREATE INDEX idx_threat_indicators_finding ON drana_threat_indicators(finding_id);
CREATE INDEX idx_threat_indicators_type ON drana_threat_indicators(indicator_type);
CREATE INDEX idx_threat_indicators_severity ON drana_threat_indicators(severity);
CREATE INDEX idx_threat_indicators_value_hash ON drana_threat_indicators(indicator_value) WHERE LENGTH(indicator_value) < 500;
CREATE INDEX idx_threat_indicators_ioc_hash ON drana_threat_indicators(ioc_hash);
CREATE INDEX idx_threat_indicators_first_seen ON drana_threat_indicators(first_seen DESC);

-- ================================================================
-- DRANA MODEL ANALYTICS TABLE
-- ================================================================
-- Analytics on multi-model performance and consensus
CREATE TABLE IF NOT EXISTS drana_model_analytics (
    analytics_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES drana_scans(scan_id) ON DELETE CASCADE,
    
    -- Model performance
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50),
    
    -- Execution metrics
    execution_time_ms INTEGER,
    tokens_used INTEGER,
    api_cost DECIMAL(10, 4),
    
    -- Detection metrics
    findings_contributed INTEGER DEFAULT 0,
    unique_findings INTEGER DEFAULT 0,
    shared_findings INTEGER DEFAULT 0,
    
    -- Quality metrics
    accuracy_score FLOAT,
    precision_score FLOAT,
    recall_score FLOAT,
    false_positive_rate FLOAT,
    
    -- Consensus analysis
    agreement_with_ensemble FLOAT,
    disagreement_areas JSONB,
    
    -- Resource usage
    gpu_usage_mb INTEGER,
    cpu_usage_percent FLOAT,
    memory_usage_mb INTEGER,
    
    -- Metadata
    metadata JSONB,
    
    -- Audit
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_model_analytics_scan ON drana_model_analytics(scan_id);
CREATE INDEX idx_model_analytics_model ON drana_model_analytics(model_name);
CREATE INDEX idx_model_analytics_created_at ON drana_model_analytics(created_at DESC);

-- ================================================================
-- DRANA COMPLIANCE ASSESSMENTS TABLE
-- ================================================================
-- Compliance assessment results from Drana-GTL scans
CREATE TABLE IF NOT EXISTS drana_compliance_assessments (
    assessment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES drana_scans(scan_id) ON DELETE CASCADE,
    
    -- Framework
    framework VARCHAR(100) NOT NULL,
    framework_version VARCHAR(50),
    
    -- Assessment results
    total_controls INTEGER NOT NULL,
    compliant_controls INTEGER DEFAULT 0,
    non_compliant_controls INTEGER DEFAULT 0,
    not_applicable_controls INTEGER DEFAULT 0,
    not_tested_controls INTEGER DEFAULT 0,
    
    -- Scoring
    compliance_score FLOAT,
    risk_score FLOAT,
    maturity_level VARCHAR(50),
    
    -- Control results (detailed)
    control_results JSONB NOT NULL,
    
    -- Gap analysis
    gaps_identified JSONB,
    critical_gaps INTEGER DEFAULT 0,
    high_priority_gaps INTEGER DEFAULT 0,
    
    -- Recommendations
    recommendations JSONB,
    remediation_roadmap JSONB,
    estimated_effort_hours INTEGER,
    
    -- Comparison to previous
    previous_assessment_id UUID,
    improvement_areas JSONB,
    regression_areas JSONB,
    
    -- FDA-specific (for medical devices)
    fda_reporting_required BOOLEAN DEFAULT FALSE,
    premarket_requirements JSONB,
    postmarket_requirements JSONB,
    
    -- Metadata
    metadata JSONB,
    
    -- Audit
    assessed_at TIMESTAMP DEFAULT NOW(),
    assessed_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_compliance_assessments_scan ON drana_compliance_assessments(scan_id);
CREATE INDEX idx_compliance_assessments_framework ON drana_compliance_assessments(framework);
CREATE INDEX idx_compliance_assessments_assessed_at ON drana_compliance_assessments(assessed_at DESC);

-- ================================================================
-- DRANA AUDIT LOG TABLE
-- ================================================================
-- Comprehensive audit trail for all Drana-GTL operations
CREATE TABLE IF NOT EXISTS drana_audit_log (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Event details
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    event_action VARCHAR(100) NOT NULL,
    
    -- Actor
    user_id VARCHAR(255),
    api_key_id VARCHAR(100),
    source_ip VARCHAR(50),
    user_agent TEXT,
    
    -- Target
    target_type VARCHAR(100),
    target_id VARCHAR(255),
    scan_id UUID,
    
    -- Event data
    event_data JSONB,
    request_data JSONB,
    response_data JSONB,
    
    -- Result
    status VARCHAR(50) NOT NULL,
    error_message TEXT,
    
    -- Timing
    duration_ms INTEGER,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Metadata
    metadata JSONB
);

-- Indexes
CREATE INDEX idx_audit_log_event_type ON drana_audit_log(event_type);
CREATE INDEX idx_audit_log_user ON drana_audit_log(user_id);
CREATE INDEX idx_audit_log_scan ON drana_audit_log(scan_id);
CREATE INDEX idx_audit_log_timestamp ON drana_audit_log(timestamp DESC);
CREATE INDEX idx_audit_log_status ON drana_audit_log(status);

-- ================================================================
-- TRIGGERS
-- ================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_drana_scans_updated_at BEFORE UPDATE ON drana_scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_drana_findings_updated_at BEFORE UPDATE ON drana_findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_indicators_updated_at BEFORE UPDATE ON drana_threat_indicators
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Calculate scan duration on completion
CREATE OR REPLACE FUNCTION calculate_scan_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.completed_at IS NOT NULL AND OLD.completed_at IS NULL THEN
        NEW.duration_seconds = EXTRACT(EPOCH FROM (NEW.completed_at - NEW.started_at))::INTEGER;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER calculate_drana_scan_duration BEFORE UPDATE ON drana_scans
    FOR EACH ROW EXECUTE FUNCTION calculate_scan_duration();

-- ================================================================
-- VIEWS
-- ================================================================

-- Comprehensive scan results view
CREATE OR REPLACE VIEW v_drana_scan_summary AS
SELECT 
    ds.scan_id,
    ds.gtl_scan_job_id,
    ds.target,
    ds.scan_type,
    ds.sector,
    ds.status,
    ds.started_at,
    ds.completed_at,
    ds.duration_seconds,
    ds.models_used,
    ds.confidence_score,
    COUNT(DISTINCT df.finding_id) as total_findings,
    COUNT(DISTINCT df.finding_id) FILTER (WHERE df.severity = 'critical') as critical_findings,
    COUNT(DISTINCT df.finding_id) FILTER (WHERE df.severity = 'high') as high_findings,
    COUNT(DISTINCT df.finding_id) FILTER (WHERE df.severity = 'medium') as medium_findings,
    COUNT(DISTINCT df.finding_id) FILTER (WHERE df.severity = 'low') as low_findings,
    COUNT(DISTINCT df.finding_id) FILTER (WHERE df.phi_exposure_risk = TRUE) as phi_risk_findings,
    ARRAY_AGG(DISTINCT dca.framework) FILTER (WHERE dca.framework IS NOT NULL) as frameworks_assessed,
    AVG(dca.compliance_score) as avg_compliance_score
FROM drana_scans ds
LEFT JOIN drana_findings df ON ds.scan_id = df.scan_id
LEFT JOIN drana_compliance_assessments dca ON ds.scan_id = dca.scan_id
GROUP BY ds.scan_id;

-- Active threats view
CREATE OR REPLACE VIEW v_active_threats AS
SELECT 
    df.finding_id,
    df.scan_id,
    df.title,
    df.severity,
    df.confidence,
    df.threat_category,
    df.attack_vector,
    df.status,
    df.phi_exposure_risk,
    df.patient_safety_impact,
    df.created_at,
    ds.target,
    ds.sector
FROM drana_findings df
JOIN drana_scans ds ON df.scan_id = ds.scan_id
WHERE df.status IN ('open', 'investigating')
    AND df.false_positive = FALSE
ORDER BY 
    CASE df.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END,
    df.created_at DESC;

-- Compliance status view
CREATE OR REPLACE VIEW v_compliance_status AS
SELECT 
    framework,
    COUNT(*) as total_assessments,
    AVG(compliance_score) as avg_compliance_score,
    MAX(assessed_at) as last_assessment,
    SUM(critical_gaps) as total_critical_gaps,
    SUM(high_priority_gaps) as total_high_priority_gaps,
    BOOL_OR(fda_reporting_required) as any_fda_reporting_needed
FROM drana_compliance_assessments
GROUP BY framework;

-- ================================================================
-- GRANTS (adjust based on your user roles)
-- ================================================================

-- Grant permissions to GTL platform application user
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO gtl_app_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO gtl_app_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO gtl_app_user;

-- Grant read-only access to reporting user
-- GRANT SELECT ON ALL TABLES IN SCHEMA public TO gtl_report_user;
-- GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO gtl_report_user;

-- ================================================================
-- COMMENTS
-- ================================================================

COMMENT ON TABLE drana_scans IS 'Drana-GTL scan executions integrated with GTL platform';
COMMENT ON TABLE drana_findings IS 'Security findings discovered by Drana-GTL multi-model analysis';
COMMENT ON TABLE drana_threat_indicators IS 'Threat intelligence indicators from Drana-GTL scans';
COMMENT ON TABLE drana_model_analytics IS 'Performance analytics for multi-model AI orchestration';
COMMENT ON TABLE drana_compliance_assessments IS 'Compliance framework assessment results';
COMMENT ON TABLE drana_audit_log IS 'Comprehensive audit trail for all Drana-GTL operations';

-- ================================================================
-- MIGRATION COMPLETE
-- ================================================================
