# GTL Platform + Drana-GTL Integration

## Overview

This document describes the integration between **Drana-Infinity GTL Edition** and the existing **GTL AI Security Platform**, creating a unified security operations platform with:

- Shared compliance database
- Unified authentication via JWT
- Combined dashboards with real-time updates
- Consolidated reporting across all data sources
- Multi-model AI security scanning (Ollama + Claude + DeepSeek)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               GTL AI SECURITY PLATFORM                       │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   API        │  │  Compliance  │  │  Incident    │     │
│  │   Gateway    │◄─┤  Engine      │◄─┤  Response    │     │
│  │   (JWT)      │  │              │  │              │     │
│  └──────┬───────┘  └──────────────┘  └──────────────┘     │
│         │                                                   │
│         │          ┌─────────────────────────┐             │
│         └─────────►│  Drana-GTL Edition      │             │
│                    │  (Scanning Engine)      │             │
│                    │                         │             │
│                    │  ┌────────────────┐    │             │
│                    │  │ Multi-Model    │    │             │
│                    │  │ Orchestrator   │    │             │
│                    │  └────────────────┘    │             │
│                    │  ┌────────────────┐    │             │
│                    │  │ Sector Threat  │    │             │
│                    │  │ Intelligence   │    │             │
│                    │  └────────────────┘    │             │
│                    └─────────────────────────┘             │
│                                                              │
│  ┌──────────────────────────────────────────────────┐     │
│  │         React Dashboard (Unified UI)             │     │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐      │     │
│  │  │ Scanning │  │Compliance│  │ Reports  │      │     │
│  │  └──────────┘  └──────────┘  └──────────┘      │     │
│  └──────────────────────────────────────────────────┘     │
│                                                              │
│  ┌──────────────────────────────────────────────────┐     │
│  │          PostgreSQL (Shared Database)            │     │
│  │  - Compliance controls                           │     │
│  │  - Assessment history                            │     │
│  │  - Threat intelligence                           │     │
│  │  - Scan results                                  │     │
│  └──────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. GTL Platform Connector (`src/integrations/gtl_platform_connector.py`)

**Purpose**: API client for integrating Drana-GTL with GTL Platform

**Key Features**:
- JWT-based authentication with automatic token refresh
- Scan request submission and result reporting
- Compliance data synchronization
- Incident management integration
- Threat intelligence sharing
- Automatic retry logic with exponential backoff

**Usage Example**:

```python
from src.integrations import GTLPlatformConnector, GTLScanRequest, ScanType, ComplianceFramework

async def run_integrated_scan():
    connector = GTLPlatformConnector(
        gtl_api_base="https://gtl-platform.example.com",
        api_key="your-api-key"
    )
    
    async with connector:
        # Submit scan request
        scan_request = GTLScanRequest(
            target="medical-ai-system.hospital.com",
            scan_type=ScanType.MEDICAL_AI_SECURITY,
            sector="healthcare",
            models=["ollama", "claude", "deepseek"],
            compliance_frameworks=[ComplianceFramework.HIPAA]
        )
        
        scan_job_id = await connector.submit_scan_request(scan_request)
        
        # Execute scan (your Drana-GTL logic)
        results = await execute_drana_scan(scan_request)
        
        # Submit results back to GTL platform
        await connector.submit_scan_results(scan_job_id, results)
```

### 2. Database Integration

**Migration Script**: `migrations/gtl_integration/001_create_drana_tables.sql`

**New Tables**:

- `drana_scans` - Scan execution records linked to GTL scan jobs
- `drana_findings` - Security findings from multi-model analysis
- `drana_threat_indicators` - Threat intelligence indicators
- `drana_model_analytics` - Multi-model performance metrics
- `drana_compliance_assessments` - Compliance assessment results
- `drana_audit_log` - Comprehensive audit trail

**Key Views**:

- `v_drana_scan_summary` - Scan results with aggregated findings
- `v_active_threats` - Currently active security threats
- `v_compliance_status` - Compliance status by framework

**Running Migration**:

```bash
export GTL_DB_HOST=localhost
export GTL_DB_PORT=5432
export GTL_DB_NAME=gtl_platform
export GTL_DB_USER=gtl_user
export GTL_DB_PASSWORD=your-password

python migrations/gtl_integration/migrate_drana_integration.py
```

### 3. React Dashboard Components

**Location**: `frontend/src/components/DranaScan/`

**Main Component**: `DranaScanView.tsx`

**Features**:
- Real-time scan monitoring via WebSocket
- Live progress updates
- Finding detection notifications
- Multi-model analytics visualization
- Compliance integration display

**Integration**:

```typescript
import { DranaScanView } from '@/components/DranaScan';

function SecurityDashboard() {
  return (
    <div>
      <h1>GTL Security Platform</h1>
      <DranaScanView />
    </div>
  );
}
```

### 4. Unified Report Generator

**Location**: `src/reporting/unified_report_generator.py`

**Report Sections**:
1. Executive Summary - Key metrics and risk assessment
2. Drana-GTL AI Analysis - Multi-model findings and insights
3. Compliance Assessment - Framework-by-framework status
4. Technical Details - Vulnerability details and evidence
5. Recommendations - Prioritized remediation roadmap
6. Appendix - Supporting data and references

**Usage**:

```python
from src.reporting import UnifiedReportGenerator, ReportConfig, ReportFormat, ReportSection
from datetime import datetime, timedelta

async def generate_security_report(db_connection):
    generator = UnifiedReportGenerator(db_connection)
    
    config = ReportConfig(
        client_id="hospital_123",
        client_name="Memorial Hospital",
        report_title="Quarterly Security Assessment",
        date_range=(
            datetime.utcnow() - timedelta(days=90),
            datetime.utcnow()
        ),
        sections=list(ReportSection),
        include_charts=True
    )
    
    # Generate PDF report
    report_path = await generator.generate_comprehensive_security_report(
        config,
        output_format=ReportFormat.PDF
    )
    
    print(f"Report generated: {report_path}")
```

### 5. WebSocket Handler

**Location**: `src/websocket/drana_scan_websocket.py`

**Real-Time Events**:
- `scan_update` - Scan status changes
- `progress_update` - Progress percentage updates
- `finding_detected` - New finding discovered
- `scan_complete` - Scan finished successfully
- `scan_failed` - Scan encountered error

**Client Connection**:

```javascript
const ws = new WebSocket('ws://localhost:8765/ws/drana-scans');

ws.onopen = () => {
  // Subscribe to scan
  ws.send(JSON.stringify({
    action: 'subscribe',
    scanId: 'scan_12345'
  }));
};

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  
  switch(message.type) {
    case 'progress_update':
      updateProgress(message.data.progress);
      break;
    case 'finding_detected':
      addFinding(message.data.finding);
      break;
    case 'scan_complete':
      showResults(message.data);
      break;
  }
};
```

## Deployment

### Prerequisites

- Docker & Docker Compose
- Python 3.9+
- PostgreSQL 15+
- Node.js 18+ (for frontend)
- NVIDIA GPU with CUDA support (for DeepSeek on RTX 5090)

### Environment Variables

Create `.env` file:

```bash
# GTL Platform
GTL_API_BASE=https://gtl-platform.example.com
GTL_API_KEY=your-api-key-here
GTL_CLIENT_ID=your-client-id

# Database
GTL_DB_HOST=postgres
GTL_DB_PORT=5432
GTL_DB_NAME=gtl_platform
GTL_DB_USER=gtl_user
GTL_DB_PASSWORD=secure-password-here

# AI Models
ANTHROPIC_API_KEY=your-claude-api-key
OLLAMA_BASE_URL=http://ollama:11434
DEEPSEEK_ENDPOINT=http://deepseek:8080

# Configuration
LOG_LEVEL=INFO
MAX_CONCURRENT_SCANS=10
```

### Deployment Steps

```bash
# 1. Navigate to deployment directory
cd deployment/gtl_integration

# 2. Set environment variables
source .env

# 3. Run deployment script
./deploy.sh

# The script will:
# - Check prerequisites
# - Build Docker images
# - Start services
# - Run database migration
# - Verify deployment
# - Run integration tests
```

### Manual Deployment

```bash
# 1. Database migration
python migrations/gtl_integration/migrate_drana_integration.py

# 2. Start services
cd deployment/gtl_integration
docker-compose up -d

# 3. Verify services
docker-compose ps
curl http://localhost:8000/health

# 4. View logs
docker-compose logs -f drana-gtl
```

## API Endpoints

### Drana-GTL API

- `POST /api/v1/drana/scans` - Start new scan
- `GET /api/v1/drana/scans` - List scans
- `GET /api/v1/drana/scans/{scan_id}` - Get scan details
- `GET /api/v1/drana/scans/{scan_id}/findings` - Get scan findings
- `POST /api/v1/drana/scans/{scan_id}/cancel` - Cancel scan
- `GET /api/v1/drana/reports/{report_id}` - Download report

### GTL Platform Integration Endpoints

- `POST /api/v1/gtl/sync/compliance` - Sync compliance data
- `POST /api/v1/gtl/sync/threats` - Sync threat intelligence
- `GET /api/v1/gtl/status` - Integration health status

## Testing

### Unit Tests

```bash
pytest tests/integration/test_gtl_integration.py -v
```

### Integration Tests

```bash
# Start test environment
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
pytest tests/integration/ -v --integration

# Cleanup
docker-compose -f docker-compose.test.yml down
```

### Performance Tests

```bash
pytest tests/integration/test_gtl_integration.py::TestPerformance -v
```

## Monitoring

### Health Checks

```bash
# Drana-GTL Backend
curl http://localhost:8000/health

# WebSocket
wscat -c ws://localhost:8765

# PostgreSQL
docker-compose exec postgres pg_isready -U gtl_user

# Redis
docker-compose exec redis redis-cli ping
```

### Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f drana-gtl

# With timestamps
docker-compose logs -f -t drana-gtl
```

### Metrics

Key metrics to monitor:

- **Scan throughput**: Scans per hour
- **API latency**: Response time < 2s
- **WebSocket connections**: Active subscribers
- **Database performance**: Query time < 100ms
- **Model inference time**: Per-model execution time
- **Finding detection rate**: Findings per scan
- **Compliance score trends**: Over time
- **Error rate**: Errors per hour

## Troubleshooting

### Common Issues

**1. Database connection failed**

```bash
# Check database is running
docker-compose ps postgres

# Check connection
docker-compose exec postgres psql -U gtl_user -d gtl_platform -c "SELECT 1;"

# View database logs
docker-compose logs postgres
```

**2. WebSocket disconnections**

```bash
# Check WebSocket server
docker-compose logs drana-gtl | grep WebSocket

# Increase timeout in client
const ws = new WebSocket('ws://localhost:8765', {
  handshakeTimeout: 30000
});
```

**3. GTL Platform API errors**

```bash
# Test API connectivity
curl -H "Authorization: Bearer $GTL_API_KEY" \
  https://gtl-platform.example.com/api/v1/health

# Check API key
echo $GTL_API_KEY
```

**4. Model inference failures**

```bash
# Check Ollama
curl http://localhost:11434/api/tags

# Check Claude API key
echo $ANTHROPIC_API_KEY

# Check DeepSeek
curl http://localhost:8080/health
```

## Security Considerations

- **JWT tokens**: Refresh every 4 hours
- **API keys**: Rotate quarterly
- **Database**: Use SSL connections in production
- **WebSocket**: Use WSS (secure WebSocket) in production
- **Audit logs**: Retained for 2 years
- **PHI data**: Encrypted at rest and in transit
- **Access control**: Role-based access control (RBAC)

## Performance Optimization

- **Database indexing**: All foreign keys and frequently queried columns
- **Connection pooling**: Max 100 connections
- **Caching**: Redis for API responses (5 min TTL)
- **WebSocket**: Fan-out to 1000+ concurrent clients
- **Scan parallelization**: Up to 10 concurrent scans
- **Report generation**: Async with background workers

## Maintenance

### Backup

```bash
# Database backup
docker-compose exec postgres pg_dump -U gtl_user gtl_platform > backup.sql

# Restore
docker-compose exec -T postgres psql -U gtl_user gtl_platform < backup.sql
```

### Updates

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose build
docker-compose up -d

# Run new migrations
python migrations/gtl_integration/migrate_drana_integration.py
```

## Support

For issues or questions:

- **Documentation**: https://docs.gtl-platform.example.com
- **GitHub Issues**: https://github.com/org/drana-infinity/issues
- **Email**: support@gtl-platform.example.com

## License

Proprietary - GTL Enterprise Edition

---

**Version**: 1.0.0  
**Last Updated**: 2025-01-18  
**Author**: GTL Security Team
