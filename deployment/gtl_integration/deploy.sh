#!/bin/bash

################################################################################
# GTL Platform + Drana-GTL Integration Deployment Script
#
# This script deploys the integrated GTL AI Security Platform with Drana-GTL
# scanning engine.
#
# Usage: ./deploy.sh [--skip-migration] [--skip-tests]
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SKIP_MIGRATION=false
SKIP_TESTS=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --skip-migration)
            SKIP_MIGRATION=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --help)
            echo "Usage: $0 [--skip-migration] [--skip-tests]"
            exit 0
            ;;
    esac
done

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check environment variables
    if [ -z "$GTL_API_KEY" ]; then
        log_error "GTL_API_KEY environment variable not set"
        exit 1
    fi
    
    if [ -z "$GTL_DB_PASSWORD" ]; then
        log_error "GTL_DB_PASSWORD environment variable not set"
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

create_directories() {
    log_info "Creating required directories..."
    
    mkdir -p "$SCRIPT_DIR/data"
    mkdir -p "$SCRIPT_DIR/logs"
    mkdir -p "$SCRIPT_DIR/reports"
    mkdir -p "$SCRIPT_DIR/ssl"
    
    log_success "Directories created"
}

build_images() {
    log_info "Building Docker images..."
    
    cd "$SCRIPT_DIR"
    docker-compose build
    
    log_success "Docker images built"
}

run_database_migration() {
    if [ "$SKIP_MIGRATION" = true ]; then
        log_warning "Skipping database migration"
        return
    fi
    
    log_info "Running database migration..."
    
    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to be ready..."
    sleep 10
    
    # Run migration
    cd "$PROJECT_ROOT"
    python3 migrations/gtl_integration/migrate_drana_integration.py
    
    log_success "Database migration completed"
}

start_services() {
    log_info "Starting services..."
    
    cd "$SCRIPT_DIR"
    docker-compose up -d
    
    log_success "Services started"
}

verify_deployment() {
    log_info "Verifying deployment..."
    
    # Wait for services to be healthy
    log_info "Waiting for services to be healthy..."
    sleep 20
    
    # Check Drana-GTL backend
    if curl -f http://localhost:8000/health > /dev/null 2>&1; then
        log_success "Drana-GTL backend is healthy"
    else
        log_error "Drana-GTL backend health check failed"
        return 1
    fi
    
    # Check WebSocket
    log_info "WebSocket server running on port 8765"
    
    # Check PostgreSQL
    if docker-compose exec -T postgres pg_isready -U gtl_user > /dev/null 2>&1; then
        log_success "PostgreSQL is healthy"
    else
        log_error "PostgreSQL health check failed"
        return 1
    fi
    
    # Check Redis
    if docker-compose exec -T redis redis-cli ping | grep -q PONG; then
        log_success "Redis is healthy"
    else
        log_error "Redis health check failed"
        return 1
    fi
    
    log_success "All services are healthy"
}

run_tests() {
    if [ "$SKIP_TESTS" = true ]; then
        log_warning "Skipping integration tests"
        return
    fi
    
    log_info "Running integration tests..."
    
    cd "$PROJECT_ROOT"
    python3 -m pytest tests/integration/test_gtl_integration.py -v
    
    log_success "Integration tests passed"
}

show_status() {
    log_info "Deployment Status:"
    echo
    docker-compose ps
    echo
    log_info "Access points:"
    echo "  - Drana-GTL API:     http://localhost:8000"
    echo "  - WebSocket:         ws://localhost:8765"
    echo "  - PostgreSQL:        localhost:5432"
    echo "  - Redis:             localhost:6379"
    echo "  - Ollama:            http://localhost:11434"
    echo
    log_info "View logs:"
    echo "  docker-compose logs -f drana-gtl"
}

main() {
    echo "=============================================================================="
    echo "  GTL Platform + Drana-GTL Integration Deployment"
    echo "=============================================================================="
    echo
    
    check_prerequisites
    create_directories
    build_images
    start_services
    run_database_migration
    verify_deployment
    run_tests
    
    echo
    echo "=============================================================================="
    log_success "Deployment completed successfully!"
    echo "=============================================================================="
    echo
    
    show_status
}

# Run main deployment
main
