#!/usr/bin/env python3
"""
GTL Platform + Drana-GTL Integration Migration Script

Executes database migration and sets up integration between
Drana-GTL Edition and GTL AI Security Platform.
"""

import os
import sys
import logging
import asyncio
from pathlib import Path
from typing import Optional
import asyncpg
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class GTLMigrationManager:
    """Manages database migration for GTL integration"""
    
    def __init__(
        self,
        db_host: str,
        db_port: int,
        db_name: str,
        db_user: str,
        db_password: str
    ):
        self.db_host = db_host
        self.db_port = db_port
        self.db_name = db_name
        self.db_user = db_user
        self.db_password = db_password
        self.connection: Optional[asyncpg.Connection] = None
    
    async def connect(self):
        """Establish database connection"""
        try:
            self.connection = await asyncpg.connect(
                host=self.db_host,
                port=self.db_port,
                database=self.db_name,
                user=self.db_user,
                password=self.db_password
            )
            logger.info(f"Connected to PostgreSQL database: {self.db_name}")
        except Exception as e:
            logger.error(f"Failed to connect to database: {str(e)}")
            raise
    
    async def disconnect(self):
        """Close database connection"""
        if self.connection:
            await self.connection.close()
            logger.info("Database connection closed")
    
    async def check_migration_status(self) -> bool:
        """Check if migration has already been applied"""
        try:
            result = await self.connection.fetchval(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'drana_scans'
                )
                """
            )
            return result
        except Exception as e:
            logger.error(f"Error checking migration status: {str(e)}")
            return False
    
    async def create_migration_tracking_table(self):
        """Create table to track applied migrations"""
        await self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_id SERIAL PRIMARY KEY,
                migration_name VARCHAR(255) NOT NULL UNIQUE,
                applied_at TIMESTAMP NOT NULL DEFAULT NOW(),
                applied_by VARCHAR(255),
                description TEXT
            )
            """
        )
        logger.info("Migration tracking table created")
    
    async def execute_migration(self, migration_file: Path):
        """Execute SQL migration file"""
        logger.info(f"Executing migration: {migration_file.name}")
        
        # Read SQL file
        with open(migration_file, 'r') as f:
            sql_content = f.read()
        
        try:
            # Execute migration in a transaction
            async with self.connection.transaction():
                await self.connection.execute(sql_content)
                
                # Record migration
                await self.connection.execute(
                    """
                    INSERT INTO schema_migrations (migration_name, applied_by, description)
                    VALUES ($1, $2, $3)
                    """,
                    migration_file.name,
                    os.getenv('USER', 'system'),
                    'GTL Platform + Drana-GTL Integration Schema'
                )
            
            logger.info(f"Migration {migration_file.name} applied successfully")
            return True
        
        except Exception as e:
            logger.error(f"Migration failed: {str(e)}")
            raise
    
    async def verify_tables(self) -> bool:
        """Verify all expected tables were created"""
        expected_tables = [
            'drana_scans',
            'drana_findings',
            'drana_threat_indicators',
            'drana_model_analytics',
            'drana_compliance_assessments',
            'drana_audit_log'
        ]
        
        for table in expected_tables:
            exists = await self.connection.fetchval(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = $1
                )
                """,
                table
            )
            
            if not exists:
                logger.error(f"Table {table} was not created")
                return False
            else:
                logger.info(f"✓ Table {table} created successfully")
        
        return True
    
    async def verify_indexes(self) -> bool:
        """Verify indexes were created"""
        index_count = await self.connection.fetchval(
            """
            SELECT COUNT(*)
            FROM pg_indexes
            WHERE schemaname = 'public'
            AND tablename LIKE 'drana_%'
            """
        )
        
        logger.info(f"✓ {index_count} indexes created on Drana tables")
        return index_count > 0
    
    async def verify_views(self) -> bool:
        """Verify views were created"""
        expected_views = [
            'v_drana_scan_summary',
            'v_active_threats',
            'v_compliance_status'
        ]
        
        for view in expected_views:
            exists = await self.connection.fetchval(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.views 
                    WHERE table_schema = 'public' 
                    AND table_name = $1
                )
                """,
                view
            )
            
            if not exists:
                logger.error(f"View {view} was not created")
                return False
            else:
                logger.info(f"✓ View {view} created successfully")
        
        return True
    
    async def insert_sample_data(self):
        """Insert sample data for testing (optional)"""
        logger.info("Inserting sample data for testing...")
        
        # Insert sample scan
        scan_id = await self.connection.fetchval(
            """
            INSERT INTO drana_scans (
                gtl_scan_job_id,
                target,
                scan_type,
                sector,
                models_used,
                status,
                compliance_frameworks
            ) VALUES (
                gen_random_uuid(),
                'test-system.example.com',
                'medical_ai_security',
                'healthcare',
                ARRAY['ollama', 'claude', 'deepseek'],
                'completed',
                ARRAY['hipaa', 'fda_cybersecurity']
            )
            RETURNING scan_id
            """
        )
        
        # Insert sample finding
        await self.connection.execute(
            """
            INSERT INTO drana_findings (
                scan_id,
                finding_type,
                threat_category,
                severity,
                confidence,
                title,
                description,
                phi_exposure_risk
            ) VALUES (
                $1,
                'model_inversion',
                'ai_security',
                'high',
                0.89,
                'Medical AI Model Inversion Vulnerability',
                'AI model susceptible to training data reconstruction attacks',
                TRUE
            )
            """,
            scan_id
        )
        
        logger.info(f"✓ Sample data inserted (scan_id: {scan_id})")
    
    async def run_migration(self, skip_sample_data: bool = False):
        """Run complete migration process"""
        logger.info("=" * 70)
        logger.info("GTL Platform + Drana-GTL Integration Migration")
        logger.info("=" * 70)
        
        await self.connect()
        
        try:
            # Create migration tracking table
            await self.create_migration_tracking_table()
            
            # Check if already migrated
            if await self.check_migration_status():
                logger.warning("Migration appears to already be applied!")
                response = input("Continue anyway? (yes/no): ")
                if response.lower() != 'yes':
                    logger.info("Migration cancelled")
                    return False
            
            # Execute main migration
            migration_file = Path(__file__).parent / "001_create_drana_tables.sql"
            if not migration_file.exists():
                logger.error(f"Migration file not found: {migration_file}")
                return False
            
            await self.execute_migration(migration_file)
            
            # Verify migration
            logger.info("\nVerifying migration...")
            
            if not await self.verify_tables():
                logger.error("Table verification failed!")
                return False
            
            if not await self.verify_indexes():
                logger.error("Index verification failed!")
                return False
            
            if not await self.verify_views():
                logger.error("View verification failed!")
                return False
            
            # Insert sample data if requested
            if not skip_sample_data:
                await self.insert_sample_data()
            
            logger.info("\n" + "=" * 70)
            logger.info("✓ Migration completed successfully!")
            logger.info("=" * 70)
            
            return True
        
        except Exception as e:
            logger.error(f"\n✗ Migration failed: {str(e)}")
            return False
        
        finally:
            await self.disconnect()


async def main():
    """Main migration script"""
    # Get database credentials from environment
    db_config = {
        'db_host': os.getenv('GTL_DB_HOST', 'localhost'),
        'db_port': int(os.getenv('GTL_DB_PORT', '5432')),
        'db_name': os.getenv('GTL_DB_NAME', 'gtl_platform'),
        'db_user': os.getenv('GTL_DB_USER', 'gtl_user'),
        'db_password': os.getenv('GTL_DB_PASSWORD', ''),
    }
    
    # Validate configuration
    if not db_config['db_password']:
        logger.error("Database password not provided. Set GTL_DB_PASSWORD environment variable.")
        sys.exit(1)
    
    logger.info(f"Database: {db_config['db_user']}@{db_config['db_host']}:{db_config['db_port']}/{db_config['db_name']}")
    
    # Run migration
    manager = GTLMigrationManager(**db_config)
    
    skip_sample = '--skip-sample-data' in sys.argv
    success = await manager.run_migration(skip_sample_data=skip_sample)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
