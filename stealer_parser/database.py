"""Database operations."""
import os
from typing import Any

import psycopg
from psycopg.rows import dict_row
from verboselogs import VerboseLogger

from stealer_parser.models.leak import Leak


def get_db_url() -> str | None:
    """Get database URL from environment."""
    return os.getenv("POSTGRES_URL")


def check_db_connection(db_url: str) -> bool:
    """Check if database is reachable."""
    try:
        with psycopg.connect(db_url, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return True
    except Exception:
        return False


def init_db(db_url: str) -> None:
    """Initialize database tables."""
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            # Create systems table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS systems (
                    id SERIAL PRIMARY KEY,
                    leak_filename TEXT NOT NULL,
                    machine_id TEXT,
                    computer_name TEXT,
                    hardware_id TEXT,
                    machine_user TEXT,
                    ip_address TEXT,
                    country TEXT,
                    log_date TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE NULLS NOT DISTINCT (machine_id, computer_name, hardware_id, machine_user, ip_address)
                );
            """)

            # Create credentials table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id SERIAL PRIMARY KEY,
                    system_id INTEGER REFERENCES systems(id) ON DELETE CASCADE,
                    leak_filename TEXT NOT NULL,
                    software TEXT,
                    host TEXT,
                    username TEXT,
                    password TEXT,
                    domain TEXT,
                    local_part TEXT,
                    email_domain TEXT,
                    filepath TEXT,
                    stealer_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE NULLS NOT DISTINCT (system_id, host, username, password)
                );
            """)
            
            # Create indexes for better performance
            cur.execute("CREATE INDEX IF NOT EXISTS idx_systems_leak ON systems(leak_filename);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_creds_leak ON credentials(leak_filename);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_creds_host ON credentials(host);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_creds_email ON credentials(username);")
            
        conn.commit()


def save_leak_to_db(db_url: str, leak: Leak, logger: VerboseLogger) -> None:
    """Save parsed leak data to database."""
    if not leak.filename:
        logger.warning("Leak filename missing, cannot save to DB.")
        return

    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                logger.info(f"Saving results to database for {leak.filename}...")
                
                # 1. Collect all unique systems (deduplicate within the current file)
                systems_to_insert = []
                unique_systems = {} 

                for system_data in leak.systems_data:
                    if system_data.system:
                        s = system_data.system
                        # Key excludes leak_filename
                        key = (
                            s.machine_id, s.computer_name, s.hardware_id,
                            s.machine_user, s.ip_address
                        )
                        if key not in unique_systems:
                            unique_systems[key] = s
                            systems_to_insert.append((
                                leak.filename, s.machine_id, s.computer_name, s.hardware_id,
                                s.machine_user, s.ip_address, s.country, s.log_date
                            ))

                # 2. Bulk Insert Systems
                inserted_systems_count = 0
                if systems_to_insert:
                    logger.info(f"Processing {len(systems_to_insert)} unique systems in this file...")
                    cur.executemany(
                        """
                        INSERT INTO systems (
                            leak_filename, machine_id, computer_name, hardware_id, 
                            machine_user, ip_address, country, log_date
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (machine_id, computer_name, hardware_id, machine_user, ip_address) 
                        DO NOTHING
                        """,
                        systems_to_insert
                    )
                    inserted_systems_count = cur.rowcount
                
                # 3. Fetch system IDs
                # Since we don't depend on leak_filename, we must find IDs by matching attributes.
                # We use a temporary table to efficiently join and retrieve IDs for all systems in this batch.
                logger.info("Fetching system IDs...")
                
                # Prepare data for temp table: just the matching columns
                temp_systems_data = [
                    (s.machine_id, s.computer_name, s.hardware_id, s.machine_user, s.ip_address)
                    for s in unique_systems.values()
                ]

                if temp_systems_data:
                    cur.execute("""
                        CREATE TEMPORARY TABLE IF NOT EXISTS temp_systems_lookup (
                            machine_id TEXT,
                            computer_name TEXT,
                            hardware_id TEXT,
                            machine_user TEXT,
                            ip_address TEXT
                        ) ON COMMIT DROP;
                    """)
                    
                    cur.executemany("""
                        INSERT INTO temp_systems_lookup (machine_id, computer_name, hardware_id, machine_user, ip_address)
                        VALUES (%s, %s, %s, %s, %s)
                    """, temp_systems_data)
                    
                    cur.execute("""
                        SELECT s.id, t.machine_id, t.computer_name, t.hardware_id, t.machine_user, t.ip_address
                        FROM systems s
                        JOIN temp_systems_lookup t ON 
                            s.machine_id IS NOT DISTINCT FROM t.machine_id AND
                            s.computer_name IS NOT DISTINCT FROM t.computer_name AND
                            s.hardware_id IS NOT DISTINCT FROM t.hardware_id AND
                            s.machine_user IS NOT DISTINCT FROM t.machine_user AND
                            s.ip_address IS NOT DISTINCT FROM t.ip_address
                    """)
                    
                    # Map key -> system_id
                    system_id_map = {}
                    for row in cur.fetchall():
                        sys_id = row[0]
                        # key = (machine_id, computer_name, hardware_id, machine_user, ip_address)
                        key = (row[1], row[2], row[3], row[4], row[5])
                        system_id_map[key] = sys_id
                else:
                    system_id_map = {}

                # 4. Prepare Credentials
                all_creds_to_insert = []
                
                for system_data in leak.systems_data:
                    system_id = None
                    if system_data.system:
                        s = system_data.system
                        key = (
                            s.machine_id, s.computer_name, s.hardware_id,
                            s.machine_user, s.ip_address
                        )
                        system_id = system_id_map.get(key)
                    
                    for cred in system_data.credentials:
                        all_creds_to_insert.append((
                            system_id, leak.filename, cred.software, cred.host, cred.username, cred.password,
                            cred.domain, cred.local_part, cred.email_domain, cred.filepath, cred.stealer_name
                        ))

                # 5. Bulk Insert Credentials
                inserted_creds_count = 0
                if all_creds_to_insert:
                    total_creds = len(all_creds_to_insert)
                    batch_size = 50000
                    logger.info(f"Inserting {total_creds} credentials in batches of {batch_size}...")
                    
                    for i in range(0, total_creds, batch_size):
                        batch = all_creds_to_insert[i : i + batch_size]
                        cur.executemany(
                            """
                            INSERT INTO credentials (
                                system_id, leak_filename, software, host, username, password,
                                domain, local_part, email_domain, filepath, stealer_name
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (system_id, host, username, password) DO NOTHING
                            """,
                            batch
                        )
                        inserted_creds_count += cur.rowcount
                    
                
            conn.commit()
            
            # Calculate duplicates
            duplicate_systems = len(systems_to_insert) - inserted_systems_count
            duplicate_creds = len(all_creds_to_insert) - inserted_creds_count
            
            logger.success(
                f"DB Save Summary:\n"
                f"  Systems:     {inserted_systems_count} inserted, {duplicate_systems} duplicates (Total: {len(systems_to_insert)})\n"
                f"  Credentials: {inserted_creds_count} inserted, {duplicate_creds} duplicates (Total: {len(all_creds_to_insert)})"
            )

    except Exception as e:
        logger.error(f"Failed to save to database: {e}")
