import sqlite3

def bootstrap_db(db_name="assets_cves.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create Assets Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT,
        environment TEXT,
        public_exposure BOOLEAN,
        critical BOOLEAN
    )
    """)

    # Create CVE Assignments Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cve_assignments (
        id INTEGER PRIMARY KEY,
        asset_id INTEGER,
        cve_id TEXT NOT NULL,
        original_score REAL,
        adjusted_score REAL,
        rationale TEXT,
        FOREIGN KEY (asset_id) REFERENCES assets(id)
    )
    """)

    # Create Asset Configurations Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS asset_configurations (
        id INTEGER PRIMARY KEY,
        asset_id INTEGER,
        selinux_enabled BOOLEAN,
        kernel_hardened BOOLEAN,
        ports_open TEXT,
        services_running TEXT,
        FOREIGN KEY (asset_id) REFERENCES assets(id)
    )
    """)

    # Create Environment Context Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS environment_context (
        id INTEGER PRIMARY KEY,
        asset_id INTEGER,
        data_sensitivity TEXT,
        segmentation TEXT,
        user_access_level TEXT,
        FOREIGN KEY (asset_id) REFERENCES assets(id)
    )
    """)

    conn.commit()
    conn.close()
def insert_asset(name, asset_type, environment, public_exposure, critical, db_name="assets_cves.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO assets (name, type, environment, public_exposure, critical)
    VALUES (?, ?, ?, ?, ?)
    """, (name, asset_type, environment, public_exposure, critical))
    conn.commit()
    conn.close()

def insert_cve_assignment(asset_id, cve_id, original_score, adjusted_score, rationale, db_name="assets_cves.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO cve_assignments (asset_id, cve_id, original_score, adjusted_score, rationale)
    VALUES (?, ?, ?, ?, ?)
    """, (asset_id, cve_id, original_score, adjusted_score, rationale))
    conn.commit()
    conn.close()

def insert_asset_configuration(asset_id, selinux_enabled, kernel_hardened, ports_open, services_running, db_name="assets_cves.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO asset_configurations (asset_id, selinux_enabled, kernel_hardened, ports_open, services_running)
    VALUES (?, ?, ?, ?, ?)
    """, (asset_id, selinux_enabled, kernel_hardened, ports_open, services_running))
    conn.commit()
    conn.close()

def insert_environment_context(asset_id, data_sensitivity, segmentation, user_access_level, db_name="assets_cves.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO environment_context (asset_id, data_sensitivity, segmentation, user_access_level)
    VALUES (?, ?, ?, ?)
    """, (asset_id, data_sensitivity, segmentation, user_access_level))
    conn.commit()
    conn.close()

def fetch_assets(db_name="assets_cves.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets")
    results = cursor.fetchall()
    conn.close()
    return results

def fetch_cve_assignments(asset_id, db_name="assets_cves.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve_assignments WHERE asset_id = ?", (asset_id,))
    results = cursor.fetchall()
    conn.close()
    return results

def fetch_environment_context(db_name="assets_cves.db"):
    """Fetch all environment contexts from the database."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM environment_context")
    results = cursor.fetchall()
    conn.close()
    return results

def delete_environment_context(environment_id, db_name="assets_cves.db"):
    """Delete an environment context by ID."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM environment_context WHERE id = ?", (environment_id,))
    conn.commit()
    conn.close()


def delete_asset(asset_id, db_name="assets_cves.db"):
    """Delete an asset by ID."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    conn.commit()
    conn.close()


def delete_cve_assignment(cve_id, db_name="assets_cves.db"):
    """Delete a CVE assignment by ID."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cve_assignments WHERE id = ?", (cve_id,))
    conn.commit()
    conn.close()


def update_environment_context(environment_id, sensitivity, segmentation, access_level, db_name="assets_cves.db"):
    """Update an environment context by ID."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE environment_context
    SET data_sensitivity = ?, segmentation = ?, user_access_level = ?
    WHERE id = ?
    """, (sensitivity, segmentation, access_level, environment_id))
    conn.commit()
    conn.close()


def update_asset(asset_id, asset_type, environment, public_exposure, critical, db_name="assets_cves.db"):
    """Update an asset by ID."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE assets
    SET type = ?, environment = ?, public_exposure = ?, critical = ?
    WHERE id = ?
    """, (asset_type, environment, public_exposure, critical, asset_id))
    conn.commit()
    conn.close()
