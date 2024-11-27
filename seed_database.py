from app.database import (
    bootstrap_db,
    insert_asset,
    insert_cve_assignment,
    insert_asset_configuration,
    insert_environment_context,
)

def seed_database(db_name="assets_cves.db"):
    # Ensure the database is initialized
    bootstrap_db(db_name)

    # Sample Assets
    assets = [
        ("WebServer01", "bare metal", "production", True, True),
        ("DBServer01", "virtual machine", "production", False, True),
        ("DevContainer01", "container", "staging", False, False),
    ]

    # Insert Assets
    for asset in assets:
        insert_asset(*asset, db_name=db_name)

    # Sample CVE Assignments
    cve_assignments = [
        (1, "CVE-2024-1163", 7.7, 6.5, "SELinux reduces exploitability."),
        (1, "CVE-2023-0456", 8.8, 8.0, "Limited network exposure."),
        (2, "CVE-2024-7890", 9.1, 9.1, "Critical vulnerability in database."),
        (3, "CVE-2023-0123", 5.5, 3.0, "Low risk due to container isolation."),
    ]

    # Insert CVE Assignments
    for assignment in cve_assignments:
        insert_cve_assignment(*assignment, db_name=db_name)

    # Sample Asset Configurations
    asset_configurations = [
        (1, True, True, "80,443", "nginx,apache"),
        (2, False, True, "3306", "mysql"),
        (3, True, False, "8080", "nodejs"),
    ]

    # Insert Asset Configurations
    for config in asset_configurations:
        insert_asset_configuration(*config, db_name=db_name)

    # Sample Environment Context
    environment_context = [
        (1, "high", "public", "admin-only"),
        (2, "high", "internal-only", "admins, devs"),
        (3, "low", "internal-only", "devs"),
    ]

    # Insert Environment Context
    for context in environment_context:
        insert_environment_context(*context, db_name=db_name)

    print("Database seeded successfully!")

# Run the seeding script
if __name__ == "__main__":
    seed_database()
