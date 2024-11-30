import streamlit as st
from llm_integration import calculate_adjusted_score, recommend_adjusted_vector
from utils import find_cve_file, load_cve_data
from database import (
    bootstrap_db,
    fetch_assets,
    fetch_cve_assignments,
    insert_asset,
    insert_cve_assignment,
    insert_environment_context,
    fetch_environment_context,
    delete_asset,
    delete_cve_assignment,
    delete_environment_context,
    update_environment_context,
    update_asset,
)

# Initialize the database
bootstrap_db()

st.title("CVE CVSS Adjuster")

# Sidebar for navigation
st.sidebar.title("Navigation")
page = st.sidebar.selectbox(
    "Choose a page:",
    ["Manage Environments", "Manage Assets", "Associate CVEs", "Recommend Adjusted Scores"]
)

# Manage Environments Page
if page == "Manage Environments":
    st.header("Manage Environments")
    st.markdown("### Add a New Environment")
    environment = st.text_input("Environment Name")
    sensitivity = st.selectbox("Data Sensitivity", ["low", "medium", "high"])
    segmentation = st.selectbox("Segmentation", ["air-gapped", "internal-only", "public"])
    access_level = st.text_input("User Access Level (e.g., 'admin-only', 'devs')")

    if st.button("Add Environment"):
        insert_environment_context(environment, sensitivity, segmentation, access_level)
        st.success(f"Environment '{environment}' added successfully!")

    st.markdown("### Existing Environments")
    environments = fetch_environment_context()
    if environments:
        for env in environments:
            st.markdown(f"**ID:** {env[0]} | **Name:** {env[1]} | **Sensitivity:** {env[2]} | **Segmentation:** {env[3]} | **Access Level:** {env[4]}")
            if st.button(f"Delete Environment {env[0]}"):
                delete_environment_context(env[0])
                st.warning(f"Environment '{env[1]}' deleted.")
            if st.checkbox(f"Edit Environment {env[0]}"):
                new_sensitivity = st.selectbox("New Sensitivity", ["low", "medium", "high"], index=["low", "medium", "high"].index(env[2]))
                new_segmentation = st.selectbox("New Segmentation", ["air-gapped", "internal-only", "public"], index=["air-gapped", "internal-only", "public"].index(env[3]))
                new_access_level = st.text_input("New Access Level", value=env[4])
                if st.button(f"Save Changes for Environment {env[0]}"):
                    update_environment_context(env[0], new_sensitivity, new_segmentation, new_access_level)
                    st.success(f"Environment '{env[1]}' updated.")

# Manage Assets Page
# Manage Assets Page
elif page == "Manage Assets":
    st.header("Manage Assets")
    st.markdown("### Add a New Asset")

    # Input fields for asset creation
    asset_name = st.text_input("Asset Name")
    asset_type = st.selectbox("Asset Type", ["bare metal", "virtual machine", "container"])

    # Fetch available environments for dropdown
    environments = fetch_environment_context()
    environment_options = [env[1] for env in environments]  # Assuming the second column is the environment name
    environment = st.selectbox("Environment", environment_options if environment_options else ["No environments available"])

    public_exposure = st.checkbox("Publicly Exposed?")
    critical = st.checkbox("Critical Asset?")

    if st.button("Add Asset"):
        if environment == "No environments available":
            st.error("Please create an environment before adding assets.")
        else:
            insert_asset(asset_name, asset_type, environment, public_exposure, critical)
            st.success(f"Asset '{asset_name}' added successfully!")

    st.markdown("### Existing Assets")
    assets = fetch_assets()
    if assets:
        for asset in assets:
            st.markdown(f"**ID:** {asset[0]} | **Name:** {asset[1]} | **Type:** {asset[2]} | **Environment:** {asset[3]} | **Public:** {asset[4]} | **Critical:** {asset[5]}")
            if st.button(f"Delete Asset {asset[0]}"):
                delete_asset(asset[0])
                st.warning(f"Asset '{asset[1]}' deleted.")
            if st.checkbox(f"Edit Asset {asset[0]}"):
                new_type = st.selectbox("New Type", ["bare metal", "virtual machine", "container"], index=["bare metal", "virtual machine", "container"].index(asset[2]))
                new_environment = st.selectbox("New Environment", environment_options, index=environment_options.index(asset[3]))
                new_public_exposure = st.checkbox("New Public Exposure", value=bool(asset[4]))
                new_critical = st.checkbox("New Critical", value=bool(asset[5]))
                if st.button(f"Save Changes for Asset {asset[0]}"):
                    update_asset(asset[0], new_type, new_environment, new_public_exposure, new_critical)
                    st.success(f"Asset '{asset[1]}' updated.")


# Associate CVEs Page
elif page == "Associate CVEs":
    st.session_state['base_score'], st.session_state['vector_string'] = "",""
    st.header("Associate CVEs with Assets")
    asset_id = st.number_input("Asset ID", step=1, min_value=1)
    cve_id = st.text_input("CVE ID")
    if cve_id:
        if st.button("Load CVE Data"):
            cve_file = find_cve_file(cve_id)
            if cve_file:
                try:
                    st.session_state['base_score'], st.session_state['vector_string'] = load_cve_data(cve_file)
                    st.success(f"Original CVSS Base Score: {st.session_state['base_score']} and Vector String: {st.session_state['vector_string']}")
                except Exception as e:
                    st.error(f"Error loading CVE data: {e}")
    if st.button(f"Associate CVE {cve_id}"):
        insert_cve_assignment(asset_id, cve_id, st.session_state['base_score'], st.session_state['base_score'], "")
        st.success("CVE associated.")
    
    

# Example LLM Recommendation Flow
elif page == "Recommend Adjusted Scores":
    st.header("Recommend Adjusted CVSS Scores")
    cve_id = st.text_input("CVE ID for Recommendation")
    asset_id = st.number_input("Asset ID for Recommendation", step=1, min_value=1)

    if st.button("Recommend Adjusted Score"):
        # Fetch CVE, asset, and environment data from the database
        cve_data = {
            "cve_id": cve_id,
            "description": "Example description for the CVE.",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
        }
        asset_data = {
            "type": "virtual machine",
            "selinux_enabled": True,
            "kernel_hardened": False,
            "ports_open": "22,80,443",
            "services_running": "ssh,nginx"
        }
        environment_data = {
            "data_sensitivity": "high",
            "segmentation": "public",
            "user_access_level": "admin-only"
        }

        # Call the LLM function
        try:
            recommendation = recommend_adjusted_vector(cve_data, asset_data, environment_data)
            adjusted_vector = recommendation["adjusted_vector"]
            explanation = recommendation["explanation"]

            # Calculate the adjusted score
            adjusted_score = calculate_adjusted_score(adjusted_vector)

            st.success(f"Recommended Adjusted Vector: {adjusted_vector}")
            st.success(f"New Adjusted Score: {adjusted_score}")
            st.markdown(f"**Explanation:** {explanation}")
        except RuntimeError as e:
            st.error(f"Error: {e}")
