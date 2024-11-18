import os
import json
import streamlit as st
from cvss import CVSS3

# Path to the cvelistV5 repository
# Uses listing of CVEs in JSON format from this repository: https://github.com/CVEProject/cvelistV5
# That repo is multiple GB. You can include just a portion to get started. 
CVE_REPO_PATH = "cvelistV5/cves"

def find_cve_file(cve_id):
    """Find the file path for a given CVE ID in the cvelistV5 repository."""
    year = cve_id.split("-")[1]
    folder_path = os.path.join(CVE_REPO_PATH, year)

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.startswith(cve_id) and file.endswith(".json"):
                return os.path.join(root, file)
    return None

def load_cve_data(cve_file):
    """Load CVE data from the JSON file and extract CVSS information."""
    with open(cve_file, "r") as file:
        data = json.load(file)

    try:
        metrics = data["containers"]["cna"].get("metrics", [])
        if isinstance(metrics, tuple):
            metrics = list(metrics)
        if not isinstance(metrics, list):
            raise TypeError(f"Unexpected type for 'metrics': {type(metrics)}. Expected a list.")

        for metric in metrics:
            if isinstance(metric, dict):
                # Check for cvssV3_1 first, fallback to cvssV3_0
                cvss_data = metric.get("cvssV3_1") or metric.get("cvssV3_0")
                if cvss_data:
                    if "vectorString" in cvss_data and "baseScore" in cvss_data:
                        vector_string = cvss_data["vectorString"]
                        base_score = cvss_data["baseScore"]
                        return base_score, vector_string
                    else:
                        raise KeyError("Missing 'vectorString' or 'baseScore' in CVSS data.")
        
        # If no CVSS data is found
        raise Exception("CVSS data not found in the metrics section.")
    except KeyError as e:
        raise Exception(f"Error parsing CVSS data: {e}")
    except TypeError as e:
        raise Exception(f"Unexpected data type encountered: {e}")


def adjust_vector_string(vector_string, adjustments):
    """Adjust the CVSS vector string with new metrics."""
    vector_parts = vector_string.split("/")
    for key, value in adjustments.items():
        for i, part in enumerate(vector_parts):
            if part.startswith(key):
                vector_parts[i] = f"{key}:{value}"
    adjusted_vector = "/".join(vector_parts)
    if not adjusted_vector.startswith("CVSS:3."):
        adjusted_vector = "CVSS:3.1/" + adjusted_vector
    return adjusted_vector

def save_as_json(cve_id, base_score, adjusted_score, adjusted_vector, rationale):
    """Save the results as a JSON file."""
    results = {
        "CVE": cve_id,
        "Original Base Score": float(base_score),
        "Adjusted Base Score": float(adjusted_score),
        "Adjusted CVSS Vector": adjusted_vector,
        "Rationale": rationale,
    }
    filename = f"adjusted_cves/{cve_id}_adjusted.json"
    with open(filename, "w") as json_file:
        json.dump(results, json_file, indent=4)
    return filename

# Streamlit App
st.title("CVE CVSS Adjuster")

# Sidebar Reference
with st.sidebar:
    st.header("CVSS Abbreviation Reference")
    st.markdown(
        """
        - **AV (Attack Vector)**: 
          - `N`: Network, `A`: Adjacent, `L`: Local, `P`: Physical
        - **AC (Attack Complexity)**: 
          - `L`: Low, `H`: High
        - **PR (Privileges Required)**: 
          - `N`: None, `L`: Low, `H`: High
        - **UI (User Interaction)**: 
          - `N`: None, `R`: Required
        - **S (Scope)**: 
          - `U`: Unchanged, `C`: Changed
        - **C (Confidentiality Impact)**: 
          - `N`: None, `L`: Low, `H`: High
        - **I (Integrity Impact)**: 
          - `N`: None, `L`: Low, `H`: High
        - **A (Availability Impact)**: 
          - `N`: None, `L`: Low, `H`: High
        """
    )
    st.button("Close Sidebar", on_click=lambda: st.sidebar.empty())

# Input CVE ID
cve_id = st.text_input("Enter CVE ID (e.g., CVE-2024-12345):")

if cve_id:
    cve_file = find_cve_file(cve_id)
    if cve_file:
        try:
            base_score, vector_string = load_cve_data(cve_file)
            st.success(f"Original CVSS Base Score: {base_score}")
            st.markdown(f"**Original CVSS Vector String:** `{vector_string}`")

            # Parse original metrics
            vector_parts = {part.split(":")[0]: part.split(":")[1] for part in vector_string.split("/")}

            # Adjustment Form
            st.subheader("Adjust CVSS Metrics")
            adjustments = {}

            for key, description in [
                ("AV", "Attack Vector"),
                ("AC", "Attack Complexity"),
                ("PR", "Privileges Required"),
                ("UI", "User Interaction"),
                ("S", "Scope"),
                ("C", "Confidentiality Impact"),
                ("I", "Integrity Impact"),
                ("A", "Availability Impact"),
            ]:
                st.markdown(f"**Original {description} ({key}):** `{vector_parts.get(key, '')}`")
                adjustments[key] = st.selectbox(
                    f"{description} ({key})",
                    ["", "N", "A", "L", "P"] if key == "AV" else
                    ["", "L", "H"] if key == "AC" else
                    ["", "N", "L", "H"] if key == "PR" else
                    ["", "N", "R"] if key == "UI" else
                    ["", "U", "C"] if key == "S" else
                    ["", "N", "L", "H"],
                )

            rationale = {}
            for key, value in adjustments.items():
                if value:
                    rationale[key] = st.text_input(f"Rationale for {key} adjustment ({value}):")

            if st.button("Recalculate CVSS"):
                adjustments = {k: v for k, v in adjustments.items() if v}
                adjusted_vector = adjust_vector_string(vector_string, adjustments)
                st.markdown(f"**Adjusted CVSS Vector String:** `{adjusted_vector}`")

                try:
                    cvss = CVSS3(adjusted_vector)
                    adjusted_score = cvss.base_score
                    st.success(f"New CVSS Base Score: {adjusted_score}")

                    filename = save_as_json(cve_id, base_score, adjusted_score, adjusted_vector, rationale)
                    st.markdown(f"Results saved to `{filename}`")
                except Exception as e:
                    st.error(f"Error recalculating CVSS: {e}")
        except Exception as e:
            st.error(f"Error loading CVE data: {e}")
    else:
        st.error(f"CVE {cve_id} not found in the local repository.")
