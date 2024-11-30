from cvss import CVSS3
import os
import json

# Path to the cvelistV5 repository
# Uses listing of CVEs in JSON format from this repository: https://github.com/CVEProject/cvelistV5
# That repo is multiple GB. You can include just a portion to get started. 
CVE_REPO_PATH = "../cvelistV5/cves"

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