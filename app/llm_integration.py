import openai
import json
from cvss import CVSS3
from dotenv import load_dotenv
import os

PROMPT_TEMPLATE = """
You are a cybersecurity expert specializing in risk assessment. Your task is to recommend adjustments to the CVSS vector string for a given CVE based on contextual information about the asset and its environment. Consider the following factors when making recommendations:

1. **CVE Information**: Analyze the base CVSS vector string, score, and description of the CVE.
2. **Asset Configuration**: Consider the asset's type (e.g., container, VM, bare metal), whether SELinux or kernel hardening is enabled, and any open ports or running services.
3. **Environment Context**: Factor in the data sensitivity (low, medium, high), segmentation (air-gapped, internal-only, public), and user access levels (e.g., admin-only, developers).

When adjusting the CVSS vector, ensure:
- Any changes are based on the provided asset and environment details.
- You explain the rationale for each change in the vector.

**Input Details**:
- CVE ID: {cve_id}
- CVE Description: {cve_description}
- Original CVSS Vector: {vector_string}
- Asset Type: {asset_type}
- SELinux Enabled: {selinux_enabled}
- Kernel Hardened: {kernel_hardened}
- Open Ports: {ports_open}
- Running Services: {services_running}
- Data Sensitivity: {data_sensitivity}
- Segmentation: {segmentation}
- User Access Level: {user_access_level}

**Example Input and Output**:
### Input
- CVE ID: CVE-2024-1234
- CVE Description: A critical vulnerability in a web application that allows remote code execution.
- Original CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- Asset Type: container
- SELinux Enabled: true
- Kernel Hardened: false
- Open Ports: 80,443
- Running Services: nginx
- Data Sensitivity: high
- Segmentation: public
- User Access Level: admin-only

### Example Output
```json
{
  "adjusted_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:M",
  "explanation": "The Attack Complexity (AC) was changed from 'Low' to 'High' because SELinux is enabled, making exploitation more difficult. The Availability Impact (A) was reduced from 'High' to 'Medium' because the container's isolation limits the potential impact on other systems."
}
"""



def initialize_llm():
    """Initialize the OpenAI API client using a key from the environment."""
    # Load environment variables from .env file
    load_dotenv()

    # Get the API key from the environment
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set in the environment.")
    
    openai.api_key = api_key


def recommend_adjusted_vector(cve_data, asset_data, environment_data):
    """
    Recommend an adjusted CVSS vector string using an LLM.

    Args:
        cve_data (dict): Information about the CVE (e.g., ID, description, vector).
        asset_data (dict): Information about the asset (e.g., type, SELinux status, ports, services).
        environment_data (dict): Information about the environment (e.g., sensitivity, segmentation, access levels).

    Returns:
        dict: A dictionary containing the adjusted vector and explanation.
    """
    # Format the prompt with the provided data
    prompt = PROMPT_TEMPLATE.format(
        cve_id=cve_data["cve_id"],
        cve_description=cve_data["description"],
        vector_string=cve_data["vector_string"],
        asset_type=asset_data["type"],
        selinux_enabled=asset_data["selinux_enabled"],
        kernel_hardened=asset_data["kernel_hardened"],
        ports_open=asset_data["ports_open"],
        services_running=asset_data["services_running"],
        data_sensitivity=environment_data["data_sensitivity"],
        segmentation=environment_data["segmentation"],
        user_access_level=environment_data["user_access_level"]
    )
    print(prompt)
    try:
        # Call the OpenAI API with the formatted prompt
        response = openai.Completion.create(
            engine="gpt-4o",  # Choose the appropriate model
            prompt=prompt,
            max_tokens=32000,
            temperature=0.7
        )

        # Parse the response and return the JSON output
        recommendation = response.choices[0].text.strip()
        return json.loads(recommendation)
    except Exception as e:
        raise RuntimeError(f"Error interacting with the LLM: {e}")

def calculate_adjusted_score(adjusted_vector):
    """
    Calculate the adjusted CVSS score using the updated vector string.

    Args:
        adjusted_vector (str): The adjusted CVSS vector string.

    Returns:
        float: The adjusted CVSS base score.
    """
    try:
        cvss = CVSS3(adjusted_vector)
        return cvss.base_score
    except Exception as e:
        raise RuntimeError(f"Error calculating CVSS score: {e}")
