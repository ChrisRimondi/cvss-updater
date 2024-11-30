from openai import OpenAI
import json
from cvss import CVSS3
from dotenv import load_dotenv
import os

PROMPT_TEMPLATE = """
You are a cybersecurity expert specializing in risk assessment. Your task is to recommend adjustments to the CVSS vector string for a given CVE based on contextual information about the asset and its environment. Provide your output strictly in the following JSON format without any extra text or line breaks outside the JSON block:

{{
  "adjusted_vector": "<updated CVSS vector string>",
  "explanation": "<reason for the changes>"
}}

### Example Input:
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

### Example Output:
{{
  "adjusted_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:M",
  "explanation": "The Attack Complexity (AC) was changed from 'Low' to 'High' because SELinux is enabled, making exploitation more difficult. The Availability Impact (A) was reduced from 'High' to 'Medium' because the container's isolation limits the potential impact on other systems."
}}

Now respond for the following input:
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
"""




def initialize_llm():
    """Initialize the OpenAI API client using a key from the environment."""
    # Load environment variables from .env file
    load_dotenv()

    # Get the API key from the environment
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set in the environment.")
    
    return OpenAI(api_key=api_key)



def recommend_adjusted_vector(cve_data, asset_data, environment_data):
    """
    Recommend an adjusted CVSS vector string using the OpenAI Chat API.

    Args:
        cve_data (dict): Information about the CVE.
        asset_data (dict): Information about the asset.
        environment_data (dict): Information about the environment.

    Returns:
        dict: A dictionary containing the adjusted vector and explanation.
    """
    # Format the prompt for the Chat API
    prompt = PROMPT_TEMPLATE.format(
    cve_id=cve_data.get("cve_id", "N/A"),
    cve_description=cve_data.get("description", "N/A"),
    vector_string=cve_data.get("vector_string", "N/A"),
    asset_type=asset_data.get("type", "N/A"),
    selinux_enabled=asset_data.get("selinux_enabled", False),
    kernel_hardened=asset_data.get("kernel_hardened", False),
    ports_open=asset_data.get("ports_open", "N/A"),
    services_running=asset_data.get("services_running", "N/A"),
    data_sensitivity=environment_data.get("data_sensitivity", "N/A"),
    segmentation=environment_data.get("segmentation", "N/A"),
    user_access_level=environment_data.get("user_access_level", "N/A")
)

    # OpenAI Chat API input
    messages = [
        {"role": "system", "content": "You are a cybersecurity expert specializing in CVSS vector adjustments."},
        {"role": "user", "content": prompt}
    ]

    try:
        # Call the Chat API
        client = initialize_llm()
        response = client.chat.completions.create(model="gpt-4o",  # Specify the model you want to use
        messages=messages,
        temperature=0.7,
        max_tokens=10000)

        # Parse the response
        recommendation = response.choices[0].message.content.strip().strip("```").strip("json")
        return json.loads(recommendation)

    except json.JSONDecodeError:
        raise RuntimeError("Invalid response format. Ensure the LLM output matches the expected JSON format.")
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