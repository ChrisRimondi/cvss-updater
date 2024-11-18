Here’s the complete **README** content in Markdown format, ready for copy-pasting:

---

# **CVSS Updater App**

---

## **Overview**

The **CVSS Updater App** is a user-friendly web application built using **Streamlit**. It allows users to:
- Analyze CVE (Common Vulnerabilities and Exposures) data from the local `cvelistV5` repository.
- View original CVSS (Common Vulnerability Scoring System) metrics.
- Make adjustments to CVSS metrics based on contextual requirements.
- Recalculate the CVSS base score dynamically.
- Save the results, including adjusted metrics and rationale, to a JSON file.

---

## **Features**

- **Dynamic CVE Analysis**: Input a CVE ID and fetch its associated data (e.g., CVSS vector string and base score) from the local `cvelistV5` repository.
- **Interactive Adjustments**: Modify CVSS metrics such as Attack Vector (AV), Attack Complexity (AC), and others through an intuitive interface.
- **Recalculation of CVSS Score**: Automatically update the base score based on user adjustments.
- **Save Results**: Export adjusted scores, vector strings, and rationales to a JSON file for further reference.
- **Reference Sidebar**: Quickly understand CVSS metric abbreviations via an accessible sidebar.

---

## **Getting Started**

### **Prerequisites**

- Python 3.9 or later
- Docker (optional, for running in a container)
- A local copy of the [cvelistV5 repository](https://github.com/CVEProject/cvelistV5)

### **Installation**

#### **1. Clone the Project**
```bash
git clone https://github.com/ChrisRimondi/cvss-updater.git
cd cvss-updater
```

#### **2. Install Dependencies**
```bash
pip install -r requirements.txt
```

#### **3. Ensure `cvelistV5` Directory**
- Copy the `cvelistV5` repository to the project directory or specify its path during Docker build.

---

## **Usage**

### **Run Locally**

1. Launch the app:
   ```bash
   streamlit run cvss-updater.py
   ```
2. Open your browser and navigate to `http://localhost:8501`.

3. Input a CVE ID (e.g., `CVE-2024-12345`).
4. View the CVSS base score and vector string.
5. Adjust metrics as needed and provide rationale for changes.
6. Recalculate the CVSS score and save results as a JSON file.

---

### **Run with Docker**

1. Build the Docker image:
   ```bash
   docker build -t streamlit-cvss-updater-app .
   ```

2. Run the container:
   ```bash
   docker run -p 8501:8501 streamlit-cvss-updater-app
   ```

3. Access the app in your browser at `http://localhost:8501`.

---

## **File Structure**

```plaintext
cvss-updater/
├── Dockerfile           # Docker configuration for containerizing the app
├── requirements.txt     # Python dependencies
├── streamlit_app.py     # Streamlit app code
├── cvelistV5/           # Local copy of the CVE database (not included in repo)
├── README.md            # Documentation for the project
```

---

## **Features in Detail**

### **CVSS Metrics**
The app allows adjustment of the following metrics:

| Metric       | Description                                                                                   | Values       |
|--------------|-----------------------------------------------------------------------------------------------|--------------|
| **AV**       | Attack Vector: How the vulnerability can be exploited.                                        | `N`, `A`, `L`, `P` |
| **AC**       | Attack Complexity: Difficulty to exploit the vulnerability.                                   | `L`, `H`     |
| **PR**       | Privileges Required: Level of privileges needed by the attacker.                              | `N`, `L`, `H` |
| **UI**       | User Interaction: Whether user action is required for exploitation.                           | `N`, `R`     |
| **S**        | Scope: Impact of the exploit on other components.                                             | `U`, `C`     |
| **C**        | Confidentiality Impact: Impact on confidentiality of information.                             | `N`, `L`, `H` |
| **I**        | Integrity Impact: Impact on integrity of data or systems.                                     | `N`, `L`, `H` |
| **A**        | Availability Impact: Impact on availability of resources.                                     | `N`, `L`, `H` |

---

## **Saving Results**

The app generates a JSON file with the following details:
- **Original Base Score**
- **Adjusted Base Score**
- **Adjusted CVSS Vector String**
- **Rationale for Adjustments**

The file is saved in a subdirectory (adjusted_cves/) of the app directory with the format:
```
<CVE-ID>_adjusted.json
```

---

## **Contributing**

Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request with your changes.

---

## **License**

This project is licensed under the [MIT License](LICENSE).

---

## **Contact**

For questions or support, please contact [Your Name](mailto:your-email@example.com).

---

Feel free to replace placeholders like `your-repo` or `Your Name` with your actual information. Let me know if you need further adjustments! 🚀
