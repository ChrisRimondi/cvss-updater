Here’s an updated **README.md** for your GitHub repository, based on the work we’ve done:

---

# CVSS Updater

The **CVSS Updater** is a tool designed to dynamically adjust CVSS vector strings and scores for Common Vulnerabilities and Exposures (CVEs) based on the contextual data of assets and environments. By leveraging OpenAI's GPT models, the tool recommends updated CVSS vectors, providing detailed rationales for changes, and enables more accurate risk prioritization in real-world scenarios.

---

## Features

1. **Dynamic CVSS Adjustment**:
   - Updates CVSS vector strings based on asset configurations and environment contexts.
   - Recalculates scores using the updated vectors.

2. **Integration with OpenAI's API**:
   - Leverages LLMs for analyzing CVE data and recommending changes to the CVSS vector.
   - Provides detailed explanations for adjustments.

3. **Asset and Environment Management**:
   - Add, edit, and delete environments and assets.
   - Associate CVEs with assets for contextual risk assessment.

4. **Database-Driven**:
   - Tracks assets, environments, and CVEs using SQLite for easy extensibility and local testing.

5. **Streamlit-Based UI**:
   - Intuitive interface for managing environments, assets, and CVE associations.
   - Dynamically recommends adjusted CVSS scores based on contextual data.

---

## Installation

### Prerequisites
- Python 3.8 or higher
- [pipenv](https://pipenv.pypa.io/) or `pip`
- OpenAI API key

### Clone the Repository
```bash
git clone https://github.com/ChrisRimondi/cvss-updater.git
cd cvss-updater
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Set Up OpenAI API Key
1. Create a `.env` file in the root directory:
   ```bash
   touch .env
   ```
2. Add your OpenAI API key:
   ```plaintext
   OPENAI_API_KEY=your_openai_api_key
   ```

---

## Usage

### Run the Streamlit Application
```bash
streamlit run app/streamlit_app.py
```

### Access the Application
Open your browser and go to:
```
http://localhost:8501
```

### Features in the UI
- **Manage Environments**:
  - Add, edit, and delete environments with contextual data like sensitivity, segmentation, and user access levels.
- **Manage Assets**:
  - Add, edit, and delete assets with attributes like type (e.g., container, VM), SELinux status, and open ports.
- **Associate CVEs**:
  - Link CVEs to assets and optionally provide rationales for manual adjustments.
- **Recommend Adjusted CVSS**:
  - Generate adjusted CVSS vector strings dynamically based on contextual data using OpenAI.

---

## Configuration

### Database
The application uses an SQLite database (`assets_cves.db`) to store:
- Assets
- Environments
- CVE associations

The database schema is automatically created on the first run.

---

## Development

### Project Structure
```plaintext
cvss-updater/
├── app/
│   ├── __init__.py              # Marks the package
│   ├── database.py              # Database schema and CRUD operations
│   ├── llm_integration.py       # Functions for interacting with OpenAI API
│   ├── streamlit_app.py         # Main Streamlit application
│   ├── utils.py                 # Helper functions
├── cvelistV5/                   # Local copy of the CVE list (if applicable)
├── .env                         # Environment variables (OpenAI API key)
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Docker configuration
├── README.md                    # Project documentation
```

### Run Tests
You can add and execute tests using a framework like `pytest`.

---

## Contribution

### Feature Ideas
- **Automated CVE Ingestion**: Integrate with external sources (e.g., NVD) to auto-populate CVEs.
- **Dashboard Enhancements**: Add visualizations for adjusted scores and associated rationales.
- **Custom Policies**: Enable custom weighting for specific CVSS metrics.

### How to Contribute
1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit changes:
   ```bash
   git commit -m "Added new feature"
   ```
4. Push changes to your fork:
   ```bash
   git push origin feature-name
   ```
5. Open a Pull Request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **OpenAI**: For providing GPT models to power the CVSS adjustments.
- **NVD (National Vulnerability Database)**: For CVE data standards and CVSS resources.

---

Let me know if you'd like further refinements or additional sections! 🚀