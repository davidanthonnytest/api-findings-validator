# API Vulnerability Findings Validator (pytest version)

This repository contains automated validation tests for a SARIF-formatted findings.json file.

## How to Run

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the tests:
```bash
pytest -s --html=report.html --self-contained-html
```
