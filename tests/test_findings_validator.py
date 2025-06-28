import json
import pytest

@pytest.fixture
def findings():
    #Load and parse the SARIF findings.json file
    with open("findings.json") as sarif:
        data = json.load(sarif)
    return data["runs"][0]["results"]

def test_total_findings(findings):
    try:
        # Assert that the total number of findings is exactly 6
        assert len(findings) == 6, f"Expected 6 findings, found {len(findings)}"
        print("✅ Found exactly 6 security findings.")
    except AssertionError as ae:
        print(f"❌ Assertion failed: {ae}")

def test_sql_injection_finding(findings):
    #Validate SQL Injection finding details
    sql = next((f for f in findings if f["ruleId"] == "php.lang.security.injection.tainted-sql-string.tainted-sql-string"), None)
    assert sql is not None, "SQL Injection finding not found"
    print("✅ SQL Injection finding found.")

    assert sql["level"] == "error", f"SQL Injection level is not 'error': {sql['level']}"
    print("✅ SQL Injection level is 'error'.")

    severity = float(sql["properties"]["security-severity"])
    assert severity > 8.0, f"SQL Injection severity is not > 8.0: {severity}"
    print(f"✅ SQL Injection severity is {severity} (> 8.0).")

    owner = sql["properties"]["issue_owner"]
    assert owner == "tmalbos", f"SQL Injection issue_owner is not 'tmalbos': {owner}"
    print("✅ SQL Injection issue_owner is 'tmalbos'.")

    file_path = sql["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert file_path == "index.php", f"SQL Injection file location is not 'index.php': {file_path}"
    print("✅ SQL Injection located in 'index.php'.")

def test_package_json_findings(findings):
    """Validate all findings related to package.json"""
    package_findings = [
        f for f in findings
        if f["ruleId"] == "json.npm.security.package-dependencies-check.package-dependencies-check"
    ]
    assert package_findings, "No findings related to package.json"
    print(f"✅ Found {len(package_findings)} findings related to package.json.")

    for idx, finding in enumerate(package_findings, 1):
        owner = finding["properties"]["issue_owner"]
        assert owner == "Jose", f"Finding #{idx} has issue_owner '{owner}', expected 'Jose'"
        print(f"✅ Finding #{idx} issue_owner is 'Jose'.")
