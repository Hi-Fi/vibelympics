import json
import urllib.request

def check_vulnerabilities(package_name, version):
    """Checks for vulnerabilities using the OSV API and returns the raw JSON response."""
    url = "https://api.osv.dev/v1/query"
    package_info = {"name": package_name, "ecosystem": "npm"}
    payload = {"package": package_info, "version": version}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})

    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                return json.loads(response.read().decode())
            else:
                print(f"API returned status {response.status}: {response.read().decode()}")
                return None
    except Exception as e:
        print(f"Error: {e}")
        return None

# Check a vulnerable package
package_name = "lodash"
version = "4.17.0"

print(f"Fetching vulnerabilities for {package_name}@{version}...")
data = check_vulnerabilities(package_name, version)

if data and "vulns" in data:
    print(f"Found {len(data['vulns'])} vulnerabilities.")
    # Print first vuln in detail
    print(json.dumps(data["vulns"][0], indent=2))
else:
    print("No vulnerabilities found or error occurred.")
