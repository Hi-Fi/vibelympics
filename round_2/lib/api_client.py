"""NPM Registry and OSV API client functions with security hardening."""

import urllib.request
import urllib.error
import json
import ssl

# --- Security Configuration ---
REQUEST_TIMEOUT = 30  # seconds
MAX_RESPONSE_SIZE = 50 * 1024 * 1024  # 50MB max response size
MAX_BATCH_SIZE = 1000  # Maximum packages per batch query

# Create SSL context with certificate verification
SSL_CONTEXT = ssl.create_default_context()


def _safe_read_response(response, max_size=MAX_RESPONSE_SIZE):
    """Safely read response with size limit to prevent memory exhaustion."""
    content_length = response.headers.get('Content-Length')
    
    if content_length and int(content_length) > max_size:
        raise ValueError(f"Response too large: {content_length} bytes (max: {max_size})")
    
    # Read in chunks to handle streaming responses
    chunks = []
    total_size = 0
    chunk_size = 8192
    
    while True:
        chunk = response.read(chunk_size)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_size:
            raise ValueError(f"Response exceeded max size: {max_size} bytes")
        chunks.append(chunk)
    
    return b''.join(chunks)


def _sanitize_error(error):
    """Sanitize error messages to avoid leaking sensitive information."""
    error_str = str(error)
    # Remove potential sensitive data patterns
    if 'Authorization' in error_str or 'token' in error_str.lower():
        return "Network request failed (details hidden for security)"
    return error_str


def get_npm_metadata(package_name):
    """Fetches package metadata from the npm registry with security hardening."""
    # Input validation
    if not package_name or not isinstance(package_name, str):
        print("Error: Invalid package name")
        return None
    
    # Validate package name format (npm naming rules)
    if len(package_name) > 214:
        print("Error: Package name too long")
        return None
    
    url = f"https://registry.npmjs.org/{urllib.parse.quote(package_name, safe='@/')}"
    
    try:
        with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT, context=SSL_CONTEXT) as response:
            if response.status == 200:
                data = _safe_read_response(response)
                return json.loads(data.decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"Error: Package '{package_name}' not found in npm registry.")
        else:
            print(f"Error fetching metadata: HTTP {e.code}")
    except urllib.error.URLError as e:
        print(f"Network error: {_sanitize_error(e.reason)}")
    except json.JSONDecodeError:
        print("Error: Invalid JSON response from registry")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception:
        print("Error: Unexpected error fetching metadata")
    return None


def check_vulnerabilities(package_name, version=None):
    """Checks for vulnerabilities using the OSV API with security hardening."""
    # Input validation
    if not package_name or not isinstance(package_name, str):
        return None
    if version and not isinstance(version, str):
        return None
    
    url = "https://api.osv.dev/v1/query"
    
    package_info = {"name": package_name, "ecosystem": "npm"}
    payload = {"package": package_info}
    if version:
        payload["version"] = version

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=SSL_CONTEXT) as response:
            if response.status == 200:
                resp_data = _safe_read_response(response)
                return json.loads(resp_data.decode())
    except urllib.error.URLError as e:
        print(f"Network error checking vulnerabilities: {_sanitize_error(e.reason)}")
    except json.JSONDecodeError:
        print("Error: Invalid JSON response from OSV API")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception:
        print("Error: Unexpected error checking vulnerabilities")
    return None


def check_vulnerabilities_batch(package_version_tuples):
    """Checks for vulnerabilities for multiple packages with security hardening."""
    if not package_version_tuples:
        return {}
    
    # Limit batch size to prevent abuse
    if len(package_version_tuples) > MAX_BATCH_SIZE:
        print(f"Warning: Batch size limited to {MAX_BATCH_SIZE} packages")
        package_version_tuples = package_version_tuples[:MAX_BATCH_SIZE]
        
    url = "https://api.osv.dev/v1/querybatch"
    
    queries = []
    for name, version in package_version_tuples:
        # Validate each package
        if not name or not isinstance(name, str):
            continue
        if not version or not isinstance(version, str):
            continue
        queries.append({
            "package": {"name": name, "ecosystem": "npm"},
            "version": version
        })
    
    if not queries:
        return {}
        
    payload = {"queries": queries}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})

    results = {}
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT * 2, context=SSL_CONTEXT) as response:
            if response.status == 200:
                resp_data = _safe_read_response(response)
                response_data = json.loads(resp_data.decode())
                batch_results = response_data.get("results", [])
                
                # Map back to inputs
                for i, res in enumerate(batch_results):
                    if i < len(package_version_tuples):
                        qt = package_version_tuples[i]
                        results[qt] = res
                        
    except urllib.error.URLError as e:
        print(f"Network error in batch query: {_sanitize_error(e.reason)}")
    except json.JSONDecodeError:
        print("Error: Invalid JSON response from OSV batch API")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception:
        print("Error: Unexpected error in batch vulnerability check")
        
    return results


# Add missing import for URL encoding
import urllib.parse
