# NPM Package Audit Tool

import urllib.request
import json
import argparse
import sys
import os

# --- Configuration ---
REGISTRY_URL = "https://registry.npmjs.org"
OSV_URL = "https://api.osv.dev/v1/query"

def get_npm_metadata(package_name):
    """Fetches package metadata from the npm registry."""
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        with urllib.request.urlopen(url) as response:
            if response.status == 200:
                return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"Error: Package '{package_name}' not found in npm registry.")
        else:
            print(f"Error fetching metadata: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    return None

def check_vulnerabilities(package_name, version=None):
    """Checks for vulnerabilities using the OSV API."""
    url = "https://api.osv.dev/v1/query"
    
    package_info = {"name": package_name, "ecosystem": "npm"}
    payload = {"package": package_info}
    if version:
        payload["version"] = version

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})

    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                return json.loads(response.read().decode())
    except Exception as e:
        print(f"Error checking vulnerabilities: {e}")
    return None

def calculate_cvss_v3_score(vector):
    # Minimal CVSS v3.1 calculator
    try:
        if not vector.startswith("CVSS:3"): return "N/A"
        
        metrics = {}
        for part in vector.split('/'):
            if ':' in part:
                k, v = part.split(':')
                metrics[k] = v
        
        # Base Metrics
        AV_MAP = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
        AC_MAP = {'L': 0.77, 'H': 0.44}
        PR_MAP = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        PR_MAP_C = {'N': 0.85, 'L': 0.68, 'H': 0.50}
        UI_MAP = {'N': 0.85, 'R': 0.62}
        S_MAP = {'U': False, 'C': True}
        C_MAP = {'H': 0.56, 'L': 0.22, 'N': 0}
        I_MAP = {'H': 0.56, 'L': 0.22, 'N': 0}
        A_MAP = {'H': 0.56, 'L': 0.22, 'N': 0}

        av = AV_MAP.get(metrics.get('AV'))
        ac = AC_MAP.get(metrics.get('AC'))
        ui = UI_MAP.get(metrics.get('UI'))
        s = S_MAP.get(metrics.get('S'), False)
        
        c = C_MAP.get(metrics.get('C'))
        i = I_MAP.get(metrics.get('I'))
        a = A_MAP.get(metrics.get('A'))
        
        pr_val = metrics.get('PR')
        pr = PR_MAP_C.get(pr_val) if s else PR_MAP.get(pr_val)

        if any(v is None for v in [av, ac, pr, ui, c, i, a]): return "N/A"

        iss = 1 - ( (1-c)*(1-i)*(1-a) )
        
        if s:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
            
        exploitability = 8.22 * av * ac * pr * ui
        
        if impact <= 0:
            base_score = 0
        else:
            if s:
                base_score = min(1.08 * (impact + exploitability), 10)
            else:
                base_score = min(impact + exploitability, 10)
                
        import math
        base_score = math.ceil(base_score * 10) / 10.0
        return str(base_score)
        
    except Exception:
        return "N/A"

def calculate_cvss_v2_score(vector):
    # Minimal CVSS v2 calculator
    try:
        clean = vector.replace('(', '').replace(')', '')
        metrics = {}
        for part in clean.split('/'):
             if ':' in part:
                 k, v = part.split(':')
                 metrics[k] = v
        
        AV_MAP = {'L': 0.395, 'A': 0.646, 'N': 1.0}
        AC_MAP = {'H': 0.35, 'M': 0.61, 'L': 0.71}
        AU_MAP = {'M': 0.45, 'S': 0.56, 'N': 0.704}
        CIA_MAP = {'N': 0.0, 'P': 0.275, 'C': 0.660}

        av = AV_MAP.get(metrics.get('AV'))
        ac = AC_MAP.get(metrics.get('AC'))
        au = AU_MAP.get(metrics.get('Au'))
        c = CIA_MAP.get(metrics.get('C'))
        i = CIA_MAP.get(metrics.get('I'))
        a = CIA_MAP.get(metrics.get('A'))
        
        if any(v is None for v in [av, ac, au, c, i, a]): return "N/A"

        impact = 10.41 * (1 - (1-c)*(1-i)*(1-a))
        exploitability = 20 * av * ac * au
        f_impact = 0 if impact == 0 else 1.176
        base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
        
        return f"{base_score:.1f}"
    except Exception:
        return "N/A"

def resolve_version(version_range):
    """
    Heuristically resolves a semver range to a concrete version.
    Handles simple cases like ^1.2.3, ~1.2.3, >=1.2.3, 1.2.3.
    """
    if not version_range:
        return None
    
    # Strip common range characters
    clean_version = version_range.strip()
    for char in ['^', '~', '>=', '>', '=', 'v']:
        clean_version = clean_version.replace(char, '')
    
    clean_version = clean_version.strip()
    
    # Simple check if it looks like x.y.z
    parts = clean_version.split('.')
    if len(parts) >= 1 and parts[0].isdigit():
         return clean_version
         
    return "latest" # Fallback

def get_severity_rating(score_str, vector):
    try:
        score = float(score_str)
    except ValueError:
        return "UNKNOWN"

    if vector.startswith("CVSS:3"):
        # CVSS v3.x Rating
        if 0.1 <= score <= 3.9: return "LOW"
        if 4.0 <= score <= 6.9: return "MEDIUM"
        if 7.0 <= score <= 8.9: return "HIGH"
        if 9.0 <= score <= 10.0: return "CRITICAL"
    else:
        # CVSS v2.0 Rating
        if 0.0 <= score <= 3.9: return "LOW"
        if 4.0 <= score <= 6.9: return "MEDIUM"
        if 7.0 <= score <= 10.0: return "HIGH"
    
    return "UNKNOWN"

def process_finding(v, package_name, version, category, severity_filter):
    # Extract CVE
    cve = "N/A"
    aliases = v.get("aliases", [])
    for alias in aliases:
        if alias.startswith("CVE-"):
            cve = alias
            break

    # Extract severity (Prefer CVSS_V2)
    severity = "N/A"
    vector = ""
    sev_list = v.get("severity", [])
    
    # First pass: Look for V2
    for s in sev_list:
        if s.get("type") == "CVSS_V2":
            vector = s.get("score", "")
            score = calculate_cvss_v2_score(vector)
            if score != "N/A":
                severity = score
            else:
                severity = vector
            break
    
    # Second pass: If still N/A, look for V3 (fallback)
    if severity == "N/A":
        for s in sev_list:
            if s.get("type") == "CVSS_V3":
                vector = s.get("score", "")
                score = calculate_cvss_v3_score(vector)
                if score != "N/A":
                    severity = score
                else:
                    severity = vector
                break
    
    # Filtering
    if severity_filter:
        rating = get_severity_rating(severity, vector)
        if rating not in severity_filter:
            return None

    # Extract fixed version
    fixed_version = "N/A"
    affected = v.get("affected", [])
    for aff in affected:
        if aff.get("package", {}).get("name") == package_name:
            ranges = aff.get("ranges", [])
            for r in ranges:
                if r.get("type") == "SEMVER":
                    events = r.get("events", [])
                    for e in events:
                        if "fixed" in e:
                            fixed_version = e["fixed"]
                            break
                    if fixed_version != "N/A": break
            if fixed_version != "N/A": break

    return {
        "package": package_name,
        "version": version,
        "id": v.get("id"),
        "cve": cve,
        "summary": v.get("summary", "No summary provided"),
        "severity": severity,
        "fixed": fixed_version,
        "category": category
    }

MAX_DEPTH = 6

def audit_recursive(package_name, version_range, visited, findings, category, severity_filter=None, debug=False, depth=0):
    indent = "  " * depth
    if depth > MAX_DEPTH:
        if debug: print(f"{indent}Max depth reached, skipping dependencies of {package_name}")
        return

    # Resolve version
    resolved_version = resolve_version(version_range)
    if not resolved_version:
        if debug: print(f"{indent}Could not resolve version for {package_name} ({version_range})")
        return

    # If 'latest' is needed logic:
    if resolved_version == "latest":
        meta = get_npm_metadata(package_name)
        if not meta:
             return
        resolved_version = meta.get("dist-tags", {}).get("latest")
        if not resolved_version:
            return
    
    # Cycle detection
    if (package_name, resolved_version) in visited:
        return
    visited.add((package_name, resolved_version))

    if debug:
        print(f"{indent}Checking {package_name}@{resolved_version} ({category})...")

    # Fetch metadata for this specific version to get dependencies
    metadata = get_npm_metadata(package_name)
    if not metadata:
        return

    versions = metadata.get("versions", {})
    if resolved_version not in versions:
         if debug: print(f"{indent}Error: Version {resolved_version} not found for {package_name}")
         return
         
    # Check vulnerabilities
    vuln_data = check_vulnerabilities(package_name, resolved_version)
    vulns = vuln_data.get("vulns", [])
    
    if vulns:
        if debug:
            print(f"{indent}  ALARM: Found {len(vulns)} vulnerabilities!")
            for v in vulns:
                id = v.get("id")
                summary = v.get("summary", "No summary provided")
                print(f"{indent}  - [{id}] {summary}")
        
        # Collect findings
        for v in vulns:
            finding = process_finding(v, package_name, resolved_version, category, severity_filter)
            if finding:
                findings.append(finding)

    # Recurse on dependencies (Prod + Optional)
    version_data = versions.get(resolved_version, {})
    
    prod_deps = version_data.get("dependencies", {})
    opt_deps = version_data.get("optionalDependencies", {})
    
    all_deps = prod_deps.copy()
    all_deps.update(opt_deps)
    
    for dep_name, dep_range in all_deps.items():
        audit_recursive(dep_name, dep_range, visited, findings, category, severity_filter, debug, depth + 1)

def audit_group(group_name, dependencies, visited, findings, severity_filter, debug):
    if not dependencies:
        return
    if debug:
        print(f"\n--- Checking {len(dependencies)} {group_name} Dependencies ---")
    for dep_name, dep_range in dependencies.items():
        audit_recursive(dep_name, dep_range, visited, findings, category=group_name, severity_filter=severity_filter, debug=debug, depth=1)

def build_dependency_graph(lock_data):
    """Builds a parent-child mapping from a lock file (v3 'packages')."""
    parent_map = {}
    if "packages" in lock_data:
        packages = lock_data["packages"]
        for pkg_path, pkg_info in packages.items():
            # Skip root entry
            if not pkg_path:
                continue
            
            # Identify parent path
            # "node_modules/A/node_modules/B" -> parent is "node_modules/A"
            parts = pkg_path.split("/node_modules/")
            if len(parts) > 1:
                # Reconstruct parent path
                # parts = ['', 'A', 'B'] -> "node_modules/A"
                if parts[0] == "": # Starts with node_modules
                    parent_parts = parts[:-1]
                else: 
                     # Should rarely happen for valid paths starting with node_modules
                    parent_parts = parts[:-1]

                if len(parent_parts) == 1 and parent_parts[0] == "":
                     # Root dependency
                     parent_path = ""
                else:
                     parent_path = "/node_modules/".join(parent_parts)
                     if parent_path.startswith("/"): parent_path = parent_path[1:] # Fix join artifact if empty start
                    
                if pkg_path.startswith("node_modules/"):
                     # Standard case
                     # node_modules/A -> parent ""
                     # node_modules/A/node_modules/B -> parent node_modules/A
                     last_slash = pkg_path.rfind("/node_modules/")
                     if last_slash == -1:
                         # Top level
                         parent_map[pkg_path] = ""
                     else:
                         parent_map[pkg_path] = pkg_path[:last_slash]

    return parent_map

def resolve_dependency_path(pkg_path, parent_map, packages):
    """Traces back from a package path to a root dependency."""
    path = []
    current = pkg_path
    
    while current:
        # Extract name
        dep_name = current.split("node_modules/")[-1]
        path.append(dep_name)
        
        current = parent_map.get(current)
        if current == "":
             break
    
    return list(reversed(path))

def check_vulnerabilities_batch(package_version_tuples):
    """Checks for vulnerabilities for multiple packages in one batch CSV query."""
    if not package_version_tuples:
        return {}
        
    url = "https://api.osv.dev/v1/querybatch"
    
    queries = []
    for name, version in package_version_tuples:
        queries.append({
            "package": {"name": name, "ecosystem": "npm"},
            "version": version
        })
        
    payload = {"queries": queries}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})

    results = {}
    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                response_data = json.loads(response.read().decode())
                batch_results = response_data.get("results", [])
                
                with open("batch_debug.json", "w") as f:
                    json.dump(batch_results, f, indent=2)
                
                # Map back to inputs
                for i, res in enumerate(batch_results):
                    qt = package_version_tuples[i]
                    results[qt] = res
                    
    except Exception as e:
        print(f"Error checking batch vulnerabilities: {e}")
        
    return results

def parse_yarn_lock(content):
    """Parses yarn.lock content and extracts package information."""
    packages = []
    
    lines = content.split('\n')
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        
        # Check if line starts a package entry (no leading whitespace in original, contains @)
        if line and not lines[i].startswith(' ') and not lines[i].startswith('\t') and '@' in line and line.endswith(':'):
            # Parse package spec(s): "package@^1.0.0", "package@^1.0.0, package@~1.0.1":
            spec_line = line.rstrip(':')
            specs = [s.strip() for s in spec_line.split(',')]
            
            # Extract package name (before @)
            if '@' in specs[0]:
                parts = specs[0].split('@')
                # Handle scoped packages: @scope/package@version
                if specs[0].startswith('@'):
                    # Scoped package
                    pkg_name = '@' + parts[1]
                else:
                    pkg_name = parts[0]
                    
                # Move to next line to find version
                i += 1
                version = None
                is_dev = False
                
                while i < len(lines):
                    inner_line = lines[i].strip()
                    
                    if inner_line.startswith('version '):
                        # Extract version: version "1.2.3"
                        version = inner_line.split('"')[1] if '"' in inner_line else None
                    
                    # Check if this is a blank line or start of next package
                    if not inner_line or (not lines[i].startswith(' ') and not lines[i].startswith('\t')):
                        break
                        
                    i += 1
                
                if version:
                    packages.append((pkg_name, version, is_dev))
        
        i += 1
    
    return packages

def parse_pnpm_lock(content):
    """Parses pnpm-lock.yaml content and extracts package information."""
    packages = []
    
    # Simple YAML parser for pnpm lock file structure
    # We'll parse the "packages:" section which has format:
    # packages:
    #   /package-name/version:
    #     ...
    
    lines = content.split('\n')
    in_packages = False
    
    for line in lines:
        if line.strip() == 'packages:':
            in_packages = True
            continue
            
        if in_packages:
            # Check for package entry (starts with / after indentation)
            if line.startswith('  /') or line.startswith('\t/'):
                # Extract package path: "  /lodash/4.17.21:" -> "lodash", "4.17.21"
                pkg_line = line.strip().rstrip(':')
                if pkg_line.startswith('/'):
                    parts = pkg_line[1:].split('/')
                    if len(parts) >= 2:
                        # Handle regular packages: /name/version
                        # Handle scoped packages: /@scope/name/version
                        if parts[0].startswith('@') and len(parts) >= 3:
                            # Scoped package
                            pkg_name = '/' + parts[0] + '/' + parts[1]
                            version = parts[2]
                        else:
                            pkg_name = parts[0]
                            version = parts[1]
                        
                        # pnpm doesn't clearly mark dev in lock file structure,
                        # but we'll default to False
                        is_dev = False
                        packages.append((pkg_name, version, is_dev))
            
            # Exit packages section if we hit another top-level key
            elif line and not line.startswith(' ') and not line.startswith('\t') and line.strip().endswith(':'):
                break
    
    return packages

def audit_lock_file(file_path, debug=False, severity_filter=None, format='npm'):
    # Handle stdin input
    if file_path == '-':
        if debug: print("Reading lock file from stdin...")
        content = sys.stdin.read()
        file_display = "stdin"
    else:
        file_display = file_path
        content = None  # Will be read later for npm format
        
    print(f"--- Auditing Lock File: {file_display} ---\n")
    
    findings = []
    
    # Dispatch to format-specific parser for yarn/pnpm
    if format == 'yarn':
        if debug: print("Parsing yarn.lock format")
        
        # Read from file if not from stdin
        if content is None:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
            except Exception as e:
                print(f"Error reading file: {e}")
                return
                
        packages_list = parse_yarn_lock(content)
        
        # Batch query
        to_check = [(name, version) for name, version, _ in packages_list]
        if debug: print(f"Batch querying OSV for {len(to_check)} packages...")
        batch_results = check_vulnerabilities_batch(to_check)
        
        # Process each package
        for pkg_name, version, is_dev in packages_list:
            category = "Dev" if is_dev else "Mandatory"
            
            if debug:
                print(f"Checking: {pkg_name}@{version} ({category})")
            
            # Check if vulnerable in batch
            batch_data = batch_results.get((pkg_name, version), {})
            batch_vulns = batch_data.get("vulns", [])
            
            if batch_vulns:
                if debug: print(f"  Vulnerabilities detected. Fetching full details...")
                
                full_data = check_vulnerabilities(pkg_name, version)
                vulns = full_data.get("vulns", [])
                
                if vulns:
                    if debug:
                        print(f"  ALARM: Found {len(vulns)} vulnerabilities!")
                    
                    for v in vulns:
                        finding = process_finding(v, pkg_name, version, category, severity_filter)
                        if finding:
                            finding['path'] = [pkg_name]  # Yarn doesn't provide dep graph easily
                            findings.append(finding)
        
        print_summary(findings)
        return
        
    elif format == 'pnpm':
        if debug: print("Parsing pnpm-lock.yaml format")
        
        # Read from file if not from stdin
        if content is None:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
            except Exception as e:
                print(f"Error reading file: {e}")
                return
                
        packages_list = parse_pnpm_lock(content)
        
        # Batch query
        to_check = [(name, version) for name, version, _ in packages_list]
        if debug: print(f"Batch querying OSV for {len(to_check)} packages...")
        batch_results = check_vulnerabilities_batch(to_check)
        
        # Process each package
        for pkg_name, version, is_dev in packages_list:
            category = "Dev" if is_dev else "Mandatory"
            
            if debug:
                print(f"Checking: {pkg_name}@{version} ({category})")
            
            # Check if vulnerable in batch
            batch_data = batch_results.get((pkg_name, version), {})
            batch_vulns = batch_data.get("vulns", [])
            
            if batch_vulns:
                if debug: print(f"  Vulnerabilities detected. Fetching full details...")
                
                full_data = check_vulnerabilities(pkg_name, version)
                vulns = full_data.get("vulns", [])
                
                if vulns:
                    if debug:
                        print(f"  ALARM: Found {len(vulns)} vulnerabilities!")
                    
                    for v in vulns:
                        finding = process_finding(v, pkg_name, version, category, severity_filter)
                        if finding:
                            finding['path'] = [pkg_name]  # PNPM structure is complex
                            findings.append(finding)
        
        print_summary(findings)
        return
    
    # NPM format (default)
    try:
        with open(file_path, 'r') as f:
            lock_data = json.load(f)
    except Exception as e:
        print(f"Error reading lock file: {e}")
        return

    # Check for "packages" (lockfileVersion 2/3)
    if "packages" in lock_data:
        if debug: print("Detected 'packages' structure (lockfileVersion 2/3)")
        packages = lock_data["packages"]
        
        # Build hierarchy for path tracing
        parent_map = build_dependency_graph(lock_data)
        
        # 1. Collect all packages to check
        to_check = []
        pkg_paths_to_audit = []
        
        for pkg_path, pkg_info in packages.items():
            if not pkg_path: continue
            if not pkg_path.startswith("node_modules/"): continue
            
            dep_name = pkg_path.split("node_modules/")[-1]
            version = pkg_info.get("version")
            if not version: continue
            
            to_check.append((dep_name, version))
            pkg_paths_to_audit.append((pkg_path, dep_name, version, pkg_info))
            
        # 2. Batch Query (Pre-filter)
        if debug: print(f"Batch querying OSV for {len(to_check)} packages...")
        batch_results = check_vulnerabilities_batch(to_check)
        
        # 3. Process Results
        for i, (pkg_path, dep_name, version, pkg_info) in enumerate(pkg_paths_to_audit):
            
            # Category
            is_dev = pkg_info.get("dev", False)
            current_category = "Dev" if is_dev else "Mandatory"
            
            if debug:
                print(f"Lock Check (Flat): {dep_name}@{version} ({current_category})")
                
            # Get pre-fetched data
            batch_data = batch_results.get((dep_name, version), {})
            batch_vulns = batch_data.get("vulns", [])
            
            if batch_vulns:
                # If vulnerabilities found in batch, fetch FULL details individually
                # because batch API returns incomplete data (e.g. no summary/severity/fixed).
                if debug: print(f"  Vulnerabilities detected in batch. Fetching full details for {dep_name}@{version}...")
                
                full_data = check_vulnerabilities(dep_name, version)
                vulns = full_data.get("vulns", [])
                
                if vulns:
                     if debug:
                        print(f"  ALARM: Found {len(vulns)} vulnerabilities!")
                     
                     # Calculate path
                     dep_path = resolve_dependency_path(pkg_path, parent_map, packages)
                     
                     if debug:
                        print(f"  Path: {' > '.join(dep_path)}")

                     for v in vulns:
                        finding = process_finding(v, dep_name, version, current_category, severity_filter)
                        if finding:
                            finding['path'] = dep_path
                            findings.append(finding)
                        
    # Fallback to "dependencies" (lockfileVersion 1 or recursed structure)
    elif "dependencies" in lock_data:
        # Note: Recursive method needs update to track path. 
        # For now, pass empty path or update recursive sig.
        # Given instruction specific to "bundled dependencies", we focus on the v3 structure first or update recursive.
        # Let's pass a path list to recursive.
        audit_lock_recursive(lock_data["dependencies"], findings, "Root", severity_filter, debug, path=[])
    else:
        if debug: print("No 'packages' or 'dependencies' found in lock file.")

    print_summary(findings)

def audit_lock_recursive(dependencies, findings, parent_category, severity_filter, debug, depth=0, path=None):
    if path is None: path = []
    
    indent = "  " * depth
    if depth > 10: 
        return

    for dep_name, dep_info in dependencies.items():
        version = dep_info.get("version")
        
        # Determine category
        is_dev = dep_info.get("dev", False)
        
        if parent_category == "Dev" or is_dev:
            current_category = "Dev"
        else:
            current_category = "Mandatory"
        
        current_path = path + [dep_name]
        
        if debug:
            print(f"{indent}Lock Check: {dep_name}@{version} ({current_category})")

        # Check Vulnerabilities
        vuln_data = check_vulnerabilities(dep_name, version)
        vulns = vuln_data.get("vulns", [])
        
        if vulns:
            if debug:
                print(f"{indent}  ALARM: Found {len(vulns)} vulnerabilities!")
            for v in vulns:
                finding = process_finding(v, dep_name, version, current_category, severity_filter)
                if finding:
                    finding['path'] = current_path
                    findings.append(finding)
        
        # Recurse
        if "dependencies" in dep_info:
            audit_lock_recursive(dep_info["dependencies"], findings, current_category, severity_filter, debug, depth + 1, current_path)

def get_category_priority(cat):
    if cat == "Root": return 0
    if cat == "Mandatory": return 1
    if cat == "Optional": return 2
    if cat == "Dev": return 3
    return 4

def print_summary(findings):
    if not findings:
        print("\n\n✅ No vulnerabilities found.")
        return

    print("\n\n=== Vulnerability Summary ===")
    
    # Sort findings
    def sort_key(f):
        return (get_category_priority(f['category']), f['package'], f['id'])
    
    findings.sort(key=sort_key)
    
    # Split into Direct and Bundled
    direct_findings = []
    bundled_findings = []
    
    for f in findings:
        path = f.get('path', [])
        # If path has 1 element, it is direct. If > 1, it is bundled.
        # If path is empty (legacy audit_package), assume direct if depth 0? 
        # Actually audit_package logic didn't provide path. 
        # But user request is specifically about "bundled dependencies" which implies lock file context.
        # For standard package audit, we can assume direct if not transient? 
        # But let's check path length if available.
        if path and len(path) > 1:
            bundled_findings.append(f)
        else:
            direct_findings.append(f)

    # Print Direct Table
    if direct_findings:
        print("\n--- Direct Dependencies ---")
        header = f"{'Category':<10} | {'Package':<15} | {'Version':<10} | {'ID':<20} | {'CVE':<15} | {'Severity':<10} | {'Fixed':<10} | {'Summary'}"
        print("-" * len(header))
        print(header)
        print("-" * len(header))

        for f in direct_findings:
            cat = f['category']
            pkg = f['package']
            ver = f['version']
            vid = f['id']
            cve = f['cve']
            sev = f['severity']
            fixed = f['fixed']
            summ = f['summary']
            
            if len(summ) > 30: summ = summ[:27] + "..."
                
            print(f"{cat:<10} | {pkg:<15} | {ver:<10} | {vid:<20} | {cve:<15} | {sev:<10} | {fixed:<10} | {summ}")
        print("-" * len(header))

    # Print Bundled Table
    if bundled_findings:
        print("\n--- Bundled Dependencies ---")
        # Add "Update via" column
        header_b = f"{'Parent':<15} | {'Package':<15} | {'Version':<10} | {'ID':<20} | {'CVE':<15} | {'Severity':<10} | {'Fixed':<10} | {'Update via'}"
        print("-" * len(header_b))
        print(header_b)
        print("-" * len(header_b))
        
        for f in bundled_findings:
            path = f.get('path', [])
            parent = path[0] if path else "Unknown"
            pkg = f['package']
            ver = f['version']
            vid = f['id']
            cve = f['cve']
            sev = f['severity']
            fixed = f['fixed']
            
            # Update instruction: "npm update <Parent>"
            update_via = f"npm update {parent}"
            
            print(f"{parent:<15} | {pkg:<15} | {ver:<10} | {vid:<20} | {cve:<15} | {sev:<10} | {fixed:<10} | {update_via}")
        print("-" * len(header_b))

    print(f"\nTotal: {len(findings)} issues found ({len(direct_findings)} direct, {len(bundled_findings)} bundled).")

def audit_package(package_name, version=None, debug=False, severity_filter=None):
    print(f"--- Auditing Package: {package_name} ---\n")
    
    # Initial setup
    visited = set()
    findings = []
    
    # 1. Fetch Metadata
    metadata = get_npm_metadata(package_name)
    if not metadata:
        return

    latest_version = metadata.get("dist-tags", {}).get("latest")
    target_version = version if version else latest_version
    
    if not target_version:
         print("Could not determine version to check.")
         return

    print(f"Auditing Version: {target_version}")
    if version and version != latest_version:
        print(f"(Latest Version is: {latest_version})")

    versions = metadata.get("versions", {})
    if target_version not in versions:
        print(f"Error: Version {target_version} not found in registry for package '{package_name}'.")
        return

    # Check deprecation
    version_data = versions.get(target_version, {})
    deprecated = version_data.get("deprecated")
    if deprecated:
        print(f"WARNING: Version {target_version} is deprecated! Message: {deprecated}")
    
    if debug:
        print("") # Spacer

    # 2. Check Vulnerabilities (Main Package)
    if debug:
        print(f"Checking {package_name}@{target_version}...")
    visited.add((package_name, target_version))
    
    vuln_data = check_vulnerabilities(package_name, target_version)
    vulns = vuln_data.get("vulns", [])
    if vulns:
        if debug:
            print(f"  ALARM: Found {len(vulns)} vulnerabilities!")
            for v in vulns:
                 print(f"  - [{v.get('id')}] {v.get('summary', 'No summary')}")
        for v in vulns:
            finding = process_finding(v, package_name, target_version, "Root", severity_filter)
            if finding:
                findings.append(finding)
    
    # 3. Check Dependencies by Category
    prod_deps = version_data.get("dependencies", {})
    audit_group("Mandatory", prod_deps, visited, findings, severity_filter, debug)

    dev_deps = version_data.get("devDependencies", {})
    audit_group("Dev", dev_deps, visited, findings, severity_filter, debug)

    opt_deps = version_data.get("optionalDependencies", {})
    audit_group("Optional", opt_deps, visited, findings, severity_filter, debug)

    if not (prod_deps or dev_deps or opt_deps):
        if debug:
            print("\nNo direct dependencies found.")
            
    # Print Summary Table
    print_summary(findings)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit an npm package for security issues.")
    parser.add_argument("package", help="Name of the npm package to audit, path to lock file, or '-' for stdin")
    parser.add_argument("--version", "-v", help="Specific version to audit", default=None)
    parser.add_argument("--debug", "-d", help="Enable verbose debug output", action="store_true")
    parser.add_argument("--severity", "-s", help="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)", default=None)
    parser.add_argument("--format", "-f", help="Lock file format (npm, yarn, pnpm)", choices=['npm', 'yarn', 'pnpm'], default='npm')
    args = parser.parse_args()

    severity_filter = None
    if args.severity:
        severity_filter = [s.strip().upper() for s in args.severity.split(',')]

    # Check if package argument is a file or stdin
    if args.package == '-' or os.path.isfile(args.package):
        audit_lock_file(args.package, args.debug, severity_filter, args.format)
    else:
        audit_package(args.package, args.version, args.debug, severity_filter)
