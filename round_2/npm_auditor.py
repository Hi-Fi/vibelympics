# NPM Package Audit Tool

import argparse
import sys
import os
import json

# --- Security Configuration ---
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max lock file size
MAX_STDIN_SIZE = 50 * 1024 * 1024  # 50MB max stdin size
ALLOWED_EXTENSIONS = {'.json', '.lock', '.yaml', '.yml'}

# Import from lib modules
from lib.api_client import get_npm_metadata, check_vulnerabilities, check_vulnerabilities_batch
from lib.cvss import (
    calculate_cvss_v3_score,
    calculate_cvss_v2_score,
    get_severity_rating,
    get_severity_priority
)
from lib.formatters import print_summary, colorize_severity
from lib.parsers import (
    parse_yarn_lock,
    parse_pnpm_lock,
    build_dependency_graph,
    resolve_dependency_path,
    resolve_version
)


def validate_file_path(file_path):
    """Validate and sanitize file path to prevent path traversal attacks."""
    if not file_path or not isinstance(file_path, str):
        return None, "Invalid file path"
    
    # Resolve to absolute path and normalize
    try:
        abs_path = os.path.abspath(os.path.normpath(file_path))
    except Exception:
        return None, "Invalid path format"
    
    # Check file exists
    if not os.path.isfile(abs_path):
        return None, f"File not found: {file_path}"
    
    # Check file extension
    _, ext = os.path.splitext(abs_path.lower())
    if ext not in ALLOWED_EXTENSIONS:
        return None, f"Unsupported file type: {ext}"
    
    # Check file size
    try:
        file_size = os.path.getsize(abs_path)
        if file_size > MAX_FILE_SIZE:
            return None, f"File too large: {file_size} bytes (max: {MAX_FILE_SIZE})"
        if file_size == 0:
            return None, "File is empty"
    except OSError:
        return None, "Could not read file size"
    
    return abs_path, None


def safe_read_file(file_path):
    """Safely read file with size validation."""
    abs_path, error = validate_file_path(file_path)
    if error:
        return None, error
    
    try:
        with open(abs_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return content, None
    except UnicodeDecodeError:
        return None, "File contains invalid UTF-8 characters"
    except PermissionError:
        return None, "Permission denied reading file"
    except Exception:
        return None, "Error reading file"


def safe_read_stdin():
    """Safely read from stdin with size limit."""
    try:
        content = sys.stdin.read(MAX_STDIN_SIZE + 1)
        if len(content) > MAX_STDIN_SIZE:
            return None, f"Stdin input too large (max: {MAX_STDIN_SIZE} bytes)"
        if not content.strip():
            return None, "No input received from stdin"
        return content, None
    except Exception:
        return None, "Error reading from stdin"


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


def audit_lock_file(file_path, debug=False, severity_filter=None, format='npm'):
    # Handle stdin input
    if file_path == '-':
        if debug: print("Reading lock file from stdin...")
        content, error = safe_read_stdin()
        if error:
            print(f"Error: {error}")
            return
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
            content, error = safe_read_file(file_path)
            if error:
                print(f"Error: {error}")
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
            content, error = safe_read_file(file_path)
            if error:
                print(f"Error: {error}")
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
    content, error = safe_read_file(file_path)
    if error:
        print(f"Error: {error}")
        return
    
    try:
        lock_data = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in lock file: {e.msg}")
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
