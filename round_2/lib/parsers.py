"""Lock file parsers for npm, yarn, and pnpm formats."""


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
          
    return "latest"  # Fallback


def build_dependency_graph(lock_data):
    """Builds a parent-child mapping from a lock file (v3 'packages')."""
    parent_map = {}
    if "packages" in lock_data:
        packages = lock_data["packages"]
        for pkg_path, pkg_info in packages.items():
            # Skip root entry
            if not pkg_path:
                continue
            
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
