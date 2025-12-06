"""Output formatting with ANSI colors, vibes, and table printing."""

from lib.cvss import get_severity_priority
import random


# --- ANSI Color Codes ---
class Colors:
    CRITICAL = '\033[1;91m'  # Bold Red
    HIGH = '\033[1;33m'      # Bold Yellow
    MEDIUM = '\033[93m'      # Yellow
    LOW = '\033[37m'         # Gray
    UNKNOWN = '\033[90m'     # Dark Gray
    RESET = '\033[0m'        # Reset
    BOLD = '\033[1m'         # Bold
    CYAN = '\033[96m'        # Cyan
    GREEN = '\033[92m'       # Green
    MAGENTA = '\033[95m'     # Magenta


# --- ASCII Art Banner with Finnish Flag ---
BANNER = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║  {Colors.MAGENTA}🔍 NPM PACKAGE AUDITOR 🛡️{Colors.CYAN}                                   ║
║  {Colors.GREEN}Security scanning with style{Colors.CYAN}              {Colors.RESET}Made in Finland 🇫🇮{Colors.CYAN} ║
╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""

# --- Fun Messages ---
SCANNING_MESSAGES = [
    "🔬 Scanning the dependency matrix...",
    "🕵️ Hunting for vulnerabilities...",
    "🔎 Peering into the node_modules abyss...",
    "🧹 Sweeping for security issues...",
    "🎯 Targeting known CVEs...",
    "🌐 Querying the OSV oracle...",
    "🔐 Checking your security posture...",
    "🚀 Launching security probes...",
]

CLEAN_MESSAGES = [
    "🌟 Sparkling clean! No vulnerabilities found!",
    "✨ Your dependencies are looking pristine!",
    "🎉 All clear! Your packages are secure!",
    "💪 Rock solid! No security issues detected!",
    "🏆 Perfect score! Zero vulnerabilities!",
    "🛡️ Fort Knox status achieved!",
    "🌈 Rainbow of security! All good here!",
]

VULN_MESSAGES = [
    "⚠️ Houston, we have vulnerabilities...",
    "🚨 Security issues detected!",
    "🔴 Heads up! Found some CVEs lurking...",
    "⛔ Alert! Your dependencies need attention!",
    "🆘 Time to update some packages!",
]

SEVERITY_EMOJIS = {
    'CRITICAL': '💀',
    'HIGH': '🔥',
    'MEDIUM': '⚡',
    'LOW': '💧',
    'UNKNOWN': '❓',
    'N/A': '❔'
}


def print_banner():
    """Print the fancy ASCII art banner."""
    print(BANNER)


def get_random_scanning_message():
    """Get a random fun scanning message."""
    return random.choice(SCANNING_MESSAGES)


def colorize_severity(severity_str, rating):
    """Apply color and emoji based on severity rating."""
    color_map = {
        'CRITICAL': Colors.CRITICAL,
        'HIGH': Colors.HIGH,
        'MEDIUM': Colors.MEDIUM,
        'LOW': Colors.LOW,
        'UNKNOWN': Colors.UNKNOWN,
        'N/A': Colors.UNKNOWN
    }
    color = color_map.get(rating, Colors.RESET)
    emoji = SEVERITY_EMOJIS.get(rating, '')
    
    # Add bold for CRITICAL and HIGH
    if rating in ['CRITICAL', 'HIGH']:
        return f"{emoji} {Colors.BOLD}{color}{severity_str}{Colors.RESET}"
    else:
        return f"{emoji} {color}{severity_str}{Colors.RESET}"


def print_severity_legend():
    """Print a colorful severity legend."""
    print(f"\n{Colors.BOLD}Severity Legend:{Colors.RESET}")
    print(f"  💀 {Colors.CRITICAL}CRITICAL{Colors.RESET} (9.0-10.0)  🔥 {Colors.HIGH}HIGH{Colors.RESET} (7.0-8.9)  ⚡ {Colors.MEDIUM}MEDIUM{Colors.RESET} (4.0-6.9)  💧 {Colors.LOW}LOW{Colors.RESET} (0.1-3.9)")


def print_summary(findings):
    """Print formatted vulnerability summary tables with vibes."""
    if not findings:
        print(f"\n\n{Colors.GREEN}{random.choice(CLEAN_MESSAGES)}{Colors.RESET}")
        print(f"\n{Colors.CYAN}╭{'─' * 38}╮{Colors.RESET}")
        print(f"{Colors.CYAN}│{Colors.RESET}   ✅ {Colors.GREEN}0 vulnerabilities found{Colors.RESET}           {Colors.CYAN}│{Colors.RESET}")
        print(f"{Colors.CYAN}╰{'─' * 38}╯{Colors.RESET}")
        return

    # Count by severity
    critical_count = sum(1 for f in findings if f.get('rating') == 'CRITICAL' or (f.get('severity_score', 0) >= 9.0))
    high_count = sum(1 for f in findings if f.get('rating') == 'HIGH' or (7.0 <= f.get('severity_score', 0) < 9.0))
    
    print(f"\n\n{Colors.BOLD}{random.choice(VULN_MESSAGES)}{Colors.RESET}")
    
    # Stats box
    print(f"\n{Colors.CYAN}╭{'─' * 50}╮{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}  📊 {Colors.BOLD}Vulnerability Summary{Colors.RESET}                       {Colors.CYAN}│{Colors.RESET}")
    print(f"{Colors.CYAN}├{'─' * 50}┤{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}  💀 Critical: {Colors.CRITICAL}{critical_count:>3}{Colors.RESET}   🔥 High: {Colors.HIGH}{high_count:>3}{Colors.RESET}   📦 Total: {len(findings):>3}  {Colors.CYAN}│{Colors.RESET}")
    print(f"{Colors.CYAN}╰{'─' * 50}╯{Colors.RESET}")
    
    # Enrich findings with severity rating for sorting
    for f in findings:
        sev_str = f.get('severity', 'N/A')
        if sev_str != 'N/A':
            try:
                score = float(sev_str)
                f['severity_score'] = score
                if score >= 9.0:
                    f['rating'] = 'CRITICAL'
                elif score >= 7.0:
                    f['rating'] = 'HIGH'
                elif score >= 4.0:
                    f['rating'] = 'MEDIUM'
                elif score >= 0.1:
                    f['rating'] = 'LOW'
                else:
                    f['rating'] = 'UNKNOWN'
            except ValueError:
                f['rating'] = 'UNKNOWN'
                f['severity_score'] = -1
        else:
            f['rating'] = 'N/A'
            f['severity_score'] = -1
    
    # Sort findings
    def sort_key(f):
        return (-f.get('severity_score', -1), f['package'], f['id'])
    
    findings.sort(key=sort_key)
    
    # Split into Direct and Bundled
    direct_findings = []
    bundled_findings = []
    
    for f in findings:
        path = f.get('path', [])
        if path and len(path) > 1:
            bundled_findings.append(f)
        else:
            direct_findings.append(f)

    # Print Direct Table
    if direct_findings:
        print(f"\n{Colors.BOLD}📦 Direct Dependencies{Colors.RESET}")
        header = f"{'Category':<10} | {'Package':<15} | {'Version':<10} | {'ID':<20} | {'CVE':<15} | {'Severity':<10} | {'Fixed':<10} | {'Summary'}"
        print(f"{Colors.CYAN}{'─' * len(header)}{Colors.RESET}")
        print(header)
        print(f"{Colors.CYAN}{'─' * len(header)}{Colors.RESET}")

        for f in direct_findings:
            cat = f['category']
            pkg = f['package']
            ver = f['version']
            vid = f['id']
            cve = f['cve']
            sev = f['severity']
            rating = f.get('rating', 'N/A')
            fixed = f['fixed']
            summ = f['summary']
            
            if len(summ) > 30:
                summ = summ[:27] + "..."
            
            sev_display = colorize_severity(str(sev), rating)
                
            print(f"{cat:<10} | {pkg:<15} | {ver:<10} | {vid:<20} | {cve:<15} | {sev_display:<25} | {fixed:<10} | {summ}")
        print(f"{Colors.CYAN}{'─' * len(header)}{Colors.RESET}")

    # Print Bundled Table
    if bundled_findings:
        print(f"\n{Colors.BOLD}📚 Bundled Dependencies{Colors.RESET}")
        header_b = f"{'Parent':<15} | {'Package':<15} | {'Version':<10} | {'ID':<20} | {'CVE':<15} | {'Severity':<10} | {'Fixed':<10} | {'Update via'}"
        print(f"{Colors.CYAN}{'─' * len(header_b)}{Colors.RESET}")
        print(header_b)
        print(f"{Colors.CYAN}{'─' * len(header_b)}{Colors.RESET}")
        
        for f in bundled_findings:
            path = f.get('path', [])
            parent = path[0] if path else "Unknown"
            pkg = f['package']
            ver = f['version']
            vid = f['id']
            cve = f['cve']
            sev = f['severity']
            rating = f.get('rating', 'N/A')
            fixed = f['fixed']
            
            sev_display = colorize_severity(str(sev), rating)
            update_via = f"npm update {parent}"
            
            print(f"{parent:<15} | {pkg:<15} | {ver:<10} | {vid:<20} | {cve:<15} | {sev_display:<25} | {fixed:<10} | {update_via}")
        print(f"{Colors.CYAN}{'─' * len(header_b)}{Colors.RESET}")

    # Final summary with vibes
    print(f"\n{Colors.BOLD}📈 Final Stats:{Colors.RESET} {len(findings)} issues ({len(direct_findings)} direct, {len(bundled_findings)} bundled)")
    
    if critical_count > 0:
        print(f"{Colors.CRITICAL}💀 {critical_count} CRITICAL issue{'s' if critical_count > 1 else ''} require{'s' if critical_count == 1 else ''} immediate attention!{Colors.RESET}")
    
    print_severity_legend()
