"""Output formatting with ANSI colors, vibes, and table printing."""

from lib.cvss import get_severity_priority
import shutil
import random
import re
import unicodedata
try:
    from wcwidth import wcswidth
except Exception:
    wcswidth = None


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
    """Print a display-aware ASCII art banner (handles emoji and ANSI colors).

    This builds the box using visible/display widths so embedded color codes
    or wide emoji do not shift the edges.
    """
    # local helpers (avoid importing wcwidth at module top-level for small cost)
    ansi_re_local = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    def _strip_ansi_local(s):
        return ansi_re_local.sub('', str(s))

    def _display_len_local(s):
        t = _strip_ansi_local(s)
        try:
            from wcwidth import wcswidth as _wcs
        except Exception:
            _wcs = None
        if _wcs:
            w = _wcs(t)
            return w if w >= 0 else len(t)
        # fallback: simple east_asian heuristic
        w = 0
        for ch in t:
            ea = unicodedata.east_asian_width(ch)
            if ea in ('F', 'W'):
                w += 2
            else:
                o = ord(ch)
                if (0x1F300 <= o <= 0x1F6FF) or (0x1F900 <= o <= 0x1FAFF) or (0x1F600 <= o <= 0x1F64F) or (0x1F680 <= o <= 0x1F6FF) or (0x1F1E6 <= o <= 0x1F1FF):
                    w += 2
                else:
                    w += 1
        return w

    def _pad(s, width):
        s = str(s)
        extra = width - _display_len_local(s)
        if extra > 0:
            return s + (' ' * extra)
        return s

    def _center(s, width):
        s = str(s)
        cur = _display_len_local(s)
        if cur >= width:
            return s
        left = (width - cur) // 2
        right = width - cur - left
        return (' ' * left) + s + (' ' * right)

    # Two-line box: first line centered title, second line left subtitle and right footer
    title = f"{Colors.MAGENTA}🔍 NPM PACKAGE AUDITOR 🛡️{Colors.RESET}"
    subtitle = f"{Colors.GREEN}Security scanning with style{Colors.RESET}"
    footer = f"Made in Finland 🇫🇮"

    # compute inner width from visible lengths
    max_content = max(_display_len_local(title), _display_len_local(subtitle) + _display_len_local(footer))

    # prefer a wider box (user prefers wide), but cap to terminal width
    try:
        term_width = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        term_width = 80

    preferred = max_content + 12
    wide_default = 60
    inner_width = min(term_width - 2, max(preferred, wide_default))

    # Build inner lines first (display-aware)
    line1 = _center(title, inner_width)

    # Line 2: subtitle on left, footer on right
    subs_len = _display_len_local(subtitle)
    foot_len = _display_len_local(footer)
    space_between = inner_width - subs_len - foot_len
    if space_between < 1:
        # truncate subtitle if necessary
        avail = max(1, inner_width - foot_len - 1)
        # naive truncation by characters after stripping ANSI
        raw_sub = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', str(subtitle))
        trunc = raw_sub[:avail - 1] + '…' if len(raw_sub) > avail else raw_sub
        subtitle_display = trunc
        left_part = subtitle_display
    else:
        left_part = subtitle

    left_width = inner_width - foot_len
    if _display_len_local(left_part) > left_width:
        raw = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', str(left_part))
        left_display = raw[:max(0, left_width)]
    else:
        left_display = _pad(left_part, left_width)

    line2 = f"{left_display}{footer}"

    # Compute the actual inner visible width from the fully wrapped, stripped inner lines
    wrapped1 = f"║{line1}║"
    wrapped2 = f"║{line2}║"
    s1 = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', wrapped1)
    s2 = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', wrapped2)
    inner_actual = max(len(s1), len(s2)) - 2
    if inner_actual < 0:
        inner_actual = 0
    horiz = '═' * inner_actual

    print(f"{Colors.CYAN}╔{horiz}╗{Colors.RESET}")
    print(f"{Colors.CYAN}║{Colors.RESET}{line1}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.CYAN}║{Colors.RESET}{line2}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.CYAN}╚{horiz}╝{Colors.RESET}")


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

    # Helper: strip ANSI and measure display length (handles wide chars if wcwidth available)
    ansi_re = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    def _strip_ansi(s):
        return ansi_re.sub('', str(s))

    def display_len(s):
        t = _strip_ansi(s)
        # Prefer wcwidth if available (best accuracy for emoji/wide chars)
        if wcswidth:
            w = wcswidth(t)
            return w if w >= 0 else len(t)

        # Fallback: estimate width using Unicode East Asian Width and emoji ranges
        width = 0
        for ch in t:
            ea = unicodedata.east_asian_width(ch)
            if ea in ('F', 'W'):
                width += 2
            else:
                o = ord(ch)
                # Common emoji / symbol ranges approximate as width 2
                if (0x1F300 <= o <= 0x1F6FF) or (0x1F900 <= o <= 0x1FAFF) or (0x1F600 <= o <= 0x1F64F) or (0x1F680 <= o <= 0x1F6FF) or (0x1F1E6 <= o <= 0x1F1FF):
                    width += 2
                else:
                    width += 1
        return width

    def pad_ansi(s, width):
        s = str(s)
        extra = width - display_len(s)
        if extra > 0:
            return s + (' ' * extra)
        return s

    def truncate_display(s, max_width):
        """Truncate string `s` to at most `max_width` display cells.

        Returns a stripped (ANSI removed) string truncated so its display_len() <= max_width.
        """
        t = _strip_ansi(s)
        if display_len(t) <= max_width:
            return t
        out_chars = []
        cur = 0
        for ch in t:
            ch_w = 2 if (wcswidth and wcswidth(ch) == 2) else (2 if unicodedata.east_asian_width(ch) in ('F', 'W') else 1)
            if cur + ch_w > max_width:
                break
            out_chars.append(ch)
            cur += ch_w
        return ''.join(out_chars)

    # Count by severity
    critical_count = sum(1 for f in findings if f.get('rating') == 'CRITICAL' or (f.get('severity_score', 0) >= 9.0))
    high_count = sum(1 for f in findings if f.get('rating') == 'HIGH' or (7.0 <= f.get('severity_score', 0) < 9.0))

    print(f"\n\n{Colors.BOLD}{random.choice(VULN_MESSAGES)}{Colors.RESET}")

    # Dynamic Stats box: compute inner content and adjust box width
    title = f"  📊 {Colors.BOLD}Vulnerability Summary{Colors.RESET}  "
    stats_line = f"  💀 Critical: {Colors.CRITICAL}{critical_count:>3}{Colors.RESET}   🔥 High: {Colors.HIGH}{high_count:>3}{Colors.RESET}   📦 Total: {len(findings):>3}  "

    inner_width = max(display_len(title), display_len(stats_line))
    sep_line = '─' * inner_width

    print(f"\n{Colors.CYAN}╭{sep_line}╮{Colors.RESET}")
    # Center title
    padding = inner_width - display_len(title)
    left = padding // 2
    right = padding - left
    print(f"{Colors.CYAN}│{Colors.RESET}{' ' * left}{title}{' ' * right}{Colors.CYAN}│{Colors.RESET}")
    print(f"{Colors.CYAN}├{sep_line}┤{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}{stats_line}{' ' * (inner_width - display_len(stats_line))}{Colors.CYAN}│{Colors.RESET}")
    print(f"{Colors.CYAN}╰{sep_line}╯{Colors.RESET}")
    
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

    # (Helpers defined earlier are used here: _strip_ansi, display_len, pad_ansi)

    # Print Direct Table
    if direct_findings:
        print(f"\n{Colors.BOLD}📦 Direct Dependencies{Colors.RESET}")

        cols = [
            ('Category', 10), ('Package', 15), ('Version', 10), ('ID', 20),
            ('CVE', 15), ('Severity', 10), ('Fixed', 10), ('Summary', 30)
        ]

        # Compute widths based on header and data (use visible length for colored fields)
        widths = {name: max(len(name), min(max_len, 200)) for (name, max_len) in cols}
        for f in direct_findings:
            widths['Category'] = max(widths['Category'], display_len(f.get('category', '')))
            widths['Package'] = max(widths['Package'], display_len(f.get('package', '')))
            widths['Version'] = max(widths['Version'], display_len(f.get('version', '')))
            widths['ID'] = max(widths['ID'], display_len(f.get('id', '')))
            widths['CVE'] = max(widths['CVE'], display_len(f.get('cve', '')))
            # Severity will include ANSI codes
            sev_disp = colorize_severity(str(f.get('severity', '')), f.get('rating', 'N/A'))
            widths['Severity'] = max(widths['Severity'], display_len(sev_disp))
            widths['Fixed'] = max(widths['Fixed'], display_len(f.get('fixed', '')))
            summ = f.get('summary', '')
            if display_len(summ) > widths['Summary']:
                widths['Summary'] = min(display_len(summ), 200)

        # Build header and separators based on display length (use same pad_ansi as rows)
        header_parts = [pad_ansi(name, widths[name]) for name, _ in cols]
        header = ' | '.join(header_parts)
        # Separator width equals sum of column widths plus separator chars between columns
        total_width = sum(widths[name] for name, _ in cols) + 3 * (len(cols) - 1)

        # Compute the actual displayed width of header and rows to catch any discrepancies
        header_display = sum(display_len(part) for part in header_parts) + 3 * (len(cols) - 1)

        # compute max display width among data rows (using current widths)
        max_row_display = 0
        for f in direct_findings:
            sev_display = colorize_severity(str(f.get('severity', '')), f.get('rating', 'N/A'))
            # Use display-aware truncation for summary when measuring
            summ_meas = truncate_display(f.get('summary', ''), widths['Summary'])
            row_parts = [
                pad_ansi(f.get('category', ''), widths['Category']),
                pad_ansi(f.get('package', ''), widths['Package']),
                pad_ansi(f.get('version', ''), widths['Version']),
                pad_ansi(f.get('id', ''), widths['ID']),
                pad_ansi(f.get('cve', ''), widths['CVE']),
                pad_ansi(sev_display, widths['Severity']),
                pad_ansi(f.get('fixed', ''), widths['Fixed']),
                pad_ansi(summ_meas, widths['Summary'])
            ]
            max_row_display = max(max_row_display, sum(display_len(p) for p in row_parts) + 3 * (len(row_parts) - 1))

        # If any row or header is wider than our computed total_width, expand the last column to match
        needed = max(header_display, max_row_display) - total_width
        if needed > 0:
            last_col = cols[-1][0]
            widths[last_col] = widths.get(last_col, 0) + needed
            total_width = sum(widths[name] for name, _ in cols) + 3 * (len(cols) - 1)
        # Add a small safety padding on the right to avoid terminal/font-specific clipping
        extra_right_pad = 2
        last_col = cols[-1][0]
        widths[last_col] = widths.get(last_col, 0) + extra_right_pad
        total_width = sum(widths[name] for name, _ in cols) + 3 * (len(cols) - 1)

        sep = '─' * total_width

        print(f"{Colors.CYAN}{sep}{Colors.RESET}")
        print(header)
        print(f"{Colors.CYAN}{sep}{Colors.RESET}")

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

            if display_len(summ) > widths['Summary']:
                # Truncate to display width using display-aware truncation, then add ellipsis
                summ = truncate_display(summ, max(1, widths['Summary'] - 3)) + '...'

            sev_display = colorize_severity(str(sev), rating)

            row_parts = [
                pad_ansi(cat, widths['Category']),
                pad_ansi(pkg, widths['Package']),
                pad_ansi(ver, widths['Version']),
                pad_ansi(vid, widths['ID']),
                pad_ansi(cve, widths['CVE']),
                pad_ansi(sev_display, widths['Severity']),
                pad_ansi(fixed, widths['Fixed']),
                pad_ansi(summ, widths['Summary'])
            ]

            print(' | '.join(row_parts))
        print(f"{Colors.CYAN}{sep}{Colors.RESET}")

    # Print Bundled Table
    if bundled_findings:
        print(f"\n{Colors.BOLD}📚 Bundled Dependencies{Colors.RESET}")

        cols_b = [
            ('Parent', 15), ('Package', 15), ('Version', 10), ('ID', 20),
            ('CVE', 15), ('Severity', 10), ('Fixed', 10), ('Update via', 20)
        ]

        widths_b = {name: max(len(name), min(max_len, 200)) for (name, max_len) in cols_b}
        for f in bundled_findings:
            path = f.get('path', [])
            parent = path[0] if path else 'Unknown'
            widths_b['Parent'] = max(widths_b['Parent'], display_len(parent))
            widths_b['Package'] = max(widths_b['Package'], display_len(f.get('package', '')))
            widths_b['Version'] = max(widths_b['Version'], display_len(f.get('version', '')))
            widths_b['ID'] = max(widths_b['ID'], display_len(f.get('id', '')))
            widths_b['CVE'] = max(widths_b['CVE'], display_len(f.get('cve', '')))
            sev_disp = colorize_severity(str(f.get('severity', '')), f.get('rating', 'N/A'))
            widths_b['Severity'] = max(widths_b['Severity'], display_len(sev_disp))
            widths_b['Fixed'] = max(widths_b['Fixed'], display_len(f.get('fixed', '')))
            update_via = f"npm update {parent}"
            widths_b['Update via'] = max(widths_b['Update via'], display_len(update_via))

        header_parts_b = [pad_ansi(name, widths_b[name]) for name, _ in cols_b]
        header_b = ' | '.join(header_parts_b)
        total_width_b = sum(widths_b[name] for name, _ in cols_b) + 3 * (len(cols_b) - 1)

        header_b_display = sum(display_len(part) for part in header_parts_b) + 3 * (len(cols_b) - 1)
        max_row_display_b = 0
        for f in bundled_findings:
            parent = f.get('path', ["Unknown"])[0] if f.get('path') else 'Unknown'
            sev_display = colorize_severity(str(f.get('severity', '')), f.get('rating', 'N/A'))
            # Use display-aware truncation for any text measurements
            update_via = f"npm update {parent}"
            row_parts_b = [
                pad_ansi(parent, widths_b['Parent']),
                pad_ansi(f.get('package', ''), widths_b['Package']),
                pad_ansi(f.get('version', ''), widths_b['Version']),
                pad_ansi(f.get('id', ''), widths_b['ID']),
                pad_ansi(f.get('cve', ''), widths_b['CVE']),
                pad_ansi(sev_display, widths_b['Severity']),
                pad_ansi(f.get('fixed', ''), widths_b['Fixed']),
                pad_ansi(update_via, widths_b['Update via'])
            ]
            max_row_display_b = max(max_row_display_b, sum(display_len(p) for p in row_parts_b) + 3 * (len(row_parts_b) - 1))

        needed_b = max(header_b_display, max_row_display_b) - total_width_b
        if needed_b > 0:
            last_col_b = cols_b[-1][0]
            widths_b[last_col_b] = widths_b.get(last_col_b, 0) + needed_b
            total_width_b = sum(widths_b[name] for name, _ in cols_b) + 3 * (len(cols_b) - 1)
        # small safety padding on right side for bundled table as well
        extra_right_pad_b = 2
        last_col_b = cols_b[-1][0]
        widths_b[last_col_b] = widths_b.get(last_col_b, 0) + extra_right_pad_b
        total_width_b = sum(widths_b[name] for name, _ in cols_b) + 3 * (len(cols_b) - 1)

        sep_b = '─' * total_width_b

        print(f"{Colors.CYAN}{sep_b}{Colors.RESET}")
        print(header_b)
        print(f"{Colors.CYAN}{sep_b}{Colors.RESET}")

        for f in bundled_findings:
            path = f.get('path', [])
            parent = path[0] if path else 'Unknown'
            pkg = f['package']
            ver = f['version']
            vid = f['id']
            cve = f['cve']
            sev = f['severity']
            rating = f.get('rating', 'N/A')
            fixed = f['fixed']

            sev_display = colorize_severity(str(sev), rating)
            update_via = f"npm update {parent}"

            row_parts = [
                pad_ansi(parent, widths_b['Parent']),
                pad_ansi(pkg, widths_b['Package']),
                pad_ansi(ver, widths_b['Version']),
                pad_ansi(vid, widths_b['ID']),
                pad_ansi(cve, widths_b['CVE']),
                pad_ansi(sev_display, widths_b['Severity']),
                pad_ansi(fixed, widths_b['Fixed']),
                pad_ansi(update_via, widths_b['Update via'])
            ]

            print(' | '.join(row_parts))
        print(f"{Colors.CYAN}{sep_b}{Colors.RESET}")

    # Final summary with vibes
    print(f"\n{Colors.BOLD}📈 Final Stats:{Colors.RESET} {len(findings)} issues ({len(direct_findings)} direct, {len(bundled_findings)} bundled)")
    
    if critical_count > 0:
        print(f"{Colors.CRITICAL}💀 {critical_count} CRITICAL issue{'s' if critical_count > 1 else ''} require{'s' if critical_count == 1 else ''} immediate attention!{Colors.RESET}")
    
    print_severity_legend()
