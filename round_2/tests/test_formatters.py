import io
import sys
from lib.formatters import print_summary, _strip_ansi, display_len


def capture_print(fn, *args, **kwargs):
    buf = io.StringIO()
    old_stdout = sys.stdout
    try:
        sys.stdout = buf
        fn(*args, **kwargs)
        return buf.getvalue()
    finally:
        sys.stdout = old_stdout


def test_print_summary_alignment():
    # deterministic small findings sample
    findings = [
        {
            'package': 'left-pad',
            'version': '1.3.0',
            'id': 'VULN-1',
            'cve': 'CVE-0001',
            'severity': '9.8',
            'fixed': '1.3.1',
            'summary': 'Example critical vuln',
            'path': [],
        },
        {
            'package': 'emoji-pkg',
            'version': '0.1.0',
            'id': 'VULN-2',
            'cve': 'CVE-0002',
            'severity': '5.0',
            'fixed': '0.1.1',
            'summary': 'Medium issue with emoji 🔥',
            'path': ['parent']
        }
    ]

    out = capture_print(print_summary, findings)

    # Find the first header separator line (box top for Direct Dependencies)
    lines = out.splitlines()
    # Ensure there is at least one separator line and header present
    assert any('Direct Dependencies' in l for l in lines)

    # Check that header separator length matches header visible length for direct table
    for i, line in enumerate(lines):
        if 'Package' in line and 'Version' in line and 'Severity' in line:
            header_line = line
            sep_line = lines[i-1]
            break
    else:
        raise AssertionError('Header line not found in output')

    # visible lengths should match
    assert len(_strip_ansi(sep_line)) == display_len(header_line)
