"""CVSS score calculation and severity rating."""

import math


def calculate_cvss_v3_score(vector):
    """Calculate CVSS v3.1 score from vector string."""
    try:
        if not vector.startswith("CVSS:3"):
            return "N/A"
        
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

        if any(v is None for v in [av, ac, pr, ui, c, i, a]):
            return "N/A"

        iss = 1 - ((1-c)*(1-i)*(1-a))
        
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
                
        base_score = math.ceil(base_score * 10) / 10.0
        return str(base_score)
        
    except Exception:
        return "N/A"


def calculate_cvss_v2_score(vector):
    """Calculate CVSS v2 score from vector string."""
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
        
        if any(v is None for v in [av, ac, au, c, i, a]):
            return "N/A"

        impact = 10.41 * (1 - (1-c)*(1-i)*(1-a))
        exploitability = 20 * av * ac * au
        f_impact = 0 if impact == 0 else 1.176
        base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
        
        return f"{base_score:.1f}"
    except Exception:
        return "N/A"


def get_severity_rating(score_str, vector):
    """Get severity rating (LOW/MEDIUM/HIGH/CRITICAL) from score."""
    try:
        score = float(score_str)
    except ValueError:
        return "UNKNOWN"

    if vector.startswith("CVSS:3"):
        # CVSS v3.x Rating
        if 0.1 <= score <= 3.9:
            return "LOW"
        if 4.0 <= score <= 6.9:
            return "MEDIUM"
        if 7.0 <= score <= 8.9:
            return "HIGH"
        if 9.0 <= score <= 10.0:
            return "CRITICAL"
    else:
        # CVSS v2.0 Rating
        if 0.0 <= score <= 3.9:
            return "LOW"
        if 4.0 <= score <= 6.9:
            return "MEDIUM"
        if 7.0 <= score <= 10.0:
            return "HIGH"
    
    return "UNKNOWN"


def get_severity_priority(rating):
    """Returns numeric priority for sorting (lower = more severe)."""
    priority_map = {
        'CRITICAL': 0,
        'HIGH': 1,
        'MEDIUM': 2,
        'LOW': 3,
        'UNKNOWN': 4,
        'N/A': 5
    }
    return priority_map.get(rating, 6)

def get_attack_vector(vector):
    """
    Extracts the Attack Vector (AV) from a CVSS string.
    Returns: 'NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL', or 'UNKNOWN'
    """
    if not vector:
        return "UNKNOWN"
        
    # Handle CVSS v3 (e.g., CVSS:3.1/AV:N/...)
    if vector.startswith("CVSS:3"):
        if "/AV:N" in vector: return "NETWORK"
        if "/AV:A" in vector: return "ADJACENT"
        if "/AV:L" in vector: return "LOCAL"
        if "/AV:P" in vector: return "PHYSICAL"
        
    # Handle CVSS v2 (e.g., AV:N/AC:L/...)
    else:
        if "AV:N" in vector: return "NETWORK"
        if "AV:A" in vector: return "ADJACENT"
        if "AV:L" in vector: return "LOCAL"
    
    return "UNKNOWN"