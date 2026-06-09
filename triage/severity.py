"""Severity Classifier — CVSS 3.1 scoring"""

SEVERITY_RULES = {
    "critical": ["remote code execution", "rce", "sandbox escape", "vm escape",
                  "container escape", "authentication bypass", "unauthenticated"],
    "high": ["local privilege escalation", "heap buffer overflow", "stack buffer overflow",
             "use-after-free", "double-free", "format string", "arbitrary write",
             "control flow hijack", "rop chain", "command injection"],
    "medium": ["denial of service", "dos", "crash", "information leak", "info leak",
               "out-of-bounds read", "null pointer dereference", "race condition",
               "integer overflow", "type confusion"],
    "low": ["minor disclosure", "best practice", "weak cryptography", "insecure default"],
}


class SeverityClassifier:
    def classify(self, finding: dict) -> dict:
        combined = f"{finding.get('impact', '')} {finding.get('bug_type', '')} {finding.get('trigger', '')}".lower()
        level = "medium"
        for sev, keywords in SEVERITY_RULES.items():
            if any(kw in combined for kw in keywords):
                level = sev
                break

        cvss_vector = self._cvss_vector(finding, level)
        cvss_score = self._cvss_score(cvss_vector)
        return {"level": level, "cvss": cvss_score, "cvss_vector": cvss_vector}

    def _cvss_vector(self, finding: dict, severity: str) -> str:
        trigger = finding.get("trigger", "").lower()
        impact = finding.get("impact", "").lower()
        av = "L" if any(w in trigger for w in ["local", "file", "cli"]) else "N"
        ac = "H" if any(w in trigger for w in ["race", "specific", "complex"]) else "L"
        pr = "H" if any(w in trigger for w in ["admin", "root"]) else ("L" if any(w in trigger for w in ["user", "login"]) else "N")
        ui = "R" if any(w in trigger for w in ["click", "open", "visit"]) else "N"
        s = "C" if any(w in impact for w in ["sandbox escape", "vm escape"]) else "U"
        impact_map = {"critical": ("H", "H", "H"), "high": ("H", "H", "L"),
                      "medium": ("L", "L", "L"), "low": ("L", "N", "N")}
        c, i, a = impact_map.get(severity, ("L", "L", "L"))
        if "info leak" in impact:
            c = "L"
        if "code execution" in impact:
            i, c = "H", "H"
        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    def _cvss_score(self, vector: str) -> float:
        parts = {}
        for comp in vector.split("/")[1:]:
            k, v = comp.split(":")
            parts[k] = v
        imp_map = {"N": 0, "L": 0.22, "H": 0.56}
        iss = 1 - ((1 - imp_map.get(parts.get("C", "N"), 0)) *
                    (1 - imp_map.get(parts.get("I", "N"), 0)) *
                    (1 - imp_map.get(parts.get("A", "N"), 0)))
        impact = 6.42 * iss if parts.get("S") == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        av_s = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_s = {"L": 0.77, "H": 0.44}
        pr_s = {"N": 0.85, "L": 0.62, "H": 0.27}
        ui_s = {"N": 0.85, "R": 0.62}
        exploit = 8.22 * av_s.get(parts.get("AV"), 0.85) * ac_s.get(parts.get("AC"), 0.77) * \
                  pr_s.get(parts.get("PR"), 0.85) * ui_s.get(parts.get("UI"), 0.85)
        if impact <= 0:
            return 0.0
        score = min(impact + exploit, 10) if parts.get("S") == "U" else min(1.08 * (impact + exploit), 10)
        return round(score, 1)
