import os
import re
import json
import yaml

base_dir = "skills/privacy"
owasp_doc = "docs/privacy/owasp-privacy-risks-mapping.md"
nist_doc = "docs/privacy/nist-privacy-framework-mapping.md"
iso_doc = "docs/privacy/iso-27701-mapping.md"

owasp_map = {}
if os.path.isfile(owasp_doc):
    with open(owasp_doc, "r", encoding="utf-8") as f:
        curr_risk = None
        for line in f:
            m_header = re.search(r"###\s+(P\d+):", line)
            if m_header:
                curr_risk = m_header.group(1)
            elif curr_risk:
                m_skill = re.search(r"\|\s*`([^`]+)`\s*\|\s*(Primary|Secondary)\s*\|", line)
                if m_skill:
                    s_id = m_skill.group(1).strip()
                    role = m_skill.group(2).strip()
                    owasp_map.setdefault(s_id, []).append(f"{curr_risk}:{role}")

nist_map = {}
if os.path.isfile(nist_doc):
    with open(nist_doc, "r", encoding="utf-8") as f:
        curr_fn = None
        for line in f:
            m_cat = re.search(r"###\s+\d+\.\d+\s+([A-Z0-9\.\-]+):", line)
            if m_cat:
                curr_fn = m_cat.group(1).strip()
            elif curr_fn and "|" in line:
                for s in re.findall(r"`([a-zA-Z0-9\-]+)`", line):
                    if curr_fn not in nist_map.setdefault(s, []):
                        nist_map[s].append(curr_fn)

iso_map = {}
if os.path.isfile(iso_doc):
    with open(iso_doc, "r", encoding="utf-8") as f:
        curr_clause = None
        for line in f:
            m_cl = re.search(r"###\s+\d+\.\d+\s+([A-B0-9\.\-]+)", line)
            if m_cl:
                curr_clause = m_cl.group(1).strip()
            elif curr_clause and "|" in line:
                for s in re.findall(r"`([a-zA-Z0-9\-]+)`", line):
                    if curr_clause not in iso_map.setdefault(s, []):
                        iso_map[s].append(curr_clause)

reg_patterns = {
    "GDPR": re.compile(r"\bGDPR\b|General Data Protection Regulation", re.I),
    "CCPA": re.compile(r"\bCCPA\b|\bCPRA\b|California Consumer Privacy", re.I),
    "HIPAA": re.compile(r"\bHIPAA\b|\bHITECH\b|Health Insurance Portability", re.I),
    "EU_AI_ACT": re.compile(r"EU AI Act|Artificial Intelligence Act|Regulation \(EU\) 2024/1689", re.I),
    "LGPD": re.compile(r"\bLGPD\b|Lei Geral de Proteção", re.I),
    "PIPL": re.compile(r"\bPIPL\b|Personal Information Protection Law", re.I),
    "DPDP": re.compile(r"\bDPDP\b|Digital Personal Data Protection", re.I),
    "ePrivacy": re.compile(r"ePrivacy|cookie directive", re.I),
    "PIPEDA": re.compile(r"\bPIPEDA\b", re.I),
    "COPPA": re.compile(r"\bCOPPA\b|Children's Online Privacy Protection", re.I),
}

skills = []
for skill_dir in sorted(os.listdir(base_dir)):
    p = os.path.join(base_dir, skill_dir, "SKILL.md")
    if not os.path.isfile(p):
        continue
    with open(p, "r", encoding="utf-8") as f:
        text = f.read()

    meta = {}
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            try:
                meta = yaml.safe_load(parts[1]) or {}
            except Exception:
                pass

    name = meta.get("name", skill_dir)
    desc = meta.get("description", "")

    regs = [r for r, pat in reg_patterns.items() if pat.search(text)]
    if not regs:
        regs = ["GeneralPrivacy"]

    linddun = []
    if "linddun" in skill_dir.lower() or "linddun" in text.lower():
        for code, l_name in [("L", "Linkability"), ("I", "Identifiability"), ("N", "Non-repudiation"),
                             ("D_detect", "Detectability"), ("D_disclose", "Disclosure"),
                             ("U", "Unawareness"), ("N_comply", "Non-compliance")]:
            if l_name.lower() in text.lower():
                linddun.append(code)
        if not linddun:
            linddun.append("LINDDUN_GENERAL")

    has_script = os.path.isfile(os.path.join(base_dir, skill_dir, "scripts", "process.py"))
    has_template = os.path.isfile(os.path.join(base_dir, skill_dir, "assets", "template.md"))

    skills.append({
        "id": skill_dir,
        "name": name,
        "description": desc.strip(),
        "regulations": regs,
        "owasp_risks": owasp_map.get(skill_dir, []),
        "nist_categories": nist_map.get(skill_dir, []),
        "iso_clauses": iso_map.get(skill_dir, []),
        "linddun_threats": linddun,
        "has_script": has_script,
        "has_template": has_template,
        "path": f"skills/privacy/{skill_dir}"
    })

out_path = "src/deep/privacy_skills_data.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(skills, f, indent=2)

print(f"Wrote {len(skills)} skills to {out_path}")
