"""Perm — Security permissions auditor core."""

import os
import stat
import json
from typing import List, Dict
from collections import defaultdict


SENSITIVE_KEYWORDS = [
    "password", "secret", "key", "token", "credential", "cert", "pem",
    "p12", "pfx", "htpasswd", ".netrc", "id_rsa", "id_dsa", "id_ecdsa",
    "shadow", "passwd", "sudoers", "krb5", "keytab",
]


SKIP_DIRS = {".git", ".svn", "__pycache__", "node_modules", ".venv", ".eggs",
             "dist", "build", ".gradle", ".idea", ".vscode"}


def check_permissions(path: str) -> Dict:
    """Check file permissions and return findings."""
    try:
        st = os.stat(path)
        mode = st.st_mode
        perms = stat.filemode(mode)

        findings = {"path": path, "mode": perms, "is_suid": False, "is_sgid": False,
                    "world_readable": False, "world_writable": False, "sensitive": False}

        # Check SUID/SGID
        if mode & stat.S_ISUID:
            findings["is_suid"] = True
        if mode & stat.S_ISGID:
            findings["is_sgid"] = True

        # Check world permissions
        if mode & stat.S_IROTH:
            findings["world_readable"] = True
        if mode & stat.S_IWOTH:
            findings["world_writable"] = True

        # Check if filename matches sensitive patterns
        basename = os.path.basename(path).lower()
        for kw in SENSITIVE_KEYWORDS:
            if kw in basename:
                findings["sensitive"] = True
                findings["sensitive_match"] = kw
                break

        return findings
    except OSError:
        return None


def scan_path(root: str) -> Dict:
    """Scan a directory tree for permission issues."""
    results = {
        "suid": [],
        "sgid": [],
        "world_readable_sensitive": [],
        "world_writable": [],
        "total_files": 0,
        "errors": 0,
    }

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            results["total_files"] += 1
            info = check_permissions(path)
            if info is None:
                results["errors"] += 1
                continue

            if info["is_suid"]:
                results["suid"].append(info)
            if info["is_sgid"]:
                results["sgid"].append(info)
            if info["sensitive"] and info["world_readable"]:
                results["world_readable_sensitive"].append(info)
            if info["world_writable"]:
                results["world_writable"].append(info)

    return results


def find_suid_binaries(paths: List[str] = None) -> List[Dict]:
    """Find SUID binaries in common locations."""
    search_paths = paths or ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
    results = []
    for sp in search_paths:
        if not os.path.isdir(sp):
            continue
        for fn in os.listdir(sp):
            path = os.path.join(sp, fn)
            try:
                st = os.stat(path)
                if st.st_mode & stat.S_ISUID:
                    results.append({"path": path, "mode": stat.filemode(st.st_mode)})
            except OSError:
                pass
    return results


def format_findings(results: Dict) -> str:
    """Format permission findings."""
    lines = ["=" * 56, "  Security Permissions Audit", "=" * 56]
    lines.append(f"  Files scanned: {results['total_files']}")
    lines.append("")

    if results["suid"]:
        lines.append(f"  [HIGH] SUID binaries ({len(results['suid'])}):")
        for f in results["suid"][:20]:
            lines.append(f"    {f['mode']}  {f['path']}")

    if results["sgid"]:
        lines.append(f"  [HIGH] SGID files ({len(results['sgid'])}):")
        for f in results["sgid"][:10]:
            lines.append(f"    {f['mode']}  {f['path']}")

    if results["world_readable_sensitive"]:
        lines.append(f"  [HIGH] World-readable sensitive files ({len(results['world_readable_sensitive'])}):")
        for f in results["world_readable_sensitive"][:30]:
            lines.append(f"    {f['mode']}  {f['path']}  [{f.get('sensitive_match', '?')}]")

    if results["world_writable"]:
        lines.append(f"  [MEDIUM] World-writable files ({len(results['world_writable'])}):")
        for f in results["world_writable"][:20]:
            lines.append(f"    {f['mode']}  {f['path']}")

    if not any([results["suid"], results["sgid"], results["world_readable_sensitive"], results["world_writable"]]):
        lines.append("  No permission issues found.")

    return "\n".join(lines)


def generate_report(results: Dict, output_path: str) -> str:
    """Generate HTML permissions report."""
    total_issues = len(results["suid"]) + len(results["sgid"]) + len(results["world_readable_sensitive"]) + len(results["world_writable"])
    status = "PASSED" if total_issues == 0 else "ISSUES FOUND"
    color = "#22c55e" if total_issues == 0 else "#ef4444"

    def make_rows(items):
        return "".join(f"<tr><td>{f.get('mode','')}</td><td>{f['path']}</td><td>{f.get('sensitive_match','-')}</td></tr>\n" for f in items)

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Perm Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}}
h1{{font-size:1.8rem;margin-bottom:0.5rem}}
.meta{{color:#94a3b8}}
.status{{font-size:1.2rem;padding:0.75rem;border-radius:0.5rem;margin:1rem 0;text-align:center}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin:1.5rem 0}}
.stat{{background:#1e293b;padding:1rem;border-radius:0.75rem;text-align:center}}
.stat-value{{font-size:1.5rem;font-weight:700}}
.stat-label{{font-size:0.8rem;color:#94a3b8}}
.card{{background:#1e293b;border-radius:0.75rem;margin-bottom:1rem}}
.card-header{{background:#334155;padding:0.75rem 1rem;font-weight:600}}
.card-body{{padding:1rem}}
table{{width:100%;border-collapse:collapse;font-size:0.85rem}}
th{{text-align:left;padding:0.5rem;background:#1e293b;border-bottom:2px solid #334155}}
td{{padding:0.5rem;border-bottom:1px solid #334155}}
code{{color:#f87171}}
</style></head><body>
<h1>Security Permissions Report</h1>
<p class="meta">Perm — Security Auditor</p>
<div class="status" style="background:{color}20;border:2px solid {color};color:{color}">{status} ({total_issues} issues)</div>
<div class="grid">
<div class="stat"><div class="stat-value">{results['total_files']}</div><div class="stat-label">Files Scanned</div></div>
<div class="stat"><div class="stat-value">{len(results['suid'])}</div><div class="stat-label">SUID</div></div>
<div class="stat"><div class="stat-value">{len(results['sgid'])}</div><div class="stat-label">SGID</div></div>
<div class="stat"><div class="stat-value">{len(results['world_readable_sensitive'])}</div><div class="stat-label">Sensitive + World Readable</div></div>
<div class="stat"><div class="stat-value">{len(results['world_writable'])}</div><div class="stat-label">World Writable</div></div>
</div>
{'' if not results['suid'] else '<div class="card"><div class="card-header">SUID Binaries</div><div class="card-body"><table><thead><tr><th>Mode</th><th>Path</th></tr></thead><tbody>' + make_rows(results['suid']) + '</tbody></table></div></div>'}
{'' if not results['world_readable_sensitive'] else '<div class="card"><div class="card-header">World-Readable Sensitive Files</div><div class="card-body"><table><thead><tr><th>Mode</th><th>Path</th><th>Match</th></tr></thead><tbody>' + make_rows(results['world_readable_sensitive']) + '</tbody></table></div></div>'}
<p style="margin-top:2rem;color:#64748b;font-size:0.8rem;">Generated by Perm</p>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
