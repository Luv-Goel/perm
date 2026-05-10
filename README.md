# Perm ðŸ”

<div align="center">

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-lightgrey)]()

**Security permissions auditor â€” find SUID binaries, world-readable secrets, weak permissions. Zero dependencies.**

</div>

---

## Features

- **SUID/SGID detection** â€” Find all setuid/setgid binaries on the system
- **World-readable secrets** â€” Detect credentials, keys, and tokens with open permissions
- **Weak permission analysis** â€” Identify files and dirs with overly permissive modes
- **HTML reports** â€” Beautiful dark-mode reports with findings summary
- **Custom scan paths** â€” Target specific directories for focused audits
- **Zero dependencies** â€” Pure Python 3.8+, stdlib only

## Quick Start

```bash
pip install perm-auditor

# Full system scan
perm scan

# Scan specific directory
perm scan /etc /home

# Run security audit (SUID + secrets + weak perms)
perm audit

# Generate HTML report
perm report
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `perm scan [paths]` | Scan file permissions (default: system-wide) |
| `perm audit [paths]` | Security audit â€” SUID, secrets, weak perms |
| `perm report` | Generate comprehensive HTML report |

## Findings

Perm classifies findings into categories:

- ðŸ”´ **SUID Binaries** â€” Executables with setuid/setgid bits (potential privilege escalation)
- ðŸŸ¡ **World-Readable Secrets** â€” Private keys, configs with credentials accessible to all users
- ðŸŸ  **Weak Permissions** â€” World-writable files, open directories, permissive configs
- â„¹ï¸ **Info** â€” Permission overview and statistics

## Architecture

```
perm/
â”œâ”€â”€ perm/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ cli.py       # CLI entry point
â”‚   â””â”€â”€ core.py      # Permission scanning, analysis, report
â”œâ”€â”€ pyproject.toml
â””â”€â”€ README.md
```

## License

MIT â€” see [LICENSE](LICENSE).
