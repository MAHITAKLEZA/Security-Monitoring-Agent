"""AI Website Security & Auto-Remediation Agent for the Japanese keyword hack (Japanese SEO spam injection).

Phase 1  detect.py, wordpress.py, files.py   detection: crawl, WordPress content, files (optional AI triage, ai.py)
Phase 2  remediate.py, approvals.py           safe remediation: proposals, approval queue, backup, apply, verify, undo
Phase 3  defense.py, investigate.py           autonomous defense: integrity monitoring, reinfection detection,
                                              root-cause investigation, controlled automatic recovery
"""

__version__ = "1.0.0"
