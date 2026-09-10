"""
Central configuration for KarmaWall.

DEFAULT_POLICY:
    "block" -> everything is blocked unless a rule explicitly allows it.
    "allow" -> everything is allowed unless a rule explicitly blocks it.

Start with "block" when you want a tight, allow-list-only sandbox
(e.g. while probing a suspicious host and you want nothing else to
leave your machine). Switch to "allow" for a normal day-to-day
firewall that just blocks specific known-bad hosts.
"""

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

DEFAULT_POLICY = "block"

# WinDivert filter string: which traffic even reaches our packet loop.
# "outbound and ip" = all outbound IPv4 traffic. You can narrow this,
# e.g. "outbound and tcp" to only look at TCP.
WINDIVERT_FILTER = "outbound and ip"

# Resolve project files relative to this module instead of the process'
# current working directory. This keeps behaviour consistent regardless
# of where `python main.py` is launched from.
RULES_FILE = BASE_DIR / "rules.json"
LOG_FILE = BASE_DIR / "karmawall.log"

# WinDivert priority — lower runs first. 0 is fine unless you're
# layering multiple WinDivert handles.
PRIORITY = 0
