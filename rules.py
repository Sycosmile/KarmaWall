"""
Rule engine.

A rule looks like:

    {
        "action": "allow" | "block",
        "ip": "93.184.216.34",       # optional, exact match
        "port": 443,                 # optional, exact match on dst port
        "proto": "tcp",              # optional: tcp / udp
        "note": "LLS host - probing window"
    }

Any field left out of a rule is treated as a wildcard. Rules are
checked in order; the first match wins. If nothing matches, the
DEFAULT_POLICY from config.py decides the outcome.
"""

import json
import os


class Rule:
    def __init__(self, action, ip=None, port=None, proto=None, note=""):
        self.action = action.lower()          # "allow" / "block"
        self.ip = ip
        self.port = port
        self.proto = proto.lower() if proto else None
        self.note = note

    def matches(self, dst_ip, dst_port, proto):
        if self.ip is not None and self.ip != dst_ip:
            return False
        if self.port is not None and self.port != dst_port:
            return False
        if self.proto is not None and self.proto != proto:
            return False
        return True

    def __repr__(self):
        return f"<Rule {self.action} ip={self.ip} port={self.port} proto={self.proto} note={self.note!r}>"


class RuleEngine:
    def __init__(self, rules_path, default_policy="block"):
        self.default_policy = default_policy.lower()
        self.rules = []
        self.rules_path = rules_path
        self.load()

    def load(self):
        if not os.path.exists(self.rules_path):
            self.rules = []
            return
        with open(self.rules_path, "r") as f:
            data = json.load(f)
        self.rules = [Rule(**r) for r in data]

    def reload(self):
        """Call this to pick up edits to rules.json without restarting."""
        self.load()

    def decide(self, dst_ip, dst_port, proto):
        """
        Returns (action, matched_rule_or_None).
        action is "allow" or "block".
        """
        for rule in self.rules:
            if rule.matches(dst_ip, dst_port, proto):
                return rule.action, rule
        return self.default_policy, None
