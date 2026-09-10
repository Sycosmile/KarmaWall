"""
Rule engine for KarmaWall.

A rule looks like:

    {
        "action": "allow" | "block",
        "ip": "93.184.216.34",       # optional, exact match
        "port": 443,                  # optional, exact match on dst port
        "proto": "tcp",              # optional: tcp / udp
        "note": "Example HTTPS rule"
    }

Any field left out of a rule is treated as a wildcard. Rules are checked
in order; the first match wins. If nothing matches, the DEFAULT_POLICY
from config.py decides the outcome.

Rule files are validated before they are loaded so a malformed or
unsupported rule fails closed with a useful configuration error instead
of causing unpredictable firewall behaviour.
"""

import ipaddress
import json
import os


VALID_ACTIONS = {"allow", "block"}
VALID_PROTOCOLS = {"tcp", "udp"}
VALID_FIELDS = {"action", "ip", "port", "proto", "note"}
MIN_PORT = 1
MAX_PORT = 65535


class RuleValidationError(ValueError):
    """Raised when a rule or rule file contains invalid configuration."""


class Rule:
    def __init__(self, action, ip=None, port=None, proto=None, note=""):
        self.action = self._validate_action(action)
        self.ip = self._validate_ip(ip)
        self.port = self._validate_port(port)
        self.proto = self._validate_protocol(proto)
        self.note = self._validate_note(note)

    @staticmethod
    def _validate_action(action):
        if not isinstance(action, str):
            raise RuleValidationError("Rule action must be a string")

        action = action.strip().lower()
        if action not in VALID_ACTIONS:
            valid = ", ".join(sorted(VALID_ACTIONS))
            raise RuleValidationError(
                f"Invalid rule action {action!r}; expected one of: {valid}"
            )
        return action

    @staticmethod
    def _validate_ip(ip):
        if ip is None:
            return None
        if not isinstance(ip, str) or not ip.strip():
            raise RuleValidationError("Rule IP must be a non-empty string")

        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise RuleValidationError(f"Invalid IP address: {ip!r}") from exc
        return ip

    @staticmethod
    def _validate_port(port):
        if port is None:
            return None
        if isinstance(port, bool) or not isinstance(port, int):
            raise RuleValidationError("Rule port must be an integer from 1 to 65535")
        if not MIN_PORT <= port <= MAX_PORT:
            raise RuleValidationError(
                f"Rule port must be between {MIN_PORT} and {MAX_PORT}, got {port}"
            )
        return port

    @staticmethod
    def _validate_protocol(proto):
        if proto is None:
            return None
        if not isinstance(proto, str):
            raise RuleValidationError("Rule protocol must be a string")

        proto = proto.strip().lower()
        if proto not in VALID_PROTOCOLS:
            valid = ", ".join(sorted(VALID_PROTOCOLS))
            raise RuleValidationError(
                f"Invalid rule protocol {proto!r}; expected one of: {valid}"
            )
        return proto

    @staticmethod
    def _validate_note(note):
        if note is None:
            return ""
        if not isinstance(note, str):
            raise RuleValidationError("Rule note must be a string")
        return note.strip()

    @classmethod
    def from_dict(cls, data, index=None):
        """Validate and construct a Rule from one JSON object."""
        location = f" at index {index}" if index is not None else ""

        if not isinstance(data, dict):
            raise RuleValidationError(f"Rule{location} must be a JSON object")

        unknown = set(data) - VALID_FIELDS
        if unknown:
            fields = ", ".join(sorted(unknown))
            raise RuleValidationError(f"Unknown rule field(s){location}: {fields}")

        if "action" not in data:
            raise RuleValidationError(f"Rule{location} is missing required field: action")

        try:
            return cls(**data)
        except TypeError as exc:
            raise RuleValidationError(f"Invalid rule structure{location}: {exc}") from exc
        except RuleValidationError as exc:
            raise RuleValidationError(f"Invalid rule{location}: {exc}") from exc

    def matches(self, dst_ip, dst_port, proto):
        if self.ip is not None and self.ip != dst_ip:
            return False
        if self.port is not None and self.port != dst_port:
            return False
        if self.proto is not None and self.proto != proto.lower():
            return False
        return True

    def __repr__(self):
        return (
            f"<Rule {self.action} ip={self.ip} port={self.port} "
            f"proto={self.proto} note={self.note!r}>"
        )


class RuleEngine:
    def __init__(self, rules_path, default_policy="block"):
        if not isinstance(default_policy, str):
            raise RuleValidationError("Default policy must be a string")

        default_policy = default_policy.strip().lower()
        if default_policy not in VALID_ACTIONS:
            valid = ", ".join(sorted(VALID_ACTIONS))
            raise RuleValidationError(
                f"Invalid default policy {default_policy!r}; expected one of: {valid}"
            )

        self.default_policy = default_policy
        self.rules = []
        self.rules_path = rules_path
        self.load()

    def load(self):
        """Load and validate the complete rule file."""
        if not os.path.exists(self.rules_path):
            self.rules = []
            return

        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise RuleValidationError(
                f"Invalid JSON in rules file {self.rules_path}: "
                f"line {exc.lineno}, column {exc.colno}: {exc.msg}"
            ) from exc
        except OSError as exc:
            raise RuleValidationError(
                f"Unable to read rules file {self.rules_path}: {exc}"
            ) from exc

        if not isinstance(data, list):
            raise RuleValidationError("Rules file must contain a JSON array")

        validated_rules = []
        for index, rule_data in enumerate(data):
            validated_rules.append(Rule.from_dict(rule_data, index=index))

        self.rules = validated_rules

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
