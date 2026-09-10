"""
KarmaWall entry point. Run this as Administrator (WinDivert requires elevated
privileges to open a packet-interception handle).

    python main.py

Ctrl+C to stop. When it stops, WinDivert releases its hold and your
machine's normal networking resumes immediately — nothing is left
half-blocked.
"""

import signal
import sys

try:
    import pydivert
except ImportError:
    print("Missing dependency. Install with:  pip install pydivert")
    sys.exit(1)

import config
from logger import setup_logger
from packet import extract_metadata
from rules import RuleEngine, RuleValidationError

running = True


def handle_sigint(sig, frame):
    """Request a clean shutdown from Ctrl+C."""
    global running
    running = False


def main():
    global running
    running = True

    if sys.platform != "win32":
        print("This firewall uses WinDivert and only runs on Windows.")
        return 1

    log = setup_logger(config.LOG_FILE)

    try:
        engine = RuleEngine(
            config.RULES_FILE,
            default_policy=config.DEFAULT_POLICY,
        )
    except RuleValidationError as exc:
        log.error("Invalid firewall configuration: %s", exc)
        return 1

    log.info("Starting KarmaWall. Default policy = %s", config.DEFAULT_POLICY)
    log.info("Loaded %d rule(s) from %s", len(engine.rules), config.RULES_FILE)
    for rule in engine.rules:
        log.info("  %s", rule)

    signal.signal(signal.SIGINT, handle_sigint)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_sigint)

    try:
        divert = pydivert.WinDivert(
            str(config.WINDIVERT_FILTER),
            priority=config.PRIORITY,
        )
    except OSError as exc:
        log.error("Failed to open WinDivert handle: %s", exc)
        log.error("Make sure WinDivert is installed and you're running as Administrator.")
        return 1

    try:
        with divert:
            log.info("KarmaWall active. Press Ctrl+C to stop.")

            while running:
                try:
                    packet = divert.recv()
                except OSError as exc:
                    if running:
                        log.error("WinDivert receive error: %s", exc)
                        return 1
                    break

                try:
                    metadata = extract_metadata(packet)
                    action, matched_rule = engine.decide(
                        metadata.destination_ip,
                        metadata.destination_port,
                        metadata.protocol,
                    )

                    if action == "block":
                        reason = matched_rule.note if matched_rule else "default policy"
                        log.warning(
                            "BLOCKED  %s -> %s:%s [%s]  (%s)",
                            metadata.source_ip,
                            metadata.destination_ip,
                            metadata.destination_port,
                            metadata.protocol,
                            reason,
                        )
                        # Drop it: simply don't call divert.send().
                        continue

                    log.info(
                        "ALLOWED  %s -> %s:%s [%s]",
                        metadata.source_ip,
                        metadata.destination_ip,
                        metadata.destination_port,
                        metadata.protocol,
                    )

                    try:
                        divert.send(packet)
                    except OSError as exc:
                        log.error(
                            "Failed to reinject allowed packet to %s:%s: %s",
                            metadata.destination_ip,
                            metadata.destination_port,
                            exc,
                        )
                        return 1
                except (AttributeError, ValueError, TypeError) as exc:
                    log.error("Failed to process intercepted packet: %s", exc)
                    continue
    except OSError as exc:
        log.error("WinDivert runtime error: %s", exc)
        return 1
    finally:
        log.info("KarmaWall stopped. Normal networking resumed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
