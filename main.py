"""
KarmaWall entry point. Run this as Administrator (WinDivert requires elevated
privileges to open a packet-interception handle).

    python main.py

Ctrl+C to stop. When it stops, WinDivert releases its hold and your
machine's normal networking resumes immediately — nothing is left
half-blocked.
"""

import sys
import signal

try:
    import pydivert
except ImportError:
    print("Missing dependency. Install with:  pip install pydivert")
    sys.exit(1)

import config
from rules import RuleEngine
from logger import setup_logger

running = True


def handle_sigint(sig, frame):
    global running
    running = False


def main():
    if sys.platform != "win32":
        print("This firewall uses WinDivert and only runs on Windows.")
        sys.exit(1)

    log = setup_logger(config.LOG_FILE)
    engine = RuleEngine(config.RULES_FILE, default_policy=config.DEFAULT_POLICY)

    log.info("Starting KarmaWall. Default policy = %s", config.DEFAULT_POLICY)
    log.info("Loaded %d rule(s) from %s", len(engine.rules), config.RULES_FILE)
    for r in engine.rules:
        log.info("  %s", r)

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        w = pydivert.WinDivert(config.WINDIVERT_FILTER, priority=config.PRIORITY)
    except OSError as e:
        log.error("Failed to open WinDivert handle: %s", e)
        log.error("Make sure you're running as Administrator.")
        sys.exit(1)

    with w:
        log.info("KarmaWall active. Press Ctrl+C to stop.")
        while running:
            try:
                packet = w.recv()
            except OSError:
                # Handle closed (e.g. during shutdown) — exit cleanly.
                break

            proto = "tcp" if packet.tcp else ("udp" if packet.udp else "other")
            dst_ip = packet.dst_addr
            dst_port = packet.dst_port if (packet.tcp or packet.udp) else None

            action, matched_rule = engine.decide(dst_ip, dst_port, proto)

            if action == "block":
                reason = matched_rule.note if matched_rule else "default policy"
                log.warning(
                    "BLOCKED  %s -> %s:%s [%s]  (%s)",
                    packet.src_addr, dst_ip, dst_port, proto, reason,
                )
                # Drop it: simply don't call w.send(), so the packet
                # never leaves the machine.
                continue

            # Allowed — re-inject the packet so it actually goes out.
            log.info(
                "ALLOWED  %s -> %s:%s [%s]",
                packet.src_addr, dst_ip, dst_port, proto,
            )
            w.send(packet)

    log.info("KarmaWall stopped. Normal networking resumed.")


if __name__ == "__main__":
    main()
