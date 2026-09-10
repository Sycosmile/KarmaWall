# KarmaWall

**A lightweight, rule-based network firewall for controlling outbound traffic.**

KarmaWall is a Windows firewall built on WinDivert. Its default policy is
**block**, with an allow/block rule set controlled through `rules.json`.
Every packet decision is logged to `karmawall.log` and the console.

> **Use responsibly.** KarmaWall can intercept and drop outbound traffic on
the machine where it runs. Test it in a VM first and only use it on systems
and networks you are authorized to control.

## Why WinDivert

Windows does not provide a simple user-mode API for arbitrary packet
interception and dropping. WinDivert supplies the packet interception layer;
KarmaWall owns the policy, rule matching, logging, and decision logic.

## Requirements

- Windows
- Python 3.11 or newer
- Administrator privileges
- WinDivert runtime/driver support supplied through `pydivert`

## Setup

```powershell
python -m pip install -r requirements.txt
```

`requirements.txt` pins the Python dependency used for packet interception.
If WinDivert cannot load on your system, follow the WinDivert installation
guidance for your environment.

## Running

KarmaWall must run as **Administrator** because WinDivert requires elevated
privileges for packet interception.

Normal enforcement mode:

```powershell
python main.py
```

Dry-run mode records what the firewall **would** block without enforcing the
block decision:

```powershell
python main.py --dry-run
```

Use dry-run mode first when validating a new ruleset. Ctrl+C requests a clean
shutdown and the WinDivert handle is closed.

## Rule configuration

Rules live in `rules.json` and are checked **top to bottom**. The first
matching rule wins. Any field other than `id` and `action` may be omitted and
is treated as a wildcard.

Each rule requires:

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Unique audit identifier, 1-64 characters using letters, digits, `.`, `_`, or `-` |
| `action` | Yes | `allow` or `block` |
| `ip` | No | Exact IPv4/IPv6 address or CIDR network |
| `port` | No | Destination port from 1 to 65535 |
| `proto` | No | `tcp` or `udp` |
| `note` | No | Human-readable explanation for the rule |

Rule IDs must be unique within the file. Invalid fields, malformed values,
duplicate IDs, and malformed JSON are rejected before the rules are loaded.

### Example

```json
[
    {
        "id": "allow-google-dns",
        "action": "allow",
        "ip": "8.8.8.8",
        "port": 53,
        "proto": "udp",
        "note": "Allow DNS queries to the documented sample resolver"
    },
    {
        "id": "allow-example-https",
        "action": "allow",
        "ip": "93.184.216.34",
        "port": 443,
        "proto": "tcp",
        "note": "Allow HTTPS to example.com over TCP/443"
    },
    {
        "id": "block-example-other",
        "action": "block",
        "ip": "93.184.216.34",
        "note": "Block other outbound traffic to example.com"
    }
]
```

CIDR networks are supported for range-based policies. For example:

```json
{
    "id": "block-private-subnet",
    "action": "block",
    "ip": "192.168.1.0/24",
    "note": "Block outbound traffic to this private subnet"
}
```

With `DEFAULT_POLICY = "block"` in `config.py`, traffic that matches no
rule is blocked.

## Logging

KarmaWall writes structured audit messages to both the console and
`karmawall.log`. The file logger rotates at 5 MiB and keeps three backups so
long-running sessions do not grow a single log file indefinitely.

Each decision includes the matched rule ID when a rule is responsible for the
outcome, making the log easier to correlate with the active policy.

## Project structure

| File | Purpose |
|---|---|
| `main.py` | Packet interception loop and enforcement/dry-run mode |
| `config.py` | Default policy, WinDivert filter, and project-relative paths |
| `rules.py` | Rule validation, loading, CIDR matching, and decisions |
| `rules.json` | Active firewall policy |
| `packet.py` | Packet metadata extraction independent of the rule engine |
| `logger.py` | Console and rotating audit logging |
| `tests/` | Unit tests for rule, packet, logger, and CLI behaviour |
| `.github/workflows/ci.yml` | Automated Windows test workflow |

## Testing

Run the test suite with:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

GitHub Actions runs the same test suite on Windows for pushes to `main` and
hardening branches and for pull requests targeting `main`.

## Extending it

- **Persist as a service:** wrap `main()` with a Windows service framework so
  KarmaWall can start automatically.
- **Inbound filtering:** broaden `WINDIVERT_FILTER` and incorporate packet
  direction into the policy engine.
- **Live reload:** call `engine.reload()` from a controlled file-watch or
  timer so policy changes can be applied without restarting the process.
- **Richer policy matching:** add additional validated fields only when they
  can be enforced and covered by tests.
