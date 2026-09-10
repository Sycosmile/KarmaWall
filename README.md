# KarmaWall

A rule-based outbound firewall for Windows, built on WinDivert. Default
policy is **block everything**, with an allow-list you control in
`rules.json`. Every decision (allowed or blocked) is logged to
`karmawall.log` and the console.

> **Use responsibly.** This tool can intercept and drop all outbound
> traffic on the machine it runs on. Test it in a VM before running on
> a machine you rely on, and don't use it to bypass network policies
> you don't have authority over.

## Why WinDivert

Windows does not allow arbitrary raw-socket packet blocking in user
mode (Microsoft locked this down since XP SP2). Intercepting and
dropping packets before they leave the machine requires either a
signed kernel driver, or a WFP-based user-mode diversion layer —
which is what WinDivert provides. You still own 100% of the firewall
*logic* (rule matching, logging, policy) — WinDivert just supplies the
packet interception plumbing that Windows otherwise reserves for
kernel-mode code.

## Setup

```powershell
pip install -r requirements.txt
```

You also need the WinDivert driver DLL/sys files, which `pydivert`
downloads/bundles automatically on first import in most cases. If you
hit a driver-load error, grab the WinDivert binaries from
https://github.com/basil00/WinDivert and place `WinDivert.dll` /
`WinDivert64.sys` next to `main.py`.

## Running

Must run as **Administrator** — WinDivert requires elevated privileges
to open a packet-interception handle.

```powershell
python main.py
```

Ctrl+C stops it. Networking returns to normal immediately — nothing
stays half-blocked.

## Configuring rules

Edit `rules.json`. Each rule can match on `ip`, `port`, `proto`, or any
combination — omitted fields are wildcards. Rules are checked top to
bottom; first match wins. Anything that matches no rule falls through
to `DEFAULT_POLICY` in `config.py`.

Example — allow only HTTPS to one specific host, block everything
else:

```json
[
    { "action": "allow", "port": 53, "proto": "udp", "note": "DNS" },
    { "action": "allow", "ip": "93.184.216.34", "port": 443, "proto": "tcp" }
]
```

With `DEFAULT_POLICY = "block"` in `config.py`, anything not matching
one of those two rules is dropped and logged.

## Files

| File | Purpose |
|---|---|
| `main.py` | Packet loop — ties everything together, run this |
| `config.py` | Default policy, WinDivert filter, file paths |
| `rules.py` | Rule engine — loads and matches `rules.json` |
| `rules.json` | Your actual rule definitions |
| `logger.py` | Logging setup (file + console) |
| `karmawall.log` | Generated at runtime — every decision, timestamped |

## Extending it

- **Persist as a service** — wrap `main()` with `pywin32`'s
  `win32serviceutil.ServiceFramework` to run at boot without a console.
- **Inbound too** — change `WINDIVERT_FILTER` in `config.py` to
  `"ip"` (drops the `outbound` restriction) and branch logic on
  `packet.is_outbound`.
- **Live reload** — call `engine.reload()` on a timer or file-watch so
  editing `rules.json` takes effect without restarting.
- **CIDR/subnet matching** — `rules.py`'s `Rule.matches()` currently
  does exact IP match; swap in `ipaddress.ip_network()` checks for
  range-based rules.
