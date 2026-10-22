# LLM guardrail

A local guardrail for traffic from this machine to AI providers. An nftables rule sends connections to known AI endpoints to a local mitmproxy, which masks personal data, holds back malicious prompts, and writes every decision to an audit log. All detection runs locally.

## Install

Run from this folder, as a normal user with sudo (not from a root login):

```
sudo bash guardrail-adm install
```

To see the plan and change nothing:

```
bash guardrail-adm install --dry-run
```

Install does:
- create the system user `guardrail-proxy`, which runs the proxy (never root);
- build a root-owned venv and app copy in `/usr/local/lib/guardrail/`;
- install the CA (creating one if the machine has none), system trust, the NSS entry `guardrail`, and the CA variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`);
- install `/usr/local/sbin/guardrail-adm`, `/etc/sudoers.d/guardrail`, the systemd units, and an empty nft table `inet guardrail`;
- enable the proxy and sync timer at boot.

Install does not divert traffic. Nothing is guarded until you arm.

Options: `--with-model`, `--with-banners`, `--persist`, `--failsafe=15m`, `--no-enable-units`, `--arm`, `--dry-run`. Exit code 3 means installed but degraded (no model layer).

## Arm

```
sudo guardrail-adm arm 15m
```

The window is 300 s to 3600 s; the rule is released by itself afterwards. Arm runs an end-to-end test first and releases the rule itself if the test fails.

`sudo bash guardrail-adm install --arm --persist` installs, arms, and keeps the rule across reboots (systemd only). `arm` alone cannot persist.

## Clients and the CA

Browsers and curl trust the CA at once. Restart node and python-requests programs that were running before `install` or `arm`; with the rule live they fail completely until restarted. Pinned apps and Firefox profiles cannot be fixed from outside.

With no session bus (the normal case under sudo), arm only prints the desktop proxy `gsettings` command. Run it as your own user.

## Check

```
bash run.sh verify
```

## Disarm and undo

| Command | Effect |
|---|---|
| `sudo guardrail-adm disarm` | release the rule, stop the failsafe timer |
| `sudo guardrail-adm rollback` | restore the previous app copy; with none, same as uninstall |
| `sudo guardrail-adm uninstall` | remove the rule, units, trust, venv, state and proxy user. Kept: audit log, helper, sudoers entry, `/etc/guardrail`, `~/.mitmproxy` |
| `sudo guardrail-adm revoke` | remove the sudoers entry and helper |
| `sudo bash run.sh panic` | emergency switch |

Run `uninstall` before `revoke`. Delete the audit log (`/var/log/guardrail/audit.jsonl`) by hand.

`install`, `uninstall`, `rollback` and `revoke` ask for your sudo password. `arm`, `disarm`, `mode` and `verify` do not.

## Limits

- The default install has no model layer: regex, checksum and ATR rules apply, but free-form names pass unmasked. Add `--with-model` (about 1.4 GB).
- Not covered: IPv6 (partial, not proven), QUIC/HTTP3, certificate pinning, loopback, traffic not on port 443.
- If the addon fails on a request, the request is forwarded and recorded as `ERROR` in the audit.
- The guardrail works on data and patterns, not intent.
- Coming back after a reboot is proven in a guest only, not on a host.

## Tested on

- openSUSE Tumbleweed, GNOME, x86_64 - the author's machine: install, arm, verify, audit.
- Debian-family guest (blankon image), clean machine: clone from the repository, install, arm,
  one provider request returns 200 while armed, disarm leaves the request working. Recorded in
  `qaladder-gates/g4.txt` of the research tree, not shipped here.
- Fedora, Arch and Alpine branches exist in the installer (package names, trust store, NSS) but have
  not been run yet. Their code paths are the same; treat those families as untested, not as broken.
