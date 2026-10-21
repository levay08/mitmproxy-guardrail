# LLM guardrail

## What it is

A local guardrail for traffic from this machine to AI providers. A kernel rule (nftables) sends connections to known AI endpoints to a local mitmproxy, which masks personal data, holds back malicious prompts, and writes every decision to an audit log. All detection runs on this machine; no third-party service takes part in any decision.

## The one command

Run it from this folder, as a normal user with sudo:

```
sudo bash guardrail-adm install
```

It asks for your sudo password once. Run through sudo, not from a root login. To see the plan first and change nothing:

```
bash guardrail-adm install --dry-run
```

Install does not divert any traffic. After it, nothing of yours is guarded yet. Check the install read-only with `bash run.sh verify` (run.sh is the user launcher in this folder).

Before you arm, log out and in once so clients pick up the CA (see Manual steps). A client that does not trust the CA fails completely while the rule is live.

To start guarding, arm the rule. `arm` takes a window of 300 s to 3600 s (example 15m) after which the rule is released by itself. Install puts `guardrail-adm` in `/usr/local/sbin`:

```
sudo guardrail-adm arm 15m
```

`install --arm --persist` installs and arms in one step and keeps the rule across reboots (systemd hosts only; without systemd it is not persisted). `arm` alone cannot persist. Arm runs an end-to-end test first and releases the rule itself if that test fails.

The default install has no model layer: regex, checksum and ATR rules apply, but free-form names (for example "Hendrik van der Westhuizen" in a sentence) pass unmasked until you install with `--with-model`. The last line of `install` states this.

Options of `install`: `--with-model` adds the model layer (about 1.4 GB; the default core is about 30 MB, and free-form names pass unmasked without the model), `--with-banners`, `--persist`, `--failsafe=15m` (default window 15m), `--no-enable-units`, `--arm`, `--dry-run`. Exit code 3 means installed but degraded (model layer missing).

## What install writes

Read from `install_all` and the functions it calls in `guardrail-adm`. Paths below can differ by distro (marked "per distro").

| Path | What |
|---|---|
| `/usr/local/sbin/guardrail-adm` | the root helper, copied from this folder |
| `/etc/sudoers.d/guardrail` | passwordless verbs for the owner, validated by `visudo` |
| `/etc/guardrail/` | `helper.conf`, `install.record`, saved ruleset `guardrail.nft` |
| `/usr/local/lib/guardrail/` | root-owned venv, app copy, `bin/proxy-run`, CA public file, optional `hf/` model |
| `/var/lib/guardrail/` | `conf/` (CA), `state/`, `pac/`, owned by `guardrail-proxy` |
| `/var/log/guardrail/` | `audit.jsonl` (group-readable, mode 640), proxy log |
| `/var/log/guardrail-adm.log` | every helper call |
| `/etc/logrotate.d/guardrail` | log rotation |
| `/etc/systemd/system/` | `guardrail-proxy.service`, `guardrail-sync.service`, `guardrail-sync.timer`, `guardrail-net.service` |
| system user `guardrail-proxy` | the proxy runs as this user, never as root |
| CA trust anchor and system bundle (per distro) | for example `/etc/pki/trust/anchors/guardrail-ca.pem` |
| NSS stores of the owner (per distro) | an entry named `guardrail` |
| `/etc/environment.d/90-guardrail-ca.conf` or `/etc/profile.d/` (per distro) | `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` |
| `/etc/systemd/user/guardrail-notify.service` | only with `--with-banners` |
| nft table `inet guardrail` | created empty by install; it diverts traffic only when armed |

By default the proxy and the sync timer are enabled at boot. The rule is never enabled by plain `install`; only `--arm --persist` does that. If the machine has no CA yet, install creates one.

## How to undo

| Command | Effect |
|---|---|
| `sudo guardrail-adm disarm` | release the rule, disable `guardrail-net.service`, stop the failsafe timer |
| `sudo guardrail-adm rollback` | put the previous app copy back; with none, same as uninstall |
| `sudo guardrail-adm uninstall` | remove the rule, units, trust, NSS entry, env file, venv, state and the proxy user. Kept: the audit log, the helper, the sudoers entry, `/etc/guardrail`, `~/.mitmproxy` |
| `sudo guardrail-adm revoke` | remove the sudoers entry and the helper; it releases an active rule first and refuses while `guardrail-net.service` is still enabled |
| `sudo bash run.sh panic` | emergency switch (run from this folder) |

Run `uninstall` before `revoke`. The audit log is deleted only by hand.

## Manual steps

- The sudo password for `install`, `uninstall`, `rollback` and `revoke`. It is never taken from you. `arm`, `disarm`, `mode` and `verify` need none.
- Log out and in once after install. The CA variables and the browser store are read at login; a client that does not trust the CA fails completely while the rule is live.
- Desktop proxy: with no session bus (the normal case under sudo) arm only prints the `gsettings` command. Run it as your own user.
- Choice of mode (`neutral` by default; stricter is `sudo guardrail-adm mode persistent`) and of the model layer (`--with-model`).
- Pinned apps and Firefox profiles cannot be fixed from outside.

## Paths that still get through

- IPv6: coverage is partial and not proven.
- QUIC / HTTP3.
- Certificate pinning.
- Loopback.
- Traffic that is not on port 443.

A language model is not a safeguard: this guardrail works on data and patterns, not intent. If the addon fails while inspecting a request, the request is forwarded and recorded as `ERROR` in the audit (default; a proxy started by hand with `GUARDRAIL_ON_INTERNAL_ERROR=block` returns a 502 instead).

## Reboot

Coming back after a reboot is proven in a guest only. It was not run on a host, so do not rely on it.

## Tested on

- openSUSE Tumbleweed, GNOME, x86_64 - the author's machine: install, arm, verify, audit.
- Debian-family guest (blankon image), clean machine: clone from the repository, install, arm,
  one provider request returns 200 while armed, disarm leaves the request working. Recorded in
  `qaladder-gates/g4.txt` of the research tree, not shipped here.
- Fedora, Arch and Alpine branches exist in the installer (package names, trust store, NSS) but have
  not been run yet. Their code paths are the same; treat those families as untested, not as broken.
