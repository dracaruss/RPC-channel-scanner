# rpcauthmap

Maps RPC **coercion sources** and NTLM **relay destinations** on Windows
networks, and can run the ESC8 relay end to end from its own code.

It answers two questions per host and ties them together:

1. **Coercion source** — can this host be made to authenticate to you (spooler,
   EFS, DFS, FSRVP, and more).
2. **Relay destination** — can a captured authentication be relayed into this
   host, and what does that grant (SMB/RPC, LDAP, LDAPS, ADCS ESC8).

> Authorized testing only. `coerce`, `hunt`, and `esc8` actively induce machines
> to authenticate to you. Point them only at systems you are cleared to test.

---

## Install

Python 3 and impacket. `ldap3` adds the LDAP/LDAPS relay checks.

```
pip install impacket ldap3
```

Everything is one file, `rpcauthmap.py`. The hunt candidate list is baked in.

---

## The four modes

```
rpcauthmap.py <mode> [[domain/]user[:pass]@]<host|CIDR|list|@file> [options]
```

Leave the password off to be prompted for it, which avoids shell-quoting issues
with special characters. Mode defaults to `map`.

- **map** (default, read-only) — discover and classify every interface, work out
  what is a coercion source and what is a relay destination, and check LDAP,
  LDAPS, and ADCS. Safe to run across a whole subnet.
- **coerce** — everything in map, then fire the known coercion methods and
  confirm with a real callback.
- **hunt** — everything in map, then blind-fire the built-in candidate list to
  find undocumented coercion methods. Loud and throttled; always `--dry-run`
  first.
- **esc8** — relay a coerced DC machine account into an AD CS web-enrollment host
  to issue a certificate (one-shot domain takeover). Runs the relay, the
  coercion, and the enrollment from this tool's own code, so no signatured
  binary (certipy, ntlmrelayx, Rubeus) is dropped. It still alerts, it just does
  not get auto-quarantined.

### Examples

```
rpcauthmap.py map CORP/alice@10.0.0.0/24 -o sweep.txt
rpcauthmap.py coerce alice@10.0.0.50
rpcauthmap.py hunt alice@10.0.0.50 --dry-run
rpcauthmap.py esc8 CORP/alice@10.0.0.50 --ca 10.0.0.60 --template DomainController
```

---

## Output

`map`, `coerce`, and `hunt` are quiet by default: a single live progress line
while scanning, then the **SUMMARY**. The summary leads with the critical
targets in colour — `DOMAIN CONTROLLERS`, `ADCS / ESC8` with its enrolment URL,
and a `>> TAKEOVER PATH` line naming the hosts a coerced machine account can be
relayed into — followed by a two-column table of coercible IPs and relay
destinations.

Add `-v` for the full per-host detail and debug errors. `-o FILE` always records
the complete per-host detail regardless of verbosity, so your evidence stays
intact.

---

## The ESC8 chain

```
rpcauthmap.py esc8 CORP/alice@<DC> --ca <ADCS> --template DomainController
```

- `<DC>` is the host to coerce; its machine account is what gets relayed.
- `--ca` is the AD CS web-enrollment host to relay into.
- `--template` matches the account you coerce: `DomainController` for a DC,
  `Machine` for a workstation or member server, `User` for a user.
- 445 on this box must be free (the relay owns it).

The issued certificate is written to the current directory (or `--loot DIR`) as
`<account>.pfx`, and the tool prints the follow-up `getTGT.py` and
`secretsdump.py` commands for PKINIT and DCSync.

---

## Options

| flag | meaning |
|------|---------|
| `-H LM:NT` | authenticate with NTLM hashes |
| `--listener-ip IP` | callback/relay IP (auto-detected if omitted) |
| `--dry-run` | coerce/hunt: show what would fire, send nothing |
| `--ca IP` | esc8: AD CS host to relay into |
| `--template NAME` | esc8: certificate template (default DomainController) |
| `--loot DIR` | esc8: where to write the .pfx (default current dir) |
| `-o FILE` | append plain-text results to a file |
| `-v` | full per-host detail and debug |
| `--show-all` | print every interface and fuzz result |
| `--no-color` | disable colour (use on older Windows consoles) |

Advanced knobs (`-threads`, `-timeout`, `--listener-port`, `--callback-wait`,
`--delay`, `--jitter`, `--max`, `--candidates`, `--rebuild`) keep their
defaults in the common case.

---

## The hunt candidate list

`hunt` fires from a list baked into the script. Opnums for undocumented
interfaces move between Windows builds, so for best results rebuild the list
from the target's build. On a Windows host of that build:

```powershell
Install-Module NtObjectManager -Scope CurrentUser -AllowClobber
Import-Module NtObjectManager
Get-RpcServer C:\Windows\System32\*.dll -Verbose |
  ForEach-Object { try { Format-RpcServer $_ } catch {} } |
  Out-File -Encoding utf8 rpc_all.txt
```

Then feed it in; `hunt` auto-loads the sidecar afterward:

```
rpcauthmap.py --rebuild rpc_all.txt
rpcauthmap.py hunt CORP/alice@dc01 --dry-run
```

---

## Notes

- SMB signing **required** only blocks relaying **into** SMB. It does not stop
  coercing a host, and it does not protect LDAP, LDAPS, or ADCS, which have their
  own gates (signing, channel binding, EPA).
- The spooler is a coercion candidate only when its remote RPC endpoint is
  published; on patched Windows that is off by default, so a running spooler is
  not always remotely coercible.
- `esc8` reuses impacket's relay internals, so the relay behaviour is still
  visible to EDR. It avoids the on-disk auto-quarantine, not the detection.

For authorized security assessment only. You are responsible for having
permission to test any system you point this at.
