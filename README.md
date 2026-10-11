# rpcauthmap

An RPC authentication-coercion and NTLM-relay surface mapper for Windows networks.

`rpcauthmap.py` answers two questions about a host or a whole subnet, and then ties
them together:

1. **Can this host be made to authenticate to me?** (a coercion *source*)
2. **Can a captured NTLM authentication be relayed *into* this host?** (a relay
   *destination*), and if so, what does that get an attacker?

It discovers every reachable RPC interface (not just the ones the endpoint mapper
advertises), classifies what each one is and what it is good for, probes whether a
relay would actually land, optionally fires the coercion to prove it, optionally
checks the cross-protocol relay destinations (LDAP, LDAPS, ADCS ESC8), and prints a
final engagement summary mapping which coercible source can be relayed to which
destination.

> **Authorized testing only.** The `--coerce` mode actively induces target machines
> to authenticate to you, and `--relay-checks` binds to LDAP/LDAPS. Only run this
> against systems you are explicitly authorized to test.

---

## What it does, stage by stage

**Stage 1 - Discovery (the full RPC surface, not just the advertised part).**
- Reads the endpoint mapper (TCP/135), which gives each registered interface and its
  exact bindings, including the dynamic `ncacn_ip_tcp` high port.
- Enumerates named pipes over SMB (`\\host\IPC$`), which surfaces pipes the endpoint
  mapper never advertised.
- Queries each pipe's MGMT interface (`inq_if_ids`) to learn which interface UUIDs it
  actually serves, catching interfaces that are invisible to an endpoint-mapper-only
  scan (for example EFS on `\PIPE\lsarpc`).
- Optional `--brute`: bind a dictionary of known UUIDs when a pipe refuses the MGMT
  query.
- Both transports are considered; an interface exposed on TCP but not a pipe (or the
  reverse) is still found. Application/IPC pipe noise (Chrome, VMware, crashpad,
  mojo, bare-GUID pipes, etc.) is filtered out.

**Stage 2 - Classification.**
Every UUID is mapped to a human name where known, flagged as a coercion source if it
exposes a method that takes a remote-target argument (a UNC path, a `\\server`, or a
share), and annotated with a short attacker-oriented `use:` note explaining what
reaching or relaying into it buys you.

**Stage 3 - Relay-destination probe.**
For each interface, the tool binds at escalating authentication levels to find the
lowest the server accepts (its enforced *floor*):

| floor      | meaning                                             |
|------------|-----------------------------------------------------|
| none       | unauthenticated bind allowed                        |
| connect    | authenticated but **unsigned** bind allowed         |
| integrity  | packet integrity (signing) required                 |
| privacy    | integrity + encryption required                     |

A relayed NTLM session cannot sign, so a `none`/`connect` floor means the RPC layer
is not a barrier. For **named-pipe** endpoints the real gate is **SMB signing**
(reported per host), because a pipe rides an SMB session; for **direct TCP**
endpoints there is no SMB layer, so the RPC floor is the only gate.

**Stage 4 - Active coercion probe (opt-in `--coerce`).**
Stands up a local callback listener, calls each coercible interface's trigger with a
UNC pointing back at you, and reports **CONFIRMED** when the target actually connects
back, **LIKELY** when the call was accepted but no callback arrived, or **CANDIDATE**
when it was not fired (for example MS-RPRN, which needs an open-printer handle
sequence).

**Stage 5 - Cross-protocol relay destinations (opt-in `--relay-checks`).**
Per host, probes:
- **LDAP signing (389)** - `NOT required` means relay here to write RBCD or shadow
  credentials.
- **LDAPS channel binding / EPA (636)** - `NOT required` means the HTTPS-origin relay
  path for the same directory writes.
- **ADCS ESC8** - checks whether `http(s)://<host>/certsrv/` answers with NTLM, i.e.
  a web-enrollment endpoint you can relay to for a certificate.

These run against **every** host scanned; a host that is not a DC or CA fails the
port pre-check and returns `closed` fast.

**Engagement summary.**
After the sweep, a colored wrap-up lists all coercible source IPs, all relay
destination IPs with what each grants, and the coerce→relay chains between them, e.g.

```
  CHAINS (coerce -> relay):
    10.0.0.1 -> relay to: 10.2.0.3[LDAP], 10.0.4.5[ADCS-ESC8]
```

---

## Install

Needs Python 3 and impacket. `ldap3` is only required for `--relay-checks`.

```bash
pip install impacket ldap3 --break-system-packages
```

If you use a virtualenv or conda env, make sure you run the tool with that same
interpreter. When using `sudo` for `--coerce` (binds port 445), call the env's
Python by full path so sudo does not drop back to system Python:

```bash
sudo "$(which python3)" rpcauthmap.py ...
```

---

## Usage

Target can be a single host, a CIDR (`192.168.1.0/24`), a comma-separated list, or a
file of hosts as `@hosts.txt`. Credentials are optional for endpoint-mapper discovery
but required for pipe discovery and the floor/coercion probes.

```
rpcauthmap.py [[domain/]user[:pass]@]<host|CIDR|list|@file> [options]
```

**Discovery only, no credentials** (endpoint-mapper surface, fast):
```bash
python3 rpcauthmap.py '@192.168.4.38' -v
```

**Authenticated map of one host** (pipe discovery + floors + classification):
```bash
python3 rpcauthmap.py 'CORP/alice:Passw0rd@192.168.4.38'
```

**Subnet sweep with the full relay picture**:
```bash
python3 rpcauthmap.py 'CORP/alice:Passw0rd@10.0.0.0/24' --relay-checks -o engagement.txt
```

**Active coercion test** (authorized engagements only; binds 445):
```bash
sudo systemctl stop smbd 2>/dev/null
sudo "$(which python3)" rpcauthmap.py 'CORP/alice:Passw0rd@10.0.0.50' \
     --coerce --listener-ip 10.0.0.10
```

### Options

| flag | description |
|------|-------------|
| `-hashes LM:NT` | authenticate with NTLM hashes instead of a password |
| `-threads N` | concurrent hosts (default 10) |
| `-timeout N` | per-connect timeout seconds (default 3) |
| `--no-pipes` | skip SMB named-pipe discovery |
| `--brute` | brute-bind known UUIDs when a pipe refuses the MGMT query |
| `--coerce` | actively test coercible interfaces (fires auth at the listener) |
| `--listener-ip IP` | address the target should call back to (required with `--coerce`) |
| `--listener-port N` | callback listener port (default 445) |
| `--coerce-timeout N` | seconds to wait for a callback (default 5) |
| `--relay-checks` | probe LDAP signing, LDAPS channel binding, and ADCS ESC8 per host |
| `-v`, `--verbose` | also print dead/no-RPC hosts and per-stage debug errors |
| `--show-all` | print every interface, not just the hits |
| `--no-color` | disable ANSI color |
| `-o FILE` | append plain-text (no color) results to a file |

On --brute: Use it selectively, when a pipe you care about refuses the MGMT query so ifids comes back empty but you still want to know which known interfaces it serves. It is extra noise and extra binds, so it is a per-host or hardened-target tool, not something to leave on for a wide sweep.

On --coerce: You need an EFS, DFS or FSRVP host for a real active fire (PrintSpooler doen't auto-fire).

On the timeout: Lower is faster because it is the per-connect wait, so dead ports and hosts fail sooner across a sweep. Too low risks missing slow hosts, and note the global socket floor is max of five or timeout plus two, so dropping below three still bottoms out around five seconds on actual socket operations. On a fast LAN one or two is fine, over VPN keep it higher.

---

## Reading the output

Each host prints three sections:

- **COERCION SOURCE** - can this host be made to authenticate to you. This host's own
  SMB signing is irrelevant here.
- **RELAY DESTINATION** - can you relay a captured NTLM auth into this host. This is
  the only place SMB signing matters, because signing gates the machine you relay
  *into*, not the machine you coerce *out of*.
- **CONCLUSION** - what is coercible and why, and what can be a relay target and why.

With `--relay-checks`, a **CROSS-PROTOCOL RELAY TARGETS** section is added (LDAP,
LDAPS, ADCS). With `--show-all`, a full **ALL INTERFACES** dump is appended, where
`local only (ncalrpc)` marks interfaces reachable only from a process on the box and
therefore not testable over the network.

---

## Notes and caveats

- The floor probe tests acceptance at **bind** time. A server can, in principle,
  accept a low-level bind and enforce a higher level only at call time on specific
  opnums. Confirm anything ambiguous with a real authenticated call or a capture.
- The LDAP signing and LDAPS channel-binding verdicts rely on interpreting specific
  server error codes (the LdapRelayScan bogus-credential technique). Validate the
  first run against a real domain controller (for example cross-check with
  `nxc ldap`) before trusting it on an engagement.
- MS-RPRN (the spooler) is reported as a coercion **candidate** rather than
  auto-fired, because its trigger needs an open-printer handle sequence. Use a
  dedicated printerbug tool to fire it.
- The coerce→relay chains pair every coercible source with every LDAP/LDAPS/ADCS
  destination, which is valid in the general machine-account case. The tool does not
  prove a specific source has rights at a specific destination; that is your call per
  target. SMB/RPC relay targets are listed separately and labeled as useful for a
  privileged *user* auth, not a coerced machine account.

---

## License / disclaimer

For authorized security assessment and research only. You are responsible for having
explicit permission to test any system you point this at.
