# rpcauthmap

An RPC authentication-coercion and NTLM-relay surface mapper for Windows networks.

`rpcauthmap.py` answers two questions about a host or a whole subnet, and then ties
them together:

1. **Is this a coercion source?** Can the host be made to authenticate to you.
2. **Is this a relay destination?** Can a captured NTLM authentication be relayed
   into the host, and if so, what does that get an attacker.

It discovers every reachable RPC interface (not just the ones the endpoint mapper
advertises), classifies what each one is and what it is good for, probes whether a
relay would actually land, optionally fires the curated coercion methods to prove
them, optionally blind-fires a broader candidate set to hunt for coercion methods
that are not in any published catalog, optionally checks the cross-protocol relay
destinations (LDAP, LDAPS, ADCS ESC8), and prints a final summary that lists
coercible IPs on the left and relay destinations on the right.

> **Authorized testing only.** The `coerce` and `hunt` modes actively induce target
> machines to authenticate to you, and every mode binds to LDAP/LDAPS for the relay
> checks. `hunt` in particular blindly fires RPC methods and can hang or crash a
> service. Only run this against systems you are explicitly authorized to test.

---

## What it does, stage by stage

**Stage 1 — Discovery (the full RPC surface, not just the advertised part).**
- Reads the endpoint mapper (TCP/135), which gives each registered interface and its
  exact bindings, including the dynamic `ncacn_ip_tcp` high port.
- Enumerates named pipes over SMB (`\\host\IPC$`), which surfaces pipes the endpoint
  mapper never advertised.
- Queries each pipe's MGMT interface (`inq_if_ids`) to learn which interface UUIDs it
  actually serves, catching interfaces that are invisible to an endpoint-mapper-only
  scan (for example EFS on `\PIPE\lsarpc`).
- In `hunt` mode it also binds a dictionary of known UUIDs when a pipe refuses the
  MGMT query, for extra discovery depth.
- Both transports are considered; an interface exposed on TCP but not a pipe (or the
  reverse) is still found. Application/IPC pipe noise (Chrome, VMware, crashpad,
  mojo, bare-GUID pipes, etc.) is filtered out.

**Stage 2 — Classification.**
Every UUID is mapped to a human name where known, flagged as a coercion source if it
exposes a method that takes a remote-target argument (a UNC path, a `\\server`, or a
share), and annotated with a short attacker-oriented `use:` note explaining what
reaching or relaying into it buys you. Interface binds use each interface's real
version, and interfaces reachable only via local RPC are labeled `local only
(ncalrpc)` rather than probed.

**Stage 3 — Relay-destination probe.**
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

**Stage 4 — Cross-protocol relay destinations (part of every mode).**
Per host, probes:
- **LDAP signing (389)** — `NOT required` means relay here to write RBCD or shadow
  credentials.
- **LDAPS channel binding / EPA (636)** — `NOT required` means the HTTPS-origin relay
  path for the same directory writes.
- **ADCS ESC8** — checks whether `http(s)://<host>/certsrv/` answers with NTLM, i.e.
  a web-enrollment endpoint you can relay to for a certificate.

These run against **every** host scanned; a host that is not a DC or CA fails the
port pre-check and returns `closed` fast.

**Stage 5 — Active coercion, "level 1" (`coerce` mode).**
Stands up a local callback listener, calls each coercible interface's trigger with a
UNC pointing back at you, and reports **CONFIRMED** when the target actually connects
back, **LIKELY** when the call was accepted but no callback arrived, or **CANDIDATE**
when it was not fired (for example MS-RPRN, which needs an open-printer handle
sequence). These are the curated, proven methods whose exact argument is hardcoded.

**Stage 6 — Targeted fuzz, "level 2" (`hunt` mode).**
This is the part that goes past a fixed catalog. The tool carries a built-in candidate
list (compiled from an NtObjectManager IDL dump of a Windows 11 box), and for every
interface it actually discovers on the target that also appears in that list, it
blind-fires each listed method with a UNC in every wide-string argument and watches
the same listener. The point is to find an interface that forces outbound
authentication even though nobody has it in a published catalog, which is the value a
hand-curated tool like Coercer cannot give you. It only fires methods whose every
incoming argument is a wide string or a simple scalar, because those are the only ones
a single blind call can satisfy; anything needing a context handle, a struct, or an
array is skipped and labelled as needing setup. Each method is reported as
**CONFIRMED** on a callback, **LIKELY** when the server threw a post-dial path error
(meaning it reached out but found nothing), **accepted** when the call returned with no
fault and no callback, or **rejected** when the argument shape or opnum was refused.
Because opnum numbering for undocumented interfaces is specific to a Windows build, you
can rebuild the list against the target's own build with `--rebuild` where it matters;
the documented interfaces such as EFS, DFS, FSRVP, and the spooler are stable by spec
and portable.

**Summary.**
After the sweep, a colored two-column table lists every coercible IP on the left and
every relay destination on the right, each destination tagged with what it grants:

```
  SUMMARY
  COERCIBLE IPs                             |   RELAY DESTINATIONS
  10.121.158.120  candidate  MS-RPRN        |   10.2.0.3  LDAP  (RBCD/shadow-creds)
  10.0.4.5  CONFIRMED  MS-EFSR              |   10.0.4.5  ADCS-ESC8  (cert then PKINIT)
```

---

## Install

Needs Python 3 and impacket. `ldap3` adds the LDAP and LDAPS relay-destination
checks and is worth having.

```bash
pip install impacket ldap3 --break-system-packages
```

If you use a virtualenv or conda env, run the tool with that same interpreter. When
using `sudo` for `coerce` or `hunt` (they bind port 445 for the callback), call the
env's Python by full path so sudo does not drop back to system Python:

```bash
sudo "$(which python3)" rpcauthmap.py ...
```

The whole thing is one self-contained file, `rpcauthmap.py`. The candidate list the
`hunt` mode uses is baked into it, and the `--rebuild` option (below) can regenerate
that list for a specific Windows build, so there is nothing else to carry.

---

## Usage

There is one shape to remember:

```
rpcauthmap.py <mode> [[domain/]user[:pass]@]<host|CIDR|list|@file> [a few options]
```

The mode is `map`, `coerce`, or `hunt`, and it defaults to `map` if you leave it out.
The domain is optional, so `alice:pw@host` is fine for a local or workgroup account.
The target can be a single host, a CIDR such as `10.0.0.0/24`, a comma-separated
list, or a file of hosts written as `@hosts.txt`.

### The three modes

**`map`** is the default and is read-only. It discovers every reachable RPC interface,
classifies each one, works out which hosts can be a coercion source and which can be a
relay destination, and checks the LDAP, LDAPS, and ADCS relay paths. It never fires an
authentication, so it is safe to run broadly.

```bash
python3 rpcauthmap.py map 'CORP/alice:Passw0rd@10.0.0.0/24' -o engagement.txt
```

**`coerce`** does everything `map` does and then actively fires the known, curated
coercion methods (EFS, DFS, FSRVP) with a UNC pointing back at you, confirming a hit
when the target calls back. It starts its own listener and auto-detects your callback
IP, so you only need root for port 445.

```bash
sudo systemctl stop smbd 2>/dev/null
sudo "$(which python3)" rpcauthmap.py coerce 'CORP/alice:Passw0rd@10.0.0.50'
```

**`hunt`** does everything `map` does and then blind-fires the built-in candidate list
at whatever interfaces it finds, looking for a coercion method that is not in any
published catalog. It is loud and throttled. Always look first with `--dry-run`, which
sends nothing:

```bash
python3 rpcauthmap.py hunt 'CORP/alice:Passw0rd@10.0.0.50' --dry-run
sudo "$(which python3)" rpcauthmap.py hunt 'CORP/alice:Passw0rd@10.0.0.50'
```

### Options

Most runs need none of these. The mode and the target are the only things you supply
in the common case.

| flag | description |
|------|-------------|
| `-H LM:NT` | authenticate with NTLM hashes instead of a password |
| `--listener-ip IP` | callback IP for `coerce`/`hunt` (auto-detected if omitted) |
| `--dry-run` | `coerce`/`hunt`: show what would fire and send nothing |
| `-o FILE` | append plain-text (no color) results to a file |
| `-v`, `--verbose` | also print dead/no-RPC hosts and per-stage debug errors |
| `--show-all` | print every interface and every fuzz result, not just the hits |
| `--no-color` | disable ANSI color |

And the advanced knobs, which have sensible defaults and are rarely touched:

| flag | description |
|------|-------------|
| `-threads N` | concurrent hosts (default 10) |
| `-timeout N` | per-connect timeout seconds (default 3) |
| `--listener-port N` | callback listener port (default 445) |
| `--callback-wait N` | seconds to wait for a callback (default 5) |
| `--delay N` | `hunt`: base seconds between calls (default 0.5) |
| `--jitter N` | `hunt`: random extra 0..N seconds per call (default 0.5) |
| `--max N` | `hunt`: maximum calls per host (default 200) |
| `--candidates FILE` | `hunt`: use a specific candidate CSV for this run only |
| `--rebuild DUMP` | parse an NtObjectManager dump into a sidecar list, then exit (then `hunt` auto-loads it) |

**On speed.** `map` and `coerce` are quick, on the order of seconds per host and
fine across a subnet with the default ten threads. `hunt` is deliberately slow,
because the throttle is the safety feature: at the default pacing it fires at most a
couple of calls a second and caps at two hundred per host, so a host with a large
exposed surface can take a few minutes. That is why `hunt` is a single-target tool,
pointed at a domain controller you care about, not something to run across a whole
range. Lower `-timeout` makes dead hosts fail faster on a sweep, but there is a global
socket floor around five seconds, so going below three has little effect.

**On the spooler.** The print spooler (MS-RPRN) is reported as a coercion candidate
rather than auto-fired, because its trigger needs a multi-call open-printer sequence.
Fire it with a dedicated printerbug tool.

---

## The candidate list (used by `hunt`)

`hunt` fires from a candidate list that is baked into `rpcauthmap.py`, so by default
there is nothing to supply. That list is interface UUID, version, opnum, and the
method's argument signature, compiled from a Windows 11 24H2 box, and it already
covers the documented coercion interfaces plus every other method on that build whose
arguments a blind call can satisfy.

Opnum numbering is fixed by specification for the documented interfaces, so those
entries work against any Windows version. For undocumented interfaces the numbering
can move between builds, so for the most accurate results against a specific target
you rebuild the list from that build. There are two steps. First, on a Windows host of
the same build as the target, produce the raw dump (this can only happen on Windows,
because the data lives in that machine's DLLs):

```powershell
Install-Module NtObjectManager -Scope CurrentUser -AllowClobber
Import-Module NtObjectManager
$servers = Get-RpcServer C:\Windows\System32\*.dll -Verbose
$servers | ForEach-Object { try { Format-RpcServer $_ } catch {} } |
    Out-File -Encoding utf8 rpc_all.txt
```

Second, copy `rpc_all.txt` to wherever you run the tool and feed it to `--rebuild`.
That parses the dump and writes a `rpcauthmap_candidates.csv` next to the script, and
from then on `hunt` loads that sidecar automatically with no extra flag:

```bash
python3 rpcauthmap.py --rebuild rpc_all.txt
python3 rpcauthmap.py hunt 'CORP/alice:pw@dc01' --dry-run
```

Delete the sidecar to go back to the built-in list, or point a single run at a
specific file with `--candidates FILE`. Because the tool only fires at interfaces it
actually finds reachable on the target, entries for interfaces that are not exposed
simply never fire, so the built-in list is safe to use as-is; it just will not know
about methods unique to the target's build.

### A note on GOAD and real domain controllers

A standalone workstation exposes very few interfaces remotely, so `hunt` has little to
chew on there. A domain controller is where this earns its keep, because a DC runs the
documented coercion services and a much larger RPC surface. The practical path is to
stand up [GOAD](https://github.com/Orange-Cyberdefense/GOAD), which builds a vulnerable
Active Directory lab automatically, dump that DC's RPC servers with the PowerShell
above, feed the dump to `--rebuild` so `hunt` is matched to that build, and then run
`hunt` against it. Keep the pacing conservative against a DC, because blindly firing
methods at a live domain controller is both loud and capable of disrupting a service.

---

## Reading the output

Each host prints these sections:

- **IS THIS A COERCION SOURCE** — can this host be made to authenticate to you. This
  host's own SMB signing is irrelevant here.
- **IS THIS A RELAY DESTINATION** — can you relay a captured NTLM auth into this host.
  This is the only place SMB signing matters, because signing gates the machine you
  relay *into*, not the machine you coerce *out of*.
- **CROSS-PROTOCOL RELAY TARGETS** — the LDAP, LDAPS, and ADCS relay paths, shown in
  every mode.
- **CONCLUSION** — what is coercible and why, and what can be a relay target and why.

In `hunt` mode a **LEVEL-2 FUZZ (UNVERIFIED)** section lists each candidate method
that was fired and its verdict, with the confirmed and likely hits first and the
rejected or skipped ones summarised unless `--show-all` is set. With `--show-all`, a
full **ALL INTERFACES** dump is appended, where `local only (ncalrpc)` marks interfaces
reachable only from a process on the box and therefore not testable over the network.
The run ends with the two-column **SUMMARY** table described above, into which any
fuzz-confirmed method is folded on the coercible side.

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
- The summary lists coercible sources and relay destinations side by side; it does
  not prove a specific source has rights at a specific destination, which is your
  call per target. The directory and certificate destinations (LDAP, LDAPS, ADCS)
  are the ones that matter for a coerced **machine** account; SMB/RPC relay targets
  are tagged separately as useful for a privileged **user** auth, not a machine
  account.
- A level-2 **LIKELY** verdict means the server dialled out and then failed to find
  the path, which is strong evidence of coercion but is not a captured authentication;
  confirm it with a real listener capture before you rely on it. An **accepted**
  verdict means the call returned cleanly with no callback, which usually means the
  string was not treated as a remote path at all, so treat those as negative rather
  than promising.
- The fuzzer builds a best-effort call from the argument signature, filling scalar
  arguments with zero. A method can accept that and still take a different code path
  than it would with real arguments, so a quiet result is not proof the method can
  never coerce, only that this particular blind call did not.

---

## License / disclaimer

For authorized security assessment and research only. You are responsible for having
explicit permission to test any system you point this at.
