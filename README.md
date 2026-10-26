# rpcauthmap

`rpcauthmap.py` discovers Windows RPC interfaces, tests selected coercion methods, observes the resulting SMB or HTTP/WebDAV callbacks, and maps relay-related destination posture.

It is designed for **authorized security testing and RPC coercion research**. It does not treat an RPC error, an accepted bind, or an untagged connection as proof of coercion or relay impact.

## How it works

1. **Discovers RPC endpoints**
   - Queries the endpoint mapper on TCP/135.
   - Enumerates SMB named pipes independently.
   - Uses RPC management `inq_if_ids` to identify interfaces.
   - Falls back to known-UUID bind checks when management enumeration fails.
   - Supports named-pipe and direct-TCP RPC transports; `ncalrpc` is local-only.

2. **Tests coercion methods**
   - `coerce` exercises curated methods such as EFSR, RPRN, DFSNM, and FSRVP triggers.
   - `hunt` tests reviewed candidates and varies one string argument per attempt.
   - Unreviewed hunt candidates are skipped unless `--lab` is explicitly enabled.

3. **Correlates callback evidence**
   - Every attempt receives a unique tag in its callback UNC or HTTP path.
   - The built-in listener observes SMB or plain HTTP/WebDAV connections and authentication.
   - `CONFIRMED` requires the matching attempt tag in the callback path.
   - Source IP plus timing without the tag is reported as an untagged, unconfirmed callback.
   - NTLM identity fields are client-asserted, not independently verified identities. Raw authentication tokens are not stored by the observer.

4. **Maps relay posture**
   - Checks SMB signing, LDAP signing, LDAPS channel binding, AD CS web authentication advertisement, and RPC `CONNECT` bind acceptance.
   - These are candidate/posture observations only. Destination authorization and practical relay impact remain unproven until separately validated.

## Requirements

- Python 3
- [Impacket](https://github.com/fortra/impacket)
- `ldap3` for LDAP and LDAPS posture checks

```bash
python3 -m pip install --upgrade impacket ldap3
```

## Quick start

Map one host without firing coercion methods:

```bash
python3 rpcauthmap.py map 10.0.0.50
```

Map a subnet with credentials:

```bash
python3 rpcauthmap.py map CORP/alice@10.0.0.0/24
```

If the password is omitted, the tool prompts for it. Credentials can also be supplied inline:

```bash
python3 rpcauthmap.py map 'CORP/alice:Password123@10.0.0.50'
```

Show all discovered interfaces and detailed results:

```bash
python3 rpcauthmap.py map CORP/alice@10.0.0.50 --show-all -v
```

## Coercion testing

Fire the curated coercion methods and confirm callbacks over SMB:

```bash
python3 rpcauthmap.py coerce CORP/alice@10.0.0.50 --listener-ip 10.0.0.25
```

Use the HTTP/WebDAV callback observer instead:

```bash
python3 rpcauthmap.py coerce CORP/alice@10.0.0.50 --webdav --listener-ip 10.0.0.25
```

Preview the selected actions without sending coercion calls:

```bash
python3 rpcauthmap.py coerce CORP/alice@10.0.0.50 --dry-run
```

The listener IP is auto-detected when omitted. Explicitly setting `--listener-ip` is recommended on multi-homed systems.

## Hunting additional methods

Preview reviewed hunt candidates:

```bash
python3 rpcauthmap.py hunt CORP/alice@10.0.0.50 --dry-run
```

Run reviewed candidates with SMB callback confirmation:

```bash
python3 rpcauthmap.py hunt CORP/alice@10.0.0.50 --listener-ip 10.0.0.25
```

Use a specific candidate CSV:

```bash
python3 rpcauthmap.py hunt CORP/alice@10.0.0.50 --candidates candidates.csv --dry-run
```

Enable unreviewed candidates **only on isolated, disposable, snapshotted lab targets**:

```bash
python3 rpcauthmap.py hunt CORP/alice@10.0.0.50 --lab --listener-ip 10.0.0.25
```

Authenticated calls are not necessarily read-only. Valid methods may change state, hang, or crash services; review candidates before marking them for engagement use.

## Reading the results

| Result | Meaning |
|---|---|
| `CANDIDATE` | A potentially interesting interface or method; active behavior is not proven. |
| `UNCONFIRMED (called, no callback)` | The RPC call was issued, but no callback was observed. |
| `UNTAGGED CALLBACK` | A connection matched source/timing, but not the unique attempt tag. |
| `CONFIRMED` | The callback path contained the unique tag for that attempt. |
| `RPC relay CANDIDATE` | An authenticated `CONNECT` bind was accepted; useful method authorization was not tested. |
| `unknown` / no callback | Inconclusive, not proof of protection or that coercion is impossible. |

## Useful options

| Option | Purpose |
|---|---|
| `--listener-ip IP` | Address targets should call back to. |
| `--listener-port PORT` | Override TCP/445 for SMB or TCP/8080 for WebDAV. |
| `--callback-wait SECONDS` | Callback wait per attempt; default is 5 seconds. |
| `--webdav` | Use plain HTTP/WebDAV instead of SMB. HTTPS callbacks are not supported. |
| `--dry-run` | Show selected actions without firing coercion calls. |
| `--lab` | Permit unreviewed hunt candidates in an isolated lab. |
| `-H LM:NT` | Authenticate with NTLM hashes; a single NT hash is also accepted. |
| `--show-all` | Show all interfaces and otherwise summarized hunt results. |
| `-o results.txt` | Append plain-text results to a file. |
| `--no-color` | Disable colored output. |

SMB callbacks normally require the tool to bind TCP/445, which may require elevated privileges. The target must be able to route to the selected listener IP and port.

## Scope and limitations

- Only `coerce` and non-dry-run `hunt` intentionally trigger outbound authentication.
- WebDAV mode observes HTTP authentication and WebDAV requests; it does not support HTTPS callbacks and does not assume that WebDAV removes the MIC.
- MIC is reported as present or absent only when `msvAvFlags` can be parsed; otherwise it is `not determined`.
- Hunt does not model every NDR type or stateful call sequence. Complex candidates may require manual setup.
- Unknown methods and undocumented opnums can be Windows-build-specific.
- No automatic takeover claim is made from combining coercion and relay posture observations.

Use only against systems you own or are explicitly authorized to test.
