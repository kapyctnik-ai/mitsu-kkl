#!/usr/bin/env python3
"""MCP server (stdio) for MUT-II diagnostics: Claude reads the engine ECU through the KKL cable,
records and analyses logs and builds the PID map of one particular car.

  python mcp_server.py                          # cable picked automatically (FTDI D2XX, else COM port)
  python mcp_server.py --iface serial:COM5      # a cable through its COM port
  python mcp_server.py --iface sim:mutlive      # simulated ECU, no car needed

Built on kkl (link, proto, livepoll, sim). Read-only, enforced again here regardless of kkl:
only MUT requests 00-BF and FD-FF ever reach the K-line, C0-FC (0xCA erases fault codes,
F1-FC drive actuators / cut injectors) is refused at the API and again at the cable, and
there is no fault code erase tool. PID names and conversions are written only to a separate
car profile (default profiles/colt_cj4a_md353925.csv); the Eclipse reference files
(pid_definicje.csv, dtc_definitions.csv) are only read.
"""

import argparse
import csv
import datetime
import functools
import json
import os
import re
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Literal

import anyio.to_thread

try:
    from mcp.server.fastmcp import FastMCP as MCPServer  # mcp 1.x
    from mcp.server.fastmcp.exceptions import ToolError
except ImportError:
    from mcp.server.mcpserver import MCPServer  # mcp 2.x: FastMCP renamed to MCPServer
    from mcp.server.mcpserver.exceptions import ToolError

from kkl import __version__, dtcdefs, piddefs, proto
from kkl.interfaces import AUTO, list_interfaces, open_interface
from kkl.link import KLine, hires_timer, now
from kkl.livepoll import NullLog, Poller
from kkl.log import RunLog

HERE = Path(__file__).resolve().parent
PROFILE_DEFAULT = HERE / "profiles" / "colt_cj4a_md353925.csv"
REFERENCE_DEFS = HERE / "pid_definicje.csv"  # Eclipse 4G63, ECU E4 3A: a hint, never the truth for this car
HYPOTHESES = HERE / "profiles" / "colt_hypotheses.csv"  # read-only: names, conversions, expected values, sources
PROTECTED = {HERE / n for n in ("pid_definicje.csv", "pid_definitions.csv", "dtc_definitions.csv",
                                "pid_profiles.csv")}
ANALYZER = HERE / "tools" / "analyze_readings.py"
ANALYZE_MODES = ("summary", "timeline", "window", "bits", "corr")

# ------------------------------------------------------------------ safety ---
# Hard-coded here, independent of kkl.proto: MUT 00-BF = sensor/RAM reads, FD-FF = ID reads.
# Nothing else is written to the K-line (see GuardedDevice) and no parameter changes that.
READ_ONLY = frozenset(range(0x00, 0xC0)) | {0xFD, 0xFE, 0xFF}
DUMP_PIDS = sorted(READ_ONLY)

KEEPALIVE_S = 2.0  # FE request when idle; the ECU drops the session after ~10-15 s without one
STALE_S = 8.0      # session idle longer than this is checked (and re-initialised) before use
MAX_PIDS, MAX_SAMPLES = 64, 500
# Init methods: proto's MUT-II 0x00 and OBD-II 0x33, plus 5-baud 0x01, which wakes the engine ECU on some cars
# (EvoEcu MUT_Protocol) but may be the A/T control unit on others: no full dump there until the IDs are compared.
INIT_METHODS = {**proto.INIT_METHODS,
                "mut01": {"addr": 0x01, "baud": 15625, "ack": False, "label": "MUT-II 0x01 @ 15625"}}
INIT_MODES = ("auto", *INIT_METHODS)
MAYBE_TCU = "mut01"
# Fault code bytes differ between ECU generations; on MD353925 all of these are candidates.
DTC_CANDIDATES = (0x36, 0x37, 0x38, 0x39, 0x3B, 0x3C, *range(0x40, 0x49), *range(0x4A, 0x4E))
DTC_LAYOUTS = {
    "mitsu-kkl Eclipse E4 3A": {"active": (0x40, 0x41), "stored": (0x45, 0x46)},
    "EvoEcu": {"active": (0x47, 0x48), "stored": (0x40, 0x41)},
    "MMCd 1990-94": {"active": (0x38, 0x39), "stored": (0x3B, 0x3C)},
}
DTC_ORDERS = {"mitsu-kkl": proto.DTC_CODES,
              "classic (MMCd/EvoScan)": (11, 12, 13, 14, 15, 21, 22, 23, 24, 25, 31, 41, 42, 43, 44, 36)}
NO_ECHO_HINT = ("the cable does not hear its own K-line echo: no power from OBD pin 16, switch not on K-line (7) "
                "or wrong interface; run selftest")
SILENT_HINT = ("the cable works (echo OK) but the ECU did not answer: ignition ON? OBD pin 1 grounded (jumper to "
               "pin 4)? then try init mut01")

PROFILE_HEADER = (
    "# Mitsubishi Colt CJ4A 1999, 4G92 1.6 SOHC, automatic, engine ECU MD353925, no O2 sensor (open loop).",
    "# Built only from logs of this car. A name ending in '?' is a hypothesis; without '?' it was confirmed",
    "# by a test (evidence in colt_cj4a_md353925_notes.md). Written by mcp_server.py (defs_set).",
)


class SafetyError(proto.SafetyError):
    pass


def check_read(pid):
    if pid not in READ_ONLY:
        raise SafetyError(f"MUT request 0x{pid:02X} refused: only read requests 00-BF and FD-FF are allowed "
                          "(C0-FC erase fault codes or drive actuators)")


def parse_pid(text):
    s = str(text).strip().upper()
    s = s[2:] if s.startswith("0X") else s
    if not re.fullmatch(r"[0-9A-F]{1,2}", s):
        raise ValueError(f"bad PID '{text}': expected hex 00-FF, e.g. '07'")
    pid = int(s, 16)
    check_read(pid)
    return pid


def init_order(mode, last_good=None):
    """Methods to try, in order; 'auto' tries all, the one that worked last first."""
    if mode in INIT_METHODS:
        return [mode]
    order = list(INIT_METHODS)
    if last_good in order:
        order.remove(last_good)
        order.insert(0, last_good)
    return order


def load_hypotheses(path):
    """colt_hypotheses.csv -> {pid: {pair, name, conversion, unit, expected, source, fn}}; bad lines are skipped."""
    out = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        f = [x.strip() for x in line.split(";")] + [""] * 7
        try:
            pid, pair = int(f[0], 16), int(f[1], 16) if f[1] else None
            check_read(pid)
            if pair is not None:
                check_read(pair)
            fn = piddefs.compile_conversion(f[3])
        except ValueError:
            continue
        out[pid] = {"pair": pair, "name": f[2], "conversion": f[3], "unit": f[4], "expected": f[5],
                    "source": f[6], "fn": fn}
    return out


def hx(pid):
    return f"{pid:02X}"


def slug(text, n=40):
    return re.sub(r"[^0-9A-Za-z_-]+", "-", text.strip())[:n].strip("-")


def stamp():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


class GuardedDevice:
    """Wraps the cable: every byte written to the K-line is checked here, under kkl.
    One exception: the single ~KB2 acknowledge byte of an OBD-II 0x33 init (ISO 9141-2
    handshake, not a MUT request), allowed only while that init runs."""

    def __init__(self, dev):
        self._dev = dev
        self.ack_budget = 0

    def __getattr__(self, name):
        return getattr(self._dev, name)

    def write(self, data):
        data = bytes(data)
        if any(b not in READ_ONLY for b in data):
            if not (self.ack_budget and len(data) == 1):
                raise SafetyError(f"K-line write {data.hex(' ').upper()} refused: only MUT read requests "
                                  "00-BF and FD-FF")
            self.ack_budget -= 1
        self._dev.write(data)


class Car:
    """The one cable session of this server. Every K-line exchange holds self.lock."""

    def __init__(self, iface=AUTO, init="auto", logdir=None, profile=None, keepalive=KEEPALIVE_S,
                 hypotheses=HYPOTHESES):
        self.iface_default, self.init_default = iface, init
        self.hyp = load_hypotheses(Path(hypotheses))
        self.logroot = Path(logdir).resolve() if logdir else HERE / "logs"
        self.profile = Path(profile).resolve() if profile else PROFILE_DEFAULT
        if self.profile in PROTECTED:
            raise ValueError(f"{self.profile.name} is a reference file of the original project; "
                             "use a separate profile")
        self.keepalive_s = keepalive
        self.lock = threading.RLock()
        self.defs_lock = threading.Lock()
        self.stop_ev = threading.Event()
        self.keeper = self.rec = None
        self._reset()

    def _reset(self):
        self.kl = self.dev = self.runlog = None
        self.iface_key = self.iface = self.ecu_id = self.init_label = self.last_good = None
        self.init_method = self.fd = None
        self.alive, self.last_ok, self.reinits, self.connected_at = False, 0.0, 0, None

    # -- files ---------------------------------------------------------------------------
    def logdir(self):
        """Where new files go: logs/, or logs/sim/ for the simulator (like kkl_probe)."""
        sim = (self.iface_key or self.iface_default or "").startswith("sim")
        d = self.logroot / "sim" if sim else self.logroot
        d.mkdir(parents=True, exist_ok=True)
        return d

    def rel(self, path):
        return Path(path).resolve().relative_to(self.logroot).as_posix()

    def log_path(self, file):
        p = Path(file)
        p = (p if p.is_absolute() else self.logroot / p).resolve()
        if not p.is_relative_to(self.logroot):
            raise ValueError(f"'{file}' is outside the logs folder")
        if not p.is_file():
            raise FileNotFoundError(f"no such log: {file} (see list_logs)")
        return p

    # -- connection ------------------------------------------------------------------------
    def connect(self, init=None, iface=None, rounds=3):
        init = init or self.init_default
        if init not in INIT_MODES:
            raise ValueError(f"init must be one of {', '.join(INIT_MODES)}")
        with self.lock:
            if self.kl:
                raise RuntimeError(f"already connected ({self.iface}); disconnect first")
            key = iface or self.iface_default
            self.dev = GuardedDevice(open_interface(key))
            self.iface_key, self.iface = key, getattr(self.dev, "label", key)
            self.kl = KLine(self.dev, NullLog())
            self.init_mode = init
            self.runlog = RunLog(self.logdir(), "mcp_connect", ["mcp_server", f"init={init}", key])
            hires_timer(True)
            try:
                self.kl.setup(15625, 1)
                self._init_session(rounds)
            except Exception:
                self._close()
                raise
            self.fd = self._query(0xFD)  # 0x20 on Evo ECUs (EvoEcu MUT_Protocol): one more identity byte
            self.connected_at = time.time()
            self.stop_ev.clear()
            if self.keepalive_s > 0:
                self.keeper = threading.Thread(target=self._keepalive, daemon=True)
                self.keeper.start()
            return self.status()

    def _init_session(self, rounds):
        """5-baud init (proto.mut with the parameters of INIT_METHODS, as proto.connect does), methods
        from init_order. Raises when the ECU stays silent, telling a deaf cable from a silent ECU."""
        self.alive, tried, echo = False, [], False
        self.kl.log = self.runlog  # byte-level log of the init only; polling would flood it
        try:
            for r in range(rounds):
                for method in init_order(self.init_mode, self.last_good):
                    p = INIT_METHODS[method]
                    params = {"method": method, "round": r}
                    self.runlog.begin(len(tried) + 1, "connect", params)
                    self.dev.ack_budget = 1 if p["ack"] else 0
                    try:
                        res = proto.mut(self.kl, self.runlog, addr=p["addr"], baud=p["baud"], ack=p["ack"],
                                        queries=proto.MUT_ID_QUERIES, require_ack=p["ack"])
                    finally:
                        self.dev.ack_budget = 0
                    self.runlog.end("connect", params, res)
                    # our own break comes back through the transceiver: proof that the cable hears the K-line
                    echo = echo or bool(res.get("loopback")) or res.get("alive_before", "-") != "-"
                    tried.append(f"{p['label']}: {res['outcome']}")
                    if res["outcome"] == "DATA":
                        self.ecu_id = "".join(q["resp"] for q in res["queries"])
                        self.init_label, self.init_method, self.last_good = p["label"], method, method
                        self.alive, self.last_ok = True, now()
                        return
                    self.kl.sleep(0.3)
                if r + 1 < rounds:
                    self.kl.sleep(2.0)
        finally:
            self.kl.log = NullLog()
        raise RuntimeError("ECU did not answer (" + "; ".join(tried) + "). "
                           + (SILENT_HINT if echo else NO_ECHO_HINT))

    def _require(self):
        if not self.kl:
            raise RuntimeError("not connected: call connect first")

    def _query(self, pid):
        check_read(pid)
        v = Poller._query(self.kl, pid)  # echo + 1 byte, 150 ms timeout
        if v is not None:
            self.last_ok = now()
        return v

    def _probe(self):
        return any(self._query(0xFE) is not None for _ in range(2))

    def _reinit(self):
        self.reinits += 1
        self.alive = False
        self.kl.sleep(0.5)
        self._init_session(rounds=2)

    def _read(self, pids):
        """One pass over `pids` -> {pid: value | None}; re-inits once if the session dropped."""
        for p in pids:
            check_read(p)
        with self.lock:
            self._require()
            if not self.alive or now() - self.last_ok > STALE_S:
                if not self._probe():
                    self._reinit()
            out, retried = {}, False
            for p in pids:
                v = self._query(p)
                if v is None and not retried and not self._probe():  # the ECU is gone, not just this PID
                    self._reinit()
                    retried, v = True, self._query(p)
                out[p] = v
            self.kl.trim()
            return out

    def _keepalive(self):
        while not self.stop_ev.wait(self.keepalive_s / 2):
            if now() - self.last_ok < self.keepalive_s or not self.lock.acquire(blocking=False):
                continue
            try:
                if self.kl and self.alive and not self._probe():
                    self.alive = False  # the next request re-inits
            except Exception:
                self.alive = False
            finally:
                self.lock.release()

    def disconnect(self):
        rec = self.record_stop() if self.rec else None
        self.stop_ev.set()
        if self.keeper:
            self.keeper.join(5)
            self.keeper = None
        with self.lock:
            was = self.kl is not None
            self._close()
        return {"disconnected": was, "recording": rec}

    def _close(self):
        if self.dev:
            try:
                self.dev.break_off()
            except Exception:
                pass
            try:
                self.dev.close()  # releases the COM port / D2XX handle
            except Exception:
                pass
            hires_timer(False)
        if self.runlog:
            self.runlog.close()
        self._reset()

    def status(self):
        with self.lock:
            st = {"connected": self.kl is not None, "session_alive": self.alive, "iface": self.iface,
                  "init": self.init_label, "ecu_id": self.ecu_id,
                  "fd": None if self.fd is None else f"{self.fd:02X}", "reinits": self.reinits,
                  "idle_s": round(now() - self.last_ok, 1) if self.kl else None,
                  "connected_for_s": round(time.time() - self.connected_at) if self.connected_at else None}
        if self.init_method == MAYBE_TCU:
            st["warning"] = ("connected through 5-baud 0x01: this may be the A/T control unit, not the engine ECU; "
                             "compare its ID with the 0x00 answer before mapping anything")
        rec = self.rec
        st["recording"] = rec.info() if rec else None
        st.update(profile=str(self.profile), logs=str(self.logroot), version=__version__,
                  safety="read-only: MUT 00-BF and FD-FF; C0-FC blocked; no fault code erase")
        return st

    def cable_info(self):
        """Interfaces seen by the system; nothing is sent."""
        out = {"version": __version__, "default_iface": self.iface_default,
               "interfaces": [{"key": i.key, "label": i.label} for i in list_interfaces()]}
        try:
            from kkl import ftdi_d2xx
            out["ftdi_d2xx"] = ftdi_d2xx.list_devices()
        except Exception as e:  # no ftd2xx.dll: COM port only
            out["ftdi_d2xx"] = f"not available ({e})"
        with self.lock:
            if self.dev:
                out["opened"] = self.dev.info()
        return out

    def selftest(self, iface=None):
        """Echo / break loopback (proto.selftest). Needs the cable to itself."""
        with self.lock:
            if self.kl:
                raise RuntimeError("connected: disconnect before selftest")
            key = iface or self.iface_default
            dev = GuardedDevice(open_interface(key))
            log = RunLog(self.logdir(), "mcp_selftest", ["mcp_server", key])
            kl = KLine(dev, log)
            try:
                kl.setup(10400, 1)
                res = proto.selftest(kl, log)
            finally:
                dev.close()
                log.close()
        hint = {"OK": "cable powered from OBD pin 16 and hears its own K-line echo",
                "NO_ECHO": "no echo: cable not powered (pin 16) or the switch is not on K-line (7)",
                "ECHO_BAD": "echo corrupted: wrong line selected, bad ground or a fake chip"}
        return {"iface": getattr(dev, "label", key), "outcome": res["outcome"],
                "meaning": hint.get(res["outcome"], ""), "summary": res["summary"], "log": self.rel(log.path)}

    # -- PID profile (this car only) -------------------------------------------------------
    def _defs(self):
        if self.profile.exists():
            defs, _problems, keep, _legacy = piddefs.load_defs(self.profile)
            return defs, keep
        return {}, list(PROFILE_HEADER)

    def _reference(self):
        if not REFERENCE_DEFS.exists():
            return {}
        return piddefs.load_defs(REFERENCE_DEFS)[0]

    @staticmethod
    def _status_of(d):
        if not d or not d.name:
            return "unknown"
        return "hypothesis" if d.name.rstrip().endswith("?") else "confirmed"

    def _meta(self, pid, defs):
        d = defs.get(pid)
        return {"pid": hx(pid), "name": d.name if d else "", "conversion": d.conv if d else "",
                "unit": d.unit if d else "", "status": self._status_of(d)}

    @staticmethod
    def _conv(d):
        try:
            return piddefs.compile_conversion(d.conv) if d else None
        except ValueError:
            return None

    def _hyp(self, pid, vals=None):
        """The hypothesis for `pid` (colt_hypotheses.csv), evaluated on `vals` when given; a pair
        (e.g. 29+2A) is converted as the 16-bit value 256*high + low."""
        h = self.hyp.get(pid)
        if not h:
            return None
        out = {k: h[k] for k in ("name", "conversion", "unit", "expected", "source") if h[k]}
        out["status"] = "hypothesis, not confirmed on MD353925"
        if h["pair"] is not None:
            out["pair"] = f"{hx(pid)}+{hx(h['pair'])}"
        if vals is not None:
            x = vals.get(pid)
            if h["pair"] is not None:
                lo = vals.get(h["pair"])
                x = out["raw16"] = None if x is None or lo is None else x * 256 + lo
            if x is not None and h["fn"]:
                out["value"] = h["fn"](x)
        return out

    def defs_get(self, pid=None):
        defs, _ = self._defs()
        if pid is not None:
            p = parse_pid(pid)
            out = self._meta(p, defs)
            h = self._hyp(p)
            if h:
                out["hypothesis"] = h
            r = self._reference().get(p)
            if r and (r.name or r.conv):
                out["eclipse_reference"] = {"name": r.name, "conversion": r.conv, "unit": r.unit,
                                            "status": "hypothesis only (Eclipse 4G63, ECU E4 3A)"}
            return out
        rows = [self._meta(p, defs) for p, d in sorted(defs.items()) if d.name or d.conv or d.unit]
        return {"profile": str(self.profile), "defined": rows, "hypotheses": len(self.hyp),
                "note": "only this car's profile; ask for one PID to see the hypothesis and the Eclipse hint"}

    def defs_set(self, pid, name, conversion="", unit="", confirmed=False, evidence=""):
        p = parse_pid(pid)
        piddefs.compile_conversion(conversion)  # ValueError if invalid
        name = name.strip().replace(";", ",").rstrip(" ?")
        if name and not confirmed:
            name += " ?"
        with self.defs_lock:
            defs, keep = self._defs()
            d = defs.setdefault(p, piddefs.PidDef(p))
            d.name, d.conv, d.unit = name, conversion.strip(), unit.strip().replace(";", ",")
            self.profile.parent.mkdir(parents=True, exist_ok=True)
            piddefs.save_defs(self.profile, defs, keep)
            self._note(p, d, evidence)
        return self._meta(p, defs)

    def _note(self, pid, d, evidence):
        notes = self.profile.with_name(self.profile.stem + "_notes.md")
        new = not notes.exists()
        cell = lambda s: str(s).replace("|", "/").replace("\n", " ")  # noqa: E731
        with open(notes, "a", encoding="utf-8") as f:
            if new:
                f.write(f"# {self.profile.stem}: PID map changes\n\n"
                        "| time | PID | name | conversion | unit | status | evidence |\n|---|---|---|---|---|---|---|\n")
            f.write(f"| {datetime.datetime.now():%Y-%m-%d %H:%M} | {hx(pid)} | {cell(d.name)} | {cell(d.conv)} | "
                    f"{cell(d.unit)} | {self._status_of(d)} | {cell(evidence)} |\n")

    # -- reading -----------------------------------------------------------------------------
    @staticmethod
    def _pid_list(pids):
        if isinstance(pids, str):
            pids = pids.replace(" ", ",").split(",")
        plist = []
        for x in pids:
            if str(x).strip():
                p = parse_pid(x)
                if p not in plist:
                    plist.append(p)
        if not plist:
            raise ValueError("empty PID list")
        if len(plist) > MAX_PIDS:
            raise ValueError(f"at most {MAX_PIDS} PIDs per call (use mutdump for all)")
        return plist

    def read_pids(self, pids, samples=1, interval_ms=0):
        plist = self._pid_list(pids)
        if not 1 <= samples <= MAX_SAMPLES:
            raise ValueError(f"samples must be 1-{MAX_SAMPLES}")
        defs, _ = self._defs()
        partners = [h["pair"] for p in plist if (h := self.hyp.get(p)) and h["pair"] is not None]
        reads = plist + [q for q in dict.fromkeys(partners) if q not in plist]  # low bytes of 16-bit pairs
        series, ts, t0 = {p: [] for p in reads}, [], time.time()
        for i in range(samples):
            vals = self._read(reads)
            ts.append(round(time.time() - t0, 3))
            for p in reads:
                series[p].append(vals[p])
            if interval_ms > 0 and i + 1 < samples:
                time.sleep(min(interval_ms, 60000) / 1000)  # outside the lock: keep-alive / recording go on
        rows = []
        for p in plist:
            vs, conv = series[p], self._conv(defs.get(p))
            row = self._meta(p, defs)
            row["raw"] = vs[-1]
            if conv and vs[-1] is not None:
                row["converted"] = conv(vs[-1])
            good = [v for v in vs if v is not None]
            if samples > 1:
                row.update(series=vs, min=min(good, default=None), max=max(good, default=None),
                           mean=round(statistics.fmean(good), 2) if good else None)
            h = self._hyp(p, {q: s[-1] for q, s in series.items()})
            if h:
                row["hypothesis"] = h
            rows.append(row)
        out = {"ecu_id": self.ecu_id, "samples": samples, "values": rows}
        if samples > 1:
            out["t_s"] = ts
        return out

    def mutdump(self, note=""):
        if self.init_method == MAYBE_TCU:
            raise RuntimeError("connected through 0x01, which may be the A/T control unit: no full dump until its ID "
                               "is compared with the 0x00 answer; read single requests with read_pids")
        vals = self._read(DUMP_PIDS)
        path = self.logdir() / f"{stamp()}_mutdump_mcp{'_' + slug(note) if slug(note) else ''}.json"
        rec = {"kind": "mcp_mutdump", "wall": datetime.datetime.now().isoformat(timespec="seconds"),
               "note": note, "ecu_id": self.ecu_id, "iface": self.iface, "init": self.init_label,
               "table": {hx(p): v for p, v in vals.items()}}
        path.write_text(json.dumps(rec, indent=1), encoding="utf-8")
        grid = []
        for row in range(0x00, 0x100, 0x10):
            cells = [vals.get(p, "") for p in range(row, row + 0x10)]
            if any(c != "" for c in cells):
                grid.append(f"{row:02X}: " + " ".join("  " if c == "" else "--" if c is None else f"{c:02X}"
                                                     for c in cells))
        answered = sum(v is not None for v in vals.values())
        pairs = {f"{hx(p)}+{hx(h['pair'])}": self._hyp(p, vals).get("raw16")
                 for p, h in self.hyp.items() if h["pair"] is not None}
        return {"file": self.rel(path), "answered": answered, "of": len(vals), "hex_grid": grid, "pairs_16bit": pairs,
                "legend": "row = high nibble, column = low nibble; -- no answer, blank = not requested"}

    @staticmethod
    def _load_dump(path):
        """mcp_server .json dump or kkl_probe mutdump .jsonl -> (table {pid: int|None}, meta)."""
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            rec = json.loads(text)
            return {k: v for k, v in rec["table"].items()}, {"note": rec.get("note"), "wall": rec.get("wall")}
        table, meta = None, {}
        for line in text.splitlines():
            ev = json.loads(line)
            if ev.get("ev") == "run_start":
                meta = {"note": ev.get("note"), "wall": ev.get("wall")}
            elif ev.get("ev") == "attempt_end" and "table" in ev.get("result", {}):
                table = ev["result"]["table"]
        if table is None:
            raise ValueError(f"{path.name}: no dump table inside")
        return {k: int(v, 16) if re.fullmatch(r"[0-9A-F]{2}", v) else None for k, v in table.items()}, meta

    def diff_dumps(self, a, b, min_delta=1):
        pa, pb = self.log_path(a), self.log_path(b)
        (ta, ma), (tb, mb) = self._load_dump(pa), self._load_dump(pb)
        defs, _ = self._defs()
        changed, lost, same = [], [], 0
        for k in sorted(set(ta) | set(tb)):
            va, vb = ta.get(k), tb.get(k)
            if va is None or vb is None:
                if va != vb:
                    lost.append({"pid": k, "a": va, "b": vb})
                continue
            if abs(vb - va) < max(1, min_delta):
                same += 1
                continue
            row = {"pid": k, "a": va, "b": vb, "delta": vb - va,
                   "bits_flipped": [i for i in range(8) if (va ^ vb) >> i & 1]}
            m = self._meta(int(k, 16), defs)
            if m["name"]:
                row.update(name=m["name"], status=m["status"])
            changed.append(row)
        changed.sort(key=lambda r: -abs(r["delta"]))
        return {"a": {"file": self.rel(pa), **ma}, "b": {"file": self.rel(pb), **mb},
                "changed": changed, "answer_changed": lost, "unchanged": same}

    def dtc_read(self):
        """Every fault code byte candidate, decoded per source layout and bit order (all hypotheses)."""
        vals = self._read(list(DTC_CANDIDATES))
        layouts = {}
        for src, kinds in DTC_LAYOUTS.items():
            layouts[src] = {}
            for kind, (lo, hi) in kinds.items():
                a, b = vals[lo], vals[hi]
                e = {"pids": f"{hx(lo)}/{hx(hi)}", "raw": [a, b]}
                if a is None or b is None:
                    e["error"] = "no answer"
                else:
                    e["bits"] = [i for i in range(16) if (a | b << 8) >> i & 1]
                    e["codes"] = {o: [dtcdefs.label(order[i]) for i in e["bits"]] for o, order in DTC_ORDERS.items()}
                layouts[src][kind] = e
        return {"raw": {hx(p): v for p, v in vals.items()}, "layouts": layouts,
                "note": ("which bytes hold the codes on MD353925 and the bit -> code order are unknown: unplug one "
                         "sensor (ignition off), compare dtc_read before/after and count check-engine blinks with "
                         "pin 1 grounded. Fault code erase is not available here.")}

    # -- recording -----------------------------------------------------------------------------
    def record_start(self, pids, note="", interval_ms=0, max_minutes=60):
        plist = self._pid_list(pids)
        with self.lock:
            self._require()
            if self.rec:
                raise RuntimeError(f"already recording to {self.rec.info()['file']}; record_stop first")
            defs, _ = self._defs()
            name = f"{stamp()}_readings_mcp{'_' + slug(note) if slug(note) else ''}.csv"
            self.rec = Recorder(self, self.logdir() / name, plist, defs, note, interval_ms, max_minutes)
        self.rec.start()
        return self.rec.info()

    def record_stop(self):
        rec = self.rec
        if not rec:
            raise RuntimeError("not recording")
        rec.stop()
        self.rec = None
        return rec.info()

    # -- analysis -------------------------------------------------------------------------------
    def analyze(self, file, mode="summary", args=None):
        if mode not in ANALYZE_MODES:
            raise ValueError(f"mode must be one of {', '.join(ANALYZE_MODES)}")
        path = self.log_path(file)
        cmd = [sys.executable, str(ANALYZER), mode, str(path), *[str(a) for a in args or []]]
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        if r.returncode:
            raise RuntimeError((r.stderr or r.stdout).strip()[-2000:] or f"analyzer exit code {r.returncode}")
        out = r.stdout
        if len(out) > 30000:
            out = out[:30000] + f"\n... ({len(r.stdout) - 30000} more characters cut)"
        return {"file": self.rel(path), "mode": mode, "output": out}

    def list_logs(self, limit=50):
        files = [p for p in self.logroot.rglob("*") if p.is_file() and not p.name.endswith(".meta.json")]
        files.sort(key=lambda p: -p.stat().st_mtime)
        kinds = (("_mutdump", "dump"), ("_readings", "readings"), ("_gui_changes", "changes"),
                 ("_odczyty", "readings"), ("attempts.jsonl", "attempts"))
        out = []
        for p in files[:max(1, limit)]:
            st = p.stat()
            out.append({"file": self.rel(p), "size": st.st_size,
                        "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                        "kind": next((k for s, k in kinds if s in p.name), "log")})
        return {"logs": str(self.logroot), "count": len(files), "files": out}


class Recorder(threading.Thread):
    """Polls a PID list into a CSV in mut_gui's readings format (tools/analyze_readings.py reads it)."""

    def __init__(self, car, path, pids, defs, note, interval_ms, max_minutes):
        super().__init__(daemon=True)
        self.car, self.path, self.pids, self.note = car, path, pids, note
        self.interval = max(0, interval_ms) / 1000
        self.max_s = max(1, max_minutes) * 60
        self.convs = {p: Car._conv(defs.get(p)) for p in pids}
        self.header = ["time", "t [s]"]
        for p in pids:
            d = defs.get(p)
            base = f"{hx(p)} {d.name if d else ''}".strip().replace("[", "(").replace("]", ")")
            self.header.append(base)
            if self.convs[p]:
                self.header.append(f"{base} [{d.unit}]" if d.unit else f"{base} (converted)")
        self.stop_ev = threading.Event()
        self.rows, self.errors, self.last_error, self.t0, self.t_end = 0, 0, None, time.time(), None
        self.f = open(path, "w", newline="", encoding="utf-8-sig")
        self.w = csv.writer(self.f)
        self.w.writerow(self.header)
        self._meta()

    def _meta(self):
        meta = {"note": self.note, "pids": [hx(p) for p in self.pids], "ecu_id": self.car.ecu_id,
                "iface": self.car.iface, "start": datetime.datetime.fromtimestamp(self.t0).isoformat(timespec="seconds"),
                "end": None if self.t_end is None else
                datetime.datetime.fromtimestamp(self.t_end).isoformat(timespec="seconds"), "rows": self.rows}
        self.path.with_name(self.path.stem + ".meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")

    def run(self):
        try:
            while not self.stop_ev.is_set() and time.time() - self.t0 < self.max_s:
                try:
                    vals = self.car._read(self.pids)
                except Exception as e:  # lost session that would not come back: keep trying
                    self.errors, self.last_error = self.errors + 1, f"{type(e).__name__}: {e}"
                    if not self.car.kl:
                        break
                    self.stop_ev.wait(1.0)
                    continue
                wall = time.time()
                row = [f"{datetime.datetime.fromtimestamp(wall):%H:%M:%S.%f}"[:-3], f"{wall - self.t0:.3f}"]
                for p in self.pids:
                    v = vals[p]
                    row.append("" if v is None else v)
                    if self.convs[p]:
                        row.append("" if v is None else self.convs[p](v))
                self.w.writerow(row)
                self.rows += 1
                if self.rows % 20 == 0:
                    self.f.flush()
                if self.interval:
                    self.stop_ev.wait(self.interval)
        finally:
            self.t_end = time.time()
            self.f.close()
            self._meta()

    def stop(self):
        self.stop_ev.set()
        self.join(10)

    def info(self):
        end = self.t_end or time.time()
        return {"file": self.car.rel(self.path), "pids": [hx(p) for p in self.pids], "note": self.note,
                "rows": self.rows, "duration_s": round(end - self.t0, 1), "running": self.t_end is None,
                "errors": self.errors, "last_error": self.last_error}


INSTRUCTIONS = """\
MUT-II diagnostics of a Mitsubishi engine ECU over a VAG KKL (FTDI) cable. Car: Mitsubishi Colt CJ4A 1999,
4G92 1.6 SOHC, automatic, engine ECU MD353925, no O2 sensor (open loop). There is no known PID map for this
ECU: we build it from this car's logs. Names from the Eclipse 4G63 map (ECU E4 3A, defs_get 'eclipse_reference')
are hypotheses only, as are the entries of profiles/colt_hypotheses.csv shown as 'hypothesis' next to values
(EvoEcu, EvoScan, MMCd, Lancer '99 manual excerpts, with expected warm-idle values). Never present a PID meaning as fact unless a logged test confirmed it; save unconfirmed
meanings with defs_set(confirmed=false) and give evidence (file, time, values) for every defs_set.
Typical flow: selftest -> connect -> read_pids / mutdump -> change ONE thing on the car -> mutdump -> diff_dumps;
record_start/record_stop for events, then analyze. Read-only: MUT 00-BF and FD-FF; C0-FC is blocked and
fault codes cannot be erased from here.
"""


def build_server(car):
    server = MCPServer("mitsu-kkl", instructions=INSTRUCTIONS)

    def tool(fn):
        """Register a blocking tool; it runs in a worker thread so the server stays responsive.
        Errors become ToolError, so the model sees the reason (mcp 2.x hides other exceptions' text)."""
        @functools.wraps(fn)
        async def run(*args, **kwargs):
            try:
                return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))
            except ToolError:
                raise
            except Exception as e:
                raise ToolError(str(e) or type(e).__name__) from e
        server.tool()(run)
        return fn

    @tool
    def cable_info() -> dict:
        """List the K-line interfaces on this computer (FTDI D2XX devices, COM ports) and the default one.
        Sends nothing to the car."""
        return car.cable_info()

    @tool
    def selftest(iface: str = "") -> dict:
        """Cable self-test (echo and break loopback at 10400/15625 baud): tells whether the cable is powered from
        OBD pin 16 and hears the K-line. Only while disconnected. iface: e.g. 'auto', 'd2xx:#0', 'serial:COM5',
        'sim:mutlive'; empty = server default."""
        return car.selftest(iface or None)

    @tool
    def connect(init: Literal["auto", "mut00", "obd33", "mut01"] = "auto", iface: str = "") -> dict:
        """Open the MUT-II session with the engine ECU (ignition ON, pin 1 grounded). init: auto = try 0x00, 0x33,
        0x01 in turn; mut00 = 5-baud 0x00 @ 15625; obd33 = ISO 9141-2 0x33 @ 10400; mut01 = 5-baud 0x01 @ 15625
        (engine ECU on some cars, possibly the A/T unit on others: status warns, mutdump refuses). Only one session
        at a time; kept alive and re-initialised automatically if the ECU drops it. On failure the error says
        whether the cable heard its own echo (cable problem) or the ECU stayed silent."""
        return car.connect({"auto": "auto", "mut00": "mut", "obd33": "obd", "mut01": "mut01"}[init], iface or None)

    @tool
    def disconnect() -> dict:
        """Stop any recording, end the session and release the cable/COM port."""
        return car.disconnect()

    @tool
    def status() -> dict:
        """Connection, ECU ID, init method, idle time, re-init count, recording, profile and logs folder."""
        return car.status()

    @tool
    def read_pids(pids: list[str], samples: int = 1, interval_ms: int = 0) -> dict:
        """Read MUT PIDs (hex strings like '07', '21'; only 00-BF and FD-FF). samples > 1 polls repeatedly
        (interval_ms between passes) and returns series with min/max/mean. Each value carries the name, conversion
        and status (confirmed / hypothesis / unknown) from this car's profile, plus 'hypothesis' from
        colt_hypotheses.csv (name, value, expected range, source); 16-bit pairs such as 29+2A are read together."""
        return car.read_pids(pids, samples, interval_ms)

    @tool
    def mutdump(note: str = "") -> dict:
        """Read every readable PID 00-BF and FD-FF once and save it as logs/<time>_mutdump_mcp_<note>.json.
        Put the car state in note (e.g. 'cold, ignition on, engine off')."""
        return car.mutdump(note)

    @tool
    def diff_dumps(a: str, b: str, min_delta: int = 1) -> dict:
        """Compare two dumps (files from list_logs; also reads kkl_probe *_mutdump.jsonl): PIDs whose value changed,
        by how much and which bits flipped, largest change first."""
        return car.diff_dumps(a, b, min_delta)

    @tool
    def record_start(pids: list[str], note: str = "", interval_ms: int = 0, max_minutes: int = 60) -> dict:
        """Start recording PIDs to logs/<time>_readings_mcp_<note>.csv (mut_gui format) until record_stop,
        disconnect or max_minutes. Few PIDs (3-8) give a fast cycle; 0 interval = as fast as possible."""
        return car.record_start(pids, note, interval_ms, max_minutes)

    @tool
    def record_stop() -> dict:
        """Stop the recording; returns file, rows and duration."""
        return car.record_stop()

    @tool
    def analyze(file: str, mode: Literal["summary", "timeline", "window", "bits", "corr"] = "summary",
                args: list[str] | None = None) -> dict:
        """Run tools/analyze_readings.py on a recording from list_logs. args per mode: summary: none;
        timeline: ['21,10,24']; window: ['26', '34'] (seconds); bits: ['A8,71']; corr: ['17']."""
        return car.analyze(file, mode, args)

    @tool
    def dtc_read() -> dict:
        """Read every fault code byte candidate (36-39, 3B, 3C, 40-48, 4A-4D) and decode them per source layout
        (Eclipse, EvoEcu, MMCd) and bit order: all hypotheses on this ECU. Erasing fault codes is not available."""
        return car.dtc_read()

    @tool
    def defs_get(pid: str = "") -> dict:
        """This car's PID map (profile file). With a pid: its entry plus the Eclipse reference name as a hint."""
        return car.defs_get(pid or None)

    @tool
    def defs_set(pid: str, name: str, conversion: str = "", unit: str = "", confirmed: bool = False,
                 evidence: str = "") -> dict:
        """Save a PID name/conversion/unit to this car's profile only (the original project's files are never
        changed). conversion: expression in x (raw byte), e.g. 'x-40', 'x*31.25', or 'bin'. confirmed=false adds
        '?' to the name (hypothesis). evidence: file, time and values that support it. Empty name clears the PID."""
        return car.defs_set(pid, name, conversion, unit, confirmed, evidence)

    @tool
    def list_logs(limit: int = 50) -> dict:
        """Files in the logs folder (dumps, recordings, connection logs), newest first."""
        return car.list_logs(limit)

    return server


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", default=os.environ.get("MITSU_KKL_IFACE", AUTO),
                    help="auto | d2xx:#0 | d2xx:<serial> | serial:COM5 | sim:mutlive (default auto)")
    ap.add_argument("--init", choices=INIT_MODES, default="auto", help="default init for connect")
    ap.add_argument("--logdir", help="default: logs/ next to this file")
    ap.add_argument("--profile", help=f"PID profile of this car (default {PROFILE_DEFAULT.relative_to(HERE)})")
    args = ap.parse_args(argv)
    car = Car(args.iface, args.init, args.logdir, args.profile)
    try:
        build_server(car).run()  # stdio
    finally:
        car.disconnect()


if __name__ == "__main__":
    main()
