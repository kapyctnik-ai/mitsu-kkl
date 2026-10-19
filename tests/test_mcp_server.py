"""mcp_server.py against the built-in ECU simulator (kkl/sim.py, model 'mutlive'). No hardware.

  python -m pytest tests -v
"""

import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import mcp_server as m  # noqa: E402
from kkl import proto  # noqa: E402

BLOCKED = ["C0", "CA", "F1", "FC", "0xF5"]


class Spy:
    """Records every byte the server writes to the (simulated) cable."""

    def __init__(self, car):
        self.sent = bytearray()
        inner = car.dev._dev
        orig = inner.write

        def write(data):
            self.sent += bytes(data)
            orig(data)
        inner.write = write


def make_car(tmp, **kw):
    return m.Car("sim:mutlive", logdir=tmp / "logs", profile=tmp / "profiles" / "colt.csv", **kw)


@pytest.fixture(scope="module")
def car(tmp_path_factory):
    c = make_car(tmp_path_factory.mktemp("car"))
    c.connect("auto")
    yield c
    c.disconnect()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_connect_status(car):
    st = car.status()
    assert st["connected"] and st["session_alive"]
    assert st["ecu_id"] == "E4B3"
    assert st["init"].startswith("MUT-II 0x00")
    assert "simulator" in st["iface"]
    assert st["fd"] is None and "warning" not in st  # the simulator does not answer FD


def test_one_session_at_a_time(car):
    with pytest.raises(RuntimeError, match="already connected"):
        car.connect()
    with pytest.raises(RuntimeError, match="disconnect"):
        car.selftest()


def test_read_pids(car):
    r = car.read_pids(["07", "21", "0x17", "FE"])
    vals = {v["pid"]: v for v in r["values"]}
    assert set(vals) == {"07", "21", "17", "FE"}
    assert vals["FE"]["raw"] == 0xE4
    assert all(v["raw"] is not None for v in vals.values())
    r = car.read_pids(["21", "17"], samples=5, interval_ms=20)
    assert len(r["t_s"]) == 5
    for v in r["values"]:
        assert len(v["series"]) == 5 and v["min"] <= v["mean"] <= v["max"]


def test_read_pids_uses_profile_conversion(car):
    car.defs_set("21", "engine speed", "x*31.25", "rpm", evidence="test")
    v = car.read_pids(["21"])["values"][0]
    assert v["name"] == "engine speed ?" and v["status"] == "hypothesis"
    assert float(v["converted"]) == v["raw"] * 31.25


@pytest.mark.parametrize("pid", BLOCKED)
def test_c0_fc_blocked(car, pid):
    spy = Spy(car)
    for call in (lambda: car.read_pids([pid]), lambda: car.read_pids(["07", pid]),
                 lambda: car.record_start([pid]), lambda: car.defs_set(pid, "x"),
                 lambda: car.defs_get(pid)):
        with pytest.raises(m.SafetyError, match="refused"):
            call()
    assert not any(0xC0 <= b <= 0xFC for b in spy.sent)
    assert car.rec is None


def test_guard_at_cable_level():
    class Dev:
        sent = b""

        def write(self, data):
            Dev.sent += bytes(data)

    g = m.GuardedDevice(Dev())
    for b in range(0x100):
        if b in m.READ_ONLY:
            g.write([b])
        else:
            with pytest.raises(m.SafetyError):
                g.write([b])
    assert not any(0xC0 <= b <= 0xFC for b in Dev.sent)
    g.ack_budget = 1  # only an OBD-II init gets one ~KB2 byte, never a multi-byte write
    with pytest.raises(m.SafetyError):
        g.write([0xCA, 0xCA])
    g.write([0xF7])
    with pytest.raises(m.SafetyError):
        g.write([0xCA])
    assert isinstance(m.SafetyError("x"), proto.SafetyError)


def test_no_unsafe_tools():
    car = m.Car("sim:mutlive")
    names = {t.name for t in asyncio.run(m.build_server(car).list_tools())}
    assert names == {"cable_info", "selftest", "connect", "disconnect", "status", "read_pids", "mutdump",
                     "diff_dumps", "record_start", "record_stop", "analyze", "dtc_read", "defs_get", "defs_set",
                     "list_logs"}
    src = (ROOT / "mcp_server.py").read_text(encoding="utf-8")
    assert "mut_clear" not in src and "CLEAR_CMD" not in src


def test_mutdump_and_diff(car):
    a = car.mutdump("cold engine off")
    assert a["of"] == len(m.DUMP_PIDS) == 195
    assert a["answered"] == 194  # the simulator does not answer FD
    assert a["file"].startswith("sim/") and "cold-engine-off" in a["file"]
    assert len(a["hex_grid"]) == 13
    assert a["pairs_16bit"]["29+2A"] == sim_value(0x29) * 256 + sim_value(0x2A) and "80+81" in a["pairs_16bit"]
    path = car.logroot / a["file"]
    rec = json.loads(path.read_text(encoding="utf-8"))
    assert rec["note"] == "cold engine off" and rec["ecu_id"] == "E4B3"
    # a second dump with known changes
    rec["table"]["10"] = rec["table"]["10"] ^ 0x81
    rec["table"]["3A"] = (rec["table"]["3A"] + 40) & 0xFF
    rec["table"]["50"] = None
    b = path.with_name("b_mutdump.json")
    b.write_text(json.dumps(rec), encoding="utf-8")
    d = car.diff_dumps(a["file"], "sim/b_mutdump.json")
    got = {c["pid"]: c for c in d["changed"]}
    assert set(got) >= {"10", "3A"}
    assert got["10"]["bits_flipped"] == [0, 7]
    assert d["answer_changed"] == [{"pid": "50", "a": rec_a(path)["50"], "b": None}]
    real = car.diff_dumps(a["file"], car.mutdump("again")["file"])
    assert real["unchanged"] + len(real["changed"]) + len(real["answer_changed"]) == 194  # FD: no answer in both


def rec_a(path):
    return json.loads(path.read_text(encoding="utf-8"))["table"]


def test_diff_reads_kkl_probe_dump(car, tmp_path):
    rows = [{"ev": "run_start", "note": "probe", "wall": "2026-01-01T10:00:00"},
            {"ev": "attempt_end", "result": {"table": {"07": "87", "10": "-", "21": "00"}}}]
    p = car.logroot / "x_mutdump.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    rows[1]["result"]["table"]["21"] = "1A"
    q = car.logroot / "y_mutdump.jsonl"
    q.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    d = car.diff_dumps("x_mutdump.jsonl", "y_mutdump.jsonl")
    assert d["changed"] == [{"pid": "21", "a": 0, "b": 26, "delta": 26, "bits_flipped": [1, 3, 4],
                             "name": "engine speed ?", "status": "hypothesis"}]
    assert d["a"]["note"] == "probe"


def test_paths_stay_in_logs(car):
    with pytest.raises(ValueError, match="outside"):
        car.diff_dumps("../../etc/passwd", "x")
    with pytest.raises(ValueError, match="outside"):
        car.analyze(str(ROOT / "README.md"))


def test_record_and_analyze(car):
    info = car.record_start(["07", "21", "17"], note="throttle sweep")
    assert info["running"] and car.status()["recording"]
    with pytest.raises(RuntimeError, match="already recording"):
        car.record_start(["07"])
    time.sleep(1.0)
    car.read_pids(["14"])  # reading still works while recording
    time.sleep(1.5)
    done = car.record_stop()
    assert not done["running"] and done["rows"] > 10 and done["errors"] == 0
    csv_path = car.logroot / done["file"]
    head = csv_path.read_text(encoding="utf-8-sig").splitlines()[0]
    assert head.startswith("time,t [s],07,21 engine speed ?,21 engine speed ? [rpm],17")
    meta = json.loads(csv_path.with_name(csv_path.stem + ".meta.json").read_text(encoding="utf-8"))
    assert meta["note"] == "throttle sweep" and meta["rows"] == done["rows"]

    out = car.analyze(done["file"], "summary")["output"]
    assert f"rows={done['rows']}" in out
    assert "[21]" in car.analyze(done["file"], "timeline", ["21,17"])["output"]
    assert "wall time" in car.analyze(done["file"], "window", ["0", "2"])["output"]
    car.analyze(done["file"], "bits", ["17"])
    assert "r=" in car.analyze(done["file"], "corr", ["21"])["output"]
    with pytest.raises(ValueError):
        car.analyze(done["file"], "rm")
    with pytest.raises(RuntimeError):
        car.analyze(done["file"], "corr", ["99"])

    logs = car.list_logs()
    kinds = {f["file"]: f["kind"] for f in logs["files"]}
    assert kinds[done["file"]] == "readings"
    assert not any(f.endswith(".meta.json") for f in kinds)


def sim_value(pid):
    return (pid * 37 + 11) & 0xFF  # kkl/sim.py 'mutlive' answer for PIDs without a model


def test_dtc_read(car):
    r = car.dtc_read()
    assert len(r["raw"]) == 19 and set(r["raw"]) >= {"36", "38", "3B", "40", "45", "47", "4D"}
    assert r["raw"]["47"] == sim_value(0x47)
    assert set(r["layouts"]) == set(m.DTC_LAYOUTS)
    for layout in r["layouts"].values():
        for e in layout.values():
            assert len(e["raw"]) == 2 and set(e["codes"]) == set(m.DTC_ORDERS)
            assert all(len(c) == len(e["bits"]) for c in e["codes"].values())
    assert "unknown" in r["note"]


def test_hypotheses(car):
    n = sum(1 for line in m.HYPOTHESES.read_text(encoding="utf-8-sig").splitlines()
            if line.strip() and not line.startswith("#"))
    assert len(car.hyp) == n  # every line of the file is valid
    assert all(0xC0 > p or p >= 0xFD for p in car.hyp)
    v = {x["pid"]: x for x in car.read_pids(["10", "29"])["values"]}
    assert "2A" not in v  # the low byte is read, but not listed as its own value
    h = v["29"]["hypothesis"]
    raw16 = v["29"]["raw"] * 256 + sim_value(0x2A)
    assert h["pair"] == "29+2A" and h["raw16"] == raw16 and float(h["value"]) == round(raw16 / 1000, 2)
    assert "not confirmed" in h["status"] and h["expected"] == "1.7-2.9"
    assert v["10"]["hypothesis"]["value"] == str(v["10"]["raw"] - 40)
    g = car.defs_get("29")
    assert g["hypothesis"]["source"] == "E, M, L" and "value" not in g["hypothesis"]


def test_init_order():
    assert m.init_order("auto") == ["mut", "obd", "mut01"]
    assert m.init_order("auto", "mut01") == ["mut01", "mut", "obd"]
    assert m.init_order("obd") == ["obd"]
    assert m.INIT_METHODS["mut01"]["addr"] == 0x01


def test_mut01_no_dump(car):
    car.init_method = "mut01"
    try:
        assert "A/T" in car.status()["warning"]
        with pytest.raises(RuntimeError, match="A/T control unit"):
            car.mutdump("x")
        car.read_pids(["FE"])  # single reads still work
    finally:
        car.init_method = "mut"


@pytest.mark.parametrize("model, hint", [("dead", "does not hear"), ("none", "echo OK")])
def test_connect_failure_says_cable_or_ecu(tmp_path, model, hint):
    c = m.Car(f"sim:{model}", logdir=tmp_path / "logs", profile=tmp_path / "colt.csv")
    with pytest.raises(RuntimeError, match=hint):
        c.connect("mut", rounds=1)
    assert not c.status()["connected"]  # port released after the failed attempt


def test_defs_only_touch_colt_profile(car):
    ref = ROOT / "pid_definicje.csv"
    before = {p: sha(p) for p in (ref, ROOT / "dtc_definitions.csv")}
    e = car.defs_set("10", "coolant temp", "x-40", "°C", confirmed=True, evidence="dump a/b")
    assert e == {"pid": "10", "name": "coolant temp", "conversion": "x-40", "unit": "°C", "status": "confirmed"}
    g = car.defs_get("10")
    assert g["status"] == "confirmed" and "Eclipse" in g["eclipse_reference"]["status"]
    with pytest.raises(ValueError):
        car.defs_set("11", "bad", "import os")
    assert car.defs_get("11")["status"] == "unknown"
    assert {r["pid"] for r in car.defs_get()["defined"]} >= {"10", "21"}
    assert {p: sha(p) for p in before} == before
    assert "coolant temp" in car.profile.read_text(encoding="utf-8-sig")
    assert "dump a/b" in car.profile.with_name("colt_notes.md").read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="reference file"):
        m.Car("sim:mutlive", profile=ref)


def test_selftest_reinit_and_release(tmp_path):
    c = make_car(tmp_path, keepalive=0)  # no keep-alive: let the session time out
    st = c.selftest()
    assert st["outcome"] == "OK"
    c.connect("mut")
    assert c.read_pids(["07"])["values"][0]["raw"] is not None
    time.sleep(6.0)  # the simulated ECU drops the session after 5 s without requests
    assert c.read_pids(["21"])["values"][0]["raw"] is not None
    assert c.status()["reinits"] == 1
    assert c.disconnect()["disconnected"]
    assert not c.status()["connected"]
    with pytest.raises(RuntimeError, match="not connected"):
        c.read_pids(["07"])
    c.connect()  # cable released: a new session opens
    c.disconnect()


def test_keepalive_holds_session(tmp_path):
    c = make_car(tmp_path, keepalive=1.0)
    c.connect("mut")
    try:
        time.sleep(6.5)
        c.read_pids(["07"])
        assert c.status()["reinits"] == 0
    finally:
        c.disconnect()


def test_stdio_end_to_end(tmp_path):
    """The real server process over stdio, as Claude Desktop / Claude Code start it."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=sys.executable, args=[
        str(ROOT / "mcp_server.py"), "--iface", "sim:mutlive", "--logdir", str(tmp_path / "logs"),
        "--profile", str(tmp_path / "colt.csv")])

    def err(r):
        return getattr(r, "is_error", None) if hasattr(r, "is_error") else r.isError

    def text(r):
        return " ".join(getattr(c, "text", "") for c in r.content)

    async def go():
        async with stdio_client(params) as (rd, wr):
            async with ClientSession(rd, wr) as s:
                await s.initialize()
                tools = {t.name for t in (await s.list_tools()).tools}
                assert "read_pids" in tools and not any("clear" in t for t in tools)
                r = await s.call_tool("read_pids", {"pids": ["07"]})
                assert err(r) and "not connected" in text(r)
                r = await s.call_tool("connect", {"init": "mut00"})
                assert not err(r) and "E4B3" in text(r)
                r = await s.call_tool("read_pids", {"pids": ["CA"]})
                assert err(r) and "refused" in text(r)
                r = await s.call_tool("read_pids", {"pids": ["21", "17"], "samples": 3})
                assert not err(r) and '"series"' in text(r)
                r = await s.call_tool("mutdump", {"note": "e2e"})
                assert not err(r) and "e2e" in text(r)
                r = await s.call_tool("disconnect", {})
                assert not err(r)

    asyncio.run(go())
