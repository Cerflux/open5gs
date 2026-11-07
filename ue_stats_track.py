#!/usr/bin/env python3
"""
Track radio stats for every IMSI that attaches.

The Amarisoft eNB remote API has no IMSI. This script polls

    {"message": "ue_get", "stats": true}

and tails the Open5GS MME log. Each attach request or attach reject is
joined to the ue_get sample taken at the same time. The MME line
ENB_UE_S1AP_ID, when present on that timestamp, picks the UE out of the
sample. Later samples for that eNB UE id keep the IMSI from the attach.

MME timestamps are read as the host's local time. The compose file
mounts the host timezone into the MME container so the two clocks match.

Usage:
  python3 ue_stats_track.py
  python3 ue_stats_track.py --interval 0.01 --window 2
  python3 ue_stats_track.py --host 127.0.0.1 --port 9001 -p secret
"""

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import re
import sys
import time
from collections import deque
from datetime import datetime, timedelta

try:
    import websockets
except ImportError:
    print("[ERROR] 'websockets' module not found. Install it with:")
    print("          pip install websockets")
    sys.exit(1)

STATS_FIELDS = ("epre", "ul_phr", "ul_path_loss", "p_ue")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RE_LOG_TS = re.compile(
    r"^(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})"
)
RE_EMPTY_ATTACH = re.compile(
    r"\[emm\].*?\[\s*\]\s+Attach\s+request", re.IGNORECASE
)
RE_NAMED_ATTACH = re.compile(
    r"\[(?:emm|mme)\].*?\[(\d+)\]\s+Attach\s+request", re.IGNORECASE
)
RE_IMSI_LINE = re.compile(r"\[emm\].*?IMSI\[(\d+)\]", re.IGNORECASE)
RE_RETX = re.compile(r"Retransmission of IMSI\[", re.IGNORECASE)
RE_REJECT = re.compile(
    r"\[(?:emm|mme)\].*?\[(\d+)\]\s+Attach\s+reject", re.IGNORECASE
)
RE_CAUSE = re.compile(r"(?:OGS_NAS_EMM_CAUSE|cause)\s*:\s*(\d+)", re.IGNORECASE)
RE_ENB_UE = re.compile(r"ENB_UE_S1AP_ID\[(\d+)\]")

MME_CONTAINER = os.environ.get("OPEN5GS_MME_CONTAINER", "open5gs-mme-1")
RECV_TIMEOUT = 5.0


def make_id(counter: list) -> str:
    counter[0] += 1
    return f"id#{counter[0]}"


def dig_stats(node) -> dict:
    """First occurrence of each radio field, at any depth."""
    found = {}

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (key in STATS_FIELDS and key not in found
                        and not isinstance(item, (dict, list))):
                    found[key] = item
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(node)
    return found


def ue_records(msg: dict) -> list:
    raw = msg.get("ue_list", msg.get("ue", []))
    if isinstance(raw, dict):
        items = list(raw.values())
    elif isinstance(raw, list):
        items = raw
    else:
        items = []
    records = []
    for ue in items:
        if not isinstance(ue, dict):
            continue
        enb_ue_id = ue.get("enb_ue_id", ue.get("ran_ue_id"))
        rnti = ue.get("rnti")
        cells = ue.get("cells", ue.get("cell_list"))
        rows = []
        if isinstance(cells, dict):
            cells = list(cells.values())
        if isinstance(cells, list) and cells:
            for cell in cells:
                if not isinstance(cell, dict):
                    continue
                blob = cell.get("stats") if isinstance(cell.get("stats"), dict) else cell
                rows.append({
                    "cell_id": cell.get("cell_id", cell.get("cell")),
                    **dig_stats(blob),
                })
        if not rows:
            rows.append({"cell_id": None, **dig_stats(ue)})
        records.append({
            "enb_ue_id": enb_ue_id,
            "rnti": rnti,
            "rows": rows,
        })
    return records


def fmt_rnti(rnti) -> str:
    if isinstance(rnti, int):
        return f"{rnti} (0x{rnti:x})"
    return str(rnti)


def rx_level(row: dict):
    """Received level in dB: UE transmit power minus uplink path loss."""
    try:
        return float(row["p_ue"]) - float(row["ul_path_loss"])
    except (KeyError, TypeError, ValueError):
        return None


def fmt_number(value) -> str:
    if isinstance(value, float) and not value.is_integer():
        return f"{value:.1f}"
    if isinstance(value, float):
        return str(int(value))
    return str(value)


def fmt_stats(rows: list) -> str:
    parts = []
    for row in rows:
        bits = []
        cell = row.get("cell_id")
        if cell is not None:
            bits.append(f"cell={cell}")
        for key in STATS_FIELDS:
            value = row.get(key, "-")
            bits.append(f"{key}={fmt_number(value) if isinstance(value, float) else value}")
        level = rx_level(row)
        bits.append(f"rx_level={fmt_number(level) if level is not None else '-'}")
        parts.append(" ".join(bits))
    return " | ".join(parts) if parts else " ".join(f"{k}=-" for k in STATS_FIELDS)


def fmt_wall(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%m/%d %H:%M:%S.%f")[:-3]


class MmeParser:
    """Turn MME log lines into an attach request or reject for any IMSI."""

    def __init__(self):
        self.empty_attach = None  # {"recv", "stamp", "when"}
        self.enb_by_stamp = {}
        self.skew_warned = False

    def _clock(self, line: str, recv_time: float) -> tuple[float, str]:
        match = RE_LOG_TS.match(line)
        if not match:
            return recv_time, ""
        month, day, hour, minute, second, millis = (int(v) for v in match.groups())
        stamp = f"{month:02d}/{day:02d} {hour:02d}:{minute:02d}:{second:02d}.{millis:03d}"
        now = datetime.now().astimezone()
        try:
            parsed = datetime(
                now.year, month, day, hour, minute, second, millis * 1000,
                tzinfo=now.tzinfo,
            )
        except ValueError:
            return recv_time, stamp
        if parsed - now > timedelta(days=2):
            parsed = parsed.replace(year=now.year - 1)
        epoch = parsed.timestamp()
        if abs(epoch - recv_time) > 30:
            if not self.skew_warned:
                print("[WARN]  MME log time differs from the host clock by "
                      "more than 30s. Joining on when the line was read. "
                      "Mount the host timezone into the MME container.",
                      flush=True)
                self.skew_warned = True
            return recv_time, stamp
        return epoch, stamp

    def feed(self, line: str, recv_time: float) -> dict | None:
        line = ANSI_RE.sub("", line).rstrip()
        if not line:
            return None
        when, stamp = self._clock(line, recv_time)
        enb = RE_ENB_UE.search(line)
        if enb and stamp:
            self.enb_by_stamp[stamp] = int(enb.group(1))
            if len(self.enb_by_stamp) > 200:
                self.enb_by_stamp.pop(next(iter(self.enb_by_stamp)))

        if self.empty_attach and recv_time - self.empty_attach["recv"] > 5:
            self.empty_attach = None

        reject = RE_REJECT.search(line)
        if reject:
            cause = RE_CAUSE.search(line)
            return self._event(reject.group(1), "reject", when, stamp, line,
                               cause.group(1) if cause else None)

        if RE_EMPTY_ATTACH.search(line):
            self.empty_attach = {"recv": recv_time, "stamp": stamp, "when": when}
            return None

        named = RE_NAMED_ATTACH.search(line)
        if named:
            return self._event(named.group(1), "request", when, stamp, line, None)

        imsi_line = RE_IMSI_LINE.search(line)
        if (self.empty_attach and imsi_line and not RE_RETX.search(line)):
            opened = self.empty_attach
            self.empty_attach = None
            return self._event(imsi_line.group(1), "request",
                               when or opened["when"], stamp, line, None)
        return None

    def _event(self, imsi: str, kind: str, when: float, stamp: str, line: str,
               cause: str | None) -> dict:
        return {
            "kind": kind,
            "imsi": imsi,
            "when": when,
            "stamp": stamp,
            "cause": cause,
            "enb_ue_id": self.enb_by_stamp.get(stamp),
            "line": line,
            "matched": False,
        }


def select_ue(sample: dict, enb_ue_id):
    ues = sample["ues"]
    if enb_ue_id is not None:
        for ue in ues:
            if ue["enb_ue_id"] == enb_ue_id:
                return ue
        return None
    if len(ues) == 1:
        return ues[0]
    return None


def closest_sample(samples, when: float, window: float):
    best = None
    best_dt = None
    for sample in samples:
        delta = abs(sample["t"] - when)
        if best_dt is None or delta < best_dt:
            best = sample
            best_dt = delta
    if best is None or best_dt > window:
        return None
    return best


def print_event(event: dict, ue: dict | None, sample_time: float | None):
    title = "ATTACH-REQUEST" if event["kind"] == "request" else "ATTACH-REJECT"
    cause = f" cause={event['cause']}" if event["cause"] else ""
    enb = event.get("enb_ue_id")
    enb_s = f" enb_ue_id={enb}" if enb is not None else ""
    print(f"[{title}] {fmt_wall(event['when'])} IMSI={event['imsi']}{enb_s}{cause}",
          flush=True)
    print(f"          {event['line']}", flush=True)
    if ue is None:
        print(f"          no ue_get sample within the join window "
              f"(sample_time={fmt_wall(sample_time) if sample_time else '-'})",
              flush=True)
        return
    print(f"          eNB sample {fmt_wall(sample_time)} "
          f"enb_ue_id={ue['enb_ue_id']} rnti={fmt_rnti(ue['rnti'])}",
          flush=True)
    print(f"          {fmt_stats(ue['rows'])}", flush=True)


async def send_and_recv(ws, payload: dict, counter: list,
                        timeout: float = RECV_TIMEOUT) -> dict | None:
    payload = {**payload, "message_id": make_id(counter)}
    await ws.send(json.dumps(payload))
    wanted = payload["message_id"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = max(0.05, deadline - time.monotonic())
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        except asyncio.TimeoutError:
            break
        msg = json.loads(raw)
        if msg.get("message_id") == wanted:
            return msg
        if msg.get("message") == "error":
            print(f"[ERROR] {msg.get('error', msg)}", flush=True)
    return None


async def handshake(ws, password: str | None, counter: list) -> bool:
    while True:
        raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
        data = json.loads(raw)
        kind = data.get("message")
        if kind == "ready":
            print(f"[INFO] eNB ready  name={data.get('name')}  "
                  f"type={data.get('type')}  version={data.get('version')}",
                  flush=True)
            return True
        if kind == "authenticate":
            if data.get("ready"):
                print("[INFO] Authenticated", flush=True)
                return True
            if not password:
                print("[ERROR] eNB requires a password. Use -p <password>.",
                      flush=True)
                return False
            if data.get("error"):
                print(f"[ERROR] Authentication error: {data['error']}", flush=True)
                return False
            digest = hmac.new(
                (data["type"] + ":" + password + ":" + data["name"]).encode(),
                data["challenge"].encode(),
                hashlib.sha256,
            ).hexdigest()
            await ws.send(json.dumps({
                "message": "authenticate",
                "res": digest,
                "message_id": make_id(counter),
            }))
            continue
        if kind == "error":
            print(f"[ERROR] {data.get('error')}", flush=True)
            return False


async def connect_enb(url: str, password: str | None, counter: list):
    while True:
        try:
            ws = await websockets.connect(url, additional_headers={"origin": "Test"})
        except TypeError:
            ws = await websockets.connect(url, extra_headers={"origin": "Test"})
        try:
            if await handshake(ws, password, counter):
                return ws
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed) as exc:
            print(f"[WARN]  eNB handshake failed ({exc})", flush=True)
        await ws.close()
        print("[WARN]  eNB websocket down. Retry in 1s", flush=True)
        await asyncio.sleep(1)


def mme_follow_source() -> tuple[str, str]:
    env = os.environ.get("OPEN5GS_MME_LOG", "").strip()
    candidates = [env] if env else []
    candidates.append("/var/log/open5gs/mme.log")
    pid = os.popen(
        "docker inspect -f '{{.State.Pid}}' " + MME_CONTAINER
    ).read().strip()
    if pid and pid != "0":
        candidates.append(f"/proc/{pid}/root/var/log/open5gs/mme.log")
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.R_OK):
            return "file", path
    return "docker", MME_CONTAINER


async def follow_mme():
    kind, target = mme_follow_source()
    if kind == "file":
        print(f"[INFO] Tailing MME log : {target}", flush=True)
        with open(target, "r", errors="replace") as handle:
            handle.seek(0, os.SEEK_END)
            pending = ""
            while True:
                chunk = handle.read()
                if chunk:
                    pending += chunk
                while "\n" in pending:
                    line, pending = pending.split("\n", 1)
                    yield line
                else:
                    await asyncio.sleep(0.05)
                    continue
    print(f"[INFO] Tailing MME log : docker logs -f {target}", flush=True)
    while True:
        proc = await asyncio.create_subprocess_exec(
            "docker", "logs", "-f", "--tail", "0", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                yield raw.decode("utf-8", errors="replace")
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
        print(f"[WARN]  docker logs {target} ended. Retry in 1s", flush=True)
        await asyncio.sleep(1)


async def run(host: str, port: int, password: str | None,
              interval: float, window: float):
    url = f"ws://{host}:{port}/"
    counter = [0]
    print(f"[INFO] Connecting to eNB at {url}", flush=True)
    ws = await connect_enb(url, password, counter)
    print("[INFO] Watching        : every IMSI that attaches", flush=True)
    pace = f"{interval * 1000:g}ms" if interval < 1 else f"{interval:g}s"
    print(f"[INFO] ue_get interval : {pace}   join window {window:g}s",
          flush=True)
    print("[INFO] Fields          : epre ul_phr ul_path_loss p_ue "
          "rx_level(p_ue - ul_path_loss)\n", flush=True)

    samples = deque(maxlen=max(32, int(120 / max(interval, 0.05))))
    pending = []
    # enb_ue_id -> {"imsi", "last"}
    bound = {}
    parser = MmeParser()

    def consider(event: dict):
        sample = closest_sample(samples, event["when"], window)
        if sample is None:
            if time.time() > event["when"] + window:
                print_event(event, None, None)
                event["matched"] = True
            return
        ue = select_ue(sample, event["enb_ue_id"])
        if ue is None and event["enb_ue_id"] is None and len(sample["ues"]) > 1:
            print_event(event, None, sample["t"])
            print(f"          {len(sample['ues'])} UEs in that sample and the "
                  "MME line had no ENB_UE_S1AP_ID. Stats for each:", flush=True)
            for item in sample["ues"]:
                print(f"          enb_ue_id={item['enb_ue_id']} "
                      f"rnti={fmt_rnti(item['rnti'])} {fmt_stats(item['rows'])}",
                      flush=True)
            event["matched"] = True
            return
        if ue is None and time.time() <= event["when"] + window:
            return
        print_event(event, ue, sample["t"] if sample else None)
        event["matched"] = True
        if event["kind"] == "request" and ue and ue["enb_ue_id"] is not None:
            bound[ue["enb_ue_id"]] = {"imsi": event["imsi"], "last": None}
            print(f"[INFO] IMSI {event['imsi']} joined to "
                  f"enb_ue_id={ue['enb_ue_id']}", flush=True)
        elif event["kind"] == "reject":
            enb_id = (ue or {}).get("enb_ue_id", event.get("enb_ue_id"))
            if enb_id in bound and bound[enb_id]["imsi"] == event["imsi"]:
                del bound[enb_id]
            else:
                for key, info in list(bound.items()):
                    if info["imsi"] == event["imsi"]:
                        del bound[key]

    async def poll_enb():
        nonlocal ws
        while True:
            started = time.monotonic()
            try:
                msg = await send_and_recv(
                    ws, {"message": "ue_get", "stats": True}, counter
                )
            except websockets.exceptions.ConnectionClosed:
                print("[WARN]  eNB websocket closed. Reconnecting …", flush=True)
                ws = await connect_enb(url, password, counter)
                continue
            now = time.time()
            if msg and not msg.get("error"):
                records = ue_records(msg)
                samples.append({"t": now, "ues": records})
                for event in pending:
                    if not event["matched"]:
                        consider(event)
                for enb_id, info in list(bound.items()):
                    ue = select_ue({"ues": records}, enb_id)
                    if ue is None:
                        print(f"[INFO] enb_ue_id={enb_id} left the eNB UE list. "
                              f"IMSI {info['imsi']} unbound.", flush=True)
                        del bound[enb_id]
                        continue
                    rendered = fmt_stats(ue["rows"])
                    if rendered != info["last"]:
                        info["last"] = rendered
                        print(f"[STATS] {fmt_wall(now)} IMSI={info['imsi']} "
                              f"enb_ue_id={ue['enb_ue_id']} "
                              f"rnti={fmt_rnti(ue['rnti'])} {rendered}",
                              flush=True)
            elif msg and msg.get("error"):
                print(f"[ERROR] ue_get: {msg.get('error')}", flush=True)
            remain = interval - (time.monotonic() - started)
            if remain > 0:
                await asyncio.sleep(remain)

    async def read_mme():
        async for line in follow_mme():
            event = parser.feed(line, time.time())
            if event is None:
                continue
            pending.append(event)
            consider(event)
            if len(pending) > 100:
                del pending[:-50]

    try:
        await asyncio.gather(poll_enb(), read_mme())
    finally:
        await ws.close()


def main():
    parser = argparse.ArgumentParser(
        description="Join Amarisoft ue_get stats to every attaching IMSI."
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="eNB WebSocket host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9001,
                        help="eNB WebSocket port (default: 9001)")
    parser.add_argument("-p", "--password", default=None,
                        help="Password for the eNB WebSocket")
    parser.add_argument("--interval", type=float, default=0.01,
                        help="Seconds between ue_get polls (default: 0.01, 10 ms)")
    parser.add_argument("--window", type=float, default=2.0,
                        help="Max seconds between an MME line and a ue_get "
                             "sample (default: 2)")
    args = parser.parse_args()
    if args.interval <= 0 or args.window <= 0:
        print("[ERROR] --interval and --window must be positive", file=sys.stderr)
        sys.exit(1)
    try:
        asyncio.run(run(args.host, args.port, args.password,
                        args.interval, args.window))
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user.")


if __name__ == "__main__":
    main()
