#!/usr/bin/env python3
"""
Amarisoft eNB TAC/CI cycler
===========================
Two modes, selected with --mode:

  timer (default)
    The first switch happens when this attach sequence names the given IMSI.
    After that, TAC/cell identity switches every --interval seconds (default 10).

  trigger
    1. The attach sequence switches immediately.
    2. Then this sequence switches immediately, and again every time it repeats:
         [mme] INFO: [Removed] Number of MME-UEs is now ...
         [emm] INFO:     IMSI[<IMSI>]
         [mme] ERROR: Cannot find Served TAI[...]
         [mme] INFO: ErrorIndication

The attach sequence is either of these:

  [emm] INFO: [] Attach request
  [emm] INFO:     GUTI[...] IMSI[Unknown IMSI]
  [emm] INFO: Identity response
  [emm] INFO:     IMSI[<IMSI>]

  [mme] INFO: [<IMSI>] known UE by IMSI
  [emm] WARNING: [<IMSI>] Attach request
  [emm] INFO:     IMSI[<IMSI>]

Payloads alternate:

  Message 1: TAC=43674, cell_identity=0x01
  Message 2: TAC=43675, cell_identity=0x02

config_get runs once at startup to see which of those is live.

Usage:
  python3 attach_monitor.py <IMSI>
  python3 attach_monitor.py <IMSI> --mode timer --interval 10
  python3 attach_monitor.py <IMSI> --mode trigger
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

try:
    import websockets
except ImportError:
    print("[ERROR] 'websockets' module not found. Install it with:")
    print("          pip install websockets")
    sys.exit(1)

CONFIGS = {
    1: {"tac": 43674, "cell_identity": 0x01},
    2: {"tac": 43675, "cell_identity": 0x02},
}

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Initial trigger is [] Attach request, then the IMSI line for the CLI IMSI.
# Two live forms both count. The IMSI line is what sends the TAC change.
#   short:  [] Attach request
#           IMSI[510115592904515]          (emm-handler.c:280)
#   long:   [] Attach request
#           GUTI[...] IMSI[Unknown IMSI]
#           Identity response
#           IMSI[510115592904515]          (emm-handler.c:530)
# A repeat attach for a UE the MME already knows is also a trigger:
#   [mme] INFO: [510115592904515] known UE by IMSI
#   [emm] WARNING: [510115592904515] Attach request
#   [emm] INFO:     IMSI[510115592904515]
RE_ATTACH_EMPTY = re.compile(
    r"\[emm\].*?\[\s*\]\s+Attach\s+request", re.IGNORECASE
)
RE_UNKNOWN_IMSI = re.compile(
    r"\[emm\].*?IMSI\[\s*Unknown\s+IMSI\s*\]", re.IGNORECASE
)
RE_IDENTITY = re.compile(
    r"\[emm\].*?Identity\s+response", re.IGNORECASE
)
RE_IMSI_LINE = re.compile(r"\[emm\].*?IMSI\[(\d+)\]", re.IGNORECASE)
# [emm] WARNING: Retransmission of IMSI[510115592904515] failed
RE_RETX = re.compile(
    r"\[emm\].*?Retransmission of IMSI\[(\d+)\] failed", re.IGNORECASE
)
# [emm] WARNING: [510115592904515] Failure in transaction
RE_TXN = re.compile(
    r"\[emm\].*?\[(\d+)\]\s+Failure in transaction", re.IGNORECASE
)
# After the initial attach switch, the next switch is this sequence:
#   [mme] INFO: [Removed] Number of MME-UEs is now 1
#   [emm] INFO:     IMSI[510115592904515]
#   [mme] ERROR: Cannot find Served TAI[PLMN_ID:15f011,TAC:43675]
#   [mme] INFO: ErrorIndication
# The count is any number. Several MMEs can be present.
RE_MME_REMOVED = re.compile(
    r"\[mme\].*?\[Removed\] Number of MME-UEs is now\s+(\d+)",
    re.IGNORECASE,
)
RE_SERVED_TAI = re.compile(
    r"\[mme\].*?Cannot find Served TAI\[.*?TAC:(\d+)\]", re.IGNORECASE
)
RE_ERROR_IND = re.compile(
    r"\[mme\].*?ErrorIndication", re.IGNORECASE
)
# Same-timestamp trigger, watched together with the initial attach.
# Whichever sequence finishes first sends.
#   [mme] INFO: Unknown UE by GUTI[...]
#   [emm] WARNING: [510115592904515] Attach request
#   [emm] INFO:     GUTI[...] IMSI[510115592904515]
RE_UNKNOWN_GUTI = re.compile(
    r"\[mme\].*?Unknown UE by GUTI\[", re.IGNORECASE
)
RE_NAMED_ATTACH = re.compile(
    r"\[emm\].*?\[(\d+)\]\s+Attach\s+request", re.IGNORECASE
)
RE_GUTI_IMSI = re.compile(
    r"\[emm\].*?GUTI\[.*?\]\s+IMSI\[(\d+)\]", re.IGNORECASE
)
# Opens the known-UE attach sequence. The IMSI line closes it.
RE_KNOWN_UE = re.compile(
    r"\[mme\].*?\[(\d+)\]\s+known UE by IMSI", re.IGNORECASE
)

# Attach lines share one timestamp. The follow-up Served TAI lines arrive
# a few seconds after the MME-UE removal, so that sequence gets longer.
PAIR_TIMEOUT = 5.0
# Served TAI usually lands 10–12s after the IMSI line. A few are ~25s.
FOLLOW_TIMEOUT = 30.0
RECV_TIMEOUT = 5.0


def make_id(counter: list) -> str:
    counter[0] += 1
    return f"id#{counter[0]}"


def make_config_set(num: int, msg_id: str) -> dict:
    c = CONFIGS[num]
    return {
        "message": "config_set",
        "message_id": msg_id,
        "cells": {
            "1": {
                "experimental": {
                    "tac": c["tac"],
                    "cell_identity": c["cell_identity"],
                }
            }
        },
    }


def fmt_config(num: int) -> str:
    c = CONFIGS[num]
    return f"Message {num}  TAC={c['tac']}  cell_identity={c['cell_identity']:#04x}"


def extract_cell_config(cfg_response: dict) -> dict | None:
    cells = cfg_response.get("cells", {})
    cell = cells.get("1") or cells.get(1)
    if not cell:
        return None
    tac = cell.get("tac")
    n_id_cell = cell.get("n_id_cell")
    if tac is None or n_id_cell is None:
        return None
    return {"tac": tac, "n_id_cell": n_id_cell}


def which_config(cell: dict) -> int | None:
    for num, cfg in CONFIGS.items():
        if cell["tac"] == cfg["tac"] and cell["n_id_cell"] == cfg["cell_identity"]:
            return num
    return None


def mme_log_path() -> str:
    # Same-container Open5GS (sigsence-epc:open5gs) writes the MME log here.
    env = os.environ.get("OPEN5GS_MME_LOG", "").strip()
    if env:
        return env
    local = "/var/log/open5gs/mme.log"
    if os.path.isfile(local):
        return local
    pid = os.popen("docker inspect -f '{{.State.Pid}}' open5gs-mme-1").read().strip()
    if not pid or pid == "0":
        raise RuntimeError(
            "open5gs-mme-1 is not running and %s does not exist" % local
        )
    return f"/proc/{pid}/root/var/log/open5gs/mme.log"


async def send_and_recv(ws, payload: dict, counter: list,
                        timeout: float = RECV_TIMEOUT) -> dict | None:
    payload = {**payload, "message_id": make_id(counter)}
    await ws.send(json.dumps(payload))
    msg_id = payload["message_id"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = max(0.05, deadline - time.monotonic())
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        except asyncio.TimeoutError:
            break
        msg = json.loads(raw)
        if msg.get("message_id") == msg_id:
            return msg
    return None


async def run(imsi: str, host: str, port: int, password: str | None,
              mode: str = "timer", interval: float = 10.0,
              verbose: bool = False):
    url = f"ws://{host}:{port}/"
    counter = [0]

    def vlog(*args):
        if verbose:
            print("[DBG] ", *args, flush=True)

    print(f"[INFO] Connecting to eNB at {url}", flush=True)
    ws_box = [None]
    drain_task = None

    async def handshake(sock) -> bool:
        while True:
            raw = await asyncio.wait_for(sock.recv(), timeout=10.0)
            data = json.loads(raw)
            mtype = data.get("message")

            if mtype == "ready":
                print(f"[INFO] Ready  name={data.get('name')}  "
                      f"type={data.get('type')}  version={data.get('version')}",
                      flush=True)
                return True

            if mtype == "authenticate":
                if data.get("ready"):
                    print("[INFO] Authenticated", flush=True)
                    return True
                if not password:
                    print("[ERROR] Server requires a password. Use -p <password>.",
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
                await sock.send(json.dumps({
                    "message": "authenticate",
                    "res": digest,
                    "message_id": make_id(counter),
                }))
                continue

            if mtype == "error":
                print(f"[ERROR] {data.get('error')}", flush=True)
                return False

    async def open_socket():
        while True:
            try:
                sock = await websockets.connect(
                    url, additional_headers={"origin": "Test"}
                )
                if await handshake(sock):
                    return sock
                await sock.close()
                return None
            except (ConnectionRefusedError, OSError,
                    websockets.exceptions.ConnectionClosed,
                    asyncio.TimeoutError) as exc:
                print(f"[WARN]  eNB websocket down ({exc}). Retry in 1s",
                      flush=True)
                await asyncio.sleep(1)

    async def start_drain(sock):
        nonlocal drain_task
        if drain_task and not drain_task.done():
            drain_task.cancel()

        async def drain_ws():
            try:
                async for raw_msg in sock:
                    msg = json.loads(raw_msg)
                    err = msg.get("error")
                    if err:
                        print(f"[ERROR] {err}", flush=True)
            except Exception:
                pass

        drain_task = asyncio.create_task(drain_ws())

    async def reconnect() -> bool:
        print("[WARN]  eNB websocket closed. Reconnecting …", flush=True)
        old = ws_box[0]
        ws_box[0] = None
        if old is not None:
            try:
                await old.close()
            except Exception:
                pass
        sock = await open_socket()
        if sock is None:
            return False
        ws_box[0] = sock
        await start_drain(sock)
        print("[INFO] Reconnected to eNB", flush=True)
        return True

    sock = await open_socket()
    if sock is None:
        return
    ws_box[0] = sock

    print("[INFO] Reading live eNB config (one-time) …", flush=True)
    cfg_resp = await send_and_recv(ws_box[0], {"message": "config_get"}, counter)
    if cfg_resp is None or cfg_resp.get("error"):
        err = (cfg_resp or {}).get("error", "timeout")
        print(f"[WARN]  config_get failed ({err}) – defaulting to Message 2",
              flush=True)
        last_sent = 2
    else:
        cell = extract_cell_config(cfg_resp)
        if cell is None:
            print("[WARN]  Could not parse TAC/n_id_cell – defaulting to Message 2",
                  flush=True)
            last_sent = 2
        else:
            last_sent = which_config(cell) or 2
            print(f"[INFO]  Live config → TAC={cell['tac']}  "
                  f"n_id_cell={cell['n_id_cell']}  → seeded as Message {last_sent}",
                  flush=True)

    await start_drain(ws_box[0])

    log_path = mme_log_path()
    print(f"\n[INFO] Watching IMSI : {imsi}", flush=True)
    print(f"[INFO] Mode          : {mode}", flush=True)
    print("[INFO] Marker        : known UE by IMSI, "
          f"[{imsi}] Attach request, IMSI[{imsi}]", flush=True)
    if mode == "trigger":
        print(f"[INFO] Trigger A     : [] Attach request then IMSI[{imsi}]",
              flush=True)
        print("[INFO] Trigger B     : Unknown UE by GUTI, "
              f"[{imsi}] Attach request, GUTI IMSI[{imsi}]", flush=True)
        print("[INFO]                 whichever finishes first sends",
              flush=True)
    if mode == "timer":
        print(f"[INFO] Interval      : first switch immediately on attach, "
              f"then every {interval:g}s",
              flush=True)
    print(f"[INFO] Tailing       : {log_path}\n", flush=True)

    log_file = open(log_path, "r", errors="replace")
    log_file.seek(0, os.SEEK_END)
    pending = ""

    # Open [] Attach request, waiting for IMSI[digits]. Unknown IMSI
    # and Identity response are optional lines in between.
    # value is {"t0", "lines"}
    attach_seq = None
    # Follow-up sequence after the initial attach switch:
    # removed → imsi → tai → error indication
    follow_seq = None
    # [Removed] often prints before the IMSI line of the same attach.
    # Hold it so the follow-up can start the moment the initial IMSI fires.
    pending_removed = None
    # Unknown UE by GUTI → [IMSI] Attach request → GUTI IMSI line.
    # step is "guti" or "attach".
    guti_seq = None
    # known UE by IMSI → [IMSI] Attach request → IMSI[digits].
    # step is "known" or "attach". Lines in between are ignored.
    known_seq = None
    initial_fired = False
    # Set by "Retransmission of IMSI failed". The known UE line after
    # that marker is the same procedure and must not send.
    ignore_known = False
    timer_task = None
    timer_started = False

    async def fire(title: str, lines: list[str], delay: float = 0.0) -> None:
        nonlocal last_sent
        body = "\n".join(f"        {row}" for row in lines)
        shown = f"[EVENT] {title}\n{body}" if body else f"[EVENT] {title}"
        if delay:
            print(shown, flush=True)
            print(f"[INFO]  TAC/CI change in {delay:g}s", flush=True)
            await asyncio.sleep(delay)
        next_num = 1 if last_sent == 2 else 2
        payload = json.dumps(make_config_set(next_num, make_id(counter)))
        try:
            await ws_box[0].send(payload)
        except websockets.exceptions.ConnectionClosed:
            if not await reconnect():
                print("[ERROR] eNB reconnect failed. TAC/CI change not sent.",
                      flush=True)
                return
            try:
                await ws_box[0].send(payload)
            except websockets.exceptions.ConnectionClosed as exc:
                print(f"[ERROR] send failed after reconnect: {exc}",
                      flush=True)
                return
        last_sent = next_num
        if not delay:
            print(shown, flush=True)
        print(f"[INFO]  Sent {fmt_config(next_num)}", flush=True)

    async def timer_loop() -> None:
        # The first switch already happened in arm_timer. This waits
        # one full interval before every later switch.
        while True:
            await asyncio.sleep(interval)
            await fire(f"Timer {interval:g}s", [])

    async def arm_timer(title: str, lines: list[str]) -> None:
        """Send the first TAC/CI change now, then repeat on the interval."""
        nonlocal timer_task, timer_started
        if timer_started:
            vlog("timer already running")
            return
        await fire(title, lines)
        timer_started = True
        print(f"[INFO]  Initial TAC/CI change sent. "
              f"Next switch in {interval:g}s.", flush=True)
        timer_task = asyncio.create_task(timer_loop())

    async def on_attach(title: str, lines: list[str]) -> None:
        nonlocal initial_fired
        if mode == "timer" and not initial_fired:
            await arm_timer(title, lines)
            initial_fired = True
        elif mode == "trigger":
            await fire(title, lines)
            initial_fired = True
        elif initial_fired:
            vlog("later attach, not a new trigger")

    try:
        while True:
            chunk = log_file.read()
            if chunk:
                pending += chunk
            if "\n" not in pending:
                await asyncio.sleep(0.005)
                continue
            raw_line, pending = pending.split("\n", 1)
            line = ANSI_RE.sub("", raw_line).rstrip()
            if not line:
                continue
            now = time.monotonic()

            if attach_seq and now - attach_seq["t0"] > PAIR_TIMEOUT:
                vlog("attach sequence expired before the IMSI was revealed")
                attach_seq = None
            if guti_seq and now - guti_seq["t0"] > PAIR_TIMEOUT:
                vlog("Unknown UE by GUTI expired before Attach request")
                guti_seq = None
            if known_seq and now - known_seq["t0"] > PAIR_TIMEOUT:
                vlog("known UE sequence expired before the IMSI line")
                known_seq = None
            if pending_removed and now - pending_removed["t0"] > FOLLOW_TIMEOUT:
                pending_removed = None
            if follow_seq and now - follow_seq["t0"] > FOLLOW_TIMEOUT:
                vlog("follow-up sequence expired before ErrorIndication")
                follow_seq = None

            # Removal often prints before the IMSI line, and sometimes
            # it does not print at all before Served TAI. Remember it.
            # Never wipe a follow-up that is already waiting for Served TAI.
            m_removed = RE_MME_REMOVED.search(line)
            if m_removed:
                pending_removed = {
                    "t0": now,
                    "line": line,
                    "count": m_removed.group(1),
                }
                if mode == "trigger" and initial_fired:
                    if follow_seq is None or follow_seq["step"] == "removed":
                        follow_seq = {
                            "step": "removed",
                            "t0": now,
                            "lines": [line],
                            "count": m_removed.group(1),
                        }
                    elif (follow_seq["step"] == "imsi"
                          and not any("[Removed]" in row
                                      for row in follow_seq["lines"])):
                        follow_seq["lines"].insert(0, line)
                        follow_seq["count"] = m_removed.group(1)
                    vlog(f"follow-up: MME-UEs now {m_removed.group(1)} | {line}")
                continue

            # Trigger B. Does not wait for the initial attach. The last
            # line sends. A named Attach request with no Unknown UE by
            # GUTI in front of it does not send.
            if mode == "trigger":
                if RE_UNKNOWN_GUTI.search(line):
                    guti_seq = {"step": "guti", "t0": now, "lines": [line]}
                    vlog(f"Unknown UE by GUTI | {line}")
                    continue
                if guti_seq and guti_seq["step"] == "guti":
                    m_named = RE_NAMED_ATTACH.search(line)
                    if m_named:
                        if m_named.group(1) == imsi:
                            guti_seq["step"] = "attach"
                            guti_seq["t0"] = now
                            guti_seq["lines"].append(line)
                            vlog(f"GUTI attach request | {line}")
                        else:
                            vlog(f"GUTI attach IMSI {m_named.group(1)} != {imsi}")
                            guti_seq = None
                        continue
                if guti_seq and guti_seq["step"] == "attach":
                    m_guti_imsi = RE_GUTI_IMSI.search(line)
                    if m_guti_imsi and not RE_RETX.search(line):
                        guti_lines = guti_seq["lines"] + [line]
                        guti_seq = None
                        if m_guti_imsi.group(1) == imsi:
                            await fire(
                                f"Unknown UE by GUTI  IMSI [{imsi}]",
                                guti_lines,
                            )
                        else:
                            vlog(f"GUTI IMSI {m_guti_imsi.group(1)} != {imsi}")
                        continue

            # Known UE already has an IMSI, so the Attach request line
            # names it. Other lines may sit between the three markers.
            m_known = RE_KNOWN_UE.search(line)
            if m_known:
                if m_known.group(1) == imsi:
                    known_seq = {"step": "known", "t0": now, "lines": [line]}
                    vlog(f"known UE | {line}")
                else:
                    vlog(f"known UE IMSI {m_known.group(1)} != {imsi}")
                    known_seq = None
                continue
            if known_seq and known_seq["step"] == "known":
                m_named = RE_NAMED_ATTACH.search(line)
                if m_named:
                    if m_named.group(1) == imsi:
                        known_seq["step"] = "attach"
                        known_seq["t0"] = now
                        known_seq["lines"].append(line)
                        vlog(f"known UE attach request | {line}")
                    else:
                        vlog(f"known UE attach IMSI {m_named.group(1)} != {imsi}")
                        known_seq = None
                    continue
            if known_seq and known_seq["step"] == "attach":
                m_known_imsi = RE_IMSI_LINE.search(line)
                if (m_known_imsi and not RE_RETX.search(line)
                        and not RE_GUTI_IMSI.search(line)):
                    known_lines = known_seq["lines"] + [line]
                    known_seq = None
                    if m_known_imsi.group(1) == imsi:
                        await on_attach(
                            f"Known UE by IMSI [{imsi}]",
                            known_lines,
                        )
                    else:
                        vlog(f"known UE IMSI line {m_known_imsi.group(1)} != {imsi}")
                    continue

            # Initial trigger. [] Attach request opens it. The next
            # IMSI[digits] closes it, with or without Unknown IMSI and
            # Identity response in between.
            revealed = None
            imsi_line = None
            if RE_ATTACH_EMPTY.search(line):
                ignore_known = False
                attach_seq = {"t0": now, "lines": [line]}
                vlog(f"attach sequence: empty Attach Request | {line}")
            elif attach_seq and (RE_UNKNOWN_IMSI.search(line)
                                  or RE_IDENTITY.search(line)):
                attach_seq["lines"].append(line)
                attach_seq["t0"] = now
                vlog(f"attach sequence: waiting for IMSI | {line}")
            elif attach_seq:
                m_imsi = RE_IMSI_LINE.search(line)
                if m_imsi and not RE_RETX.search(line):
                    revealed = m_imsi.group(1)
                    imsi_line = line
                    seq_lines = attach_seq["lines"] + [line]
                    attach_seq = None

            if revealed is not None:
                if revealed == imsi:
                    await on_attach(
                        f"Attach Request with IMSI [{imsi}]",
                        seq_lines,
                    )
                else:
                    print(f"[SKIP]  Attach Request IMSI {revealed} "
                          f"!= watching {imsi}", flush=True)
                continue

            if mode == "timer" or not initial_fired:
                continue
    except asyncio.CancelledError:
        pass
    finally:
        if timer_task:
            timer_task.cancel()
        if drain_task and not drain_task.done():
            drain_task.cancel()
        if ws_box[0] is not None:
            try:
                await ws_box[0].close()
            except Exception:
                pass
        log_file.close()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Toggle eNB TAC/cell_identity on the attach sequence, then on each "
            "Served TAI rejection in trigger mode."
        )
    )
    parser.add_argument("imsi", help="IMSI to watch (e.g. 510115592904515)")
    parser.add_argument("--mode", choices=("timer", "trigger"), default="timer",
                        help="timer: switch on a fixed interval after the first "
                             "Attach Request; trigger: switch on MME log pairs "
                             "(default: timer)")
    parser.add_argument("--interval", type=float, default=10.0,
                        help="Seconds between switches in timer mode (default: 10)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="eNB WebSocket host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9001,
                        help="eNB WebSocket port (default: 9001)")
    parser.add_argument("-p", "--password", default=None,
                        help="Password for WebSocket authentication")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print half-open pairs while waiting for the second line")
    args = parser.parse_args()

    try:
        asyncio.run(run(args.imsi, args.host, args.port, args.password,
                        args.mode, args.interval, args.verbose))
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user.")
    except ConnectionRefusedError:
        print(f"[ERROR] Connection refused – is the eNB running on "
              f"{args.host}:{args.port}?")
        sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Unexpected error: {exc}")
        raise


if __name__ == "__main__":
    main()
