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

The same process keeps a UE map for the watched IMSI. It tails the
Amarisoft eNB log and the Open5GS MME log and joins them on the
eNB UE S1AP ID (Amarisoft prints it in hex, the MME in decimal).
Each RRC, S1, and NAS change prints the current lifecycle.

RX level comes from the eNB PHY log over the same websocket:
  {"message":"log_get","log_options":"phy.level=debug"}
Only UL PUSCH lines are used. EPRE is the power of one resource element,
and each PRB has 12 subcarriers, so
  rx_level = epre + 10*log10(n_prb * 12)
The line also shows PRB, TA, SNR, and HARQ.

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
import math
import os
import re
import sys
import time
from datetime import datetime

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

RE_CLOCK = re.compile(r"(\d{2}:\d{2}:\d{2}\.\d+)")
# prb and symb are start:count. EPRE is dBm per resource element.
RE_PUSCH = re.compile(
    r"harq=(?P<harq>\d+)\s+"
    r"prb=(?P<prb_start>\d+):(?P<n_prb>\d+)\s+"
    r"symb=(?P<symb_start>\d+):(?P<n_symb>\d+).*?"
    r"snr=(?P<snr>-?\d+(?:\.\d+)?)\s+"
    r"epre=(?P<epre>-?\d+(?:\.\d+)?)\s+"
    r"ta=(?P<ta>-?\d+(?:\.\d+)?)"
)
RE_PUSCH_CRC = re.compile(r"\bcrc=(\w+)")
# One summary a second. log_get itself is polled faster so the PHY buffer drains.
RX_PRINT_EVERY = 1.0
PHY_POLL_EVERY = 0.2
RE_ENB_RRC_NOTE = re.compile(
    r"\[RRC\]\s+-\s+(\d{4})\s+\d+\s+(No S1AP connection.*)$"
)
RE_ENB_RRC = re.compile(
    r"\[RRC\]\s+(?:UL|DL|-)\s+(\d{4})\s+\d+\s+\S+:\s+(.*)$"
)
RE_ENB_NAS = re.compile(
    r"\[NAS\]\s+(?:UL|DL)\s+(\d{4})\s+\S+:\s+(.*)$"
)
RE_ENB_S1 = re.compile(
    r"\[S1AP\]\s+(TO|FROM)\s+(\S+)\s+(\S+)\s+\S+\s+(.*)$"
)
RE_ENB_S1_LINK = re.compile(
    r"\[S1AP\]\s+-\s+(Closing connection|Connected|Connecting)\b"
)
RE_MME_IDS = re.compile(
    r"ENB_UE_S1AP_ID\[(\d+)\]\s+MME_UE_S1AP_ID\[(\d+)\]"
    r"(?:\s+TAC\[(\d+)\]\s+CellID\[(0x[0-9a-fA-F]+)\])?"
)
RE_MME_UE_EVENT = re.compile(
    r"\[(\d+)\]\s+(known UE by IMSI|Unknown UE by IMSI|"
    r"Holding S1 Context|Holding S1 context has already been removed|"
    r"Authentication ignored|Discard Detach|Attach reject)"
)
RE_MME_RELEASE = re.compile(r"UE Context Release \[Action:(\d+)\]")
RE_MME_IMPLICIT = re.compile(r"Implicit S1 release")
RE_MME_INITIAL = re.compile(r"InitialUEMessage")
RE_MME_LINK_DOWN = re.compile(r"eNB-S1\[.*?\] connection refused")

# UE Context Release action, from s1ap-handler.c.
S1_ACTION = {
    "1": ("s1-removed", "S1 context removed"),
    "2": ("left-enb", "UE left this eNB"),
    "3": ("ue-removed", "MME UE context removed"),
}


def clock_of(line: str) -> str:
    match = RE_CLOCK.search(line)
    return match.group(1) if match else "--:--:--.---"


def parse_pusch(text: str) -> dict | None:
    """RX level (dBm) from a PUSCH HARQ line.

    EPRE is the measured power of one resource element. The allocation
    covers n_prb resource blocks and each resource block has 12 subcarriers,
    so the received power of that PUSCH is

        rx_level = epre + 10*log10(n_prb * 12)
    """
    match = RE_PUSCH.search(text)
    if not match:
        return None
    n_prb = int(match.group("n_prb"))
    if n_prb <= 0:
        return None
    epre = float(match.group("epre"))
    crc = RE_PUSCH_CRC.search(text)
    return {
        "harq": int(match.group("harq")),
        "prb_start": int(match.group("prb_start")),
        "n_prb": n_prb,
        "symb_start": int(match.group("symb_start")),
        "n_symb": int(match.group("n_symb")),
        "snr": float(match.group("snr")),
        "epre": epre,
        "ta": float(match.group("ta")),
        "crc": crc.group(1) if crc else "-",
        "rx": epre + 10.0 * math.log10(n_prb * 12),
    }


def phy_clock(timestamp) -> str:
    if isinstance(timestamp, (int, float)) and timestamp > 1_000_000_000_000:
        return datetime.fromtimestamp(timestamp / 1000.0).strftime("%H:%M:%S.%f")[:-3]
    return "--:--:--.---"


def hex_id(token: str) -> int | None:
    if token == "-":
        return None
    try:
        return int(token, 16)
    except ValueError:
        return None


class UeRec:
    def __init__(self):
        self.imsi = None
        self.enb_id = None
        self.mme_id = None
        self.tac = None
        self.cell = None
        self.rrc = "-"
        self.s1 = "-"
        self.nas = "-"
        self.enb_ts = "-"
        self.enb_event = "-"
        self.mme_ts = "-"
        self.mme_event = "-"
        self.rx_level = None
        self.rx_epre = None
        self.rx_prb = None
        self.rx_ta = None
        self.rx_snr = None
        self.rx_harq = None

    def phase(self) -> str:
        if self.s1 == "link-down":
            return "eNB S1 link down"
        if self.s1 == "missing":
            return "eNB has no S1 association"
        if self.s1 == "held":
            return "previous S1 held on MME"
        if self.s1 == "expired":
            return "held S1 released on MME"
        if self.s1 == "left-enb":
            return "UE left this eNB"
        if self.s1 == "ue-removed":
            return "MME UE context removed"
        if self.s1 == "s1-removed":
            return "S1 context removed"
        if self.nas == "detach-discarded":
            return "detach discarded, still on this eNB"
        if self.nas == "detach-request" and self.s1 == "associated":
            return "UE sent detach, S1 still up"
        if self.nas == "auth-ignored" and self.s1 == "associated":
            return "auth-ignored, connected to this eNB"
        if self.nas == "auth-ignored":
            return "auth-ignored"
        if self.nas == "attach-reject":
            return "attach rejected"
        if self.nas == "attach" and self.s1 == "associated":
            return "attach sent, S1 associated"
        if self.rrc == "released":
            return "RRC released"
        if self.s1 == "associated":
            return "S1 associated"
        if self.s1 == "initial":
            return "S1 initial UE"
        if self.rrc == "connected":
            return "RRC connected"
        if self.rrc == "connecting":
            return "RRC connecting"
        return "seen"


class UeMap:
    """Join one IMSI across the Amarisoft eNB log and the Open5GS MME log."""

    def __init__(self, imsi: str):
        self.imsi = imsi
        self.by_enb: dict[int, UeRec] = {}
        self.by_imsi: dict[str, UeRec] = {}
        # ("hold", imsi) | ("release", action) | ("implicit", None)
        self.pending = None
        self.active: UeRec | None = None
        self._rx_bucket: list[dict] = []
        self._rx_enb = None
        self._rx_print_at = 0.0

    def on_enb(self, line: str) -> None:
        ts = clock_of(line)
        link = RE_ENB_S1_LINK.search(line)
        if link:
            kind = link.group(1)
            if kind == "Closing connection":
                for rec in self._watched():
                    rec.s1 = "link-down"
                    self._show(rec, "enb", ts, "S1 link closed")
            elif kind == "Connected":
                for rec in self._watched():
                    if rec.s1 == "link-down":
                        rec.s1 = "-"
                        self._show(rec, "enb", ts, "S1 link connected")
            return

        note = RE_ENB_RRC_NOTE.search(line)
        if note:
            rec = self._enb(int(note.group(1), 16))
            rec.s1 = "missing"
            self._show(rec, "enb", ts, note.group(2))
            return

        rrc = RE_ENB_RRC.search(line)
        if rrc:
            enb_id = int(rrc.group(1), 16)
            text = rrc.group(2).strip()
            if text.startswith("RRC connection request"):
                rec = self._fresh_enb(enb_id)
                rec.rrc = "connecting"
                self._show(rec, "enb", ts, "RRC connection request")
            elif text.startswith("RRC connection setup complete"):
                rec = self._enb(enb_id)
                rec.rrc = "connected"
                self._show(rec, "enb", ts, "RRC connection setup complete")
            elif text.startswith("RRC connection release"):
                rec = self._enb(enb_id)
                rec.rrc = "released"
                self._show(rec, "enb", ts, "RRC connection release")
            return

        nas = RE_ENB_NAS.search(line)
        if nas:
            rec = self._enb(int(nas.group(1), 16))
            text = nas.group(2).strip()
            if text.startswith("Attach request"):
                if rec.nas != "auth-ignored":
                    rec.nas = "attach"
                if rec.rrc == "-":
                    rec.rrc = "connected"
                self._show(rec, "enb", ts, "Attach request")
            elif text.startswith("Detach request"):
                rec.nas = "detach-request"
                self._show(rec, "enb", ts, "Detach request")
            elif text.startswith("Authentication"):
                self._show(rec, "enb", ts, text)
            return

        s1 = RE_ENB_S1.search(line)
        if not s1:
            return
        direction, mme_tok, enb_tok, text = s1.groups()
        enb_id = hex_id(enb_tok)
        mme_id = hex_id(mme_tok)
        text = text.strip()
        if enb_id is None:
            return
        if text.startswith("Initial UE message"):
            rec = self._fresh_enb(enb_id)
            rec.s1 = "initial"
            if mme_id is not None:
                rec.mme_id = mme_id
            if rec.rrc == "-":
                rec.rrc = "connected"
            self.active = rec
            self._show(rec, "enb", ts, "Initial UE message")
            return
        rec = self._enb(enb_id)
        if mme_id is not None:
            rec.mme_id = mme_id
        if text.startswith("Connection establishment indication"):
            rec.s1 = "associated"
            self._show(rec, "enb", ts, "Connection establishment indication")
        elif text.startswith("Uplink NAS transport"):
            if rec.s1 in ("-", "initial", "missing"):
                rec.s1 = "associated"
            self._show(rec, "enb", ts, "Uplink NAS transport")
        elif text.lower().startswith("ue context release command"):
            self._show(rec, "enb", ts, "UE context release command")
        elif text.lower().startswith("ue context release complete"):
            if rec.s1 not in ("left-enb", "ue-removed", "s1-removed", "expired"):
                rec.s1 = "s1-removed"
            rec.rrc = "released"
            self._show(rec, "enb", ts, "UE context release complete")
        elif direction == "FROM" and "Error indication" in text:
            self._show(rec, "enb", ts, "Error indication")

    def on_mme(self, line: str) -> None:
        ts = clock_of(line)
        if RE_MME_LINK_DOWN.search(line):
            for rec in self._watched():
                rec.s1 = "link-down"
                self._show(rec, "mme", ts, "eNB S1 connection refused")
            return
        if RE_MME_INITIAL.search(line):
            return

        ids = RE_MME_IDS.search(line)
        if ids and ids.group(3):
            enb_id = int(ids.group(1))
            mme_id = int(ids.group(2))
            rec = self.by_enb.get(enb_id)
            if (rec is None or rec.mme_id not in (None, mme_id)
                    or rec.s1 in ("released", "left-enb", "ue-removed",
                                  "expired", "held", "link-down", "s1-removed")):
                rec = UeRec()
                rec.enb_id = enb_id
                self.by_enb[enb_id] = rec
            rec.mme_id = mme_id
            rec.tac = int(ids.group(3))
            rec.cell = ids.group(4)
            if rec.s1 in ("-", "missing"):
                rec.s1 = "initial"
            self.pending = None
            self.active = rec
            self._show(rec, "mme", ts,
                       f"Initial UE  TAC {rec.tac}  CI {rec.cell}")
            return

        if ids and self.pending:
            kind, extra = self.pending
            self.pending = None
            enb_id = int(ids.group(1))
            mme_id = int(ids.group(2))
            rec = self.by_enb.get(enb_id)
            if rec is None:
                rec = UeRec()
                rec.enb_id = enb_id
                self.by_enb[enb_id] = rec
            rec.mme_id = mme_id
            if kind == "hold":
                rec.imsi = rec.imsi or extra
                rec.s1 = "held"
                self._show(rec, "mme", ts, "Holding previous S1")
            elif kind == "implicit":
                rec.s1 = "expired"
                self._show(rec, "mme", ts, "Implicit S1 release")
            elif kind == "release":
                state, label = S1_ACTION.get(extra, ("s1-removed", "S1 released"))
                rec.s1 = state
                if state in ("left-enb", "ue-removed", "s1-removed"):
                    rec.rrc = "released"
                self._show(rec, "mme", ts, f"{label}  action {extra}")
            return

        event = RE_MME_UE_EVENT.search(line)
        if event:
            imsi, name = event.group(1), event.group(2)
            if name in ("known UE by IMSI", "Unknown UE by IMSI"):
                rec = self._current_unbound() or self.by_imsi.get(imsi)
                if rec is None:
                    rec = UeRec()
                self.active = rec
                rec.imsi = imsi
                if rec.enb_id is not None:
                    self.by_enb[rec.enb_id] = rec
                self.by_imsi[imsi] = rec
                label = "known UE" if name.startswith("known") else "unknown UE"
                self._show(rec, "mme", ts, label)
                return
            if name == "Holding S1 Context":
                self.pending = ("hold", imsi)
                return
            if name == "Holding S1 context has already been removed":
                rec = self.by_imsi.get(imsi)
                if rec is not None:
                    self._show(rec, "mme", ts, "previous held S1 already gone")
                return
            rec = self.by_imsi.get(imsi)
            if rec is None:
                return
            if name == "Authentication ignored":
                rec.nas = "auth-ignored"
                self._show(rec, "mme", ts, "Authentication ignored, connection held")
            elif name == "Discard Detach":
                rec.nas = "detach-discarded"
                self._show(rec, "mme", ts, "Detach discarded, S1 still held")
            elif name == "Attach reject":
                rec.nas = "attach-reject"
                self._show(rec, "mme", ts, "Attach reject")
            return

        if RE_MME_IMPLICIT.search(line):
            self.pending = ("implicit", None)
            return
        release = RE_MME_RELEASE.search(line)
        if release:
            self.pending = ("release", release.group(1))
            return

        named = RE_NAMED_ATTACH.search(line)
        if named and named.group(1) == self.imsi:
            rec = self.by_imsi.get(self.imsi)
            if rec is not None:
                if rec.nas != "auth-ignored":
                    rec.nas = "attach"
                self._show(rec, "mme", ts, "Attach request")
            return
        if RE_ATTACH_EMPTY.search(line):
            rec = self._current_unbound()
            if rec is not None and rec.imsi in (None, self.imsi):
                rec.nas = "attach"
                self._show(rec, "mme", ts, "Attach request")
            return
        imsi_line = RE_IMSI_LINE.search(line)
        if imsi_line and not RE_RETX.search(line) and not RE_GUTI_IMSI.search(line):
            imsi = imsi_line.group(1)
            rec = self._current_unbound() or self.by_imsi.get(imsi)
            if rec is None or rec.imsi not in (None, imsi):
                return
            # known/unknown UE already printed this IMSI. This line is
            # the first identification only when that line was absent.
            if rec.imsi == imsi:
                return
            rec.imsi = imsi
            if rec.enb_id is not None:
                self.by_enb[rec.enb_id] = rec
            self.by_imsi[imsi] = rec
            if rec.nas == "-":
                rec.nas = "attach"
            self._show(rec, "mme", ts, f"IMSI {imsi}")

    def _enb(self, enb_id: int) -> UeRec:
        rec = self.by_enb.get(enb_id)
        if rec is None:
            rec = UeRec()
            rec.enb_id = enb_id
            self.by_enb[enb_id] = rec
        return rec

    def _fresh_enb(self, enb_id: int) -> UeRec:
        rec = self.by_enb.get(enb_id)
        if rec is not None and rec.rrc == "released":
            rec = None
        if rec is None or rec.s1 in ("left-enb", "ue-removed", "expired",
                                     "s1-removed", "link-down"):
            rec = UeRec()
            rec.enb_id = enb_id
            self.by_enb[enb_id] = rec
        return rec

    def _current_unbound(self) -> UeRec | None:
        if self.active is not None and self.active.imsi is None:
            return self.active
        fresh = [rec for rec in self.by_enb.values()
                 if rec.imsi is None and rec.s1 in ("initial", "associated", "-")]
        if not fresh:
            return None
        return fresh[-1]

    def _watched(self) -> list[UeRec]:
        return [rec for rec in self.by_enb.values() if rec.imsi == self.imsi]

    def _show(self, rec: UeRec, side: str, ts: str, event: str) -> None:
        if side == "enb":
            rec.enb_ts = ts
            rec.enb_event = event
        else:
            rec.mme_ts = ts
            rec.mme_event = event
        if rec.imsi != self.imsi:
            return
        enb = "-" if rec.enb_id is None else str(rec.enb_id)
        mme = "-" if rec.mme_id is None else str(rec.mme_id)
        tac = "-" if rec.tac is None else str(rec.tac)
        cell = rec.cell or "-"
        print(
            f"[UE] {ts}  IMSI {rec.imsi}  "
            f"eNB-UE {enb}  MME-UE {mme}  TAC {tac}  CI {cell}\n"
            f"     {rec.phase()}\n"
            f"     RRC {rec.rrc}   S1 {rec.s1}   NAS {rec.nas}\n"
            f"     eNB {rec.enb_ts}  {rec.enb_event}\n"
            f"     MME {rec.mme_ts}  {rec.mme_event}"
            f"{self._rx_line(rec)}",
            flush=True,
        )

    def on_phy(self, msg: dict) -> None:
        """Take UL PUSCH HARQ lines for the watched UE out of a log_get reply."""
        rec = self.by_imsi.get(self.imsi)
        if rec is None or rec.enb_id is None:
            return
        if self._rx_enb != rec.enb_id:
            self._rx_bucket.clear()
            self._rx_enb = rec.enb_id
        for entry in msg.get("logs") or []:
            if entry.get("channel") != "PUSCH" or entry.get("dir") not in (None, "UL"):
                continue
            if entry.get("ue_id") != rec.enb_id:
                continue
            data = entry.get("data") or []
            text = data if isinstance(data, str) else " ".join(data)
            sample = parse_pusch(text)
            if sample is None:
                continue
            sample["rnti"] = entry.get("rnti")
            sample["ts"] = phy_clock(entry.get("timestamp"))
            self._rx_bucket.append(sample)
        if not self._rx_bucket:
            return
        good = [sample for sample in self._rx_bucket if sample["crc"] == "OK"]
        latest = (good or self._rx_bucket)[-1]
        rec.rx_level = latest["rx"]
        rec.rx_epre = latest["epre"]
        rec.rx_prb = f"{latest['prb_start']}:{latest['n_prb']}"
        rec.rx_ta = latest["ta"]
        rec.rx_snr = latest["snr"]
        rec.rx_harq = latest["harq"]
        now = time.monotonic()
        if now - self._rx_print_at < RX_PRINT_EVERY:
            return
        self._print_rx(rec)
        self._rx_bucket.clear()
        self._rx_print_at = now

    def _print_rx(self, rec: UeRec) -> None:
        samples = self._rx_bucket
        ok = [sample for sample in samples if sample["crc"] == "OK"]
        good = ok or samples
        latest = good[-1]
        mean_rx = sum(sample["rx"] for sample in good) / len(good)
        rnti = latest["rnti"]
        rnti_text = "-" if rnti is None else str(rnti)
        print(
            f"[RX] {latest['ts']}  IMSI {rec.imsi}  eNB-UE {rec.enb_id}  "
            f"rnti {rnti_text}  harq {latest['harq']}  "
            f"prb {latest['prb_start']}:{latest['n_prb']}  "
            f"symb {latest['symb_start']}:{latest['n_symb']}  "
            f"epre {latest['epre']:.1f} dBm  ta {latest['ta']:.1f}  "
            f"snr {latest['snr']:.1f} dB  crc {latest['crc']}  "
            f"rx_level {latest['rx']:.1f} dBm  "
            f"({len(samples)} PUSCH, {len(ok)} crc OK, mean {mean_rx:.1f})",
            flush=True,
        )

    @staticmethod
    def _rx_line(rec: UeRec) -> str:
        if rec.rx_level is None:
            return ""
        return (
            f"\n     RX epre {rec.rx_epre:.1f} dBm  prb {rec.rx_prb}  "
            f"ta {rec.rx_ta:.1f}  snr {rec.rx_snr:.1f} dB  "
            f"harq {rec.rx_harq}  rx_level {rec.rx_level:.1f} dBm"
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


def enb_log_path(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    env = os.environ.get("AMARISOFT_ENB_LOG", "").strip()
    if env:
        return env
    for path in (
        "/home/cerflux/amarisoft/www/live/enb0.log",
        "/home/cerflux/amarisoft/ltewww-2025-12-12/live/enb0.log",
    ):
        if os.path.isfile(path):
            return path
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


async def tail_enb(path: str, ue_map: UeMap) -> None:
    log_file = open(path, "r", errors="replace")
    log_file.seek(0, os.SEEK_END)
    pending = ""
    try:
        while True:
            try:
                size = os.fstat(log_file.fileno()).st_size
                if size < log_file.tell():
                    log_file.seek(0)
            except OSError:
                pass
            chunk = log_file.read(262144)
            if not chunk:
                await asyncio.sleep(0.02)
                continue
            pending += chunk
            while "\n" in pending:
                raw, pending = pending.split("\n", 1)
                if ("[RRC]" not in raw and "[NAS]" not in raw
                        and "[S1AP]" not in raw):
                    continue
                ue_map.on_enb(ANSI_RE.sub("", raw).rstrip())
    finally:
        log_file.close()


async def run(imsi: str, host: str, port: int, password: str | None,
              mode: str = "timer", interval: float = 10.0,
              verbose: bool = False, enb_log: str | None = None):
    url = f"ws://{host}:{port}/"
    counter = [0]

    def vlog(*args):
        if verbose:
            print("[DBG] ", *args, flush=True)

    print(f"[INFO] Connecting to eNB at {url}", flush=True)
    ws_box = [None]
    ue_map_box = [None]
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
                    url, additional_headers={"origin": "Test"},
                    max_size=8 * 1024 * 1024,
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
                    if msg.get("message") == "log_get":
                        ue_map = ue_map_box[0]
                        if ue_map is not None:
                            try:
                                ue_map.on_phy(msg)
                            except Exception as exc:
                                print(f"[WARN]  PHY log parse failed: {exc}",
                                      flush=True)
                        continue
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
    enb_path = enb_log_path(enb_log)
    ue_map = UeMap(imsi)
    ue_map_box[0] = ue_map
    enb_task = None
    phy_task = None
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
    print(f"[INFO] Tailing MME   : {log_path}", flush=True)
    if enb_path:
        print(f"[INFO] Tailing eNB   : {enb_path}", flush=True)
        print("[INFO] UE map        : eNB UE id joined to MME S1AP ids",
              flush=True)
    else:
        print("[WARN]  Amarisoft eNB log not found. "
              "UE map will follow the MME log only.", flush=True)
    print("[INFO] RX level      : PUSCH epre + 10*log10(n_prb * 12) "
          "from log_get phy.level=debug\n",
          flush=True)

    log_file = open(log_path, "r", errors="replace")
    log_file.seek(0, os.SEEK_END)
    pending = ""
    if enb_path:
        enb_task = asyncio.create_task(tail_enb(enb_path, ue_map))

    async def poll_phy() -> None:
        while True:
            sock = ws_box[0]
            if sock is None:
                await asyncio.sleep(PHY_POLL_EVERY)
                continue
            payload = {
                "message": "log_get",
                "log_options": "phy.level=debug",
                "message_id": make_id(counter),
            }
            try:
                await sock.send(json.dumps(payload))
            except (websockets.exceptions.ConnectionClosed, OSError):
                await asyncio.sleep(1.0)
                continue
            await asyncio.sleep(PHY_POLL_EVERY)

    phy_task = asyncio.create_task(poll_phy())

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
            ue_map.on_mme(line)
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
        if enb_task and not enb_task.done():
            enb_task.cancel()
        if phy_task and not phy_task.done():
            phy_task.cancel()
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
    parser.add_argument("--enb-log", default=None,
                        help="Amarisoft eNB log to join with the MME "
                             "(default: the live enb0.log)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print half-open pairs while waiting for the second line")
    args = parser.parse_args()

    try:
        asyncio.run(run(args.imsi, args.host, args.port, args.password,
                        args.mode, args.interval, args.verbose, args.enb_log))
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
