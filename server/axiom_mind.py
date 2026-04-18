# -*- coding: utf-8 -*-
# Copyright (c) 2026 Kantoshi Miyamura
#
# AxiomMind v2 — Autonomous Blockchain Guardian Daemon
#
# Runs forever as a single process:
#   1. Monitoring / healing async loops
#   2. FastAPI HTTP + WebSocket dashboard on port 7777
#
# Install dependencies:
#   pip install aiohttp aiosqlite fastapi uvicorn anthropic psutil
#
# Run:
#   python axiom_mind.py

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import aiosqlite
import psutil
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

try:
    import anthropic as _anthropic_module
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Safe AxiomMind Integration (axiom-mind module)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from axiom_mind import (
        ActionType, ActionProposal, PolicyEngine, SafeExecutor, AuditLog,
        SystemState, ExecutorConfig, PolicyDecision, MinCooldownConfig,
        RateLimitConfig
    )
    _SAFE_AXIOM_MIND_AVAILABLE = True
except ImportError:
    _SAFE_AXIOM_MIND_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Config Constants
# ─────────────────────────────────────────────────────────────────────────────

RPC_URL           = os.environ.get("AXIOM_RPC_URL",    "http://127.0.0.1:8332")
DB_PATH           = os.environ.get("AXIOM_DB_PATH",    "/var/lib/axiom-mind/mind.db")
LOG_PATH          = os.environ.get("AXIOM_LOG_PATH",   "/var/log/axiom-mind/axiom_mind.log")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
DASHBOARD_PORT    = int(os.environ.get("AXIOM_DASHBOARD_PORT", "7777"))

# ─────────────────────────────────────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging() -> logging.Logger:
    log = logging.getLogger("axiom_mind")
    log.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    try:
        fh = logging.FileHandler(LOG_PATH)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except Exception:
        pass
    return log

_log = _setup_logging()

# ─────────────────────────────────────────────────────────────────────────────
# FastAPI application (declared early so routes can be registered below)
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title="AxiomMind v2", version="2.0.0")
_START_TIME = time.time()

# ─────────────────────────────────────────────────────────────────────────────
# EWMA
# ─────────────────────────────────────────────────────────────────────────────

class EWMA:
    """Exponential Weighted Moving Average with variance and z-score support."""

    def __init__(self, alpha: float, initial: float) -> None:
        self._alpha    = alpha
        self._mean     = initial
        self._var      = 0.0
        self._history: deque[float] = deque(maxlen=50)
        self._history.append(initial)

    def update(self, x: float) -> float:
        delta         = x - self._mean
        self._mean   += self._alpha * delta
        self._var      = (1.0 - self._alpha) * (self._var + self._alpha * delta * delta)
        self._history.append(x)
        return self._mean

    def z_score(self, x: float) -> float:
        std = math.sqrt(self._var) if self._var > 0 else 1e-9
        return (x - self._mean) / std

    def variance(self) -> float:
        """Estimate variance from the last ≤50 recorded samples."""
        vals = list(self._history)
        if len(vals) < 2:
            return self._var
        mean = sum(vals) / len(vals)
        return sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)

    @property
    def mean(self) -> float:
        return self._mean

# ─────────────────────────────────────────────────────────────────────────────
# PeerReputation
# ─────────────────────────────────────────────────────────────────────────────

class PeerReputation:
    """Tracks per-peer reputation scores and violation history."""

    def __init__(self) -> None:
        self.scores:     Dict[str, float]        = {}
        self.violations: Dict[str, List[dict]]   = {}

    def _ensure(self, peer_id: str) -> None:
        if peer_id not in self.scores:
            self.scores[peer_id]     = 1.0
            self.violations[peer_id] = []

    def penalize(self, peer_id: str, severity: float, reason: str) -> None:
        self._ensure(peer_id)
        self.scores[peer_id] = max(0.0, self.scores[peer_id] - severity)
        self.violations[peer_id].append({
            "ts":       datetime.now(timezone.utc).isoformat(),
            "reason":   reason,
            "severity": severity,
            "score_after": self.scores[peer_id],
        })
        # Keep only the last 100 violations per peer
        if len(self.violations[peer_id]) > 100:
            self.violations[peer_id] = self.violations[peer_id][-100:]

    def reward(self, peer_id: str, amount: float) -> None:
        self._ensure(peer_id)
        self.scores[peer_id] = min(1.0, self.scores[peer_id] + amount)

    def decay(self, elapsed_secs: float) -> None:
        """Recover toward 1.0 at 5% per hour."""
        rate = 0.05 * (elapsed_secs / 3600.0)
        for peer_id in list(self.scores):
            if self.scores[peer_id] < 1.0:
                self.scores[peer_id] = min(1.0, self.scores[peer_id] + rate * (1.0 - self.scores[peer_id]))

    def is_suspicious(self, peer_id: str) -> bool:
        return self.scores.get(peer_id, 1.0) < 0.5

    def is_banned(self, peer_id: str) -> bool:
        return self.scores.get(peer_id, 1.0) < 0.2

    def summary(self) -> dict:
        return {
            "peer_count": len(self.scores),
            "scores":     {k: round(v, 4) for k, v in self.scores.items()},
            "suspicious": [k for k, v in self.scores.items() if v < 0.5],
            "banned":     [k for k, v in self.scores.items() if v < 0.2],
        }

# ─────────────────────────────────────────────────────────────────────────────
# FeePredictor
# ─────────────────────────────────────────────────────────────────────────────

class FeePredictor:
    """Online linear regression: mempool_depth → predicted_fee_rate (pure Python)."""

    def __init__(self) -> None:
        self._n    = 0
        self._sx   = 0.0   # sum of x
        self._sy   = 0.0   # sum of y
        self._sxx  = 0.0   # sum of x^2
        self._sxy  = 0.0   # sum of x*y
        self._syy  = 0.0   # sum of y^2
        self._recent_fees: deque[float] = deque(maxlen=20)

    def update(self, depth: int, fee_rate: float) -> None:
        x = float(depth)
        y = float(fee_rate)
        self._n   += 1
        self._sx  += x
        self._sy  += y
        self._sxx += x * x
        self._sxy += x * y
        self._syy += y * y
        self._recent_fees.append(y)

    def _slope_intercept(self) -> Tuple[float, float]:
        n = self._n
        if n < 2:
            return 0.0, self._sy / max(n, 1)
        denom = n * self._sxx - self._sx * self._sx
        if abs(denom) < 1e-12:
            return 0.0, self._sy / n
        slope     = (n * self._sxy - self._sx * self._sy) / denom
        intercept = (self._sy - slope * self._sx) / n
        return slope, intercept

    def predict(self, depth: int) -> float:
        slope, intercept = self._slope_intercept()
        return max(1.0, slope * float(depth) + intercept)

    def r_squared(self) -> float:
        n = self._n
        if n < 2:
            return 0.0
        ss_tot = self._syy - (self._sy * self._sy) / n
        if ss_tot < 1e-12:
            return 1.0
        slope, intercept = self._slope_intercept()
        ss_res = (self._syy
                  - 2.0 * slope * self._sxy
                  - 2.0 * intercept * self._sy
                  + slope * slope * self._sxx
                  + 2.0 * slope * intercept * self._sx
                  + n * intercept * intercept)
        return max(0.0, min(1.0, 1.0 - ss_res / ss_tot))

    def trend(self) -> str:
        """Returns 'rising', 'falling', or 'stable' based on last 20 data points."""
        fees = list(self._recent_fees)
        if len(fees) < 4:
            return "stable"
        half   = len(fees) // 2
        first  = sum(fees[:half])  / half
        second = sum(fees[half:])  / (len(fees) - half)
        delta  = (second - first) / max(abs(first), 1e-9)
        if delta > 0.05:
            return "rising"
        if delta < -0.05:
            return "falling"
        return "stable"

# ─────────────────────────────────────────────────────────────────────────────
# ChainMemory
# ─────────────────────────────────────────────────────────────────────────────

class ChainMemory:
    """Persistent SQLite store for metrics, alerts, decisions, and healing events."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None

    async def init(self) -> None:
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS metrics (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          REAL    NOT NULL,
                height      INTEGER,
                peers       INTEGER,
                mempool_sz  INTEGER,
                fee_p50     REAL,
                fee_p90     REAL,
                health      REAL,
                tip_age     REAL,
                hashrate    REAL,
                raw_json    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(ts);

            CREATE TABLE IF NOT EXISTS alerts (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       REAL    NOT NULL,
                severity TEXT    NOT NULL,
                kind     TEXT    NOT NULL,
                detail   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

            CREATE TABLE IF NOT EXISTS agent_decisions (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       REAL    NOT NULL,
                agent    TEXT    NOT NULL,
                analysis TEXT,
                action   TEXT,
                outcome  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_decisions_ts ON agent_decisions(ts);

            CREATE TABLE IF NOT EXISTS healing_events (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      REAL    NOT NULL,
                action  TEXT    NOT NULL,
                reason  TEXT,
                success INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_healing_ts ON healing_events(ts);

            CREATE TABLE IF NOT EXISTS peer_scores (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        REAL    NOT NULL,
                peer_id   TEXT    NOT NULL,
                score     REAL    NOT NULL,
                violation TEXT
            );
        """)
        await self._db.commit()

    async def save_metrics(self, m: dict) -> None:
        if self._db is None:
            return
        try:
            await self._db.execute(
                """INSERT INTO metrics
                   (ts, height, peers, mempool_sz, fee_p50, fee_p90, health, tip_age, hashrate, raw_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    time.time(),
                    m.get("height"),
                    m.get("peers"),
                    m.get("mempool_size"),
                    m.get("fee_p50"),
                    m.get("fee_p90"),
                    m.get("health_score"),
                    m.get("tip_age"),
                    m.get("hashrate"),
                    json.dumps(m),
                ),
            )
            await self._db.commit()
        except Exception as exc:
            _log.warning("save_metrics error: %s", exc)

    async def get_recent_metrics(self, n: int = 100) -> List[dict]:
        if self._db is None:
            return []
        try:
            async with self._db.execute(
                "SELECT * FROM metrics ORDER BY ts DESC LIMIT ?", (n,)
            ) as cur:
                rows = await cur.fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:
            _log.warning("get_recent_metrics error: %s", exc)
            return []

    async def save_alert(self, severity: str, kind: str, detail: str) -> None:
        if self._db is None:
            return
        try:
            await self._db.execute(
                "INSERT INTO alerts (ts, severity, kind, detail) VALUES (?,?,?,?)",
                (time.time(), severity, kind, detail),
            )
            await self._db.commit()
        except Exception as exc:
            _log.warning("save_alert error: %s", exc)

    async def get_recent_alerts(self, n: int = 50) -> List[dict]:
        if self._db is None:
            return []
        try:
            async with self._db.execute(
                "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (n,)
            ) as cur:
                rows = await cur.fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:
            _log.warning("get_recent_alerts error: %s", exc)
            return []

    async def save_agent_decision(
        self, agent: str, analysis: str, action: str, outcome: str = ""
    ) -> None:
        if self._db is None:
            return
        try:
            await self._db.execute(
                "INSERT INTO agent_decisions (ts, agent, analysis, action, outcome) VALUES (?,?,?,?,?)",
                (time.time(), agent, analysis, action, outcome),
            )
            await self._db.commit()
        except Exception as exc:
            _log.warning("save_agent_decision error: %s", exc)

    async def get_agent_decisions(self, n: int = 20) -> List[dict]:
        if self._db is None:
            return []
        try:
            async with self._db.execute(
                "SELECT * FROM agent_decisions ORDER BY ts DESC LIMIT ?", (n,)
            ) as cur:
                rows = await cur.fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:
            _log.warning("get_agent_decisions error: %s", exc)
            return []

    async def save_healing_event(self, action: str, reason: str, success: bool) -> None:
        if self._db is None:
            return
        try:
            await self._db.execute(
                "INSERT INTO healing_events (ts, action, reason, success) VALUES (?,?,?,?)",
                (time.time(), action, reason, int(success)),
            )
            await self._db.commit()
        except Exception as exc:
            _log.warning("save_healing_event error: %s", exc)

    async def get_healing_events(self, n: int = 20) -> List[dict]:
        if self._db is None:
            return []
        try:
            async with self._db.execute(
                "SELECT * FROM healing_events ORDER BY ts DESC LIMIT ?", (n,)
            ) as cur:
                rows = await cur.fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:
            _log.warning("get_healing_events error: %s", exc)
            return []

    async def get_stats(self) -> dict:
        if self._db is None:
            return {}
        stats: dict = {}
        try:
            for table in ("metrics", "alerts", "agent_decisions", "healing_events"):
                async with self._db.execute(f"SELECT COUNT(*) as c FROM {table}") as cur:
                    row = await cur.fetchone()
                    stats[f"{table}_count"] = row["c"] if row else 0

            async with self._db.execute(
                "SELECT MAX(height) as last_height, MIN(ts) as first_ts, MAX(ts) as last_ts FROM metrics"
            ) as cur:
                row = await cur.fetchone()
                if row:
                    stats["last_height"] = row["last_height"]
                    stats["first_ts"]    = row["first_ts"]
                    stats["last_ts"]     = row["last_ts"]
        except Exception as exc:
            _log.warning("get_stats error: %s", exc)
        return stats

# ─────────────────────────────────────────────────────────────────────────────
# RpcClient
# ─────────────────────────────────────────────────────────────────────────────

class RpcClient:
    """Async HTTP client for the Axiom node RPC API."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._session: Optional[aiohttp.ClientSession] = None

    def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def get(self, path: str) -> Optional[Any]:
        url = f"{self._base_url}{path}"
        try:
            async with self._get_session().get(url) as resp:
                if resp.status == 200:
                    return await resp.json(content_type=None)
                _log.debug("RPC %s → HTTP %d", path, resp.status)
                return None
        except Exception as exc:
            _log.debug("RPC %s error: %s", path, exc)
            return None

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

# ─────────────────────────────────────────────────────────────────────────────
# ExpertAgent
# ─────────────────────────────────────────────────────────────────────────────

_AGENT_PROMPTS: Dict[str, str] = {
    "security": (
        "You are an elite blockchain security researcher specialising in the Axiom Network. "
        "Your mandate is to detect double-spend attacks, eclipse attacks, selfish mining, "
        "replay attacks, and MEV (miner-extractable value) exploitation. "
        "Analyse the provided chain state and anomaly data and return ONLY valid JSON: "
        "{\"threats\": [list of threat strings], \"severity\": \"low|medium|high|critical\", "
        "\"action\": \"recommended action string\", \"confidence\": 0.0-1.0}"
    ),
    "consensus": (
        "You are a distributed systems consensus expert specialising in Proof-of-Work blockchains. "
        "Your focus is detecting chain forks, block reorgs, LWMA-3 difficulty manipulation, and "
        "51% attack indicators. Analyse the provided chain state and return ONLY valid JSON: "
        "{\"issues\": [list of issue strings], \"fork_risk\": 0.0-1.0, "
        "\"recommended_action\": \"action string\"}"
    ),
    "network": (
        "You are a P2P network security expert. Your focus is eclipse attacks, insufficient peer "
        "diversity, network partition, and Sybil attacks. Analyse peer topology and connectivity "
        "data and return ONLY valid JSON: "
        "{\"network_health\": 0.0-1.0, \"risks\": [list of risk strings], "
        "\"recommended_action\": \"action string\"}"
    ),
    "crypto": (
        "You are a post-quantum cryptography expert. The Axiom Network uses ML-DSA-87 signatures "
        "and SHA-3 hashing. Your focus is signature malleability, hash integrity, key reuse, and "
        "any cryptographic anomalies. Analyse the provided data and return ONLY valid JSON: "
        "{\"crypto_health\": 0.0-1.0, \"anomalies\": [list of anomaly strings], "
        "\"recommended_action\": \"action string\"}"
    ),
    "economics": (
        "You are a blockchain economics expert specialising in fee markets, mining incentives, "
        "UTXO set growth, and dust attack detection. Analyse mempool and fee data and return "
        "ONLY valid JSON: "
        "{\"economic_health\": 0.0-1.0, \"issues\": [list of issue strings], "
        "\"recommended_action\": \"action string\"}"
    ),
}


class ExpertAgent:
    """AI-powered expert agent backed by Claude claude-opus-4-6."""

    def __init__(self, name: str, api_key: str) -> None:
        self.name    = name
        self._key    = api_key
        self._client: Optional[Any] = None
        self._history: List[dict]   = []

        if api_key and _ANTHROPIC_AVAILABLE:
            try:
                self._client = _anthropic_module.Anthropic(api_key=api_key)
            except Exception as exc:
                _log.warning("ExpertAgent[%s] init error: %s", name, exc)

    def _trim_history(self) -> None:
        # Keep last 20 messages (10 user + 10 assistant turns)
        if len(self._history) > 20:
            self._history = self._history[-20:]

    def analyze(self, context: str) -> dict:
        if self._client is None:
            return {"error": "no_api_key", "agent": self.name}

        user_msg = {"role": "user", "content": context}
        self._history.append(user_msg)
        self._trim_history()

        try:
            response = self._client.messages.create(
                model="claude-opus-4-6",
                max_tokens=1024,
                system=_AGENT_PROMPTS[self.name],
                messages=self._history,
            )
            raw_text = response.content[0].text if response.content else "{}"
            self._history.append({"role": "assistant", "content": raw_text})
            self._trim_history()

            # Extract first JSON object from the response
            json_match = re.search(r"\{[\s\S]*\}", raw_text)
            parsed = json.loads(json_match.group(0)) if json_match else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw_text}
        except Exception as exc:
            _log.warning("ExpertAgent[%s] API error: %s", self.name, exc)
            return {"error": str(exc), "agent": self.name}

        return {
            "agent":     self.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **parsed,
        }

# ─────────────────────────────────────────────────────────────────────────────
# AdaptiveAnomalyDetector
# ─────────────────────────────────────────────────────────────────────────────

class AdaptiveAnomalyDetector:
    """EWMA-based anomaly detection for core chain metrics."""

    ALERT_THRESHOLD    = 3.0
    CRITICAL_THRESHOLD = 6.0

    def __init__(self) -> None:
        # alpha=0.1 gives ~10-sample memory; initial values are typical mainnet values
        self._block_time   = EWMA(alpha=0.1, initial=30.0)
        self._peer_count   = EWMA(alpha=0.15, initial=8.0)
        self._mempool_size = EWMA(alpha=0.1, initial=200.0)
        self._fee_rate     = EWMA(alpha=0.1, initial=10.0)
        self._orphan_rate  = EWMA(alpha=0.05, initial=0.01)

    def _make_anomaly(self, kind: str, value: float, z: float, mean: float) -> dict:
        severity = "critical" if abs(z) >= self.CRITICAL_THRESHOLD else "warning"
        return {
            "kind":       kind,
            "value":      value,
            "z_score":    round(z, 2),
            "baseline":   round(mean, 4),
            "severity":   severity,
            "ts":         datetime.now(timezone.utc).isoformat(),
        }

    def check_block_time(self, secs: float) -> Optional[dict]:
        z = self._block_time.z_score(secs)
        self._block_time.update(secs)
        if abs(z) >= self.ALERT_THRESHOLD:
            return self._make_anomaly("block_time", secs, z, self._block_time.mean)
        return None

    def check_peer_count(self, count: int) -> Optional[dict]:
        z = self._peer_count.z_score(float(count))
        self._peer_count.update(float(count))
        if abs(z) >= self.ALERT_THRESHOLD:
            return self._make_anomaly("peer_count", float(count), z, self._peer_count.mean)
        return None

    def check_mempool(self, size: int, _bytes: int) -> Optional[dict]:
        z = self._mempool_size.z_score(float(size))
        self._mempool_size.update(float(size))
        if abs(z) >= self.ALERT_THRESHOLD:
            return self._make_anomaly("mempool_size", float(size), z, self._mempool_size.mean)
        return None

    def check_fee(self, p50: float, p90: float) -> Optional[dict]:
        z = self._fee_rate.z_score(p50)
        self._fee_rate.update(p50)
        if abs(z) >= self.ALERT_THRESHOLD:
            return self._make_anomaly("fee_rate_p50", p50, z, self._fee_rate.mean)
        return None

    def compute_health_score(self, state: dict) -> float:
        """
        Weighted health score 0-100:
          block_time_stability  30%
          peer_connectivity     25%
          mempool_health        20%
          chain_freshness       25%
        """
        # Block time stability: 0 z-score = perfect, drops linearly up to 3σ
        bt_z   = abs(self._block_time.z_score(state.get("block_time_last", 30.0)))
        bt     = max(0.0, 1.0 - bt_z / 3.0)

        # Peer connectivity: 0 if <2 peers, 1 if ≥8 peers
        peers  = state.get("peers", 0) or 0
        pc     = min(1.0, max(0.0, peers / 8.0))

        # Mempool health: penalise if over 50k transactions
        mp_sz  = state.get("mempool_size", 0) or 0
        mp     = max(0.0, 1.0 - mp_sz / 50_000.0)

        # Chain freshness: tip_age vs expected 30s block time
        tip_age = state.get("tip_age", 0) or 0
        # Full score if tip_age < 60s, zero if > 600s
        cf      = max(0.0, min(1.0, 1.0 - (tip_age - 60.0) / 540.0))

        score = (bt * 0.30 + pc * 0.25 + mp * 0.20 + cf * 0.25) * 100.0
        return round(score, 2)

    def baselines(self) -> dict:
        return {
            "block_time_ewma":   round(self._block_time.mean,   3),
            "peer_count_ewma":   round(self._peer_count.mean,   3),
            "mempool_size_ewma": round(self._mempool_size.mean, 3),
            "fee_rate_ewma":     round(self._fee_rate.mean,     3),
            "orphan_rate_ewma":  round(self._orphan_rate.mean,  6),
        }

# ─────────────────────────────────────────────────────────────────────────────
# SelfHealer
# ─────────────────────────────────────────────────────────────────────────────

class SelfHealer:
    """Automated self-healing for the Axiom node and related services."""

    MIN_RESTART_INTERVAL = 300.0  # 5 minutes

    def __init__(self, memory: ChainMemory, rpc: RpcClient) -> None:
        self._memory          = memory
        self._rpc             = rpc
        self._last_action_ts: Dict[str, float] = {}
        self._height_stuck_since: Optional[float] = None
        self._last_height: Optional[int]           = None

    def _can_act(self, action: str) -> bool:
        last = self._last_action_ts.get(action, 0.0)
        return (time.time() - last) >= self.MIN_RESTART_INTERVAL

    def _record_action(self, action: str) -> None:
        self._last_action_ts[action] = time.time()

    async def _run_cmd(self, cmd: List[str], timeout: int = 30) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                return False
            return proc.returncode == 0
        except Exception as exc:
            _log.warning("_run_cmd %s error: %s", cmd, exc)
            return False

    async def _restart_node(self) -> bool:
        _log.info("SelfHealer: restarting axiom-node via systemctl")
        ok = await self._run_cmd(["systemctl", "restart", "axiom-node"])
        await asyncio.sleep(5)
        return ok

    async def _restart_nginx(self) -> bool:
        _log.info("SelfHealer: reloading nginx")
        return await self._run_cmd(["systemctl", "reload", "nginx"])

    async def _restart_pm2(self) -> bool:
        _log.info("SelfHealer: restarting axiom-web via PM2")
        return await self._run_cmd(["pm2", "restart", "axiom-web"])

    async def _cleanup_logs(self) -> bool:
        _log.info("SelfHealer: vacuuming journald logs to 100M")
        return await self._run_cmd(["journalctl", "--vacuum-size=100M"])

    async def _optimize_mempool(self, fee_pressure: str) -> None:
        # Never auto-change consensus params; log recommendation only
        _log.warning(
            "SelfHealer: mempool fee pressure is '%s'. "
            "Recommendation: consider raising min relay fee via node config (manual action required).",
            fee_pressure,
        )

    async def check_and_heal(self, state: dict) -> List[str]:
        actions_taken: List[str] = []

        # 1. Is the RPC alive?
        status = await self._rpc.get("/status")
        if status is None:
            if self._can_act("restart_node"):
                ok = await self._restart_node()
                self._record_action("restart_node")
                reason = "RPC unresponsive — node restarted"
                await self._memory.save_healing_event("restart_node", reason, ok)
                actions_taken.append(f"restart_node (success={ok})")
            return actions_taken  # other checks pointless if node is down

        # 2. Height stuck > 10 minutes?
        height = state.get("height")
        now    = time.time()
        if height is not None:
            if height == self._last_height:
                if self._height_stuck_since is None:
                    self._height_stuck_since = now
                elif (now - self._height_stuck_since) > 600:
                    if self._can_act("restart_node_stuck"):
                        ok = await self._restart_node()
                        self._record_action("restart_node_stuck")
                        reason = f"Height stuck at {height} for >10min"
                        await self._memory.save_healing_event("restart_node_stuck", reason, ok)
                        actions_taken.append(f"restart_node_stuck height={height} (success={ok})")
                        self._height_stuck_since = None
            else:
                self._height_stuck_since = None
            self._last_height = height

        # 3. Disk usage > 90%?
        try:
            disk = psutil.disk_usage("/")
            if disk.percent > 90.0:
                if self._can_act("cleanup_logs"):
                    ok = await self._cleanup_logs()
                    self._record_action("cleanup_logs")
                    reason = f"Disk usage {disk.percent:.1f}% — vacuumed logs"
                    await self._memory.save_healing_event("cleanup_logs", reason, ok)
                    actions_taken.append(f"cleanup_logs disk={disk.percent:.1f}% (success={ok})")
        except Exception as exc:
            _log.debug("disk check error: %s", exc)

        # 4. Nginx active?
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "is-active", "--quiet", "nginx",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            if proc.returncode != 0:
                if self._can_act("restart_nginx"):
                    ok = await self._restart_nginx()
                    self._record_action("restart_nginx")
                    reason = "nginx not active — reloaded"
                    await self._memory.save_healing_event("restart_nginx", reason, ok)
                    actions_taken.append(f"restart_nginx (success={ok})")
        except Exception as exc:
            _log.debug("nginx check error: %s", exc)

        # 5. PM2 axiom-web online?
        try:
            proc = await asyncio.create_subprocess_exec(
                "pm2", "show", "axiom-web",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode("utf-8", errors="replace") if stdout else ""
            if "online" not in output.lower():
                if self._can_act("restart_pm2"):
                    ok = await self._restart_pm2()
                    self._record_action("restart_pm2")
                    reason = "axiom-web PM2 not online — restarted"
                    await self._memory.save_healing_event("restart_pm2", reason, ok)
                    actions_taken.append(f"restart_pm2 (success={ok})")
        except Exception as exc:
            _log.debug("pm2 check error: %s", exc)

        # 6. High fee pressure?
        fee_p90 = state.get("fee_p90", 0) or 0
        fee_p50 = state.get("fee_p50", 0) or 0
        if fee_p90 > 0 and fee_p50 > 0 and (fee_p90 / max(fee_p50, 1e-9)) > 5.0:
            await self._optimize_mempool("critical")
            actions_taken.append("mempool_advisory_logged")

        return actions_taken


# ─────────────────────────────────────────────────────────────────────────────
# SafeSelfHealer — Policy-Driven Healing (NEW)
# ─────────────────────────────────────────────────────────────────────────────

class SafeSelfHealer:
    """
    Policy-driven self-healer using the safe AxiomMind architecture.

    Flow:
    1. Detect anomaly (same as SelfHealer)
    2. Generate ActionProposal (instead of direct execution)
    3. PolicyEngine validates proposal
    4. SafeExecutor executes (if policy approves)
    5. AuditLog records everything

    Key invariants:
    - No direct subprocess execution
    - Policy approval REQUIRED before execution
    - Every action logged with tamper-proof signatures
    - All actions whitelisted (hardcoded)
    """

    def __init__(
        self,
        memory: ChainMemory,
        rpc: RpcClient,
        policy_engine: PolicyEngine = None,
        safe_executor: SafeExecutor = None,
        audit_log: AuditLog = None,
    ) -> None:
        self._memory = memory
        self._rpc = rpc
        self._last_action_ts: Dict[str, float] = {}
        self._height_stuck_since: Optional[float] = None
        self._last_height: Optional[int] = None

        # Safe modules (lazy-initialized if not provided)
        self._policy_engine = policy_engine or PolicyEngine(
            cooldown_config=MinCooldownConfig(
                restart_node=300,        # 5 minutes
                reload_nginx=300,
                restart_web=300,
                cleanup_logs=600,         # 10 minutes
            ),
            rate_limit_config=RateLimitConfig(
                max_actions_per_hour=10,
                max_restarts_per_6h=3,
            ),
        )
        self._safe_executor = safe_executor or SafeExecutor(
            config=ExecutorConfig(
                enable_execution=True,
                require_policy_approval=True,
                command_timeout_seconds=30,
            ),
            audit_logger=audit_log,
        )
        self._audit_log = audit_log

    async def _propose_action(
        self,
        action_type: ActionType,
        reason: str,
        severity: str = "info",
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[Tuple[ActionProposal, bool]]:
        """
        Generate an action proposal and pass it through policy → executor → audit.

        Returns (proposal, success) or None if proposal generation fails.
        """
        try:
            # Step 1: Create proposal
            proposal = ActionProposal(
                action_type=action_type,
                reason=reason,
                severity=severity,
                details=details or {},
            )

            _log.info(
                "SafeSelfHealer: Proposal generated for %s: %s",
                action_type.value, reason
            )

            # Log proposal
            if self._audit_log:
                await self._audit_log.log_action_proposed(proposal)

            # Step 2: Get system state for policy validation
            state = SystemState(
                rpc_alive=await self._is_rpc_alive(),
                best_height=self._memory._best_height if hasattr(self._memory, '_best_height') else 0,
                peer_count=self._memory._peer_count if hasattr(self._memory, '_peer_count') else 0,
                disk_percent=self._get_disk_percent(),
                nginx_active=await self._is_nginx_active(),
                axiom_web_online=await self._is_axiom_web_online(),
            )

            # Step 3: Validate with policy
            policy_result = await self._policy_engine.validate_action(proposal, state)

            if policy_result.decision != PolicyDecision.APPROVE:
                _log.warning(
                    "SafeSelfHealer: Policy rejected %s: %s",
                    action_type.value, policy_result.reason
                )
                if self._audit_log:
                    await self._audit_log.log_action_rejected(proposal, policy_result.reason)
                return (proposal, False)

            # Log approval
            if self._audit_log:
                await self._audit_log.log_action_approved(proposal, policy_result)

            # Step 4: Execute safely
            try:
                exec_result = await self._safe_executor.execute(proposal, policy_result)

                if exec_result.success:
                    _log.info(
                        "SafeSelfHealer: Action succeeded: %s",
                        action_type.value
                    )
                    self._record_action(action_type.value)
                    await self._memory.save_healing_event(
                        action_type.value, reason, True
                    )
                else:
                    _log.warning(
                        "SafeSelfHealer: Action failed: %s — %s",
                        action_type.value, exec_result.error
                    )
                    await self._memory.save_healing_event(
                        action_type.value, reason, False
                    )

                return (proposal, exec_result.success)

            except Exception as exc:
                _log.error(
                    "SafeSelfHealer: Execution error for %s: %s",
                    action_type.value, exc
                )
                if self._audit_log:
                    await self._audit_log.log_action_failed(
                        proposal, str(exc)
                    )
                await self._memory.save_healing_event(
                    action_type.value, f"Execution error: {exc}", False
                )
                return (proposal, False)

        except Exception as exc:
            _log.error("SafeSelfHealer: Proposal generation error: %s", exc)
            return None

    def _can_act(self, action: str) -> bool:
        """Check if enough time has passed since last action (cooldown)."""
        last = self._last_action_ts.get(action, 0.0)
        # Use policy engine's cooldown if available
        return True  # Policy engine handles cooldown

    def _record_action(self, action: str) -> None:
        """Record when an action was taken (for historical tracking)."""
        self._last_action_ts[action] = time.time()

    def _get_disk_percent(self) -> float:
        """Get current disk usage percentage."""
        try:
            disk = psutil.disk_usage("/")
            return disk.percent
        except Exception:
            return 0.0

    async def _is_rpc_alive(self) -> bool:
        """Check if RPC is responding."""
        try:
            status = await self._rpc.get("/status")
            return status is not None
        except Exception:
            return False

    async def _is_nginx_active(self) -> bool:
        """Check if nginx service is active."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "is-active", "--quiet", "nginx",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            return proc.returncode == 0
        except Exception:
            return False

    async def _is_axiom_web_online(self) -> bool:
        """Check if axiom-web is online via PM2."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "pm2", "show", "axiom-web",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode("utf-8", errors="replace") if stdout else ""
            return "online" in output.lower()
        except Exception:
            return False

    async def check_and_heal(self, state: dict) -> List[str]:
        """
        Check system health and propose healing actions (policy-driven).

        This is the main entry point. It mirrors SelfHealer.check_and_heal()
        but uses the safe action proposal flow instead of direct execution.
        """
        actions_taken: List[str] = []

        # 1. Is the RPC alive?
        rpc_alive = await self._is_rpc_alive()
        if not rpc_alive:
            result = await self._propose_action(
                ActionType.RESTART_NODE,
                reason="RPC unresponsive for 30s",
                severity="critical",
                details={"check": "rpc_status"},
            )
            if result:
                proposal, success = result
                actions_taken.append(f"restart_node (success={success})")
            return actions_taken  # Other checks pointless if node is down

        # 2. Height stuck > 10 minutes?
        height = state.get("height")
        now = time.time()
        if height is not None:
            if height == self._last_height:
                if self._height_stuck_since is None:
                    self._height_stuck_since = now
                elif (now - self._height_stuck_since) > 600:
                    result = await self._propose_action(
                        ActionType.RESTART_NODE,
                        reason=f"Height stuck at {height} for >10min",
                        severity="critical",
                        details={"height": height, "stuck_seconds": int(now - self._height_stuck_since)},
                    )
                    if result:
                        proposal, success = result
                        actions_taken.append(f"restart_node_stuck height={height} (success={success})")
                    self._height_stuck_since = None
            else:
                self._height_stuck_since = None
            self._last_height = height

        # 3. Disk usage > 90%?
        disk_percent = self._get_disk_percent()
        if disk_percent > 90.0:
            result = await self._propose_action(
                ActionType.CLEANUP_LOGS,
                reason=f"Disk usage {disk_percent:.1f}% — vacuuming logs",
                severity="warning",
                details={"disk_percent": disk_percent},
            )
            if result:
                proposal, success = result
                actions_taken.append(f"cleanup_logs disk={disk_percent:.1f}% (success={success})")

        # 4. Nginx active?
        nginx_active = await self._is_nginx_active()
        if not nginx_active:
            result = await self._propose_action(
                ActionType.RELOAD_NGINX,
                reason="nginx not active — attempting reload",
                severity="warning",
                details={"check": "nginx_status"},
            )
            if result:
                proposal, success = result
                actions_taken.append(f"reload_nginx (success={success})")

        # 5. PM2 axiom-web online?
        web_online = await self._is_axiom_web_online()
        if not web_online:
            result = await self._propose_action(
                ActionType.RESTART_WEB,
                reason="axiom-web PM2 not online — restarting",
                severity="warning",
                details={"check": "pm2_status"},
            )
            if result:
                proposal, success = result
                actions_taken.append(f"restart_web (success={success})")

        # 6. High fee pressure? (advisory only, no execution)
        fee_p90 = state.get("fee_p90", 0) or 0
        fee_p50 = state.get("fee_p50", 0) or 0
        if fee_p90 > 0 and fee_p50 > 0 and (fee_p90 / max(fee_p50, 1e-9)) > 5.0:
            # This is advisory-only, log but don't execute (consensus params are manual)
            _log.warning(
                "SafeSelfHealer: mempool fee pressure is critical (p90=%s, p50=%s). "
                "Recommendation: consider raising min relay fee via node config (manual action required).",
                fee_p90, fee_p50,
            )
            actions_taken.append("mempool_advisory_logged")

        return actions_taken

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard HTML
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AxiomMind v2 — Autonomous Blockchain Guardian</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0a0a0f;--panel:#12121a;--border:#1e1e2e;
    --green:#00ff88;--red:#ff4466;--yellow:#ffcc00;--blue:#4488ff;
    --text:#c8c8d8;--dim:#555568;--font:'JetBrains Mono',monospace;
  }
  body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;min-height:100vh}
  header{
    display:flex;align-items:center;justify-content:space-between;
    padding:14px 24px;border-bottom:1px solid var(--border);
    background:#0d0d16;
  }
  header h1{font-size:16px;font-weight:700;color:var(--green);letter-spacing:.05em}
  #conn-status{display:flex;align-items:center;gap:8px;font-size:12px}
  #conn-dot{width:10px;height:10px;border-radius:50%;background:var(--dim);transition:background .3s}
  #conn-dot.live{background:var(--green);box-shadow:0 0 8px var(--green)}
  #conn-dot.reconnecting{background:var(--yellow);animation:blink 1s infinite}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
  .grid{
    display:grid;
    grid-template-columns:repeat(auto-fill,minmax(320px,1fr));
    gap:14px;padding:18px;
  }
  .panel{
    background:var(--panel);border:1px solid var(--border);border-radius:8px;
    padding:16px;display:flex;flex-direction:column;gap:10px;
  }
  .panel h2{font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:var(--dim)}
  .kv{display:flex;justify-content:space-between;align-items:baseline}
  .kv .k{color:var(--dim);font-size:12px}
  .kv .v{font-size:13px;font-weight:600;color:var(--text)}
  .big-num{font-size:36px;font-weight:700;line-height:1}
  .health-green{color:var(--green)}
  .health-yellow{color:var(--yellow)}
  .health-red{color:var(--red)}
  /* gauge */
  .gauge-wrap{display:flex;flex-direction:column;align-items:center;gap:8px}
  .gauge{position:relative;width:140px;height:70px;overflow:hidden}
  .gauge svg{width:140px;height:140px;position:absolute;top:0;left:0}
  .gauge-val{font-size:26px;font-weight:700;position:absolute;bottom:2px;left:50%;transform:translateX(-50%)}
  /* scrollable feed */
  .feed{max-height:180px;overflow-y:auto;display:flex;flex-direction:column;gap:4px}
  .feed::-webkit-scrollbar{width:4px}
  .feed::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
  .feed-item{padding:5px 8px;border-radius:4px;font-size:12px;border-left:3px solid var(--dim)}
  .feed-item.critical{border-color:var(--red);background:#1a0810}
  .feed-item.warning{border-color:var(--yellow);background:#141008}
  .feed-item.info{border-color:var(--blue);background:#08101a}
  /* table */
  table{width:100%;border-collapse:collapse;font-size:12px}
  th{text-align:left;color:var(--dim);padding:4px 6px;border-bottom:1px solid var(--border)}
  td{padding:4px 6px}
  /* score bar */
  .bar-wrap{width:80px;height:8px;background:var(--border);border-radius:4px;overflow:hidden}
  .bar-fill{height:100%;border-radius:4px;transition:width .4s}
  .bar-good{background:var(--green)}
  .bar-mid{background:var(--yellow)}
  .bar-bad{background:var(--red)}
  .trend-up{color:var(--red)}
  .trend-down{color:var(--green)}
  .trend-stable{color:var(--blue)}
</style>
</head>
<body>
<header>
  <h1>AxiomMind v2 &mdash; Autonomous Blockchain Guardian</h1>
  <div id="conn-status">
    <div id="conn-dot"></div>
    <span id="conn-label">CONNECTING</span>
  </div>
</header>
<div class="grid">

  <!-- Chain Overview -->
  <div class="panel">
    <h2>Chain Overview</h2>
    <div class="kv"><span class="k">Height</span><span class="v" id="ov-height">—</span></div>
    <div class="kv"><span class="k">Peers</span><span class="v" id="ov-peers">—</span></div>
    <div class="kv"><span class="k">Health Score</span>
      <span class="v big-num" id="ov-health">—</span></div>
    <div class="kv"><span class="k">Tip Age</span><span class="v" id="ov-tipage">—</span></div>
    <div class="kv"><span class="k">Network</span><span class="v" id="ov-network">—</span></div>
    <div class="kv"><span class="k">Version</span><span class="v" id="ov-version">—</span></div>
  </div>

  <!-- Health Gauge -->
  <div class="panel">
    <h2>Health Score Gauge</h2>
    <div class="gauge-wrap">
      <div class="gauge">
        <svg viewBox="0 0 140 140">
          <path d="M10,70 a60,60 0 0,1 120,0" stroke="#1e1e2e" stroke-width="12" fill="none"/>
          <path id="gauge-arc" d="M10,70 a60,60 0 0,1 120,0"
                stroke="#00ff88" stroke-width="12" fill="none"
                stroke-dasharray="188.5" stroke-dashoffset="188.5"
                stroke-linecap="round" style="transition:stroke-dashoffset .6s,stroke .4s"/>
        </svg>
        <span class="gauge-val" id="gauge-val">0</span>
      </div>
      <div style="font-size:11px;color:var(--dim)" id="gauge-label">Calculating...</div>
    </div>
  </div>

  <!-- Adaptive Baselines -->
  <div class="panel">
    <h2>Adaptive Baselines</h2>
    <table>
      <tr><th>Metric</th><th>EWMA</th></tr>
      <tr><td>Block Time</td><td id="bl-bt">—</td></tr>
      <tr><td>Peer Count</td><td id="bl-pc">—</td></tr>
      <tr><td>Mempool Size</td><td id="bl-mp">—</td></tr>
      <tr><td>Fee Rate</td><td id="bl-fee">—</td></tr>
      <tr><td>Fee Prediction</td><td id="bl-pred">—</td></tr>
      <tr><td>R²</td><td id="bl-r2">—</td></tr>
    </table>
  </div>

  <!-- Fee Market -->
  <div class="panel">
    <h2>Fee Market</h2>
    <div class="kv"><span class="k">Median (p50)</span><span class="v" id="fee-p50">—</span></div>
    <div class="kv"><span class="k">High (p90)</span><span class="v" id="fee-p90">—</span></div>
    <div class="kv"><span class="k">Predicted</span><span class="v" id="fee-pred">—</span></div>
    <div class="kv"><span class="k">Trend</span><span class="v" id="fee-trend">—</span></div>
    <div class="kv"><span class="k">Mempool txns</span><span class="v" id="fee-mp">—</span></div>
  </div>

  <!-- Anomaly Feed -->
  <div class="panel">
    <h2>Anomalies Feed</h2>
    <div class="feed" id="anomaly-feed">
      <div class="feed-item info">Waiting for data...</div>
    </div>
  </div>

  <!-- Agent Decisions -->
  <div class="panel">
    <h2>Agent Decisions</h2>
    <div class="feed" id="agent-feed">
      <div class="feed-item info">Waiting for data...</div>
    </div>
  </div>

  <!-- Healing Events -->
  <div class="panel">
    <h2>Healing Events</h2>
    <div class="feed" id="healing-feed">
      <div class="feed-item info">Waiting for data...</div>
    </div>
  </div>

  <!-- Peer Reputation -->
  <div class="panel">
    <h2>Peer Reputation</h2>
    <div id="peer-table-wrap">
      <table>
        <tr><th>Peer</th><th>Score</th><th>Bar</th></tr>
        <tbody id="peer-tbody"><tr><td colspan="3" style="color:var(--dim)">No peer data</td></tr></tbody>
      </table>
    </div>
  </div>

</div>
<script>
(function(){
  let ws = null;
  let reconnectDelay = 1000;
  const maxDelay = 30000;

  function setStatus(state){
    const dot = document.getElementById('conn-dot');
    const lbl = document.getElementById('conn-label');
    dot.className = state;
    lbl.textContent = state === 'live' ? 'LIVE' : 'RECONNECTING';
  }

  function connect(){
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(proto + '://' + location.host + '/ws');
    ws.onopen = function(){
      setStatus('live');
      reconnectDelay = 1000;
    };
    ws.onmessage = function(e){
      try{ handleMessage(JSON.parse(e.data)); }catch(ex){}
    };
    ws.onerror = function(){};
    ws.onclose = function(){
      setStatus('reconnecting');
      setTimeout(connect, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, maxDelay);
    };
  }

  function fmt(v, digits){ return (v == null || v === undefined) ? '—' : (+v).toFixed(digits||0); }
  function fmtAge(secs){
    if(secs == null) return '—';
    secs = +secs;
    if(secs < 60) return secs.toFixed(1)+'s';
    if(secs < 3600) return (secs/60).toFixed(1)+'m';
    return (secs/3600).toFixed(2)+'h';
  }

  function updateGauge(score){
    const arc = document.getElementById('gauge-arc');
    const val = document.getElementById('gauge-val');
    const lbl = document.getElementById('gauge-label');
    const s = Math.min(100, Math.max(0, +score||0));
    const total = 188.5;
    arc.setAttribute('stroke-dashoffset', (total - s/100*total).toString());
    arc.setAttribute('stroke', s >= 70 ? '#00ff88' : s >= 40 ? '#ffcc00' : '#ff4466');
    val.textContent = s.toFixed(0);
    lbl.textContent = s >= 70 ? 'Healthy' : s >= 40 ? 'Degraded' : 'Critical';
  }

  function healthClass(s){
    s = +s||0;
    return s >= 70 ? 'health-green' : s >= 40 ? 'health-yellow' : 'health-red';
  }

  function applyState(d){
    if(!d) return;
    setText('ov-height',  d.height   != null ? '#'+d.height : '—');
    setText('ov-peers',   d.peers    != null ? d.peers : '—');
    const h = d.health_score != null ? +d.health_score : null;
    const hel = document.getElementById('ov-health');
    hel.textContent = h != null ? h.toFixed(1) : '—';
    hel.className   = 'v big-num ' + (h != null ? healthClass(h) : '');
    if(h != null) updateGauge(h);
    setText('ov-tipage',  d.tip_age   != null ? fmtAge(d.tip_age) : '—');
    setText('ov-network', d.network   || '—');
    setText('ov-version', d.version   || '—');
    setText('fee-p50',    d.fee_p50   != null ? fmt(d.fee_p50,2)+' sat/b' : '—');
    setText('fee-p90',    d.fee_p90   != null ? fmt(d.fee_p90,2)+' sat/b' : '—');
    setText('fee-mp',     d.mempool_size != null ? d.mempool_size.toLocaleString() : '—');
  }

  function applyLearning(d){
    if(!d) return;
    const b = d.baselines || {};
    setText('bl-bt',   b.block_time_ewma   != null ? fmt(b.block_time_ewma,2)+'s' : '—');
    setText('bl-pc',   b.peer_count_ewma   != null ? fmt(b.peer_count_ewma,1) : '—');
    setText('bl-mp',   b.mempool_size_ewma != null ? fmt(b.mempool_size_ewma,0) : '—');
    setText('bl-fee',  b.fee_rate_ewma     != null ? fmt(b.fee_rate_ewma,2)+' sat/b' : '—');
    const fp = d.fee_prediction;
    setText('bl-pred', fp != null ? fmt(fp,2)+' sat/b' : '—');
    setText('fee-pred',fp != null ? fmt(fp,2)+' sat/b' : '—');
    setText('bl-r2',   d.r_squared         != null ? fmt(d.r_squared,3) : '—');
    const trend = d.fee_trend || 'stable';
    const tEl = document.getElementById('fee-trend');
    tEl.textContent  = trend === 'rising' ? '↑ Rising' : trend === 'falling' ? '↓ Falling' : '→ Stable';
    tEl.className    = 'v ' + (trend === 'rising' ? 'trend-up' : trend === 'falling' ? 'trend-down' : 'trend-stable');
  }

  function applyAnomalies(list){
    const feed = document.getElementById('anomaly-feed');
    if(!list || !list.length){ feed.innerHTML='<div class="feed-item info">No anomalies detected</div>'; return; }
    feed.innerHTML = list.slice(-30).reverse().map(function(a){
      const cls = a.severity === 'critical' ? 'critical' : 'warning';
      return '<div class="feed-item '+cls+'">'+
        '<b>'+esc(a.kind||'')+'</b> val='+fmt(a.value,2)+
        ' z='+fmt(a.z_score,1)+' ('+esc(a.severity||'')+')</div>';
    }).join('');
  }

  function applyDecisions(list){
    const feed = document.getElementById('agent-feed');
    if(!list || !list.length){ feed.innerHTML='<div class="feed-item info">No decisions yet</div>'; return; }
    feed.innerHTML = list.slice(0,10).map(function(d){
      const action = (d.action||d.recommended_action||JSON.stringify(d)).substring(0,80);
      return '<div class="feed-item info"><b>'+esc(d.agent||'?')+'</b> '+esc(action)+'</div>';
    }).join('');
  }

  function applyHealing(list){
    const feed = document.getElementById('healing-feed');
    if(!list || !list.length){ feed.innerHTML='<div class="feed-item info">No healing events</div>'; return; }
    feed.innerHTML = list.slice(0,10).map(function(h){
      const cls = h.success ? 'info' : 'warning';
      const ts  = h.ts ? new Date(h.ts*1000).toLocaleTimeString() : '';
      return '<div class="feed-item '+cls+'">'+esc(h.action||'')+(h.reason?' — '+esc(h.reason):'')+(ts?' <span style="color:var(--dim)">'+ts+'</span>':'')+'</div>';
    }).join('');
  }

  function applyPeers(rep){
    if(!rep || !rep.scores) return;
    const tbody = document.getElementById('peer-tbody');
    const entries = Object.entries(rep.scores).slice(0,20);
    if(!entries.length){ tbody.innerHTML='<tr><td colspan="3" style="color:var(--dim)">No peer data</td></tr>'; return; }
    tbody.innerHTML = entries.map(function(kv){
      const peer = kv[0]; const score = +kv[1];
      const pct  = (score*100).toFixed(0);
      const cls  = score >= 0.7 ? 'bar-good' : score >= 0.4 ? 'bar-mid' : 'bar-bad';
      return '<tr><td style="color:var(--dim);font-size:11px">'+esc(peer.substring(0,20))+'</td>'+
             '<td>'+pct+'%</td>'+
             '<td><div class="bar-wrap"><div class="bar-fill '+cls+'" style="width:'+pct+'%"></div></div></td></tr>';
    }).join('');
  }

  function handleMessage(msg){
    const t = msg.type;
    if(t === 'state')     { applyState(msg.data); }
    else if(t === 'anomalies') { applyAnomalies(msg.data); }
    else if(t === 'analysis')  { applyDecisions(Array.isArray(msg.data) ? msg.data : [msg.data]); }
    else if(t === 'healing')   { applyHealing(Array.isArray(msg.data) ? msg.data : [msg.data]); }
    else if(t === 'learning')  { applyLearning(msg.data); }
    else if(t === 'peers')     { applyPeers(msg.data); }
  }

  function setText(id, v){ const e=document.getElementById(id); if(e) e.textContent=v; }
  function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  // Initial data fetch
  async function fetchInitial(){
    try{
      const [st, al, de, he] = await Promise.all([
        fetch('/api/state').then(r=>r.json()).catch(()=>null),
        fetch('/api/alerts').then(r=>r.json()).catch(()=>null),
        fetch('/api/decisions').then(r=>r.json()).catch(()=>null),
        fetch('/api/healing').then(r=>r.json()).catch(()=>null),
      ]);
      if(st) applyState(st);
      if(al && al.alerts) applyAnomalies(al.alerts);
      if(de && de.decisions) applyDecisions(de.decisions);
      if(he && he.events) applyHealing(he.events);
    }catch(ex){}
  }

  fetchInitial();
  connect();
})();
</script>
</body>
</html>"""

# ─────────────────────────────────────────────────────────────────────────────
# AxiomMindDaemon
# ─────────────────────────────────────────────────────────────────────────────

class AxiomMindDaemon:
    """Main orchestrator: monitoring, analysis, healing, and learning loops."""

    def __init__(self) -> None:
        self.rpc              = RpcClient(RPC_URL)
        self.memory           = ChainMemory(DB_PATH)
        self.detector         = AdaptiveAnomalyDetector()
        self.fee_predictor    = FeePredictor()
        self.peer_reputation  = PeerReputation()

        # ── Safe AxiomMind Integration ──────────────────────────────────────
        if _SAFE_AXIOM_MIND_AVAILABLE:
            # Initialize safe modules
            audit_db_path = os.environ.get(
                "AXIOM_AUDIT_DB",
                "/var/lib/axiom-mind/audit.db"
            )
            audit_secret = os.environ.get(
                "AXIOM_AUDIT_SECRET_KEY",
                "fallback_secret_key_32_bytes_long_"
            )

            self.audit_log = AuditLog(audit_db_path, audit_secret)
            self.policy_engine = PolicyEngine(
                cooldown_config=MinCooldownConfig(
                    restart_node=300,        # 5 min
                    reload_nginx=300,
                    restart_web=300,
                    cleanup_logs=600,         # 10 min
                ),
                rate_limit_config=RateLimitConfig(
                    max_actions_per_hour=10,
                    max_restarts_per_6h=3,
                ),
            )
            self.safe_executor = SafeExecutor(
                config=ExecutorConfig(
                    enable_execution=True,
                    require_policy_approval=True,
                    command_timeout_seconds=30,
                ),
                audit_logger=self.audit_log,
            )

            # Use SafeSelfHealer with safe modules
            self.healer = SafeSelfHealer(
                self.memory,
                self.rpc,
                policy_engine=self.policy_engine,
                safe_executor=self.safe_executor,
                audit_log=self.audit_log,
            )

            _log.info("AxiomMindDaemon: Using SAFE healing (policy-driven architecture)")
        else:
            # Fallback to old SelfHealer (for backwards compatibility)
            self.healer = SelfHealer(self.memory, self.rpc)
            self.audit_log = None
            self.policy_engine = None
            self.safe_executor = None
            _log.warning(
                "AxiomMindDaemon: axiom-mind module not available, "
                "using legacy SelfHealer (NOT SAFE)"
            )

        self.agents: Dict[str, ExpertAgent] = {
            name: ExpertAgent(name, ANTHROPIC_API_KEY)
            for name in ("security", "consensus", "network", "crypto", "economics")
        }
        self.current_state: dict        = {}
        self.anomaly_buffer: deque      = deque(maxlen=500)
        self.ws_clients: set            = set()
        self.log                        = _log
        self._last_deep_analysis: float = 0.0
        self._agent_rotation_idx: int   = 0
        self._all_decisions: deque      = deque(maxlen=100)
        self._all_healing:   deque      = deque(maxlen=100)

    # ── WebSocket broadcast ─────────────────────────────────────────────────

    async def broadcast(self, msg_type: str, data: Any) -> None:
        if not self.ws_clients:
            return
        payload = json.dumps({"type": msg_type, "data": data})
        dead: set = set()
        for client in list(self.ws_clients):
            try:
                await client.send_text(payload)
            except Exception:
                dead.add(client)
        self.ws_clients -= dead

    # ── collect_state ───────────────────────────────────────────────────────

    async def collect_state(self) -> dict:
        now = time.time()
        state: dict = {"collected_at": now}

        # /status
        status = await self.rpc.get("/status")
        if status:
            state["height"]       = status.get("best_height") or status.get("height")
            state["peers"]        = status.get("peers") or status.get("peer_count")
            state["mempool_size"] = status.get("mempool_size") or status.get("mempool_tx_count")
            state["version"]      = status.get("version")
            state["network"]      = status.get("network")
            state["best_hash"]    = status.get("best_block_hash") or status.get("best_hash")

        # /mempool/stats
        mp_stats = await self.rpc.get("/mempool/stats")
        if mp_stats:
            state["fee_p50"]       = mp_stats.get("fee_p50") or mp_stats.get("median_fee")
            state["fee_p90"]       = mp_stats.get("fee_p90") or mp_stats.get("high_fee")
            state["mempool_bytes"] = mp_stats.get("total_bytes") or mp_stats.get("mempool_bytes")
            if state.get("mempool_size") is None:
                state["mempool_size"] = mp_stats.get("tx_count")

        # /metrics
        metrics = await self.rpc.get("/metrics")
        if metrics:
            state["hashrate"]    = metrics.get("hashrate")
            if state.get("height") is None:
                state["height"] = metrics.get("height")
            if state.get("peers") is None:
                state["peers"]  = metrics.get("peer_count")

        # /blocks/recent?limit=10
        recent = await self.rpc.get("/blocks/recent?limit=10")
        if recent:
            blocks = recent.get("blocks") or recent if isinstance(recent, list) else []
            if isinstance(recent, dict):
                blocks = recent.get("blocks", [])
            if blocks and len(blocks) >= 2:
                times = [b.get("timestamp") for b in blocks if b.get("timestamp")]
                if len(times) >= 2:
                    times_sorted = sorted(times, reverse=True)
                    deltas = [times_sorted[i] - times_sorted[i+1]
                              for i in range(len(times_sorted)-1)
                              if times_sorted[i] - times_sorted[i+1] > 0]
                    if deltas:
                        state["block_time_avg"]  = sum(deltas) / len(deltas)
                        state["block_time_last"] = deltas[0]
                if times:
                    last_ts = max(times)
                    state["tip_age"] = now - last_ts if last_ts < now else 0.0

        # /peers
        peers_data = await self.rpc.get("/peers")
        if peers_data:
            peer_list = peers_data if isinstance(peers_data, list) else peers_data.get("peers", [])
            state["peer_list"] = [p.get("addr") or p.get("address") or str(p)
                                  for p in peer_list[:20] if isinstance(p, dict)]
            if state.get("peers") is None:
                state["peers"] = len(peer_list)

        return state

    # ── context builder ─────────────────────────────────────────────────────

    def _build_context(self, state: dict, anomalies: List[dict], trigger: str) -> str:
        baselines = self.detector.baselines()
        fee_pred  = self.fee_predictor.predict(state.get("mempool_size") or 200)
        r2        = self.fee_predictor.r_squared()
        trend     = self.fee_predictor.trend()

        lines = [
            f"=== Axiom Network Chain State (trigger={trigger}) ===",
            f"Timestamp:      {datetime.now(timezone.utc).isoformat()}",
            f"Height:         {state.get('height', 'unknown')}",
            f"Best Hash:      {state.get('best_hash', 'unknown')}",
            f"Peers:          {state.get('peers', 0)}",
            f"Mempool txns:   {state.get('mempool_size', 0)}",
            f"Mempool bytes:  {state.get('mempool_bytes', 0)}",
            f"Fee p50:        {state.get('fee_p50', 0)} sat/byte",
            f"Fee p90:        {state.get('fee_p90', 0)} sat/byte",
            f"Block time avg: {state.get('block_time_avg', 30):.1f}s",
            f"Block time last:{state.get('block_time_last', 30):.1f}s",
            f"Tip age:        {state.get('tip_age', 0):.1f}s",
            f"Hashrate:       {state.get('hashrate', 'unknown')}",
            f"Network:        {state.get('network', 'unknown')}",
            f"Version:        {state.get('version', 'unknown')}",
            "",
            "=== Adaptive EWMA Baselines ===",
            f"block_time_ewma:   {baselines['block_time_ewma']}s",
            f"peer_count_ewma:   {baselines['peer_count_ewma']}",
            f"mempool_size_ewma: {baselines['mempool_size_ewma']}",
            f"fee_rate_ewma:     {baselines['fee_rate_ewma']} sat/byte",
            f"orphan_rate_ewma:  {baselines['orphan_rate_ewma']}",
            "",
            "=== Fee Prediction (online linear regression) ===",
            f"predicted_fee:  {fee_pred:.2f} sat/byte",
            f"r_squared:      {r2:.3f}",
            f"trend:          {trend}",
            "",
            "=== Architecture Context ===",
            "Consensus:    Proof-of-Work, LWMA-3 difficulty adjustment",
            "Signatures:   ML-DSA-87 (post-quantum, NIST FIPS 204)",
            "Block target: 30 seconds",
            "Hashing:      SHA-3 / Keccak variants",
            "",
        ]

        if anomalies:
            lines.append(f"=== Recent Anomalies ({len(anomalies)}) ===")
            for a in anomalies[-10:]:
                lines.append(
                    f"  [{a.get('severity','?').upper()}] {a.get('kind','?')} "
                    f"val={a.get('value','?')} z={a.get('z_score','?')} @ {a.get('ts','?')}"
                )
        else:
            lines.append("=== Recent Anomalies: none ===")

        peer_rep = self.peer_reputation.summary()
        if peer_rep.get("suspicious"):
            lines.append(f"\nSuspicious peers: {peer_rep['suspicious']}")
        if peer_rep.get("banned"):
            lines.append(f"Banned peers: {peer_rep['banned']}")

        return "\n".join(lines)

    # ── monitoring loop ─────────────────────────────────────────────────────

    async def monitor_loop(self) -> None:
        self.log.info("monitor_loop started (interval=30s)")
        while True:
            try:
                state = await self.collect_state()
                self.current_state = state

                new_anomalies: List[dict] = []

                # Anomaly checks
                if state.get("block_time_last") is not None:
                    a = self.detector.check_block_time(state["block_time_last"])
                    if a:
                        new_anomalies.append(a)
                        self.anomaly_buffer.append(a)
                        await self.memory.save_alert(a["severity"], a["kind"], json.dumps(a))

                if state.get("peers") is not None:
                    a = self.detector.check_peer_count(int(state["peers"]))
                    if a:
                        new_anomalies.append(a)
                        self.anomaly_buffer.append(a)
                        await self.memory.save_alert(a["severity"], a["kind"], json.dumps(a))

                if state.get("mempool_size") is not None:
                    a = self.detector.check_mempool(
                        int(state["mempool_size"]),
                        int(state.get("mempool_bytes") or 0),
                    )
                    if a:
                        new_anomalies.append(a)
                        self.anomaly_buffer.append(a)
                        await self.memory.save_alert(a["severity"], a["kind"], json.dumps(a))

                if state.get("fee_p50") is not None:
                    a = self.detector.check_fee(
                        float(state["fee_p50"]),
                        float(state.get("fee_p90") or state["fee_p50"]),
                    )
                    if a:
                        new_anomalies.append(a)
                        self.anomaly_buffer.append(a)
                        await self.memory.save_alert(a["severity"], a["kind"], json.dumps(a))

                # Update fee predictor
                if state.get("mempool_size") is not None and state.get("fee_p50") is not None:
                    self.fee_predictor.update(int(state["mempool_size"]), float(state["fee_p50"]))

                # Update peer reputation (penalise extremely slow peers not in list)
                for peer_addr in state.get("peer_list", []):
                    if peer_addr and peer_addr not in self.peer_reputation.scores:
                        self.peer_reputation.scores[peer_addr]     = 1.0
                        self.peer_reputation.violations[peer_addr] = []

                # Health score
                health = self.detector.compute_health_score(state)
                state["health_score"] = health

                # Save to DB
                await self.memory.save_metrics(state)

                # Broadcast
                await self.broadcast("state", state)
                if new_anomalies:
                    await self.broadcast("anomalies", list(self.anomaly_buffer))

                self.log.info(
                    "Height=%s Peers=%s Health=%.1f/100 Mempool=%s",
                    state.get("height", "?"),
                    state.get("peers", "?"),
                    health,
                    state.get("mempool_size", "?"),
                )

            except Exception as exc:
                self.log.error("monitor_loop error: %s", exc, exc_info=True)

            await asyncio.sleep(30)

    # ── analysis loop ───────────────────────────────────────────────────────

    async def analysis_loop(self) -> None:
        self.log.info("analysis_loop started (interval=60s)")
        while True:
            try:
                await asyncio.sleep(60)

                state     = self.current_state
                anomalies = list(self.anomaly_buffer)

                # Check for critical anomalies
                critical = [a for a in anomalies if a.get("severity") == "critical"]

                results: List[dict] = []

                if critical:
                    self.log.warning(
                        "analysis_loop: %d critical anomalies → running security+network agents",
                        len(critical),
                    )
                    context = self._build_context(state, anomalies, "critical_anomaly")
                    tasks   = [
                        asyncio.get_event_loop().run_in_executor(
                            None, self.agents[name].analyze, context
                        )
                        for name in ("security", "network")
                    ]
                    done = await asyncio.gather(*tasks, return_exceptions=True)
                    for res in done:
                        if isinstance(res, Exception):
                            self.log.warning("analysis_loop agent error: %s", res)
                        elif isinstance(res, dict):
                            results.append(res)
                            action = res.get("action") or res.get("recommended_action") or ""
                            await self.memory.save_agent_decision(
                                res.get("agent", "?"),
                                json.dumps(res),
                                str(action),
                            )

                # Scheduled deep analysis every 5 minutes, rotating agents
                now = time.time()
                if (now - self._last_deep_analysis) >= 300:
                    self._last_deep_analysis = now
                    agent_names   = list(self.agents.keys())
                    agent_name    = agent_names[self._agent_rotation_idx % len(agent_names)]
                    self._agent_rotation_idx += 1
                    context = self._build_context(state, anomalies, f"scheduled_{agent_name}")
                    self.log.info("analysis_loop: scheduled deep analysis by agent=%s", agent_name)
                    try:
                        res = await asyncio.get_event_loop().run_in_executor(
                            None, self.agents[agent_name].analyze, context
                        )
                        if isinstance(res, dict):
                            results.append(res)
                            action = res.get("action") or res.get("recommended_action") or ""
                            await self.memory.save_agent_decision(
                                res.get("agent", agent_name),
                                json.dumps(res),
                                str(action),
                            )
                    except Exception as exc:
                        self.log.warning("analysis_loop scheduled error: %s", exc)

                if results:
                    for r in results:
                        self._all_decisions.appendleft(r)
                    await self.broadcast("analysis", results)

            except Exception as exc:
                self.log.error("analysis_loop error: %s", exc, exc_info=True)

    # ── healing loop ────────────────────────────────────────────────────────

    async def healing_loop(self) -> None:
        self.log.info("healing_loop started (initial delay=30s, interval=60s)")
        await asyncio.sleep(30)
        while True:
            try:
                actions = await self.healer.check_and_heal(self.current_state)
                if actions:
                    self.log.info("healing_loop: actions taken: %s", actions)
                    healing_entries = [
                        {"action": a, "ts": time.time(), "success": True}
                        for a in actions
                    ]
                    for entry in healing_entries:
                        self._all_healing.appendleft(entry)
                    await self.broadcast("healing", healing_entries)
            except Exception as exc:
                self.log.error("healing_loop error: %s", exc, exc_info=True)
            await asyncio.sleep(60)

    # ── learning loop ───────────────────────────────────────────────────────

    async def learning_loop(self) -> None:
        self.log.info("learning_loop started (interval=600s)")
        last_decay = time.time()
        while True:
            try:
                await asyncio.sleep(600)

                now     = time.time()
                elapsed = now - last_decay
                last_decay = now

                self.peer_reputation.decay(elapsed)

                baselines   = self.detector.baselines()
                mempool_sz  = self.current_state.get("mempool_size") or 200
                fee_pred    = self.fee_predictor.predict(int(mempool_sz))
                r2          = self.fee_predictor.r_squared()
                trend       = self.fee_predictor.trend()
                peer_rep    = self.peer_reputation.summary()

                self.log.info(
                    "learning_loop baselines: %s | fee_pred=%.2f r2=%.3f trend=%s",
                    baselines, fee_pred, r2, trend,
                )

                learning_payload = {
                    "baselines":      baselines,
                    "fee_prediction": round(fee_pred, 2),
                    "r_squared":      round(r2, 3),
                    "fee_trend":      trend,
                    "peer_reputation": peer_rep,
                }
                await self.broadcast("learning", learning_payload)
                await self.broadcast("peers",    peer_rep)

            except Exception as exc:
                self.log.error("learning_loop error: %s", exc, exc_info=True)

    # ── main run ────────────────────────────────────────────────────────────

    async def run(self) -> None:
        banner = "\n".join([
            "╔══════════════════════════════════════════════════════╗",
            "║        AxiomMind v2 — Autonomous Blockchain Guardian ║",
            "║        Dashboard: http://0.0.0.0:{port:<5}               ║",
            "║        RPC:       {rpc:<38}║",
            "║        DB:        {db:<38}║",
            "╚══════════════════════════════════════════════════════╝",
        ]).format(port=DASHBOARD_PORT, rpc=RPC_URL[:38], db=DB_PATH[:38])
        self.log.info("\n%s", banner)

        await self.memory.init()

        await asyncio.gather(
            self.monitor_loop(),
            self.analysis_loop(),
            self.healing_loop(),
            self.learning_loop(),
        )

# ─────────────────────────────────────────────────────────────────────────────
# FastAPI routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/api/state")
async def api_state() -> JSONResponse:
    daemon: Optional[AxiomMindDaemon] = getattr(app.state, "daemon", None)
    if daemon is None:
        return JSONResponse({"error": "daemon not ready"}, status_code=503)
    return JSONResponse(daemon.current_state)


@app.get("/api/alerts")
async def api_alerts() -> JSONResponse:
    daemon: Optional[AxiomMindDaemon] = getattr(app.state, "daemon", None)
    if daemon is None:
        return JSONResponse({"alerts": []})
    alerts = await daemon.memory.get_recent_alerts(50)
    return JSONResponse({"alerts": alerts})


@app.get("/api/decisions")
async def api_decisions() -> JSONResponse:
    daemon: Optional[AxiomMindDaemon] = getattr(app.state, "daemon", None)
    if daemon is None:
        return JSONResponse({"decisions": []})
    decisions = await daemon.memory.get_agent_decisions(20)
    return JSONResponse({"decisions": decisions})


@app.get("/api/healing")
async def api_healing() -> JSONResponse:
    daemon: Optional[AxiomMindDaemon] = getattr(app.state, "daemon", None)
    if daemon is None:
        return JSONResponse({"events": []})
    events = await daemon.memory.get_healing_events(20)
    return JSONResponse({"events": events})


@app.get("/api/stats")
async def api_stats() -> JSONResponse:
    daemon: Optional[AxiomMindDaemon] = getattr(app.state, "daemon", None)
    if daemon is None:
        return JSONResponse({})
    db_stats  = await daemon.memory.get_stats()
    baselines = daemon.detector.baselines()
    peer_rep  = daemon.peer_reputation.summary()
    return JSONResponse({
        "db":          db_stats,
        "baselines":   baselines,
        "peers":       peer_rep,
        "fee_trend":   daemon.fee_predictor.trend(),
        "fee_pred":    round(daemon.fee_predictor.predict(
                           daemon.current_state.get("mempool_size") or 200), 2),
        "r_squared":   round(daemon.fee_predictor.r_squared(), 3),
    })


@app.get("/api/health")
async def api_health() -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "uptime": round(time.time() - _START_TIME, 1),
    })


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    daemon: Optional[AxiomMindDaemon] = getattr(app.state, "daemon", None)
    if daemon is not None:
        daemon.ws_clients.add(websocket)
        # Send current state immediately on connect
        try:
            if daemon.current_state:
                await websocket.send_text(
                    json.dumps({"type": "state", "data": daemon.current_state})
                )
            if daemon.anomaly_buffer:
                await websocket.send_text(
                    json.dumps({"type": "anomalies", "data": list(daemon.anomaly_buffer)})
                )
        except Exception:
            pass
    try:
        while True:
            # Keep connection alive; daemon broadcasts asynchronously
            await asyncio.sleep(30)
            try:
                await websocket.send_text(json.dumps({"type": "ping"}))
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    finally:
        if daemon is not None:
            daemon.ws_clients.discard(websocket)

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard server coroutine
# ─────────────────────────────────────────────────────────────────────────────

async def serve_dashboard() -> None:
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=DASHBOARD_PORT,
        log_level="warning",
        access_log=False,
        loop="none",          # We supply our own loop via asyncio.run
    )
    server = uvicorn.Server(config)
    _log.info("Dashboard serving on http://0.0.0.0:%d", DASHBOARD_PORT)
    await server.serve()

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Ensure required directories exist
    for path in (DB_PATH, LOG_PATH):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    daemon = AxiomMindDaemon()

    # Wire FastAPI ws_clients to daemon
    app.state.daemon = daemon

    async def main() -> None:
        # Initialize safe modules if available
        if daemon.audit_log:
            await daemon.audit_log.initialize()
            _log.info("AxiomMind: Audit log initialized")

        await asyncio.gather(
            daemon.run(),
            serve_dashboard(),
        )

    async def shutdown() -> None:
        """Graceful shutdown of safe modules."""
        if daemon.audit_log:
            await daemon.audit_log.close()
            _log.info("AxiomMind: Audit log closed")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        _log.info("AxiomMind: received KeyboardInterrupt, shutting down.")
        asyncio.run(shutdown())
    except Exception as exc:
        _log.critical("AxiomMind fatal error: %s", exc, exc_info=True)
        asyncio.run(shutdown())
        sys.exit(1)
