import html
import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timedelta
from difflib import SequenceMatcher

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template_string, request
try:
    from pymongo import MongoClient
except ImportError:
    MongoClient = None

load_dotenv()

app = Flask(__name__)

DB_PATH = os.getenv("PAX_MEMORY_PATH", "memoria_agente.json")
SIMILARITY_MATCH_THRESHOLD = 0.86
MIN_STRONG_FEATURE_MATCHES = 3
MIN_MATCH_MARGIN = 0.05
ALIAS_CONFIRMATION_HITS = 2
MAX_FEATURE_SAMPLES = 20
PENDING_MATCH_TTL = timedelta(minutes=5)

ENABLE_OMNISTATUS = os.getenv("ENABLE_OMNISTATUS", "0")
OMNISTATUS_API = os.getenv("OMNISTATUS_ENDPOINT", "")

MONGO_URI = os.getenv("MONGO_URI", "")
MONGO_DB_NAME = os.getenv("MONGO_DB", "omnistatus")
MONGO_EVENTS_COLLECTION = os.getenv("MONGO_EVENTS_COLLECTION", "events")
MONGO_SERVER_SELECTION_TIMEOUT_MS = int(os.getenv("MONGO_SERVER_SELECTION_TIMEOUT_MS", "2500"))

ENABLE_TELEGRAM = os.getenv("ENABLE_TELEGRAM", "0")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_MIN_PROX = int(os.getenv("TELEGRAM_MIN_PROX", "60"))
TELEGRAM_COOLDOWN_SECONDS = int(os.getenv("TELEGRAM_COOLDOWN_SECONDS", "300"))

FIELD_WEIGHTS = {
    "ies": 0.22,
    "rates": 0.14,
    "xrates": 0.06,
    "vendors": 0.15,
    "extcaps": 0.10,
    "htcaps": 0.10,
    "vhtcaps": 0.05,
    "rsn": 0.07,
    "extids": 0.05,
    "probe_bucket": 0.03,
    "wildcard_bucket": 0.03,
}

STABLE_PROFILE_FIELDS = (
    "ies",
    "rates",
    "xrates",
    "vendors",
    "extcaps",
    "htcaps",
    "vhtcaps",
    "rsn",
    "extids",
)


mongo_client = None
mongo_events_collection = None

if MONGO_URI and MongoClient:
    try:
        mongo_client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=MONGO_SERVER_SELECTION_TIMEOUT_MS,
        )
        mongo_client.admin.command("ping")
        mongo_events_collection = mongo_client[MONGO_DB_NAME][MONGO_EVENTS_COLLECTION]
    except Exception as exc:
        print(f"MongoDB Error: {exc}")
        mongo_client = None
        mongo_events_collection = None


def mongo_events_enabled():
    return mongo_events_collection is not None


def mongo_event_count():
    if mongo_events_collection is None:
        return 0
    try:
        return mongo_events_collection.count_documents({})
    except Exception as exc:
        print(f"MongoDB count error: {exc}")
        return 0


def recent_omnistatus_events(limit=12):
    if mongo_events_collection is None:
        return []

    try:
        rows = mongo_events_collection.find(
            {},
            {
                "source": 1,
                "text": 1,
                "score": 1,
                "detected_at": 1,
                "created_at": 1,
                "pattern_id": 1,
                "display_id": 1,
                "prox": 1,
                "confidence_label": 1,
            },
        ).sort("_id", -1).limit(limit)

        events = []
        for row in rows:
            created_at = row.get("created_at", "")
            if isinstance(created_at, datetime):
                created_at = created_at.replace(microsecond=0).isoformat() + "Z"

            events.append({
                "source": row.get("source", ""),
                "text": row.get("text", ""),
                "score": row.get("score", 0),
                "detected_at": row.get("detected_at", ""),
                "created_at": created_at,
                "pattern_id": row.get("pattern_id", ""),
                "display_id": row.get("display_id", "--"),
                "prox": row.get("prox", 0),
                "confidence_label": row.get("confidence_label", ""),
            })
        return events
    except Exception as exc:
        print(f"MongoDB recent events error: {exc}")
        return []


def save_omnistatus_event(event):
    if not MONGO_URI:
        return False, "disabled"
    if not MongoClient:
        return False, "missing_pymongo"
    if mongo_events_collection is None:
        return False, "unavailable"

    try:
        mongo_events_collection.insert_one(event)
        return True, "saved"
    except Exception as exc:
        print(f"MongoDB event save error: {exc}")
        return False, "error"


def build_omnistatus_event(obj, score, detected_at):
    source = f"PaxRadar-{obj.get('display_id', '--')}"
    text = obj.get("signal_summary", "")
    return {
        "source": source,
        "text": text,
        "score": score,
        "service": "PaxRadar",
        "type": "pax_radar_detection",
        "detected_at": detected_at,
        "created_at": datetime.utcnow(),
        "pattern_id": obj.get("pattern_id", ""),
        "profile_id": obj.get("profile_id", ""),
        "display_id": obj.get("display_id", "--"),
        "custom_name": obj.get("custom_name", ""),
        "prox": int(obj.get("prox", 0) or 0),
        "score_pct": obj.get("score_pct", 0),
        "confidence_label": obj.get("confidence_label", "Baja"),
        "recurrent": bool(obj.get("recurrent")),
        "rotated": bool(obj.get("rotated")),
        "payload": obj.copy(),
    }


def inject_omnistatus(source: str, text: str, score: float):
    if ENABLE_OMNISTATUS != "1" or not OMNISTATUS_API:
        return

    target_url = OMNISTATUS_API
    if not target_url.endswith("/event") and not target_url.endswith("/events"):
        target_url = target_url.rstrip("/") + "/event"

    try:
        payload = {"source": source, "text": text, "score": score}
        r = requests.post(target_url, json=payload, timeout=5)

        if r.status_code == 422:
            print(f"OmniStatus 422 Unprocessable Entity! Response: {r.text} | Payload: {json.dumps(payload)}")
        elif r.status_code != 200:
            print(f"OmniStatus returned {r.status_code}: {r.text}")

    except Exception as e:
        print(f"OmniStatus Error: {e}")


def telegram_enabled():
    return ENABLE_TELEGRAM == "1" and bool(TELEGRAM_BOT_TOKEN) and bool(TELEGRAM_CHAT_ID)


def send_telegram_alert(message: str):
    if not telegram_enabled():
        return False, "disabled"

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    try:
        response = requests.post(url, json=payload, timeout=6)
        if response.status_code == 200:
            return True, "sent"
        print(f"Telegram returned {response.status_code}: {response.text}")
        return False, f"http_{response.status_code}"
    except Exception as exc:
        print(f"Telegram Error: {exc}")
        return False, "error"


def build_telegram_message(obj, detected_at, alert_reason):
    label = obj.get("custom_name") or f"ID {obj.get('display_id', '--')}"
    lines = [
        "<b>PaxRadar alerta</b>",
        f"Fecha: <code>{html.escape(detected_at)}</code>",
        f"Dispositivo: <b>{html.escape(label)}</b>",
        f"Estado: {html.escape(alert_reason)}",
        f"Proximidad: <b>{obj.get('prox', 0)}%</b>",
        f"Patron: <code>{html.escape(obj.get('pattern_id', '--'))}</code>",
        f"Huella: <code>{html.escape(obj.get('profile_id', '--'))}</code>",
        f"Confianza: {html.escape(obj.get('confidence_label', 'Baja'))} ({obj.get('score_pct', 0)}%)",
    ]

    if obj.get("signal_summary"):
        lines.append(f"Senales: {html.escape(obj['signal_summary'])}")

    return "\n".join(lines)


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>PaxRadar</title>
    <style>
        :root {
            --bg: #050505;
            --panel: #111111;
            --ink: #00ff55;
            --muted: #7a7a7a;
            --accent: #00d1ff;
            --warn: #ff4d4d;
            --recurrent: #ff4dff;
        }
        body {
            background: radial-gradient(circle at top left, #0b0b0b, var(--bg) 55%);
            color: var(--ink);
            font-family: monospace;
            padding: 20px;
        }
        .header {
            border-bottom: 2px solid var(--ink);
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .main-wrap {
            display: flex;
            gap: 20px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
            gap: 15px;
            flex: 3;
        }
        .sidebar {
            flex: 1;
            border: 1px solid var(--ink);
            background: linear-gradient(180deg, rgba(20,20,20,0.95), rgba(10,10,10,0.95));
            padding: 15px;
            min-width: 250px;
            height: fit-content;
        }
        .log-item {
            font-size: 0.8em;
            padding: 8px 0;
            border-bottom: 1px solid #333;
        }
        .status-line {
            color: var(--muted);
            font-size: 0.8em;
            margin-top: 6px;
        }
        .btn {
            background: var(--warn);
            color: #fff;
            border: none;
            padding: 5px 10px;
            cursor: pointer;
            font-family: monospace;
            font-weight: bold;
            float: right;
        }
        .card {
            border: 1px solid var(--ink);
            padding: 15px;
            background: linear-gradient(180deg, rgba(20,20,20,0.95), rgba(10,10,10,0.95));
            min-height: 175px;
        }
        .card.recurrent {
            border-color: var(--recurrent);
            box-shadow: 0 0 10px rgba(255, 77, 255, 0.25);
        }
        .card.new {
            border-color: var(--warn);
            box-shadow: 0 0 10px rgba(255, 77, 77, 0.5);
        }
        .card.high {
            border-color: var(--accent);
            box-shadow: 0 0 10px rgba(0, 209, 255, 0.2);
        }
        .card.home {
            border-color: #ffd166;
            box-shadow: 0 0 12px rgba(255, 209, 102, 0.35);
        }
        .eyebrow {
            font-size: 0.75em;
            color: var(--muted);
            margin-bottom: 4px;
        }
        .score {
            font-size: 2em;
            margin: 6px 0 10px;
        }
        .detail {
            font-size: 0.75em;
            color: var(--muted);
            margin-top: 6px;
            overflow-wrap: anywhere;
        }
        .meta {
            margin-top: 8px;
            font-size: 0.85em;
        }
        .clue-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 6px;
            margin-top: 10px;
        }
        .clue {
            border: 1px solid #2b2b2b;
            padding: 6px;
            background: rgba(255, 255, 255, 0.03);
            min-width: 0;
        }
        .clue-label {
            color: var(--muted);
            font-size: 0.72em;
            margin-bottom: 3px;
        }
        .clue-value {
            color: #e8e8e8;
            font-size: 0.85em;
            overflow-wrap: anywhere;
        }
        .chips {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            margin-top: 10px;
        }
        .chip {
            border: 1px solid #333;
            color: #e8e8e8;
            padding: 3px 6px;
            font-size: 0.72em;
            background: rgba(0, 209, 255, 0.08);
        }
        .hint {
            color: var(--muted);
            font-size: 0.75em;
            margin-top: 10px;
            line-height: 1.35;
        }
        .recurrent-name {
            font-size: 1.2em;
            color: var(--ink);
            font-weight: bold;
            display: inline-block;
            margin-bottom: 5px;
        }
        .edit-btn {
            cursor: pointer;
            color: var(--accent);
            text-decoration: none;
            margin-left: 10px;
            font-size: 0.9em;
        }
        .edit-btn:hover {
            color: #fff;
        }
        .side-section {
            margin-top: 18px;
            padding-top: 12px;
            border-top: 1px solid #333;
        }
        .section-title {
            margin: 0 0 8px;
            color: var(--accent);
        }
    </style>
    <script>
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const HOME_PROX_THRESHOLD = 60;
        let wasInteracted = false;
        let knownIds = new Set();

        document.addEventListener('click', () => {
            if (!wasInteracted) {
                wasInteracted = true;
                audioCtx.resume();
            }
        }, {once: true});

        function playBeep() {
            if (!wasInteracted || audioCtx.state === 'suspended') return;
            const oscillator = audioCtx.createOscillator();
            const gainNode = audioCtx.createGain();
            oscillator.type = 'sawtooth';
            oscillator.frequency.value = 880;
            oscillator.connect(gainNode);
            gainNode.connect(audioCtx.destination);
            oscillator.start();
            gainNode.gain.exponentialRampToValueAtTime(0.00001, audioCtx.currentTime + 0.15);
            oscillator.stop(audioCtx.currentTime + 0.15);
        }

        function resetCounters() {
            if (confirm("¿Estás seguro de que quieres borrar todos los historiales y memorias?")) {
                fetch('/api/reset', {method: 'POST'}).then(() => {
                    knownIds.clear();
                });
            }
        }

        function setCustomName(patternId, currentName) {
            const newName = prompt("Ingresa un nombre para este dispositivo:", currentName || "");
            if (newName !== null) {
                fetch('/api/name', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({pattern_id: patternId, name: newName})
                });
            }
        }

        function esc(value) {
            return String(value ?? "")
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#39;");
        }

        function cleanMac(id) {
            return String(id || "").replace(/[^0-9a-f]/gi, "").toUpperCase();
        }

        function macKind(id) {
            const clean = cleanMac(id);
            if (clean.length < 2) return "sin dato";
            const firstByte = parseInt(clean.slice(0, 2), 16);
            return (firstByte & 0x02) ? "MAC aleatoria" : "MAC global";
        }

        function macOui(id) {
            const clean = cleanMac(id);
            if (clean.length < 6) return "--";
            if (macKind(clean) === "MAC aleatoria") return clean.slice(0, 6) + " (no fabricante)";
            return clean.slice(0, 6);
        }

        function vendorLabel(vendors) {
            const names = {
                "0017F2": "Apple",
                "000A27": "Apple",
                "0050F2": "Microsoft/WMM",
                "506F9A": "Wi-Fi Alliance",
                "001018": "Broadcom",
                "001374": "Atheros/Qualcomm",
                "8CFDF0": "Qualcomm",
                "00E04C": "Realtek",
                "AABBCC": "Privado/Test"
            };
            const tokens = String(vendors || "").split(";").filter(Boolean);
            const labels = tokens.map(token => names[token] || token);
            return labels.length ? labels.join(", ") : "sin OUI IE";
        }

        function featureChips(o) {
            const chips = [];
            if (o.rsn) chips.push("RSN/WPA");
            if (o.htcaps) chips.push("HT 802.11n");
            if (o.vhtcaps) chips.push("VHT 802.11ac");
            if (o.extcaps) chips.push("ExtCaps");
            if (o.extids) chips.push("Ext IE " + esc(o.extids));
            if (!chips.length) chips.push("huella basica");
            return chips.map(label => `<span class="chip">${esc(label)}</span>`).join("");
        }

        function renderCard(o) {
            const classes = ["card"];
            if (o.association_pending) {
                classes.push("high");
            } else if (o.recurrent) {
                classes.push("recurrent");
            } else {
                classes.push("new");
            }
            if (o.score_pct >= 82 && o.recurrent) classes.push("high");
            if (o.prox >= HOME_PROX_THRESHOLD) classes.push("home");

            const status = o.association_pending
                ? "[ASOCIACION PENDIENTE]"
                : o.recurrent
                    ? `[${o.recurrent_label}]`
                    : "[PATRON NUEVO]";
            const safeCurrentName = o.custom_name ? o.custom_name.replace(/'/g, "\\'") : "";
            const seenCountHtml = o.seen_count > 1 ? `<div class="meta" style="color: var(--accent);">Visto: ${o.seen_count} veces</div>` : "";
            const homeStatusHtml = o.prox >= HOME_PROX_THRESHOLD
                ? `<div class="meta" style="color: #ffd166;">EN CASA >= ${HOME_PROX_THRESHOLD}%</div>`
                : "";

            const titleHtml = o.custom_name
                ? `<div class="recurrent-name">${o.custom_name}</div>`
                : "";
            const detectedAt = o.detected_at ? new Date(o.detected_at).toLocaleString() : "--";
            const fullId = String(o.id || "").toUpperCase();
            const probes = Number(o.probes || 0);
            const wildcards = Number(o.wildcards || 0);
            const directed = Math.max(probes - wildcards, 0);
            const wildcardRatio = probes ? Math.round((wildcards / probes) * 100) : 0;

            return `
                <div class="${classes.join(" ")}">
                    ${titleHtml}
                    <div class="eyebrow">
                        MAC vista: ${esc(o.display_id)} ${status}
                        <a class="edit-btn" onclick="setCustomName('${esc(o.pattern_id)}', '${safeCurrentName}')">✎</a>
                    </div>
                    <div class="score">${esc(o.prox)}%</div>
                    ${homeStatusHtml}
                    <div class="clue-grid">
                        <div class="clue">
                            <div class="clue-label">Tipo MAC</div>
                            <div class="clue-value">${macKind(fullId)}</div>
                        </div>
                        <div class="clue">
                            <div class="clue-label">OUI MAC</div>
                            <div class="clue-value">${esc(macOui(fullId))}</div>
                        </div>
                        <div class="clue">
                            <div class="clue-label">Vendor IE</div>
                            <div class="clue-value">${esc(vendorLabel(o.vendors))}</div>
                        </div>
                        <div class="clue">
                            <div class="clue-label">Radio</div>
                            <div class="clue-value">vistos ${esc(o.observed_channels || "--")} · anunciado ${o.channel || "--"} · RSSI ${o.rssi ?? "--"} dBm</div>
                        </div>
                        <div class="clue">
                            <div class="clue-label">Probes</div>
                            <div class="clue-value">${probes} total · ${directed} dirigidos · ${wildcardRatio}% wildcard</div>
                        </div>
                    </div>
                    <div class="chips">${featureChips(o)}</div>
                    <div class="meta">Patron: ${esc(o.pattern_id)}</div>
                    <div class="meta">Huella: ${esc(o.profile_id)}</div>
                    ${seenCountHtml}
                    <div class="meta">Fecha: ${detectedAt}</div>
                    <div class="meta">Confianza: ${esc(o.confidence_label)} (${esc(o.score_pct)}%)</div>
                    <div class="detail">MAC completa: ${esc(fullId || "--")}</div>
                    <div class="detail">IEs: ${esc(o.ies || "--")}</div>
                    <div class="detail">Senales: ${esc(o.signal_summary)}</div>
                    <div class="hint">Estas pistas ayudan a reconocer y nombrar un celular recurrente; por MAC aleatoria no garantizan marca o modelo exacto.</div>
                </div>
            `;
        }

        setInterval(() => {
            fetch('/api/data').then(r => r.json()).then(data => {
                document.getElementById('pax').innerText = data.pax;
                let newFound = false;

                document.getElementById('grid').innerHTML =
                    data.objetivos.map(o => {
                        if (!knownIds.has(o.pattern_id)) {
                            knownIds.add(o.pattern_id);
                            if (!o.recurrent) newFound = true;
                        }
                        return renderCard(o);
                    }).join('') || 'Buscando señales...';

                if (newFound) playBeep();

                if (data.status) {
                    const tg = data.status.telegram_enabled ? "Telegram ON" : "Telegram OFF";
                    const mongo = data.status.mongo_events_enabled ? "Mongo ON (" + (data.status.mongo_event_count || 0) + ")" : "Mongo OFF";
                    document.getElementById('status-line').innerText = tg + " · " + mongo + " · ultimo reporte: " + (data.status.last_report_at || "--") + " · evento: " + (data.status.last_mongo_event_status || "--");
                }

                if (data.recent) {
                    const html = data.recent.map(r => {
                        const timeObj = new Date(r.seen_last);
                        const timeStr = timeObj.toLocaleString();
                        const nameDisplay = r.custom_name ? `<span style="color:var(--accent)">${r.custom_name}</span>` : `ID: ${r.display_id}`;
                        return `<div class="log-item"><span style="color:var(--muted)">[${timeStr}]</span> ${nameDisplay} <br><span style="color:var(--muted)">Visto: ${r.seen_count} veces</span></div>`;
                    }).join('');
                    document.getElementById('recent-list').innerHTML = html;
                }

                if (data.mongo_recent) {
                    const mongoHtml = data.mongo_recent.map(e => {
                        const when = e.detected_at || e.created_at || "";
                        const timeStr = when ? new Date(when).toLocaleString() : "--";
                        const label = e.source || "PaxRadar-" + (e.display_id || "--");
                        return `<div class="log-item"><span style="color:var(--muted)">[${timeStr}]</span> ${label}<br><span style="color:var(--accent)">${e.prox || 0}% · ${e.confidence_label || "--"}</span><br><span style="color:var(--muted)">${e.text || "sin detalle"}</span></div>`;
                    }).join('') || '<div class="log-item">Sin eventos en Mongo todavía</div>';
                    document.getElementById('mongo-events-list').innerHTML = mongoHtml;
                }
            });
        }, 1000);
    </script>
</head>
<body>
    <div class="header">
        <button class="btn" onclick="resetCounters()">Resetear Radar</button>
        <h1>PAX-RADAR: <span id="pax">0</span></h1>
        <div id="status-line" class="status-line">Estado inicializando...</div>
        <div style="font-size: 0.8em; color: var(--muted); margin-top: 5px;">(Haz click en cualquier parte de la pagina para activar el audio de alertas)</div>
        <div class="hint">Tip: ponle nombre con el lapiz cuando reconozcas un equipo; PaxRadar lo sigue por patron aunque cambie la MAC.</div>
    </div>
    <div class="main-wrap">
        <div id="grid" class="grid"></div>
        <div class="sidebar">
            <h3 class="section-title">Últimas Detecciones</h3>
            <div id="recent-list">Esperando datos...</div>
            <div class="side-section">
                <h3 class="section-title">Eventos OmniStatus</h3>
                <div id="mongo-events-list">Esperando eventos...</div>
            </div>
        </div>
    </div>
</body>
</html>
"""


def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def build_empty_memory():
    return {
        "schema_version": 3,
        "next_entity_seq": 1,
        "entities": {},
        "pending_matches": {},
    }


def load_raw_memory():
    if os.path.exists(DB_PATH):
        with open(DB_PATH, "r", encoding="utf-8") as file:
            return json.load(file)
    return build_empty_memory()


def save_memory(data):
    with open(DB_PATH, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def allocate_entity_id(memory):
    entity_id = f"PT-{memory['next_entity_seq']:04d}"
    memory["next_entity_seq"] += 1
    return entity_id


def upgrade_memory(raw):
    if (
        isinstance(raw, dict)
        and raw.get("schema_version") == 3
        and isinstance(raw.get("entities"), dict)
    ):
        raw.setdefault("pending_matches", {})
        return raw

    if (
        isinstance(raw, dict)
        and raw.get("schema_version") == 2
        and isinstance(raw.get("entities"), dict)
    ):
        upgraded = build_empty_memory()
        upgraded["next_entity_seq"] = int(raw.get("next_entity_seq", 1) or 1)
        for entity_id, legacy_entity in raw["entities"].items():
            entity = dict(legacy_entity)
            features = entity.get("features", {})
            entity["feature_samples"] = [features] if features else []
            entity["features"] = consensus_features(entity["feature_samples"])
            upgraded["entities"][entity_id] = entity
        return upgraded

    upgraded = build_empty_memory()
    if not isinstance(raw, dict):
        return upgraded

    for legacy_fp, legacy_data in raw.items():
        entity_id = allocate_entity_id(upgraded)
        last_id = ""
        seen_first = now_iso()

        if isinstance(legacy_data, dict):
            last_id = str(legacy_data.get("last_id", "")).upper()
            seen_first = legacy_data.get("visto_por_primera_vez", seen_first)

        upgraded["entities"][entity_id] = {
            "entity_id": entity_id,
            "primary_profile_id": str(legacy_fp).upper()[:12],
            "profile_ids": [str(legacy_fp).upper()[:12]],
            "last_id": last_id,
            "aliases": [last_id] if last_id else [],
            "seen_first": seen_first,
            "seen_last": seen_first,
            "seen_count": 1,
            "features": {},
            "feature_samples": [],
            "last_score": 1.0,
            "last_confidence": "Legado",
            "custom_name": "",
        }

    return upgraded


def normalize_text(value):
    return str(value or "").strip().upper()


def bucket_probe_count(value):
    if value <= 1:
        return "1"
    if value <= 3:
        return "2-3"
    if value <= 6:
        return "4-6"
    if value <= 10:
        return "7-10"
    return "11+"


def bucket_wildcard_ratio(wildcards, probes):
    if probes <= 0:
        return ""

    ratio = wildcards / probes
    if ratio == 0:
        return "DIR"
    if ratio < 0.35:
        return "MIX-LOW"
    if ratio < 0.70:
        return "MIX"
    if ratio < 1:
        return "MIX-HIGH"
    return "WILD"


def split_tokens(value, chunk_size=None, separator="-"):
    raw = normalize_text(value)
    if not raw:
        return []

    if chunk_size:
        return [raw[index:index + chunk_size] for index in range(0, len(raw), chunk_size)]

    return [token for token in raw.split(separator) if token]


def token_similarity(left, right, separator="-"):
    left_tokens = split_tokens(left, separator=separator)
    right_tokens = split_tokens(right, separator=separator)
    if not left_tokens and not right_tokens:
        return None
    if not left_tokens or not right_tokens:
        return 0.0

    left_set = set(left_tokens)
    right_set = set(right_tokens)
    jaccard = len(left_set & right_set) / len(left_set | right_set)
    ordered = SequenceMatcher(None, left_tokens, right_tokens).ratio()
    return round((jaccard + ordered) / 2, 4)


def byte_similarity(left, right):
    left_tokens = split_tokens(left, chunk_size=2)
    right_tokens = split_tokens(right, chunk_size=2)
    if not left_tokens and not right_tokens:
        return None
    if not left_tokens or not right_tokens:
        return 0.0

    matches = sum(1 for l_val, r_val in zip(left_tokens, right_tokens) if l_val == r_val)
    return round(matches / max(len(left_tokens), len(right_tokens)), 4)


def categorical_similarity(left, right):
    left = normalize_text(left)
    right = normalize_text(right)
    if not left and not right:
        return None
    if not left or not right:
        return 0.0
    return 1.0 if left == right else 0.0


def consensus_features(samples):
    valid_samples = [sample for sample in samples if isinstance(sample, dict)]
    consensus = {}

    for field in FIELD_WEIGHTS:
        values = [
            normalize_text(sample.get(field))
            for sample in valid_samples
            if normalize_text(sample.get(field))
        ]
        if not values:
            consensus[field] = ""
            continue

        counts = Counter(values)
        highest_count = max(counts.values())
        consensus[field] = next(
            value for value in reversed(values) if counts[value] == highest_count
        )

    return consensus


def is_locally_administered(identifier):
    clean = normalize_text(identifier).replace(":", "").replace("-", "")
    if len(clean) < 2:
        return False
    try:
        return bool(int(clean[:2], 16) & 0x02)
    except ValueError:
        return False


def build_features(obj):
    probes = int(obj.get("probes", 0) or 0)
    wildcards = int(obj.get("wildcards", 0) or 0)

    features = {
        "ies": normalize_text(obj.get("ies")),
        "rates": normalize_text(obj.get("rates")),
        "xrates": normalize_text(obj.get("xrates")),
        "vendors": normalize_text(obj.get("vendors")),
        "extcaps": normalize_text(obj.get("extcaps")),
        "htcaps": normalize_text(obj.get("htcaps")),
        "vhtcaps": normalize_text(obj.get("vhtcaps")),
        "rsn": normalize_text(obj.get("rsn")),
        "extids": normalize_text(obj.get("extids")),
        "probe_bucket": bucket_probe_count(probes),
        "wildcard_bucket": bucket_wildcard_ratio(wildcards, probes),
    }

    profile_parts = [
        f"{key}={features[key]}"
        for key in STABLE_PROFILE_FIELDS
        if features.get(key)
    ]

    profile_source = "|".join(profile_parts)
    if profile_source:
        profile_id = hashlib.sha1(profile_source.encode("utf-8")).hexdigest()[:12].upper()
    else:
        fallback = normalize_text(obj.get("id")) or now_iso()
        profile_id = hashlib.sha1(fallback.encode("utf-8")).hexdigest()[:12].upper()

    return features, profile_id


def compare_feature_details(current, stored):
    weighted_score = 0.0
    possible_score = 0.0
    strong_fields = []

    comparers = {
        "ies": lambda a, b: token_similarity(a, b, separator="-"),
        "rates": byte_similarity,
        "xrates": byte_similarity,
        "vendors": lambda a, b: token_similarity(a, b, separator=";"),
        "extcaps": byte_similarity,
        "htcaps": byte_similarity,
        "vhtcaps": byte_similarity,
        "rsn": byte_similarity,
        "extids": lambda a, b: token_similarity(a, b, separator="-"),
        "probe_bucket": categorical_similarity,
        "wildcard_bucket": categorical_similarity,
    }

    for field, weight in FIELD_WEIGHTS.items():
        similarity = comparers[field](current.get(field, ""), stored.get(field, ""))
        if similarity is None:
            continue
        possible_score += weight
        weighted_score += weight * similarity
        if field in STABLE_PROFILE_FIELDS and similarity >= 0.80:
            strong_fields.append(field)

    if possible_score == 0:
        return 0.0, strong_fields

    coverage = possible_score / sum(FIELD_WEIGHTS.values())
    base_score = weighted_score / possible_score
    score = round(base_score * (0.65 + 0.35 * coverage), 4)
    return score, strong_fields


def compare_features(current, stored):
    score, _ = compare_feature_details(current, stored)
    return score


def confidence_label(score):
    if score >= 0.82:
        return "Alta"
    if score >= 0.68:
        return "Media"
    return "Baja"


def recurrent_label(score):
    if score >= 0.82:
        return "ALTA RECURRENCIA"
    if score >= 0.68:
        return "CORRELACION MEDIA"
    return "SIMILITUD BAJA"


def short_id(value):
    value = normalize_text(value)
    if not value:
        return "--"
    return value[-6:]


def build_signal_summary(features):
    parts = []

    if features.get("ies"):
        parts.append(f"IE {features['ies'][:26]}")

    phy = []
    if features.get("htcaps"):
        phy.append("HT")
    if features.get("vhtcaps"):
        phy.append("VHT")
    if features.get("rsn"):
        phy.append("RSN")
    if features.get("extids"):
        phy.append(f"EXT {features['extids']}")
    if phy:
        parts.append("/".join(phy))

    if features.get("vendors"):
        parts.append(f"OUI {features['vendors'][:24]}")

    behavior = []
    if features.get("probe_bucket"):
        behavior.append(f"probes {features['probe_bucket']}")
    if features.get("wildcard_bucket"):
        behavior.append(features["wildcard_bucket"])
    if behavior:
        parts.append(" | ".join(behavior))

    return " · ".join(parts) if parts else "ritmo 1"


def match_entity(memory, features, profile_id, current_id=""):
    best_entity = None
    best_score = 0.0
    second_best_score = 0.0
    best_strong_fields = []

    for entity in memory.get("entities", {}).values():
        if current_id and current_id in entity.get("aliases", []):
            return entity, 1.0, True

        score, strong_fields = compare_feature_details(
            features,
            entity.get("features", {}),
        )
        if score > best_score:
            second_best_score = best_score
            best_entity = entity
            best_score = score
            best_strong_fields = strong_fields
        elif score > second_best_score:
            second_best_score = score

    if (
        best_score >= SIMILARITY_MATCH_THRESHOLD
        and len(best_strong_fields) >= MIN_STRONG_FEATURE_MATCHES
        and best_score - second_best_score >= MIN_MATCH_MARGIN
    ):
        return best_entity, best_score, False
    return None, best_score, False


def prune_pending_matches(memory, seen_at):
    current = parse_iso(seen_at)
    if not current:
        return

    pending_matches = memory.setdefault("pending_matches", {})
    stale_ids = []
    for current_id, pending in pending_matches.items():
        previous = parse_iso(pending.get("seen_last"))
        if not previous or current - previous > PENDING_MATCH_TTL:
            stale_ids.append(current_id)

    for current_id in stale_ids:
        pending_matches.pop(current_id, None)


def confirm_alias_candidate(memory, current_id, entity_id, score, seen_at):
    pending_matches = memory.setdefault("pending_matches", {})
    previous = pending_matches.get(current_id, {})
    previous_seen = parse_iso(previous.get("seen_last"))
    current_seen = parse_iso(seen_at)
    still_fresh = (
        previous_seen
        and current_seen
        and current_seen - previous_seen <= timedelta(minutes=2)
    )

    if previous.get("entity_id") == entity_id and still_fresh:
        hits = int(previous.get("hits", 0) or 0) + 1
    else:
        hits = 1

    pending_matches[current_id] = {
        "entity_id": entity_id,
        "hits": hits,
        "score": score,
        "seen_last": seen_at,
    }

    if hits >= ALIAS_CONFIRMATION_HITS:
        pending_matches.pop(current_id, None)
        return True
    return False


def create_entity(memory, current_id, profile_id, features):
    entity_id = allocate_entity_id(memory)
    entity = {
        "entity_id": entity_id,
        "primary_profile_id": profile_id,
        "profile_ids": [profile_id],
        "last_id": current_id,
        "aliases": [current_id] if current_id else [],
        "seen_first": now_iso(),
        "seen_last": now_iso(),
        "seen_count": 0,
        "features": features,
        "feature_samples": [],
        "last_score": 0.0,
        "last_confidence": "Baja",
        "custom_name": "",
    }
    memory["entities"][entity_id] = entity
    return entity


def update_entity(entity, current_id, profile_id, features, score, matched_existing, seen_at):
    if profile_id and profile_id not in entity.get("profile_ids", []):
        entity.setdefault("profile_ids", []).append(profile_id)
    if current_id and current_id not in entity.get("aliases", []):
        entity.setdefault("aliases", []).append(current_id)

    entity["last_id"] = current_id or entity.get("last_id", "")
    entity["seen_last"] = seen_at
    entity["seen_count"] = int(entity.get("seen_count", 0) or 0) + 1
    if features:
        samples = entity.setdefault("feature_samples", [])
        samples.append(features)
        del samples[:-MAX_FEATURE_SAMPLES]
        entity["features"] = consensus_features(samples)
    entity["last_score"] = score
    entity["last_confidence"] = confidence_label(score if matched_existing else 0.0)
    entity.setdefault("custom_name", "")


raw_memory = load_raw_memory()
agente_memory = upgrade_memory(raw_memory)
save_memory(agente_memory)
telegram_alert_cache = {}
server_status = {
    "started_at": now_iso(),
    "last_report_at": "",
    "last_alert_at": "",
    "last_alert_status": "idle",
    "last_mongo_event_at": "",
    "last_mongo_event_status": "idle",
}
radar_data = {"pax": 0, "objetivos": [], "recent": [], "status": {}}


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


def current_status():
    return {
        "started_at": server_status.get("started_at", ""),
        "last_report_at": server_status.get("last_report_at", ""),
        "last_alert_at": server_status.get("last_alert_at", ""),
        "last_alert_status": server_status.get("last_alert_status", "idle"),
        "telegram_enabled": telegram_enabled(),
        "telegram_min_prox": TELEGRAM_MIN_PROX,
        "omnistatus_enabled": ENABLE_OMNISTATUS == "1" and bool(OMNISTATUS_API),
        "mongo_events_enabled": mongo_events_enabled(),
        "mongo_db": MONGO_DB_NAME if MONGO_URI else "",
        "mongo_events_collection": MONGO_EVENTS_COLLECTION if MONGO_URI else "",
        "mongo_event_count": mongo_event_count(),
        "last_mongo_event_at": server_status.get("last_mongo_event_at", ""),
        "last_mongo_event_status": server_status.get("last_mongo_event_status", "idle"),
    }


@app.route("/api/data")
def api_data():
    global radar_data, agente_memory
    recent = []
    entities = list(agente_memory["entities"].values())
    entities.sort(key=lambda x: x.get("seen_last", ""), reverse=True)
    for e in entities[:15]:
        recent.append({
            "display_id": e.get("last_id", "")[-6:] if e.get("last_id") else "--",
            "custom_name": e.get("custom_name", ""),
            "seen_last": e.get("seen_last", ""),
            "seen_count": e.get("seen_count", 0),
            "pattern_id": e.get("entity_id", "")
        })
    radar_data["recent"] = recent
    radar_data["mongo_recent"] = recent_omnistatus_events()
    radar_data["status"] = current_status()
    return jsonify(radar_data)


@app.route("/api/status")
def api_status():
    return jsonify(current_status())


@app.route("/api/reset", methods=["POST"])
def api_reset():
    global agente_memory, radar_data
    agente_memory = build_empty_memory()
    save_memory(agente_memory)
    radar_data["pax"] = 0
    radar_data["objetivos"] = []
    radar_data["recent"] = []
    radar_data["status"] = current_status()
    telegram_alert_cache.clear()
    server_status["last_alert_at"] = ""
    server_status["last_alert_status"] = "idle"
    return jsonify({"status": "ok"}), 200


@app.route("/api/name", methods=["POST"])
def api_name():
    global agente_memory
    try:
        data = request.get_json(force=True)
        pattern_id = data.get("pattern_id")
        name = data.get("name", "").strip()

        if pattern_id and pattern_id in agente_memory["entities"]:
            agente_memory["entities"][pattern_id]["custom_name"] = name
            save_memory(agente_memory)

            for obj in radar_data.get("objetivos", []):
                if obj.get("pattern_id") == pattern_id:
                    obj["custom_name"] = name

            return jsonify({"status": "ok"}), 200
        return jsonify({"status": "not_found"}), 404
    except Exception as exc:
        print(f"Error setting name: {exc}")
        return jsonify({"status": "error"}), 400


def telegram_alert_reason(obj, recurrent, rotated):
    if obj.get("association_pending"):
        return ""
    prox = int(obj.get("prox", 0) or 0)
    if rotated:
        return "MAC rotada detectada"
    if not recurrent and prox >= TELEGRAM_MIN_PROX:
        return f"Patron nuevo cercano >= {TELEGRAM_MIN_PROX}%"
    return ""


def telegram_allowed(pattern_id, detected_at):
    last_sent = parse_iso(telegram_alert_cache.get(pattern_id))
    current = parse_iso(detected_at)
    if not last_sent or not current:
        return True
    return current - last_sent >= timedelta(seconds=TELEGRAM_COOLDOWN_SECONDS)


@app.route("/api/report", methods=["POST"])
def api_report():
    global radar_data, agente_memory

    try:
        data = request.get_json(force=True)
        detected_at = now_iso()
        prune_pending_matches(agente_memory, detected_at)
        server_status["last_report_at"] = detected_at
        objetivos_procesados = []
        memory_changed = False

        for obj in data.get("objetivos", []):
            current_id = normalize_text(obj.get("id"))
            features, profile_id = build_features(obj)
            entity, score, known_alias = match_entity(
                agente_memory,
                features,
                profile_id,
                current_id,
            )
            matched_existing = known_alias
            association_pending = False

            if entity and not known_alias:
                if is_locally_administered(current_id):
                    matched_existing = confirm_alias_candidate(
                        agente_memory,
                        current_id,
                        entity["entity_id"],
                        score,
                        detected_at,
                    )
                    association_pending = not matched_existing
                    memory_changed = True
                else:
                    entity = None

            if not entity:
                agente_memory.setdefault("pending_matches", {}).pop(current_id, None)

            if not entity:
                entity = create_entity(agente_memory, current_id, profile_id, features)
                score = 0.0
                memory_changed = True

            previous_aliases = set(entity.get("aliases", []))
            if not association_pending:
                update_entity(
                    entity,
                    current_id,
                    profile_id,
                    features,
                    score,
                    matched_existing,
                    detected_at,
                )
                memory_changed = True

            recurrent = (
                not association_pending
                and (matched_existing or entity.get("seen_count", 0) > 1)
            )
            rotated = (
                not association_pending
                and matched_existing
                and current_id
                and current_id not in previous_aliases
                and bool(previous_aliases)
            )

            obj["display_id"] = short_id(current_id)
            obj["pattern_id"] = entity["entity_id"]
            obj["profile_id"] = profile_id
            obj["recurrent"] = recurrent
            obj["rotated"] = rotated
            obj["association_pending"] = association_pending
            obj["recurrent_label"] = recurrent_label(score if matched_existing else 0.0)
            obj["confidence_label"] = (
                "Pendiente" if association_pending else confidence_label(score)
            )
            obj["score_pct"] = int(round(score * 100))
            obj["signal_summary"] = build_signal_summary(features)
            obj["custom_name"] = entity.get("custom_name", "")
            obj["seen_count"] = entity.get("seen_count", 1)
            obj["detected_at"] = detected_at
            objetivos_procesados.append(obj)

            alert_reason = telegram_alert_reason(obj, recurrent, rotated)
            if alert_reason and telegram_allowed(entity["entity_id"], detected_at):
                ok, status = send_telegram_alert(build_telegram_message(obj, detected_at, alert_reason))
                server_status["last_alert_status"] = status
                if ok:
                    telegram_alert_cache[entity["entity_id"]] = detected_at
                    server_status["last_alert_at"] = detected_at

            mongo_ok, mongo_status = save_omnistatus_event(
                build_omnistatus_event(obj, score, detected_at)
            )
            server_status["last_mongo_event_status"] = mongo_status
            if mongo_ok:
                server_status["last_mongo_event_at"] = detected_at

            inject_omnistatus(
                source=f"PaxRadar-{obj['display_id']}",
                text=obj["signal_summary"],
                score=score
            )

        if memory_changed:
            save_memory(agente_memory)

        radar_data = {
            "pax": data.get("pax", 0),
            "objetivos": objetivos_procesados,
            "status": current_status(),
        }
        return jsonify({"status": "ok"}), 200

    except Exception as exc:
        print(f"Error: {exc}")
        return jsonify({"status": "error"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
