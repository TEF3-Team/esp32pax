import hashlib
import json
import os
from datetime import datetime
from difflib import SequenceMatcher

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template_string, request

load_dotenv()

app = Flask(__name__)

DB_PATH = "memoria_agente.json"
SIMILARITY_MATCH_THRESHOLD = 0.68

ENABLE_OMNISTATUS = os.getenv("ENABLE_OMNISTATUS", "0")
OMNISTATUS_API = os.getenv("OMNISTATUS_ENDPOINT", "")

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

        function renderCard(o) {
            const classes = ["card"];
            if (o.recurrent) {
                classes.push("recurrent");
            } else {
                classes.push("new");
            }
            if (o.score_pct >= 82 && o.recurrent) classes.push("high");
            if (o.prox >= HOME_PROX_THRESHOLD) classes.push("home");

            const status = o.recurrent ? `[${o.recurrent_label}]` : "[PATRON NUEVO]";
            const safeCurrentName = o.custom_name ? o.custom_name.replace(/'/g, "\\'") : "";
            const seenCountHtml = o.seen_count > 1 ? `<div class="meta" style="color: var(--accent);">Visto: ${o.seen_count} veces</div>` : "";
            const homeStatusHtml = o.prox >= HOME_PROX_THRESHOLD
                ? `<div class="meta" style="color: #ffd166;">EN CASA >= ${HOME_PROX_THRESHOLD}%</div>`
                : "";

            const titleHtml = o.custom_name
                ? `<div class="recurrent-name">${o.custom_name}</div>`
                : "";

            return `
                <div class="${classes.join(" ")}">
                    ${titleHtml}
                    <div class="eyebrow">
                        MAC vista: ${o.display_id} ${status}
                        <a class="edit-btn" onclick="setCustomName('${o.pattern_id}', '${safeCurrentName}')">✎</a>
                    </div>
                    <div class="score">${o.prox}%</div>
                    ${homeStatusHtml}
                    <div class="meta">Patron: ${o.pattern_id}</div>
                    <div class="meta">Huella: ${o.profile_id}</div>
                    ${seenCountHtml}
                    <div class="meta">Confianza: ${o.confidence_label} (${o.score_pct}%)</div>
                    <div class="detail">Senales: ${o.signal_summary}</div>
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

                if (data.recent) {
                    const html = data.recent.map(r => {
                        const timeObj = new Date(r.seen_last);
                        const timeStr = timeObj.toLocaleTimeString();
                        const nameDisplay = r.custom_name ? `<span style="color:var(--accent)">${r.custom_name}</span>` : `ID: ${r.display_id}`;
                        return `<div class="log-item"><span style="color:var(--muted)">[${timeStr}]</span> ${nameDisplay} <br><span style="color:var(--muted)">Visto: ${r.seen_count} veces</span></div>`;
                    }).join('');
                    document.getElementById('recent-list').innerHTML = html;
                }
            });
        }, 1000);
    </script>
</head>
<body>
    <div class="header">
        <button class="btn" onclick="resetCounters()">Resetear Radar</button>
        <h1>PAX-RADAR: <span id="pax">0</span></h1>
        <div style="font-size: 0.8em; color: var(--muted); margin-top: 5px;">(Haz click en cualquier parte de la página para activar el audio de alertas)</div>
    </div>
    <div class="main-wrap">
        <div id="grid" class="grid"></div>
        <div class="sidebar">
            <h3 style="margin-top: 0; color: var(--accent);">Últimas Detecciones</h3>
            <div id="recent-list">Esperando datos...</div>
        </div>
    </div>
</body>
</html>
"""


def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def build_empty_memory():
    return {
        "schema_version": 2,
        "next_entity_seq": 1,
        "entities": {},
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
        and raw.get("schema_version") == 2
        and isinstance(raw.get("entities"), dict)
    ):
        return raw

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


def compare_features(current, stored):
    weighted_score = 0.0
    possible_score = 0.0

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

    if possible_score == 0:
        return 0.0

    coverage = possible_score / sum(FIELD_WEIGHTS.values())
    base_score = weighted_score / possible_score
    return round(base_score * (0.65 + 0.35 * coverage), 4)


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


def match_entity(memory, features, profile_id):
    best_entity = None
    best_score = 0.0

    for entity in memory.get("entities", {}).values():
        if profile_id in entity.get("profile_ids", []):
            return entity, 1.0

        score = compare_features(features, entity.get("features", {}))
        if score > best_score:
            best_entity = entity
            best_score = score

    if best_score >= SIMILARITY_MATCH_THRESHOLD:
        return best_entity, best_score
    return None, best_score


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
        "last_score": 0.0,
        "last_confidence": "Baja",
        "custom_name": "",
    }
    memory["entities"][entity_id] = entity
    return entity


def update_entity(entity, current_id, profile_id, features, score, matched_existing):
    if profile_id and profile_id not in entity.get("profile_ids", []):
        entity.setdefault("profile_ids", []).append(profile_id)
    if current_id and current_id not in entity.get("aliases", []):
        entity.setdefault("aliases", []).append(current_id)

    entity["last_id"] = current_id or entity.get("last_id", "")
    entity["seen_last"] = now_iso()
    entity["seen_count"] = int(entity.get("seen_count", 0) or 0) + 1
    entity["features"] = features or entity.get("features", {})
    entity["last_score"] = score
    entity["last_confidence"] = confidence_label(score if matched_existing else 0.0)
    entity.setdefault("custom_name", "")


raw_memory = load_raw_memory()
agente_memory = upgrade_memory(raw_memory)
save_memory(agente_memory)
radar_data = {"pax": 0, "objetivos": [], "recent": []}


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


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
    return jsonify(radar_data)


@app.route("/api/reset", methods=["POST"])
def api_reset():
    global agente_memory, radar_data
    agente_memory = build_empty_memory()
    save_memory(agente_memory)
    radar_data["pax"] = 0
    radar_data["objetivos"] = []
    radar_data["recent"] = []
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


@app.route("/api/report", methods=["POST"])
def api_report():
    global radar_data, agente_memory

    try:
        data = request.get_json(force=True)
        objetivos_procesados = []
        memory_changed = False

        for obj in data.get("objetivos", []):
            current_id = normalize_text(obj.get("id"))
            features, profile_id = build_features(obj)
            entity, score = match_entity(agente_memory, features, profile_id)
            matched_existing = entity is not None

            if not entity:
                entity = create_entity(agente_memory, current_id, profile_id, features)
                score = 0.0
                memory_changed = True

            previous_aliases = set(entity.get("aliases", []))
            update_entity(entity, current_id, profile_id, features, score, matched_existing)
            memory_changed = True

            recurrent = matched_existing or entity.get("seen_count", 0) > 1
            rotated = current_id and current_id not in previous_aliases and bool(previous_aliases)

            obj["display_id"] = short_id(current_id)
            obj["pattern_id"] = entity["entity_id"]
            obj["profile_id"] = profile_id
            obj["recurrent"] = recurrent
            obj["rotated"] = rotated
            obj["recurrent_label"] = recurrent_label(score if matched_existing else 0.0)
            obj["confidence_label"] = confidence_label(score)
            obj["score_pct"] = int(round(score * 100))
            obj["signal_summary"] = build_signal_summary(features)
            obj["custom_name"] = entity.get("custom_name", "")
            obj["seen_count"] = entity.get("seen_count", 1)
            objetivos_procesados.append(obj)

            inject_omnistatus(
                source=f"PaxRadar-{obj['display_id']}",
                text=obj["signal_summary"],
                score=score
            )

        if memory_changed:
            save_memory(agente_memory)

        radar_data = {"pax": data.get("pax", 0), "objetivos": objetivos_procesados}
        return jsonify({"status": "ok"}), 200

    except Exception as exc:
        print(f"Error: {exc}")
        return jsonify({"status": "error"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
