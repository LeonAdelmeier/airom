#!/usr/bin/env python3
# airmon -- Live-Collector + Ortungs-Webserver fuer WLAN-RSSI-Sensoren.
#   - nimmt die Sensor-Verbindungen (node1, node2, ...) per TCP auf Port 9999
#   - loggt jedes Sample nach rssi-log.jsonl
#   - serviert unter http://localhost:8000 ein Live-Dashboard mit echten Daten:
#       Ziel-MAC waehlen -> Position der Knoten eintragen -> Trilateration live
#   - Statistik ueberlebt Neustarts (State-Datei neben dem Log)
#
# Start:  python3 airmon.py
#         python3 airmon.py 9999 8000 meinlog.jsonl
# SSIDs ausblenden:  AIRMON_HIDE="meinwlan,gastnetz" python3 airmon.py
# Dann im Browser oeffnen:  http://localhost:8000
# Stop:   Strg+C

import socket, json, sys, threading, statistics, time, os, urllib.request
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------- OUI / Hersteller-Datenbank ----------------
# Reihenfolge: lokaler Cache -> Download (Wireshark manuf) -> eingebaute Liste.
# Liefert fuer echte MACs den Hersteller; bei zufaelligen MACs leer.
OUI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui_cache.tsv")
OUI_URL  = "https://www.wireshark.org/download/automated/data/manuf"
OUI_FALLBACK = {
    "00:1a:11":"Google","3c:5a:b4":"Google","f4:f5:e8":"Google","da:a1:19":"Google",
    "34:2c:c4":"ASUSTek","ac:22:0b":"ASUSTek","a8:fb:40":"HonHai","ac:22:05":"AzureWave",
    "90:5c:44":"Intel","34:41:5d":"Intel","00:1b:77":"Intel","a4:50:46":"Xiaomi",
    "28:6c:07":"Xiaomi","f0:2f:74":"Huawei","1c:bf:ce":"Huawei","50:ec:50":"Samsung",
    "9c:b1:50":"Samsung","d4:63:c6":"Samsung","34:2e:b7":"Samsung","d4:63:fe":"Apple",
    "a4:83:e7":"Apple","3c:06:30":"Apple","f0:18:98":"Apple","dc:a6:32":"RaspberryPi",
    "b8:27:eb":"RaspberryPi","e4:5f:01":"RaspberryPi","24:4c:ab":"Espressif",
    "a0:20:a6":"Espressif","7c:9e:bd":"Espressif","fc:ec:da":"Ubiquiti","74:ac:b9":"Ubiquiti",
    "00:c0:ca":"Alfa","00:13:37":"Pineapple","0c:ef:af":"Pineapple","e4:4e:2d":"Fiberhome",
    "c0:d7:aa":"Cambridge Ind","38:94:ed":"AVM/Fritz","3c:a6:f6":"AVM/Fritz",
}
OUI_DB = {}
OUI_SRC = "eingebaut"

def _parse_manuf(text):
    db = {}
    for ln in text.splitlines():
        if not ln or ln[0] == "#":
            continue
        parts = ln.split("\t")
        if len(parts) < 2:
            continue
        pre = parts[0].strip().lower().replace("-", ":")
        name = parts[1].strip()
        # nur 24-bit-Praefixe (XX:XX:XX) uebernehmen
        if len(pre) == 8 and pre.count(":") == 2 and name:
            db[pre] = name
    return db

def load_oui():
    global OUI_DB, OUI_SRC
    OUI_DB = dict(OUI_FALLBACK)
    # 1) Cache
    try:
        if os.path.exists(OUI_FILE):
            with open(OUI_FILE, encoding="utf-8", errors="ignore") as fh:
                db = _parse_manuf(fh.read())
            if db:
                OUI_DB.update(db); OUI_SRC = f"Cache ({len(db)})"; return
    except OSError:
        pass
    # 2) Download (Laptop hat Internet)
    try:
        req = urllib.request.Request(OUI_URL, headers={"User-Agent": "rssi-collector"})
        with urllib.request.urlopen(req, timeout=8) as r:
            text = r.read().decode("utf-8", "ignore")
        db = _parse_manuf(text)
        if db:
            OUI_DB.update(db); OUI_SRC = f"Download ({len(db)})"
            try:
                with open(OUI_FILE, "w", encoding="utf-8") as fh:
                    fh.write(text)
            except OSError:
                pass
            return
    except Exception:
        pass
    OUI_SRC = f"eingebaut ({len(OUI_DB)})"

def vendor_of(mac):
    if not mac or len(mac) < 8:
        return ""
    if mac[1].lower() in "26ae":   # zufaellige MAC -> kein echter Hersteller
        return ""
    return OUI_DB.get(mac[:8].lower(), "")

# SSIDs, die im Dashboard ausgeblendet werden (case-insensitiv, Teilstring).
# Per Umgebungsvariable setzen, z.B.:  AIRMON_HIDE="meinwlan,gastnetz"
HIDE_SSIDS = tuple(x.strip().lower() for x in os.environ.get("AIRMON_HIDE", "").split(",") if x.strip())
def hidden_ssid(s):
    s = (s or "").lower()
    return any(h in s for h in HIDE_SSIDS)

TCP_PORT  = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
HTTP_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
LOGFILE   = sys.argv[3] if len(sys.argv) > 3 else "rssi-log.jsonl"
WINDOW    = 60   # Samples pro (node,mac) fuer den gleitenden Median

win   = defaultdict(lambda: deque(maxlen=WINDOW))  # (node,mac) -> rssi
cnt   = defaultdict(int)                            # mac -> gesamt (fuer Dropdown)
nodes_seen = {}                                     # node -> letzter Zeitpunkt
nodes_ip   = {}                                     # node -> IP-Adresse (fuer SSH)
# Probe-Requests: welche MAC sucht welche SSID, wann zuletzt + wie oft
probe_hits = defaultdict(lambda: defaultdict(lambda: {"last": 0.0, "n": 0, "rssi": 0}))  # mac -> ssid -> info
probe_feed = deque(maxlen=600)                      # Live-Feed: JEDER Probe-Treffer
probe_seq  = 0                                       # fortlaufende ID je Feed-Event
best_rssi  = defaultdict(lambda: -999)              # mac -> staerkster je gesehener RSSI
# --- Dashboard-Aggregation ---
mac_last   = {}                                      # mac -> letzter Zeitpunkt (devices.now)
mac_conn   = {}                                      # mac -> True wenn an einem AP gesehen (verbunden)
frame_feed = deque(maxlen=120)                       # letzte Frames fuer die Konsole
frame_seq  = 0
pkt_sec    = 0                                        # Pakete in der laufenden Sekunde
pps_hist   = deque([0]*90, maxlen=90)                # Pakete/s Verlauf
byte_total = 0                                        # Summe Frame-Groessen (Datenmenge)
pkt_total  = 0
aps        = {}                                       # bssid -> {ssid, rssi, ch, last}
ap_clients = defaultdict(dict)                        # bssid -> {client_mac: last}
all_ssids  = {}                                       # ssid -> last (AP + gesucht)
log   = open(LOGFILE, "a")
lock  = threading.Lock()

# ---------------- Statistik ueber Neustarts hinweg ----------------
# Kleine State-Datei neben dem Log; wird regelmaessig gespeichert und beim
# Start wieder geladen, damit Zaehler (Pakete, Datenmenge, Top-Talker,
# Netze, Probe-Historie) nicht bei jedem Neustart auf 0 springen.
STATE_FILE = LOGFILE + ".state.json"

def save_state():
    with lock:
        data = {
            "pkt_total": pkt_total, "byte_total": byte_total,
            "cnt": dict(cnt), "best_rssi": dict(best_rssi),
            "mac_last": mac_last, "mac_conn": mac_conn,
            "aps": aps, "ap_clients": {b: dict(c) for b, c in ap_clients.items()},
            "all_ssids": all_ssids,
            "probe_hits": {m: dict(s) for m, s in probe_hits.items()},
        }
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass

def load_state():
    global pkt_total, byte_total
    if not os.path.exists(STATE_FILE):
        return
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return
    with lock:
        pkt_total = int(d.get("pkt_total", 0))
        byte_total = int(d.get("byte_total", 0))
        for m, c in d.get("cnt", {}).items():
            cnt[m] = c
        for m, r in d.get("best_rssi", {}).items():
            best_rssi[m] = r
        mac_last.update(d.get("mac_last", {}))
        mac_conn.update(d.get("mac_conn", {}))
        aps.update(d.get("aps", {}))
        for b, c in d.get("ap_clients", {}).items():
            ap_clients[b].update(c)
        all_ssids.update(d.get("all_ssids", {}))
        for m, ssids in d.get("probe_hits", {}).items():
            for s, info in ssids.items():
                probe_hits[m][s] = info

def state_saver():
    while True:
        time.sleep(15)
        save_state()

# ---------------- TCP-Collector ----------------
def handle(conn, addr):
    ip = addr[0]
    buf = b""
    with conn:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                s = line.decode(errors="ignore").strip()
                if not s:
                    continue
                try:
                    m = json.loads(s)
                    node = m["node"]; rssi = int(m["rssi"]); mac = m.get("sa", "")
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
                if not mac:
                    continue
                typ = m.get("type", "")
                ssid = m.get("ssid", "")
                role = m.get("role", "meas")   # alte Sensoren ohne role -> meas
                ln   = int(m.get("len", 0))
                da    = m.get("da", "")
                bssid = m.get("bssid", "")
                now = time.time()
                with lock:
                    log.write(s + "\n")
                    nodes_seen[node] = now
                    nodes_ip[node] = ip
                    if rssi > best_rssi[mac]:
                        best_rssi[mac] = rssi
                    if role != "probe":
                        win[(node, mac)].append(rssi)
                        cnt[mac] += 1
                    # --- Dashboard-Aggregation ---
                    mac_last[mac] = now
                    globals()["pkt_sec"] += 1
                    globals()["pkt_total"] += 1
                    globals()["byte_total"] += ln
                    globals()["frame_seq"] += 1
                    frame_feed.append({"id": frame_seq, "ts": now, "rssi": rssi,
                                       "sa": mac, "da": da, "type": typ, "len": ln,
                                       "node": node, "ssid": ssid, "bssid": bssid})
                    # Beacon -> AP-Liste
                    if typ == "beacon" and bssid:
                        a = aps.get(bssid, {})
                        a["ssid"] = ssid or a.get("ssid", "")
                        a["rssi"] = max(rssi, a.get("rssi", -999))
                        a["last"] = now
                        aps[bssid] = a
                        if ssid:
                            all_ssids[ssid] = now
                    # Data-Frame mit BSSID -> Client verbunden mit diesem AP
                    if typ == "data" and bssid and bssid not in ("ff:ff:ff:ff:ff:ff", ""):
                        if mac != bssid:
                            ap_clients[bssid][mac] = now
                            mac_conn[mac] = now
                        if da and da != bssid and da != "ff:ff:ff:ff:ff:ff":
                            ap_clients[bssid][da] = now
                            mac_conn[da] = now
                    # Probe-Request mit echter SSID
                    if typ == "probe" and ssid:
                        info = probe_hits[mac][ssid]
                        info["last"] = now; info["n"] += 1; info["rssi"] = rssi
                        all_ssids[ssid] = now
                        globals()["probe_seq"] += 1
                        probe_feed.append({"id": probe_seq, "mac": mac, "ssid": ssid,
                                           "ts": now, "rssi": rssi})

def tcp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", TCP_PORT))
    srv.listen(8)
    print(f"[TCP] Sensoren -> Port {TCP_PORT}")
    while True:
        c, addr = srv.accept()
        threading.Thread(target=handle, args=(c, addr), daemon=True).start()

# ---------------- Status-Zeile im Terminal ----------------
def status_printer():
    while True:
        time.sleep(3)
        with lock:
            now = time.time()
            nodes = sorted(nodes_seen.keys())
            if not nodes:
                continue
            parts = []
            for n in nodes:
                age = now - nodes_seen[n]
                ip = nodes_ip.get(n, "?")
                stat = "OK " if age < 5 else f"STILL {age:4.0f}s"
                parts.append(f"{n} [{ip}] {stat} (ssh root@{ip})")
            print("  ".join(parts))

# ---------------- Daten fuer die Webseite ----------------
def snapshot():
    with lock:
        now = time.time()
        nodes = sorted(nodes_seen.keys())
        node_state = {n: ("aktiv" if now - nodes_seen[n] < 5 else "still") for n in nodes}
        node_ip = dict(nodes_ip)
        node_age = {n: round(now - nodes_seen[n], 1) for n in nodes}
        # Top-MACs nach Sample-Zahl
        macs = sorted(cnt.items(), key=lambda kv: kv[1], reverse=True)[:60]
        mac_list = [{"mac": m, "count": c} for m, c in macs]
        # Median je (node, mac)
        rssi = {}
        for (node, mac), dq in win.items():
            if dq:
                rssi.setdefault(node, {})[mac] = statistics.median(dq)
    return {"nodes": nodes, "node_state": node_state, "node_ip": node_ip,
            "node_age": node_age, "macs": mac_list, "rssi": rssi}

def pps_ticker():
    # jede Sekunde: Pakete der Sekunde in den Verlauf schieben
    while True:
        time.sleep(1)
        with lock:
            pps_hist.append(pkt_sec)
            globals()["pkt_sec"] = 0

def human_bytes(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{u}" if u != "B" else f"{int(n)}B"
        n /= 1024
    return f"{n:.1f}PB"

def dash_snapshot():
    now = time.time()
    with lock:
        active = [mm for mm, t in mac_last.items() if now - t <= 60]
        conn_now = [mm for mm in active if mm in mac_conn and now - mac_conn.get(mm, 0) <= 120]
        ndev = len(active); nconn = len(conn_now); nscan = ndev - nconn
        pps = pps_hist[-1] if pps_hist else 0
        hist = list(pps_hist)
        movies = byte_total / (1.5 * 1024**3)   # grob: 1 Film ~1,5 GB
        ssid_recent = [s for s, t in all_ssids.items() if now - t <= 600]
        ap_recent = {b: a for b, a in aps.items() if now - a["last"] <= 600}
        # Live-Frame-Feed (neueste zuerst)
        feed = [{"id": f["id"], "ts": round(now - f["ts"], 1), "rssi": f["rssi"],
                 "sa": f["sa"], "da": f["da"], "type": f["type"], "len": f["len"],
                 "node": f.get("node", ""),
                 "net": (f.get("ssid") or "") if f["type"] in ("beacon", "probe") else (f.get("bssid") or ""),
                 "rnd": is_random_mac(f["sa"]), "vendor": vendor_of(f["sa"])} for f in list(frame_feed)]
        # Top-Talker
        talk = sorted(cnt.items(), key=lambda kv: kv[1], reverse=True)[:7]
        talkers = [{"mac": mm, "n": c, "rnd": is_random_mac(mm), "vendor": vendor_of(mm)} for mm, c in talk]
        # APs in der Luft
        aplist = sorted(ap_recent.items(), key=lambda kv: kv[1]["rssi"], reverse=True)[:16]
        aps_out = [{"ssid": a["ssid"] or "(hidden)", "rssi": a["rssi"], "bssid": b}
                   for b, a in aplist]
        # Clients pro Netz (AP mit SSID + Anzahl aktuell verbundener Clients)
        cpn = []
        for b, clients in ap_clients.items():
            act = [c for c, t in clients.items() if now - t <= 120]
            if not act:
                continue
            nm = aps.get(b, {}).get("ssid", "") or b
            cpn.append({"net": nm, "n": len(act)})
        cpn = sorted(cpn, key=lambda x: x["n"], reverse=True)[:8]
        # gesucht von Geraeten (per AIRMON_HIDE ausgeblendete SSIDs rausfiltern)
        searched = []
        for mm, ssids in probe_hits.items():
            act = {s: i for s, i in ssids.items()
                   if now - i["last"] <= 600 and not hidden_ssid(s)}
            if not act:
                continue
            nets = sorted(act.items(), key=lambda kv: kv[1]["last"], reverse=True)
            searched.append({"mac": mm, "rnd": is_random_mac(mm),
                             "last": round(now - max(i["last"] for i in act.values())),
                             "ssids": [s for s, _ in nets][:6]})
        searched = sorted(searched, key=lambda d: d["last"])[:60]
        nodes_up = sum(1 for t in nodes_seen.values() if now - t < 10)
    return {
        "dev_now": ndev, "conn": nconn, "scan": nscan,
        "pps": pps, "pps_hist": hist, "pkt_total": pkt_total,
        "bytes": byte_total, "bytes_h": human_bytes(byte_total), "movies": round(movies, 1),
        "ssid_count": len(ssid_recent), "ap_count": len(ap_recent),
        "feed": feed, "talkers": talkers, "aps": aps_out,
        "clients_per_net": cpn, "searched": searched, "nodes_up": nodes_up,
    }

def is_random_mac(mac):
    # lokal verwaltete (zufaellige) MAC: 2. Hex-Zeichen 2/6/a/e
    try:
        return mac[1].lower() in "26ae"
    except IndexError:
        return False

def probes_snapshot(since_id=0):
    now = time.time()
    with lock:
        # Live-Feed: alle Events mit id > since_id (neu seit letztem Poll), aelteste zuerst
        # damit der Client sie der Reihe nach oben einschieben kann.
        feed = [f for f in probe_feed if f["id"] > since_id]
        feed_out = [{"id": f["id"], "mac": f["mac"], "ssid": f["ssid"],
                     "ago": round(now - f["ts"]), "rssi": f["rssi"],
                     "rnd": is_random_mac(f["mac"])} for f in feed]
        # Pro Geraet: ALLE je gesehenen gesuchten Netze (komplette Liste)
        devices = []
        for mac, ssids in probe_hits.items():
            nets = sorted(ssids.items(), key=lambda kv: kv[1]["last"], reverse=True)
            devices.append({
                "mac": mac,
                "rnd": is_random_mac(mac),
                "rssi": best_rssi.get(mac, -999),
                "last": round(now - max(i["last"] for i in ssids.values())),
                "ssids": [{"ssid": s, "ago": round(now - i["last"]), "n": i["n"]} for s, i in nets]
            })
        devices = sorted(devices, key=lambda d: d["last"])   # zuletzt aktive oben, alle
        max_id = probe_seq
    return {"feed": feed_out, "devices": devices, "max_id": max_id}

# ---------------- HTTP-Server ----------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # ruhig halten
        pass
    def _send(self, body, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path.startswith("/dash-data"):
            self._send(json.dumps(dash_snapshot()).encode(), "application/json")
        elif self.path.startswith("/data"):
            self._send(json.dumps(snapshot()).encode(), "application/json")
        elif self.path.startswith("/probes-data"):
            since = 0
            if "?since=" in self.path:
                try: since = int(self.path.split("?since=")[1])
                except (ValueError, IndexError): since = 0
            self._send(json.dumps(probes_snapshot(since)).encode(), "application/json")
        elif self.path.startswith("/probes"):
            self._send(PROBE_PAGE.encode(), "text/html; charset=utf-8")
        elif self.path.startswith("/orten"):
            self._send(PAGE.encode(), "text/html; charset=utf-8")
        else:
            self._send(DASH_PAGE.encode(), "text/html; charset=utf-8")

PAGE = r"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RSSI Live Locator</title>
<style>
  :root{--bg:#0c1413;--panel:#121d1c;--ink:#e6efee;--muted:#8aa09e;--line:#223231;
    --grid:#1b2928;--accent:#2bd4c0;--target:#ff5a5a;
    --n0:#2bd4c0;--n1:#5a93ff;--n2:#ff79a8;color-scheme:dark}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,sans-serif}
  .wrap{max-width:1100px;margin:0 auto;padding:18px 16px 50px}
  h1{font-size:1.4rem;margin:0 0 2px}
  .sub{color:var(--muted);margin:0 0 16px;font-size:.9rem}
  .layout{display:grid;grid-template-columns:320px 1fr;gap:18px;align-items:start}
  @media(max-width:760px){.layout{grid-template-columns:1fr}}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;min-width:0}
  h2{font-size:.7rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);margin:0 0 10px}
  label{display:block;font-size:.7rem;color:var(--muted);margin:8px 0 3px}
  select,input{width:100%;background:var(--bg);color:var(--ink);border:1px solid var(--line);
    border-radius:7px;padding:7px 8px;font:inherit;font-variant-numeric:tabular-nums}
  select{font-family:ui-monospace,monospace;font-size:.85rem}
  .node-card{margin:12px 0;padding-bottom:10px;border-bottom:1px solid var(--line)}
  .node-head{display:flex;align-items:center;gap:8px}
  .dot{width:11px;height:11px;border-radius:50%}
  .node-head .nm{font-weight:700}
  .node-head .st{margin-left:auto;font-size:.7rem;color:var(--muted);font-family:ui-monospace,monospace}
  .row{display:flex;gap:10px}
  .row .field{flex:1;min-width:0}
  .rssi{font-family:ui-monospace,monospace;color:var(--accent);font-weight:700}
  .dist{font-family:ui-monospace,monospace;color:var(--muted);font-size:.8rem}
  canvas{width:100%;height:auto;display:block;border-radius:8px;touch-action:none;
    background:var(--panel);border:1px solid var(--line)}
  .readout{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
  .tile{flex:1;min-width:130px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 13px}
  .tile .k{font-size:.66rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
  .tile .v{font-family:ui-monospace,monospace;font-size:1.2rem;font-weight:700;margin-top:2px;font-variant-numeric:tabular-nums}
  .tile.t .v{color:var(--target)}
  .note{font-size:.8rem;color:var(--muted);margin-top:12px}
  .live{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--accent);margin-right:5px;animation:p 1.4s infinite}
  @keyframes p{50%{opacity:.3}}
</style></head><body>
<div class="wrap">
  <div style="margin-bottom:6px"><a href="/probes" style="color:var(--accent);text-decoration:none;font-size:.85rem">Probe Monitor →</a></div>
  <h1>RSSI Live Locator</h1>
  <p class="sub"><span class="live"></span>Live aus dem Collector. Ziel-MAC waehlen, Knoten-Positionen einmal eintragen (werden gespeichert).</p>
  <div class="layout">
    <div class="panel">
      <h2>Ziel-Geraet</h2>
      <select id="mac"></select>
      <div id="nodes"></div>
      <h2 style="margin-top:16px">Raum &amp; Kalibrierung</h2>
      <div class="row">
        <div class="field"><label>Breite (m)</label><input type="number" id="roomW" value="10" step="0.5"></div>
        <div class="field"><label>Höhe (m)</label><input type="number" id="roomH" value="10" step="0.5"></div>
      </div>
      <div class="row">
        <div class="field"><label>RSSI @ 1 m</label><input type="number" id="rssi0" value="-40" step="1"></div>
        <div class="field"><label>Pfadverlust n</label><input type="number" id="pathN" value="2.8" step="0.1"></div>
      </div>
    </div>
    <div>
      <canvas id="radar" width="1000" height="1000"></canvas>
      <div class="readout">
        <div class="tile t"><div class="k">Geschätzte Position</div><div class="v" id="est">—</div></div>
        <div class="tile"><div class="k">Methode</div><div class="v" id="meth" style="font-size:.95rem">—</div></div>
        <div class="tile"><div class="k">Rest-Fehler</div><div class="v" id="res">—</div></div>
      </div>
      <p class="note">2 Knoten = zwei moegliche Punkte (Mehrdeutigkeit). Ab 3 Knoten eindeutig. RSSI-Ortung im Innenraum: 2–4 m Unschaerfe.</p>
    </div>
  </div>
</div>
<script>
var COLORS=["--n0","--n1","--n2"];
var css=function(v){return getComputedStyle(document.documentElement).getPropertyValue(v).trim()};
var cv=document.getElementById("radar"),ctx=cv.getContext("2d");
var E={mac:document.getElementById("mac"),nodes:document.getElementById("nodes"),
  roomW:document.getElementById("roomW"),roomH:document.getElementById("roomH"),
  rssi0:document.getElementById("rssi0"),pathN:document.getElementById("pathN"),
  est:document.getElementById("est"),meth:document.getElementById("meth"),res:document.getElementById("res")};

var data={nodes:[],node_state:{},macs:[],rssi:{}};
var pos={};        // node -> {x,y}  (vom Nutzer, gespeichert)
var selMac="";

function loadPos(){try{pos=JSON.parse(localStorage.getItem("rssi_pos")||"{}")}catch(e){pos={}}}
function savePos(){try{localStorage.setItem("rssi_pos",JSON.stringify(pos))}catch(e){}}
function num(el,d){var v=parseFloat(el.value);return isFinite(v)?v:d}
function room(){return{w:num(E.roomW,10),h:num(E.roomH,10)}}
function d2(r){var p=num(E.rssi0,-40),n=num(E.pathN,2.8);return Math.pow(10,(p-r)/(10*n))}

function defaultPos(i){var rm=room();var xs=[rm.w*0.2,rm.w*0.8,rm.w*0.5],ys=[rm.h*0.2,rm.h*0.2,rm.h*0.8];
  return{x:+xs[i%3].toFixed(1),y:+ys[i%3].toFixed(1)}}

function curRssi(node){var r=data.rssi[node];return (r&&selMac in r)?r[selMac]:null}

function buildPanel(){
  // Dropdown
  var prev=E.mac.value;
  E.mac.innerHTML="";
  data.macs.forEach(function(m){
    var o=document.createElement("option");o.value=m.mac;
    o.textContent=m.mac+"  ("+m.count+")";E.mac.appendChild(o);
  });
  if(selMac) E.mac.value=selMac; else if(data.macs[0]){selMac=data.macs[0].mac;E.mac.value=selMac;}
  // Knoten
  E.nodes.innerHTML="";
  data.nodes.forEach(function(node,i){
    if(!pos[node]) pos[node]=defaultPos(i);
    var col=css(COLORS[i%3]);
    var r=curRssi(node);
    var card=document.createElement("div");card.className="node-card";
    var ip=(data.node_ip&&data.node_ip[node])?data.node_ip[node]:"?";
    var age=(data.node_age&&node in data.node_age)?data.node_age[node]:null;
    var ageTxt=(age==null)?"":(age<5?"vor "+age.toFixed(0)+"s":"STILL "+age.toFixed(0)+"s");
    card.innerHTML='<div class="node-head"><span class="dot" style="background:'+col+'"></span>'+
      '<span class="nm">'+node+'</span><span class="st">'+ageTxt+'</span></div>'+
      '<div class="dist" style="margin:2px 0 6px">'+ip+' · ssh root@'+ip+'</div>'+
      '<div class="row"><div class="field"><label>X (m)</label>'+
        '<input type="number" step="0.1" data-n="'+node+'" data-k="x" value="'+pos[node].x+'"></div>'+
      '<div class="field"><label>Y (m)</label>'+
        '<input type="number" step="0.1" data-n="'+node+'" data-k="y" value="'+pos[node].y+'"></div></div>'+
      '<label>RSSI (live): <span class="rssi">'+(r==null?"—":r.toFixed(0)+" dBm")+'</span> '+
        '<span class="dist">'+(r==null?"":"≈ "+d2(r).toFixed(1)+" m")+'</span></label>';
    E.nodes.appendChild(card);
  });
}

E.nodes.addEventListener("input",function(e){
  var t=e.target,n=t.dataset.n,k=t.dataset.k;if(!n)return;
  var v=parseFloat(t.value);if(!isFinite(v))return;
  pos[n][k]=v;savePos();draw();
});
E.mac.addEventListener("change",function(){selMac=E.mac.value;buildPanel();draw()});
[E.roomW,E.roomH,E.rssi0,E.pathN].forEach(function(x){x.addEventListener("input",function(){buildPanel();draw()})});

// ---- Schaetzung ----
function estimate(){
  var pts=[];
  data.nodes.forEach(function(node){
    var r=curRssi(node);if(r==null||!pos[node])return;
    pts.push({x:pos[node].x,y:pos[node].y,r:d2(r)});
  });
  if(pts.length<2)return null;
  if(pts.length===2)return est2(pts[0],pts[1]);
  return estLS(pts);
}
function est2(a,b){
  var dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy);
  if(d===0)return{p:{x:a.x,y:a.y},alt:null,method:"2 Knoten",resid:null};
  if(d<=a.r+b.r&&d>=Math.abs(a.r-b.r)){
    var aa=(a.r*a.r-b.r*b.r+d*d)/(2*d),h=Math.sqrt(Math.max(0,a.r*a.r-aa*aa));
    var mx=a.x+aa*dx/d,my=a.y+aa*dy/d,ox=-dy/d*h,oy=dx/d*h;
    return{p:{x:mx+ox,y:my+oy},alt:{x:mx-ox,y:my-oy},method:"2 Knoten (Schnitt)",resid:null};
  }
  var t=a.r/(a.r+b.r);
  return{p:{x:a.x+dx*t,y:a.y+dy*t},alt:null,method:"2 Knoten (geschätzt)",resid:null};
}
function estLS(pts){
  var n=pts.length,ref=pts[n-1],A=[],bv=[];
  for(var i=0;i<n-1;i++){var p=pts[i];
    A.push([2*(p.x-ref.x),2*(p.y-ref.y)]);
    bv.push((ref.r*ref.r-p.r*p.r)-(ref.x*ref.x-p.x*p.x)-(ref.y*ref.y-p.y*p.y));}
  var a11=0,a12=0,a22=0,b1=0,b2=0;
  for(var k=0;k<A.length;k++){a11+=A[k][0]*A[k][0];a12+=A[k][0]*A[k][1];a22+=A[k][1]*A[k][1];
    b1+=A[k][0]*bv[k];b2+=A[k][1]*bv[k];}
  var det=a11*a22-a12*a12;
  if(Math.abs(det)<1e-9)return{p:{x:ref.x,y:ref.y},alt:null,method:"kollinear",resid:null};
  var x=(b1*a22-b2*a12)/det,y=(a11*b2-a12*b1)/det,err=0;
  for(var j=0;j<pts.length;j++)err+=Math.abs(Math.hypot(x-pts[j].x,y-pts[j].y)-pts[j].r);
  err/=pts.length;
  return{p:{x:x,y:y},alt:null,method:pts.length+" Knoten (LS)",resid:err};
}

// ---- Zeichnen ----
var PAD=70,scale=1;
function toPx(mx,my){return{x:PAD+mx*scale,y:cv.height-PAD-my*scale}}
function draw(){
  var rm=room(),W=cv.width,H=cv.height;
  scale=Math.min((W-PAD*2)/rm.w,(H-PAD*2)/rm.h);
  ctx.clearRect(0,0,W,H);
  // Gitter
  ctx.strokeStyle=css("--grid");ctx.lineWidth=1;ctx.fillStyle=css("--muted");
  ctx.font="22px ui-monospace,monospace";ctx.textAlign="center";ctx.textBaseline="middle";
  for(var gx=0;gx<=rm.w+1e-6;gx++){var a=toPx(gx,0),b=toPx(gx,rm.h);
    ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();
    if(gx%2===0)ctx.fillText(gx,a.x,a.y+24);}
  for(var gy=0;gy<=rm.h+1e-6;gy++){var c=toPx(0,gy),d=toPx(rm.w,gy);
    ctx.beginPath();ctx.moveTo(c.x,c.y);ctx.lineTo(d.x,d.y);ctx.stroke();
    if(gy%2===0)ctx.fillText(gy,c.x-26,c.y);}
  ctx.strokeStyle=css("--line");ctx.lineWidth=2;
  var p0=toPx(0,0),p1=toPx(rm.w,rm.h);ctx.strokeRect(p0.x,p1.y,rm.w*scale,rm.h*scale);
  // Kreise
  data.nodes.forEach(function(node,i){var r=curRssi(node);if(r==null||!pos[node])return;
    var c=toPx(pos[node].x,pos[node].y),rp=d2(r)*scale,col=css(COLORS[i%3]);
    ctx.strokeStyle=col;ctx.globalAlpha=.45;ctx.lineWidth=2;ctx.setLineDash([6,6]);
    ctx.beginPath();ctx.arc(c.x,c.y,Math.max(0,rp),0,7);ctx.stroke();
    ctx.setLineDash([]);ctx.globalAlpha=1;});
  // Schaetzung
  var est=estimate();
  if(est){if(est.alt)tgt(est.alt,true);tgt(est.p,false);}
  // Knoten
  data.nodes.forEach(function(node,i){if(!pos[node])return;
    var c=toPx(pos[node].x,pos[node].y),col=css(COLORS[i%3]);
    ctx.fillStyle=col;ctx.beginPath();ctx.arc(c.x,c.y,13,0,7);ctx.fill();
    ctx.fillStyle=css("--panel");ctx.beginPath();ctx.arc(c.x,c.y,5,0,7);ctx.fill();
    ctx.fillStyle=col;ctx.font="700 24px system-ui,sans-serif";ctx.textAlign="center";ctx.textBaseline="bottom";
    ctx.fillText(node,c.x,c.y-18);});
  // Readout
  if(est){E.est.textContent=est.p.x.toFixed(1)+" , "+est.p.y.toFixed(1)+" m";
    E.meth.textContent=est.method;E.res.textContent=est.resid==null?"n/a":"± "+est.resid.toFixed(1)+" m";}
  else{E.est.textContent="—";E.meth.textContent="warte auf Daten";E.res.textContent="—";}
}
function tgt(pt,alt){var c=toPx(pt.x,pt.y);ctx.globalAlpha=alt?.4:1;
  ctx.strokeStyle=css("--target");ctx.fillStyle=css("--target");ctx.lineWidth=2;
  ctx.beginPath();ctx.arc(c.x,c.y,16,0,7);ctx.stroke();
  ctx.beginPath();ctx.moveTo(c.x-24,c.y);ctx.lineTo(c.x+24,c.y);ctx.moveTo(c.x,c.y-24);ctx.lineTo(c.x,c.y+24);ctx.stroke();
  ctx.beginPath();ctx.arc(c.x,c.y,5,0,7);ctx.fill();ctx.globalAlpha=1;}

// ---- Live-Poll ----
function poll(){
  fetch("/data").then(function(r){return r.json()}).then(function(d){
    data=d;buildPanel();draw();
  }).catch(function(){});
}
loadPos();poll();setInterval(poll,1000);
</script></body></html>"""

PROBE_PAGE = r"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Probe Monitor</title>
<style>
  :root{--bg:#0c1413;--panel:#121d1c;--ink:#e6efee;--muted:#8aa09e;--line:#223231;
    --accent:#2bd4c0;--rnd:#e2a24a;--real:#5a93ff;color-scheme:dark}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,sans-serif}
  .wrap{max-width:1100px;margin:0 auto;padding:18px 16px 50px}
  h1{font-size:1.4rem;margin:0 0 2px}
  .sub{color:var(--muted);margin:0 0 10px;font-size:.9rem}
  .nav a{color:var(--accent);text-decoration:none;font-size:.85rem;margin-right:14px}
  .live{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--accent);margin-right:5px;animation:p 1.4s infinite}
  @keyframes p{50%{opacity:.3}}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:14px}
  @media(max-width:760px){.grid{grid-template-columns:1fr}}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px;min-width:0}
  h2{font-size:.72rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);margin:0 0 10px}
  .muted2{color:var(--muted)}
  .feed{font-family:ui-monospace,monospace;font-size:.82rem;height:72vh;overflow-y:auto}
  .devlist{height:72vh;overflow-y:auto}
  .feed .row{padding:5px 0;border-bottom:1px solid var(--line);display:flex;gap:8px;align-items:baseline}
  .ago{color:var(--muted);width:52px;flex:none;text-align:right}
  .mac{flex:none}
  .arr{color:var(--muted)}
  .ssid{color:var(--accent);font-weight:700;word-break:break-all}
  .tag{font-size:.62rem;padding:1px 5px;border-radius:4px;flex:none}
  .tag.r{background:rgba(226,162,74,.16);color:var(--rnd)}
  .tag.e{background:rgba(90,147,255,.16);color:var(--real)}
  .dev{border-bottom:1px solid var(--line);padding:8px 0}
  .dev .h{display:flex;gap:8px;align-items:baseline;font-family:ui-monospace,monospace;font-size:.84rem}
  .dev .nets{margin-top:3px;display:flex;flex-wrap:wrap;gap:5px}
  .net{background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:1px 7px;font-size:.78rem;color:var(--accent)}
  .rssi{color:var(--muted);margin-left:auto;font-size:.78rem}
  .empty{color:var(--muted);padding:20px 0;text-align:center}
</style></head><body>
<div class="wrap">
  <div class="nav"><a href="/">← Ortung</a><a href="/probes">Probe Monitor</a></div>
  <h1>Probe Monitor</h1>
  <p class="sub"><span class="live"></span>Welche Geraete suchen nach welchen WLANs.
  <span class="tag e">echt</span> stabil trackbar · <span class="tag r">zufall</span> wechselnde MAC ·
  <span id="cnt" class="muted2">0 Geraete</span></p>
  <div class="grid">
    <div class="panel">
      <h2>Live-Feed · neueste oben</h2>
      <div class="feed" id="feed"><div class="empty">warte auf Probes…</div></div>
    </div>
    <div class="panel">
      <h2>Alle Geraete · gesuchte Netze</h2>
      <div class="devlist" id="devs"><div class="empty">warte auf Daten…</div></div>
    </div>
  </div>
</div>
<script>
function esc(s){return (s+"").replace(/[&<>]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;"}[c]})}
function tag(rnd){return rnd?'<span class="tag r">zufall</span>':'<span class="tag e">echt</span>'}
var MAXROWS=500, lastId=0, feedEl=document.getElementById("feed"), hasFeed=false;

function poll(){
  fetch("/probes-data?since="+lastId).then(function(r){return r.json()}).then(function(d){
    // --- Feed: neue Events oben einschieben (durchrutschen) ---
    if(d.feed && d.feed.length){
      if(!hasFeed){ feedEl.innerHTML=""; hasFeed=true; }
      d.feed.forEach(function(x){                 // aelteste zuerst -> jede oben einfuegen
        var row=document.createElement("div");
        row.className="row";
        row.innerHTML='<span class="ago" data-ts="'+x.ago+'">'+x.ago+'s</span>'+
          '<span class="mac">'+x.mac+'</span>'+tag(x.rnd)+
          '<span class="arr">→</span><span class="ssid">'+esc(x.ssid)+'</span>';
        feedEl.insertBefore(row, feedEl.firstChild);
        if(x.id>lastId) lastId=x.id;
      });
      while(feedEl.children.length>MAXROWS) feedEl.removeChild(feedEl.lastChild);
    }
    if(typeof d.max_id==="number" && d.max_id>lastId) lastId=d.max_id;

    // --- rechts: komplette Geraeteliste ---
    var v=document.getElementById("devs");
    document.getElementById("cnt").textContent=(d.devices?d.devices.length:0)+" Geraete";
    if(!d.devices || !d.devices.length){ if(v.children.length===0||v.querySelector(".empty")) v.innerHTML='<div class="empty">noch keine Geraete</div>'; }
    else v.innerHTML=d.devices.map(function(dev){
      var nets=dev.ssids.map(function(s){return '<span class="net">'+esc(s.ssid)+'</span>'}).join("");
      return '<div class="dev"><div class="h">'+dev.mac+tag(dev.rnd)+
        '<span class="rssi">'+dev.rssi+' dBm · vor '+dev.last+'s</span></div>'+
        '<div class="nets">'+nets+'</div></div>';
    }).join("");
  }).catch(function(){});
}
poll();setInterval(poll,1200);
</script></body></html>"""

def _local_ipv4s():
    ips = set()
    try:
        for res in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(res[4][0])
    except OSError:
        pass
    # Interface, ueber das der Default-Verkehr laeuft (oft der Hotspot)
    try:
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.connect(("8.8.8.8", 80)); ips.add(t.getsockname()[0]); t.close()
    except OSError:
        pass
    return [i for i in ips if not i.startswith("127.")]

def beacon():
    # Broadcast "ich bin der Collector" -- Sensoren finden die IP selbst,
    # egal welches Subnetz der Hotspot gerade vergibt. Kein IP-Aendern mehr.
    # Windows schickt 255.255.255.255 gern uebers falsche Interface, darum
    # funken wir zusaetzlich gezielt in die /24-Broadcast-Adresse jedes
    # lokalen Interfaces (z.B. 192.168.137.255 beim Mobile Hotspot).
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    msg = f"RSSI_COLLECTOR:{TCP_PORT}".encode()
    while True:
        targets = {"255.255.255.255"}
        for ip in _local_ipv4s():
            p = ip.split(".")
            if len(p) == 4:
                targets.add(".".join(p[:3]) + ".255")
        for dst in targets:
            try:
                s.sendto(msg, (dst, 9998))
            except OSError:
                pass
        time.sleep(2)

DASH_PAGE = r"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Airspace Monitor</title>
<style>
  :root{--bg:#060b09;--panel:#0a110e;--panel2:#070d0b;--ink:#c4e8d0;--dim:#4a7b5e;--dim2:#223a30;
    --green:#4fd98a;--amber:#d9a44e;--red:#e05563;--cyan:#5cc6d6;--mag:#cc6a9e;color-scheme:dark}
  *{box-sizing:border-box}html,body{height:100%}
  body{margin:0;background:var(--bg);color:var(--ink);overflow:hidden;font-family:"Share Tech Mono",ui-monospace,monospace;font-size:13px;letter-spacing:.3px}
  body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:9998;background:repeating-linear-gradient(0deg,rgba(0,0,0,.06) 0,rgba(0,0,0,.06) 1px,transparent 1px,transparent 4px)}
  body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:9997;background:radial-gradient(ellipse at center,transparent 70%,rgba(0,0,0,.3) 100%)}
  .glow{text-shadow:0 0 3px rgba(79,217,138,.4)}
  .app{height:100%;display:grid;grid-template-rows:auto auto 1.5fr auto;gap:8px;padding:10px}
  .topbar{display:flex;align-items:center;gap:14px;border:1px solid var(--dim2);background:var(--panel);padding:6px 12px;flex-wrap:wrap}
  .prompt{color:var(--green)}.prompt .u{color:var(--cyan)}.prompt .p{color:var(--amber)}
  .cursor{display:inline-block;width:8px;height:14px;background:var(--green);vertical-align:-2px;animation:blink 1s step-end infinite}
  @keyframes blink{50%{opacity:0}}
  .leds{margin-left:auto;display:flex;gap:16px;font-size:11px;color:var(--dim)}
  .led{display:flex;align-items:center;gap:6px}.led b{color:var(--ink)}
  .led .d{width:7px;height:7px;border-radius:50%;background:var(--green);animation:blink2 2.6s infinite}
  @keyframes blink2{50%{opacity:.55}}.led .d.a{background:var(--amber)}.led .d.off{background:var(--red)}
  .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}
  .kpi{border:1px solid var(--dim2);background:var(--panel);padding:7px 11px;position:relative}
  .kpi::before{content:"";position:absolute;top:0;left:0;width:8px;height:8px;border-top:1px solid var(--green);border-left:1px solid var(--green)}
  .kpi::after{content:"";position:absolute;bottom:0;right:0;width:8px;height:8px;border-bottom:1px solid var(--green);border-right:1px solid var(--green)}
  .kpi .k{font-size:.62rem;text-transform:uppercase;letter-spacing:.14em;color:var(--dim)}
  .kpi .v{font-size:1.45rem;color:var(--green);margin-top:1px;font-variant-numeric:tabular-nums}
  .kpi .d{font-size:.64rem;color:var(--dim)}.kpi .d b{color:var(--amber)}
  @media(max-width:820px){.kpis{grid-template-columns:repeat(3,1fr)}}
  .main{display:grid;grid-template-columns:1.7fr 1fr;gap:8px;min-height:0}
  @media(max-width:820px){.main{grid-template-columns:1fr;overflow-y:auto}}
  .box{border:1px solid var(--dim2);background:var(--panel);display:flex;flex-direction:column;min-height:0;min-width:0}
  .box .hd{display:flex;align-items:center;gap:8px;padding:5px 11px;border-bottom:1px solid var(--dim2);background:var(--panel2);flex:none;font-size:.64rem;text-transform:uppercase;letter-spacing:.14em;color:var(--dim)}
  .box .hd b{color:var(--green)}.box .hd .r{margin-left:auto;color:var(--dim)}
  .console{padding:4px 0;overflow:hidden;position:relative;flex:1}
  .line{display:flex;gap:9px;padding:1px 11px;white-space:nowrap;font-size:12px;animation:in .15s ease-out}
  @keyframes in{from{opacity:0}to{opacity:1}}
  .line .ts{color:var(--dim)}.line .rssi{width:46px;text-align:right}.line .src{color:var(--ink)}
  .line .ar{color:var(--dim)}.line .dst{color:var(--dim)}.line .ty{width:54px}
  .line .nd{color:var(--dim2);width:46px}
  .line .bar{letter-spacing:1px}
  .line .vend{width:120px;color:var(--dim2);overflow:hidden;text-overflow:ellipsis}
  .line .net{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;color:var(--cyan)}
  .line .ln{color:var(--dim);width:48px;text-align:right}.line .ch{color:var(--dim2)}
  .t-data{color:var(--green)}.t-probe{color:var(--amber)}.t-beacon{color:var(--cyan)}.t-mgmt{color:var(--mag)}.t-ctrl{color:var(--dim)}.t-other{color:var(--dim)}
  .rssi-s{color:var(--green)}.rssi-m{color:var(--amber)}.rssi-w{color:var(--red)}
  .side{display:grid;grid-template-rows:auto 1fr;gap:8px;min-height:0}
  .gwrap{padding:8px 10px}canvas{width:100%;display:block}
  .score{padding:3px 11px 8px;overflow:hidden;flex:1;min-height:0}
  .srow{display:flex;align-items:center;gap:8px;padding:3px 0;border-bottom:1px solid var(--dim2);font-size:12px}
  .srow:last-child{border-bottom:none}.rank{color:var(--dim);width:14px;text-align:right}
  .scnt{margin-left:auto;color:var(--green)}.svend{color:var(--dim);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .tag{font-size:.54rem;padding:0 4px;border:1px solid;flex:none}
  .tag.e{color:var(--cyan);border-color:var(--cyan)}.tag.r{color:var(--amber);border-color:var(--amber)}
  .bar{height:2px;background:var(--green);opacity:.7;margin-top:2px}
  .bottom{display:grid;grid-template-columns:1.3fr 1.3fr 1fr;gap:8px;min-height:0;height:150px}
  @media(max-width:820px){.bottom{grid-template-columns:1fr;height:auto}}
  .chips{padding:8px 11px;overflow-y:auto;display:flex;flex-wrap:wrap;gap:5px;align-content:flex-start}
  .chip{border:1px solid var(--dim2);padding:3px 7px;font-size:11px;background:var(--panel2)}
  .chip .nm{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:150px;display:block}
  .chip .mt{color:var(--dim);font-size:10px}
  .scrolly{overflow-y:auto;flex:1;min-height:0;padding:3px 11px}
  #searched{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:2px 16px;align-content:start}
  .drow{padding:5px 0;border-bottom:1px solid var(--dim2)}
  .drow .nets{display:flex;flex-wrap:wrap;gap:4px;align-items:center}
  .nchip{border:1px solid var(--cyan);padding:1px 7px;font-size:14px;font-weight:600;color:var(--cyan)}
  .drow .dh{display:flex;gap:7px;align-items:baseline;font-size:11px;color:var(--dim);margin-top:3px}
  .empty{color:var(--dim);padding:16px 0;text-align:center;font-size:12px}
  ::-webkit-scrollbar{width:7px;height:7px}::-webkit-scrollbar-thumb{background:var(--dim2)}::-webkit-scrollbar-track{background:transparent}
</style>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap">
</head><body>
<div class="app">
  <div class="topbar">
    <span class="prompt glow"><span class="u">root@airspace</span>:<span class="p">~</span># ./airmon --live<span class="cursor"></span></span>
    <div class="leds">
      <span class="led"><span class="d" id="ledcap"></span>CAPTURE <b id="capst">--</b></span>
      <span class="led"><span class="d a"></span>NODES <b id="lednodes">0</b></span>
      <span class="led">PKT/S <b id="ledpps">0</b></span>
    </div>
  </div>
  <div class="kpis">
    <div class="kpi"><div class="k">devices.now</div><div class="v glow" id="kDev">0</div><div class="d"><b id="kConn">0</b> conn · <span id="kScan">0</span> scan</div></div>
    <div class="kpi"><div class="k">pkt.rate</div><div class="v glow" id="kPps">0</div><div class="d">total <b id="kPkt">0</b></div></div>
    <div class="kpi"><div class="k">data.volume</div><div class="v glow" id="kGb">0</div><div class="d">≈ <b id="kMov">0</b> movies</div></div>
    <div class="kpi"><div class="k">ssid.count</div><div class="v glow" id="kSsid">0</div><div class="d"><b id="kAp">0</b> ap</div></div>
    <div class="kpi"><div class="k">radios</div><div class="v glow">5</div><div class="d">4×2g4 1×5g0</div></div>
    <div class="kpi"><div class="k">channels</div><div class="v glow" style="font-size:1.1rem">1·6·11</div><div class="d">hopping</div></div>
  </div>
  <div class="main">
    <div class="box"><div class="hd"><b>&gt;</b> packet_stream.raw <span class="r" id="cMeta">0 pkt/s</span></div><div class="console" id="console"></div></div>
    <div class="side">
      <div class="box"><div class="hd"><b>#</b> traffic.pps <span class="r">90s</span></div><div class="gwrap"><canvas id="graph" width="520" height="138"></canvas></div></div>
      <div class="box"><div class="hd"><b>#</b> probe_requests <span class="r" id="pbcnt">0</span></div><div class="scrolly" id="searched" style="flex:1;min-height:0"></div></div>
    </div>
  </div>
  <div class="bottom">
    <div class="box"><div class="hd"><b>#</b> nets_in_air <span class="r" id="apcnt">0</span></div><div class="chips" id="aps"></div></div>
    <div class="box"><div class="hd"><b>#</b> top_talkers <span class="r" id="ttcnt">0</span></div><div class="score" id="score"></div></div>
    <div class="box"><div class="hd"><b>#</b> clients_per_net <span class="r" id="connmeta">0</span></div><div class="scrolly" id="clients"></div></div>
  </div>
</div>
<script>
var css=function(v){return getComputedStyle(document.documentElement).getPropertyValue(v).trim()};
function esc(s){return (s+"").replace(/[&<>]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;"}[c]})}
function tag(r){return r?'<span class="tag r">rnd</span>':'<span class="tag e">ok</span>'}
var con=document.getElementById("console"),MAXL=58,lastId=0,hasF=false,fqueue=[];

// Graph
var g=document.getElementById("graph"),gx=g.getContext("2d");
function drawGraph(hist){
  var W=g.width,H=g.height,pad=16,N=hist.length||1;gx.clearRect(0,0,W,H);
  var max=Math.max(1,Math.max.apply(null,hist))*1.15,min=0;
  gx.strokeStyle=css("--dim2");gx.lineWidth=1;
  for(var r=0;r<=3;r++){var y=pad+(H-2*pad)*r/3;gx.beginPath();gx.moveTo(pad,y);gx.lineTo(W-4,y);gx.stroke()}
  var st=(W-pad-4)/Math.max(1,N-1);function X(i){return pad+i*st}function Y(v){return pad+(H-2*pad)*(1-(v-min)/(max-min))}
  var gr=gx.createLinearGradient(0,pad,0,H-pad);gr.addColorStop(0,"rgba(79,217,138,.18)");gr.addColorStop(1,"rgba(79,217,138,0)");
  gx.beginPath();gx.moveTo(X(0),H-pad);for(var i=0;i<N;i++)gx.lineTo(X(i),Y(hist[i]));gx.lineTo(X(N-1),H-pad);gx.closePath();gx.fillStyle=gr;gx.fill();
  gx.beginPath();for(var i=0;i<N;i++){i?gx.lineTo(X(i),Y(hist[i])):gx.moveTo(X(i),Y(hist[i]))}
  gx.strokeStyle=css("--green");gx.lineWidth=1.5;gx.stroke();
}
var OUI={"34:2c:c4":"Asus","00:1a:11":"Google","3c:5a:b4":"Google","f4:f5:e8":"Google",
  "a8:fb:40":"Hon Hai","ac:22:0b":"AzureWave","ac:22:05":"AzureWave","90:5c:44":"Intel",
  "60:b5:8d":"Sichuan AI","e4:4e:2d":"Fiberhome","c0:d7:aa":"Cambridge","a4:50:46":"Xiaomi",
  "28:6c:07":"Xiaomi","50:ec:50":"Samsung","9c:b1:50":"Samsung","d4:63:c6":"Motorola",
  "f0:2f:74":"Huawei","1c:bf:ce":"Shenzhen","dc:a6:32":"RaspberryPi","b8:27:eb":"RaspberryPi",
  "00:c0:ca":"Alfa","00:13:37":"Pineapple","0c:ef:af":"Pineapple"};
function vend(f){
  if(f.rnd)return"· random ·";
  if(f.vendor)return f.vendor;           // echte Hersteller-DB vom Collector
  var p=(f.sa||"").slice(0,8);
  return OUI[p]||p;                      // Fallback: kleine Liste / OUI-Praefix
}
function sbar(r){
  var n=Math.max(0,Math.min(5,Math.round((r+92)/10))),s="";
  for(var i=0;i<5;i++)s+=i<n?"█":"·";
  return s;
}
function addFrame(f){
  var rc=f.rssi>-55?"rssi-s":f.rssi>-75?"rssi-m":"rssi-w";
  var l=document.createElement("div");l.className="line";
  var net=f.net?((f.type==="beacon"||f.type==="probe")?'«'+esc(f.net)+'»':esc(f.net)):"";
  l.innerHTML='<span class="ts">+'+f.ts+'s</span><span class="rssi '+rc+'">'+f.rssi+'</span>'+
    '<span class="bar '+rc+'">'+sbar(f.rssi)+'</span>'+
    '<span class="nd">'+esc(f.node||"")+'</span>'+
    '<span class="src">'+f.sa+'</span>'+
    '<span class="vend">'+esc(vend(f))+'</span><span class="ar">></span>'+
    '<span class="dst">'+esc(f.da||"")+'</span><span class="ty t-'+f.type+'">'+(f.type||"").toUpperCase()+'</span>'+
    '<span class="net t-'+f.type+'">'+net+'</span>'+
    '<span class="ln">'+f.len+'</span>';
  con.appendChild(l);while(con.children.length>MAXL)con.removeChild(con.firstChild);
}
function poll(){
  fetch("/dash-data").then(function(r){return r.json()}).then(function(d){
    // LEDs + KPIs
    var up=d.nodes_up>0;
    document.getElementById("ledcap").className="d"+(up?"":" off");
    document.getElementById("capst").textContent=up?"ON":"OFF";
    document.getElementById("lednodes").textContent=d.nodes_up;
    document.getElementById("ledpps").textContent=d.pps;
    document.getElementById("kDev").textContent=d.dev_now;
    document.getElementById("kConn").textContent=d.conn;
    document.getElementById("kScan").textContent=d.scan;
    document.getElementById("kPps").textContent=(d.pps||0).toLocaleString("de");
    document.getElementById("kPkt").textContent=(d.pkt_total||0).toLocaleString("de");
    document.getElementById("kGb").textContent=d.bytes_h;
    document.getElementById("kMov").textContent=d.movies;
    document.getElementById("kSsid").textContent=d.ssid_count;
    document.getElementById("kAp").textContent=d.ap_count;
    document.getElementById("cMeta").textContent=(d.pps||0)+" pkt/s";
    drawGraph(d.pps_hist||[]);
    // Konsole: neue Frames in die Queue -> fliessen gleichmaessig ein
    if(d.feed&&d.feed.length){
      if(!hasF){con.innerHTML="";hasF=true;}
      d.feed.forEach(function(f){if(f.id>lastId){fqueue.push(f);lastId=f.id;}});
      if(fqueue.length>200)fqueue.splice(0,fqueue.length-200); // Rueckstau kappen
    }
    // top talkers
    var mx=d.talkers[0]?d.talkers[0].n:1;
    document.getElementById("ttcnt").textContent=d.talkers.length+" dev";
    document.getElementById("score").innerHTML=d.talkers.length?d.talkers.map(function(t,i){
      var ven=t.vendor?'<span class="svend">'+esc(t.vendor)+'</span>':(t.rnd?'':'<span class="svend">?</span>');
      return '<div><div class="srow"><span class="rank">'+(i+1)+'</span><span>'+t.mac+'</span>'+tag(t.rnd)+ven+
        '<span class="scnt">'+t.n+'</span></div><div class="bar" style="width:'+(t.n/mx*100)+'%"></div></div>';
    }).join(""):'<div class="empty">warte auf traffic...</div>';
    // nets in air
    document.getElementById("apcnt").textContent=d.ap_count+" ap";
    document.getElementById("aps").innerHTML=d.aps.length?d.aps.map(function(a){
      var col=a.rssi>-55?"--green":a.rssi>-75?"--amber":"--red";
      return '<div class="chip"><span class="nm" style="color:'+css(col)+'">'+esc(a.ssid)+'</span>'+
        '<span class="mt">'+a.rssi+'dBm</span></div>';
    }).join(""):'<div class="empty">scanne...</div>';
    // probe requests
    document.getElementById("pbcnt").textContent=d.searched.length+" dev";
    document.getElementById("searched").innerHTML=d.searched.length?d.searched.map(function(x){
      return '<div class="drow">'+
        '<div class="nets">'+x.ssids.map(function(n){return '<span class="nchip">'+esc(n)+'</span>'}).join("")+'</div>'+
        '<div class="dh">'+x.mac+tag(x.rnd)+
        '<span class="svend" style="margin-left:auto">'+x.last+'s</span></div></div>';
    }).join(""):'<div class="empty">keine directed probes</div>';
    // clients per net
    document.getElementById("connmeta").textContent=d.conn+" conn";
    var cmx=d.clients_per_net[0]?d.clients_per_net[0].n:1;
    document.getElementById("clients").innerHTML=d.clients_per_net.length?d.clients_per_net.map(function(n){
      return '<div class="drow"><div class="dh"><span style="color:'+css("--green")+'">'+esc(n.net)+'</span>'+
        '<span style="margin-left:auto;color:'+css("--green")+'">'+n.n+'</span></div>'+
        '<div class="bar" style="width:'+(n.n/cmx*100)+'%"></div></div>';
    }).join(""):'<div class="empty">keine clients erkannt</div>';
  }).catch(function(){});
}
poll();setInterval(poll,1000);
// Frames gleichmaessig einspeisen (~16/s); bei Rueckstau schneller aufholen
setInterval(function(){
  if(!fqueue.length)return;
  var n=fqueue.length>40?3:(fqueue.length>15?2:1);
  for(var i=0;i<n&&fqueue.length;i++)addFrame(fqueue.shift());
},60);
</script></body></html>"""

def main():
    load_oui()
    print(f"[OUI]  Hersteller-DB: {OUI_SRC}")
    load_state()
    print(f"[STATE] geladen aus {STATE_FILE}: {pkt_total} Pakete, {len(cnt)} MACs bekannt" if os.path.exists(STATE_FILE) else "[STATE] frisch (keine gespeicherte Statistik)")
    threading.Thread(target=tcp_server, daemon=True).start()
    threading.Thread(target=status_printer, daemon=True).start()
    threading.Thread(target=beacon, daemon=True).start()
    threading.Thread(target=pps_ticker, daemon=True).start()
    threading.Thread(target=state_saver, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    print(f"[HTTP] Ortungsseite -> http://localhost:{HTTP_PORT}")
    print(f"[BEACON] Broadcast auf UDP 9998 (Sensoren finden mich selbst)")
    print(f"[LOG]  -> {LOGFILE}")
    print("Strg+C zum Beenden.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        save_state()
        log.close()
        print("\nStatistik gespeichert. Beendet.")

if __name__ == "__main__":
    main()
