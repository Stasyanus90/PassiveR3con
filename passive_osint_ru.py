#!/usr/bin/env python3
import argparse
import datetime as dt
import html
import json
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple

TARGET_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
WHOIS_FIELD_PATTERNS = {
    "registrar": re.compile(r"(?im)^\s*registrar\s*:\s*(.+)$"),
    "org": re.compile(r"(?im)^\s*(?:org|organization|registrant organization)\s*:\s*(.+)$"),
    "country": re.compile(r"(?im)^\s*country\s*:\s*(.+)$"),
    "created": re.compile(r"(?im)^\s*(?:creation date|created on|created)\s*:\s*(.+)$"),
    "expires": re.compile(r"(?im)^\s*(?:registry expiry date|expiry date|paid-till|expires)\s*:\s*(.+)$"),
}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            input_type TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            report_path TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            source TEXT NOT NULL,
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """
    )
    conn.commit()
    return conn


def create_scan(conn: sqlite3.Connection, target: str, input_type: str) -> int:
    cur = conn.execute(
        "INSERT INTO scans(target, input_type, started_at, status) VALUES (?, ?, ?, ?)",
        (target, input_type, now_iso(), "running"),
    )
    conn.commit()
    return int(cur.lastrowid)


def complete_scan(conn: sqlite3.Connection, scan_id: int, status: str, report_path: Path) -> None:
    conn.execute(
        "UPDATE scans SET finished_at=?, status=?, report_path=? WHERE id=?",
        (now_iso(), status, str(report_path), scan_id),
    )
    conn.commit()


def save_finding(conn: sqlite3.Connection, scan_id: int, category: str, source: str, data: Dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO findings(scan_id, category, source, data_json, created_at) VALUES (?, ?, ?, ?, ?)",
        (scan_id, category, source, json.dumps(data, ensure_ascii=False), now_iso()),
    )
    conn.commit()


def run_command(command: List[str], timeout: int = 25) -> Dict[str, Any]:
    binary = command[0]
    if not shutil.which(binary):
        return {
            "command": " ".join(command),
            "available": False,
            "exit_code": None,
            "stdout": "",
            "stderr": f"Инструмент '{binary}' не найден в системе.",
        }

    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        return {
            "command": " ".join(command),
            "available": True,
            "exit_code": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(command),
            "available": True,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Команда превысила лимит времени ({timeout} сек).",
        }


def resolve_ips(target: str) -> Dict[str, Any]:
    try:
        records = socket.getaddrinfo(target, None)
        ips = sorted({item[4][0] for item in records})
        return {"target": target, "ips": ips, "count": len(ips)}
    except socket.gaierror as err:
        return {"target": target, "ips": [], "count": 0, "error": str(err)}


def crtsh_query(target: str) -> Dict[str, Any]:
    query = urllib.parse.quote(f"%.{target}")
    url = f"https://crt.sh/?q={query}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "PassiveR3con/1.0"})

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = response.read().decode("utf-8", errors="ignore")
        if not payload.strip():
            return {"url": url, "entries": [], "count": 0}
        data = json.loads(payload)
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as err:
        return {"url": url, "entries": [], "count": 0, "error": str(err)}

    domains = set()
    for item in data:
        for line in item.get("name_value", "").splitlines():
            clean = line.strip().lower()
            if clean:
                domains.add(clean)

    return {"url": url, "entries": sorted(domains), "count": len(domains)}


def load_targets(single_target: str | None, file_path: Path | None) -> Tuple[List[str], str]:
    if single_target and file_path:
        raise ValueError("Укажите либо один таргет (--target), либо файл (--file), но не оба одновременно.")
    if not single_target and not file_path:
        raise ValueError("Нужно указать --target или --file.")

    if single_target:
        target = single_target.strip().lower()
        if not TARGET_RE.match(target):
            raise ValueError(f"Некорректный домен/поддомен: {single_target}")
        return [target], "single"

    assert file_path is not None
    if not file_path.exists():
        raise ValueError(f"Файл не найден: {file_path}")

    valid: List[str] = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        candidate = line.strip().lower()
        if candidate and not candidate.startswith("#") and TARGET_RE.match(candidate):
            valid.append(candidate)

    unique_targets = sorted(set(valid))
    if not unique_targets:
        raise ValueError("В файле нет валидных доменов/поддоменов.")
    return unique_targets, "file"


def parse_targets_text(raw: str) -> List[str]:
    out: List[str] = []
    for line in raw.splitlines():
        target = line.strip().lower()
        if target and TARGET_RE.match(target):
            out.append(target)
    return sorted(set(out))


def parse_whois_fields(whois_text: str) -> Dict[str, str]:
    info: Dict[str, str] = {}
    for key, pattern in WHOIS_FIELD_PATTERNS.items():
        match = pattern.search(whois_text)
        if match:
            info[key] = match.group(1).strip()
    return info


def extract_dns_records(lines: str) -> List[str]:
    out = []
    for line in lines.splitlines():
        value = line.strip()
        if value and not value.startswith(";"):
            out.append(value)
    return out


def analyze_findings(target: str, findings_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    whois_data = findings_map.get("whois", {})
    dig_data = findings_map.get("dig", {})
    nslookup_data = findings_map.get("nslookup", {})
    host_data = findings_map.get("host", {})
    socket_data = findings_map.get("socket.getaddrinfo", {})
    crt_data = findings_map.get("crt.sh", {})

    whois_text = whois_data.get("stdout", "")
    whois_info = parse_whois_fields(whois_text) if whois_text else {}
    dns_from_dig = extract_dns_records(dig_data.get("stdout", ""))
    dns_from_host = extract_dns_records(host_data.get("stdout", ""))
    ips = socket_data.get("ips", []) if isinstance(socket_data.get("ips", []), list) else []
    subdomains = crt_data.get("entries", []) if isinstance(crt_data.get("entries", []), list) else []

    unavailable_tools = []
    for tool in ["whois", "dig", "nslookup", "host"]:
        data = findings_map.get(tool, {})
        if not data.get("available", False):
            unavailable_tools.append(tool)

    risk_score = 0
    if len(subdomains) > 20:
        risk_score += 2
    elif len(subdomains) > 5:
        risk_score += 1

    if len(ips) > 3:
        risk_score += 1

    if unavailable_tools:
        risk_score += 1

    level = "Низкий"
    if risk_score >= 4:
        level = "Высокий"
    elif risk_score >= 2:
        level = "Средний"

    conclusions = [
        f"Для цели {target} найдено {len(ips)} уникальных IP-адресов.",
        f"В CT-логах обнаружено {len(subdomains)} связанных доменных имён.",
    ]

    if whois_info.get("registrar"):
        conclusions.append(f"Регистратор домена: {whois_info['registrar']}.")

    if unavailable_tools:
        conclusions.append(
            f"Часть инструментов отсутствует в системе: {', '.join(unavailable_tools)}. Полнота разведки снижена."
        )

    recommendations = [
        "Проверить найденные поддомены на актуальность и принадлежность организации.",
        "Сопоставить IP-адреса с ASN/провайдерами и исключить стороннюю инфраструктуру.",
    ]
    if len(subdomains) > 20:
        recommendations.append("Приоритизировать поддомены с dev/stage/admin в названии для ручного анализа.")
    if unavailable_tools:
        recommendations.append("Установить отсутствующие инструменты для повышения точности пассивной разведки.")

    return {
        "risk_level": level,
        "risk_score": risk_score,
        "metrics": {
            "ip_count": len(ips),
            "ct_subdomains_count": len(subdomains),
            "dns_records_dig": len(dns_from_dig),
            "dns_records_host": len(dns_from_host),
        },
        "whois_summary": whois_info,
        "dns_summary": {
            "dig_records": dns_from_dig[:20],
            "host_records": dns_from_host[:20],
            "nslookup_excerpt": nslookup_data.get("stdout", "")[:1200],
            "ip_addresses": ips,
        },
        "ct_summary": {
            "sample": subdomains[:30],
            "total": len(subdomains),
        },
        "tooling": {
            "missing": unavailable_tools,
            "errors": {
                source: data.get("stderr", "")
                for source, data in findings_map.items()
                if isinstance(data, dict) and data.get("stderr")
            },
        },
        "conclusions": conclusions,
        "recommendations": recommendations,
    }


def render_html(scan_id: int, target: str, started: str, finished: str, analysis: Dict[str, Any]) -> str:
    metrics = analysis["metrics"]
    whois_summary = analysis["whois_summary"]
    dns_summary = analysis["dns_summary"]
    ct_summary = analysis["ct_summary"]
    tooling = analysis["tooling"]

    def esc(value: Any) -> str:
        return html.escape(str(value))

    whois_rows = "".join(
        f"<li><span>{esc(k)}</span><b>{esc(v)}</b></li>" for k, v in whois_summary.items()
    ) or "<li><span>whois</span><b>Данные не извлечены</b></li>"

    conclusions = "".join(f"<li>{esc(item)}</li>" for item in analysis["conclusions"])
    recommendations = "".join(f"<li>{esc(item)}</li>" for item in analysis["recommendations"])
    ct_sample = "".join(f"<li>{esc(item)}</li>" for item in ct_summary["sample"][:15]) or "<li>Не найдено</li>"
    missing = ", ".join(tooling["missing"]) if tooling["missing"] else "нет"

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>RedTeam Passive Report — {esc(target)}</title>
  <style>
    :root {{
      --bg: #070707;
      --panel: #111111;
      --line: #252525;
      --text: #e6e6e6;
      --muted: #a2a2a2;
      --red: #ff2e2e;
      --red-soft: #ff2e2e20;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--text); font-family: Inter, Segoe UI, sans-serif; }}
    .wrap {{ max-width: 1120px; margin: 0 auto; padding: 24px; }}
    .top {{ border: 1px solid var(--line); background: var(--panel); padding: 20px; border-radius: 10px; }}
    h1, h2 {{ margin: 0 0 12px; font-weight: 650; letter-spacing: .4px; }}
    .label {{ color: var(--muted); font-size: 13px; }}
    .risk {{ display: inline-block; margin-top: 8px; padding: 6px 10px; border: 1px solid var(--red); color: var(--red); background: var(--red-soft); border-radius: 8px; font-size: 13px; }}
    .grid {{ margin-top: 14px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }}
    .metric {{ border: 1px solid var(--line); border-radius: 10px; padding: 12px; background: #0f0f0f; }}
    .metric b {{ display: block; font-size: 24px; margin-top: 4px; color: #fff; }}
    .layout {{ margin-top: 14px; display: grid; gap: 12px; grid-template-columns: 1fr 1fr; }}
    .card {{ border: 1px solid var(--line); border-radius: 10px; background: var(--panel); padding: 14px; }}
    ul {{ margin: 0; padding-left: 18px; }}
    li {{ margin-bottom: 6px; }}
    .kv li {{ list-style: none; padding: 6px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed #2f2f2f; }}
    .kv span {{ color: var(--muted); text-transform: capitalize; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; color: #cfcfcf; font-size: 12px; }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns: repeat(2, 1fr); }} .layout {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main class="wrap">
    <section class="top">
      <h1>PassiveR3con / RedTeam Report</h1>
      <div class="label">Цель: {esc(target)} · Scan ID: {scan_id} · Начало: {esc(started)} · Окончание: {esc(finished)}</div>
      <span class="risk">Риск: {esc(analysis['risk_level'])} (score {esc(analysis['risk_score'])})</span>
      <div class="grid">
        <div class="metric"><span class="label">IP-адреса</span><b>{esc(metrics['ip_count'])}</b></div>
        <div class="metric"><span class="label">CT-поддомены</span><b>{esc(metrics['ct_subdomains_count'])}</b></div>
        <div class="metric"><span class="label">Записи dig</span><b>{esc(metrics['dns_records_dig'])}</b></div>
        <div class="metric"><span class="label">Записи host</span><b>{esc(metrics['dns_records_host'])}</b></div>
      </div>
    </section>

    <section class="layout">
      <article class="card">
        <h2>Выводы</h2>
        <ul>{conclusions}</ul>
      </article>
      <article class="card">
        <h2>Рекомендации</h2>
        <ul>{recommendations}</ul>
      </article>
      <article class="card">
        <h2>Кратко по WHOIS</h2>
        <ul class="kv">{whois_rows}</ul>
      </article>
      <article class="card">
        <h2>CT-лог (примеры)</h2>
        <ul>{ct_sample}</ul>
      </article>
      <article class="card">
        <h2>DNS-данные</h2>
        <p class="label">IP: {esc(', '.join(dns_summary['ip_addresses']) if dns_summary['ip_addresses'] else 'нет')}</p>
        <p class="label">Инструменты отсутствуют: {esc(missing)}</p>
        <div class="mono">{esc(dns_summary['nslookup_excerpt'] or 'nslookup не вернул содержимого')}</div>
      </article>
      <article class="card">
        <h2>Служебные ошибки</h2>
        <div class="mono">{esc(json.dumps(tooling['errors'], ensure_ascii=False, indent=2) if tooling['errors'] else 'Ошибок не зафиксировано')}</div>
      </article>
    </section>
  </main>
</body>
</html>
"""


def collect_for_target(conn: sqlite3.Connection, target: str, input_type: str, report_dir: Path) -> Path:
    scan_id = create_scan(conn, target, input_type)
    started = now_iso()
    collected: Dict[str, Dict[str, Any]] = {}

    command_sets = [
        ("whois", ["whois", target]),
        ("dig", ["dig", "+short", target]),
        ("nslookup", ["nslookup", target]),
        ("host", ["host", target]),
    ]

    for source, command in command_sets:
        result = run_command(command)
        collected[source] = result
        save_finding(conn, scan_id, "tool", source, result)

    socket_result = resolve_ips(target)
    crtsh_result = crtsh_query(target)
    collected["socket.getaddrinfo"] = socket_result
    collected["crt.sh"] = crtsh_result
    save_finding(conn, scan_id, "dns", "socket.getaddrinfo", socket_result)
    save_finding(conn, scan_id, "certificates", "crt.sh", crtsh_result)

    analysis = analyze_findings(target, collected)
    save_finding(conn, scan_id, "analysis", "summary", analysis)

    finished = now_iso()
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"report_{target.replace('.', '_')}_{scan_id}.html"
    report_path.write_text(render_html(scan_id, target, started, finished, analysis), encoding="utf-8")

    complete_scan(conn, scan_id, "finished", report_path)
    return report_path


def web_dashboard_html() -> str:
    return """<!doctype html>
<html lang='ru'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>PassiveR3con UI</title>
  <style>
    :root{--bg:#080808;--panel:#111;--line:#252525;--text:#ebebeb;--muted:#9a9a9a;--red:#ff3434;}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,sans-serif}
    .wrap{max-width:980px;margin:0 auto;padding:28px}
    .head,.card{border:1px solid var(--line);background:var(--panel);border-radius:10px}
    .head{padding:18px;margin-bottom:12px}
    .card{padding:16px}
    h1{margin:0 0 8px;font-size:28px;letter-spacing:.3px}
    .muted{color:var(--muted);font-size:13px}
    .badge{display:inline-block;border:1px solid var(--red);color:var(--red);padding:4px 8px;border-radius:6px;font-size:12px;margin-top:8px}
    label{display:block;font-size:13px;margin:10px 0 6px;color:#cfcfcf}
    input,textarea{width:100%;background:#0c0c0c;border:1px solid #2a2a2a;color:#fff;border-radius:8px;padding:11px}
    textarea{min-height:130px;resize:vertical}
    button{margin-top:12px;border:1px solid var(--red);background:#170b0b;color:#ff6b6b;padding:10px 14px;border-radius:8px;cursor:pointer}
    ul{margin:0;padding-left:18px}
  </style>
</head>
<body>
  <main class='wrap'>
    <section class='head'>
      <h1>PassiveR3con</h1>
      <div class='muted'>Минималистичный RedTeam-интерфейс для пассивной разведки.</div>
      <span class='badge'>PASSIVE / OPSEC-SAFE</span>
    </section>

    <section class='card'>
      <form method='post' action='/scan'>
        <label>Один домен/поддомен</label>
        <input name='target' placeholder='example.com'>

        <label>Или список целей (по одной на строку)</label>
        <textarea name='targets_text' placeholder='example.com\nmail.example.com'></textarea>

        <button type='submit'>Запустить разведку</button>
      </form>
      <p class='muted'>Инструменты: whois, dig, nslookup, host, socket.getaddrinfo, crt.sh</p>
    </section>
  </main>
</body>
</html>
"""


def render_scan_result(reports: List[Path], errors: List[str]) -> str:
    report_items = "".join(
        f"<li><a href='/{html.escape(str(path))}' target='_blank'>{html.escape(str(path))}</a></li>" for path in reports
    )
    error_items = "".join(f"<li>{html.escape(error)}</li>" for error in errors)
    return f"""<!doctype html>
<html lang='ru'>
<head>
  <meta charset='utf-8'>
  <title>Результаты сканирования</title>
  <style>
    body{{font-family:Inter,Segoe UI,sans-serif;background:#080808;color:#efefef;padding:24px}}
    .box{{max-width:900px;border:1px solid #2c2c2c;background:#111;padding:16px;border-radius:10px}}
    a{{color:#ff5c5c}}
  </style>
</head>
<body>
  <section class='box'>
    <h1>Сканирование завершено</h1>
    <h3>Отчёты</h3>
    <ul>{report_items or '<li>Отчёты не созданы.</li>'}</ul>
    <h3>Ошибки</h3>
    <ul>{error_items or '<li>Ошибок нет.</li>'}</ul>
    <p><a href='/'>← Назад</a></p>
  </section>
</body>
</html>
"""


class PassiveUIHandler(BaseHTTPRequestHandler):
    conn: sqlite3.Connection
    report_dir: Path
    lock: threading.Lock

    def do_GET(self) -> None:
        if self.path in ["/", "/index.html"]:
            self.respond_html(web_dashboard_html())
            return

        report_candidate = Path(self.path.lstrip("/"))
        safe_report = (Path.cwd() / report_candidate).resolve()
        allowed_root = (Path.cwd() / self.report_dir).resolve()
        if safe_report.exists() and str(safe_report).startswith(str(allowed_root)):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(safe_report.read_bytes())
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Страница не найдена")

    def do_POST(self) -> None:
        if self.path != "/scan":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length).decode("utf-8", errors="ignore")
        data = urllib.parse.parse_qs(payload)
        target = data.get("target", [""])[0].strip().lower()
        targets_text = data.get("targets_text", [""])[0]

        targets: List[str] = []
        if target:
            targets = [target] if TARGET_RE.match(target) else []
        elif targets_text.strip():
            targets = parse_targets_text(targets_text)

        if not targets:
            self.respond_html(render_scan_result([], ["Не удалось получить валидные цели."]))
            return

        reports: List[Path] = []
        errors: List[str] = []
        for item in targets:
            try:
                with self.lock:
                    report = collect_for_target(self.conn, item, "ui", self.report_dir)
                reports.append(report)
            except Exception as exc:
                errors.append(f"{item}: {exc}")

        self.respond_html(render_scan_result(reports, errors))

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def respond_html(self, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def run_ui(host: str, port: int, conn: sqlite3.Connection, report_dir: Path) -> None:
    handler = PassiveUIHandler
    handler.conn = conn
    handler.report_dir = report_dir
    handler.lock = threading.Lock()
    server = ThreadingHTTPServer((host, port), handler)
    print(f"[+] UI запущен: http://{host}:{port}")
    print("[+] Для остановки нажмите Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Платформа пассивной разведки (OSINT) с БД, аналитическим отчётом и web UI."
    )
    parser.add_argument("--target", help="Один домен или поддомен для анализа.")
    parser.add_argument("--file", type=Path, help="Файл со списком доменов/поддоменов (по одному на строку).")
    parser.add_argument("--db", type=Path, default=Path("passive_osint.db"), help="Путь к SQLite БД.")
    parser.add_argument("--report-dir", type=Path, default=Path("reports"), help="Каталог для HTML отчётов.")
    parser.add_argument("--ui", action="store_true", help="Запустить минималистичный web UI в RedTeam-стиле.")
    parser.add_argument("--host", default="127.0.0.1", help="Хост для web UI.")
    parser.add_argument("--port", type=int, default=8080, help="Порт для web UI.")
    return parser.parse_args()


def run_cli(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    try:
        targets, input_type = load_targets(args.target, args.file)
    except ValueError as err:
        print(f"[Ошибка] {err}")
        return 2

    reports: List[Path] = []
    for target in targets:
        print(f"[+] Запуск пассивной разведки для: {target}")
        report = collect_for_target(conn, target, input_type, args.report_dir)
        reports.append(report)
        print(f"[+] Отчёт сохранён: {report}")

    print("\nГотово. Отчёты:")
    for rep in reports:
        print(f" - {rep}")
    return 0


def main() -> int:
    args = parse_args()
    conn = init_db(args.db)
    if args.ui:
        run_ui(args.host, args.port, conn, args.report_dir)
        return 0
    return run_cli(conn, args)


if __name__ == "__main__":
    raise SystemExit(main())
