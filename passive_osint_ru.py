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
from typing import Dict, List, Tuple

TARGET_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")


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


def save_finding(conn: sqlite3.Connection, scan_id: int, category: str, source: str, data: Dict) -> None:
    conn.execute(
        "INSERT INTO findings(scan_id, category, source, data_json, created_at) VALUES (?, ?, ?, ?, ?)",
        (scan_id, category, source, json.dumps(data, ensure_ascii=False), now_iso()),
    )
    conn.commit()


def run_command(command: List[str], timeout: int = 25) -> Dict:
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


def resolve_ips(target: str) -> Dict:
    try:
        records = socket.getaddrinfo(target, None)
        ips = sorted({item[4][0] for item in records})
        return {"target": target, "ips": ips, "count": len(ips)}
    except socket.gaierror as err:
        return {"target": target, "ips": [], "count": 0, "error": str(err)}


def crtsh_query(target: str) -> Dict:
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

    valid = []
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


def render_html(scan_id: int, target: str, started: str, finished: str, findings: List[Tuple[str, str, Dict]]) -> str:
    cards = []
    for category, source, data in findings:
        pretty = html.escape(json.dumps(data, ensure_ascii=False, indent=2))
        cards.append(f'<section class="card"><div class="meta">{html.escape(category)} · {html.escape(source)}</div><pre>{pretty}</pre></section>')
    cards_html = "\n".join(cards) if cards else "<p>Нет данных для отображения.</p>"
    return f"""<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/><title>Отчёт Passive OSINT — {html.escape(target)}</title><style>
:root{{--bg:#070b1a;--p:#111936;--c:#16254c;--txt:#e8ebf4;--m:#94a3b8;--a:#38bdf8;--a2:#22d3ee;}}
body{{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;color:var(--txt);background:radial-gradient(circle at 20% 0%,#172554 0%,#070b1a 45%),var(--bg)}}
.container{{max-width:1120px;margin:0 auto;padding:26px}}.hero{{padding:24px;border-radius:18px;background:linear-gradient(135deg,rgba(56,189,248,.20),rgba(34,211,238,.10));border:1px solid rgba(148,163,184,.25);box-shadow:0 10px 35px rgba(0,0,0,.3)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px;margin-top:22px}}.card{{background:rgba(22,37,76,.85);border:1px solid rgba(148,163,184,.15);border-radius:14px;padding:12px}}.meta{{color:var(--a2);font-weight:700;margin-bottom:8px}}pre{{margin:0;white-space:pre-wrap;word-break:break-word}}.muted{{color:var(--m)}}
</style></head><body><div class=\"container\"><section class=\"hero\"><h1>Отчёт пассивной разведки</h1><p><b>Цель:</b> {html.escape(target)}</p><p class=\"muted\">ID: {scan_id} · Начало: {html.escape(started)} · Окончание: {html.escape(finished)}</p></section><div class=\"grid\">{cards_html}</div></div></body></html>"""


def collect_for_target(conn: sqlite3.Connection, target: str, input_type: str, report_dir: Path) -> Path:
    scan_id = create_scan(conn, target, input_type)
    started = now_iso()
    collection: List[Tuple[str, str, Dict]] = []

    commands = [
        ("whois", ["whois", target]),
        ("dns", ["dig", "+short", target]),
        ("dns", ["nslookup", target]),
        ("dns", ["host", target]),
    ]
    for category, cmd in commands:
        result = run_command(cmd)
        save_finding(conn, scan_id, category, cmd[0], result)
        collection.append((category, cmd[0], result))

    dns_result = resolve_ips(target)
    cert_result = crtsh_query(target)
    for category, source, data in [
        ("dns", "socket.getaddrinfo", dns_result),
        ("certificates", "crt.sh", cert_result),
    ]:
        save_finding(conn, scan_id, category, source, data)
        collection.append((category, source, data))

    finished = now_iso()
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"report_{target.replace('.', '_')}_{scan_id}.html"
    report_path.write_text(render_html(scan_id, target, started, finished, collection), encoding="utf-8")
    complete_scan(conn, scan_id, "finished", report_path)
    return report_path


def web_dashboard_html() -> str:
    return """<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>PassiveR3con UI</title><style>
:root{--bg:#0a1022;--card:#111b3b;--card2:#182851;--text:#eef2ff;--muted:#94a3b8;--accent:#38bdf8;--ok:#22c55e;}
*{box-sizing:border-box}body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 10% 0%,#1d4ed8 0,#0a1022 48%),var(--bg);color:var(--text)}
.container{max-width:1100px;margin:0 auto;padding:26px}.hero{background:linear-gradient(130deg,rgba(56,189,248,.22),rgba(34,211,238,.11));border:1px solid rgba(148,163,184,.2);border-radius:20px;padding:22px;box-shadow:0 18px 50px rgba(0,0,0,.35)}
.grid{display:grid;grid-template-columns:1.2fr .8fr;gap:16px;margin-top:18px}@media(max-width:920px){.grid{grid-template-columns:1fr}}
.card{background:rgba(17,27,59,.88);border:1px solid rgba(148,163,184,.18);border-radius:16px;padding:16px}.input,textarea{width:100%;padding:12px;border-radius:12px;border:1px solid #243b70;background:#0f1835;color:#e2e8f0;outline:none}
textarea{min-height:130px;resize:vertical}.btn{cursor:pointer;padding:12px 16px;border:none;border-radius:12px;background:linear-gradient(90deg,#38bdf8,#22d3ee);color:#03111f;font-weight:700;margin-top:10px}.hint{color:var(--muted);font-size:13px}
ul{padding-left:20px}a{color:var(--accent)}
</style></head><body><div class='container'><section class='hero'><h1>PassiveR3con — современный UI</h1><p>Русскоязычная пассивная OSINT-разведка с сохранением в БД и HTML-отчётами.</p></section>
<div class='grid'><section class='card'><h2>Новый запуск</h2><form method='post' action='/scan'><label>Один домен/поддомен</label><input class='input' name='target' placeholder='example.com'>
<p class='hint'>Или укажите список ниже (по одному значению на строку).</p><label>Список целей</label><textarea name='targets_text' placeholder='example.com\nsub.example.com'></textarea><button class='btn' type='submit'>Запустить пассивную разведку</button></form></section>
<section class='card'><h2>Что делает программа</h2><ul><li>Реально запускает whois/dig/nslookup/host</li><li>Собирает DNS и CT-данные</li><li>Сохраняет результаты в SQLite</li><li>Формирует красивый HTML-отчёт на русском</li></ul></section></div></div></body></html>"""


def render_scan_result(reports: List[Path], errors: List[str]) -> str:
    report_items = "".join(f"<li><a href='/{html.escape(str(path))}' target='_blank'>{html.escape(str(path))}</a></li>" for path in reports)
    err_items = "".join(f"<li>{html.escape(err)}</li>" for err in errors)
    return f"""<!doctype html><html lang='ru'><head><meta charset='utf-8'><title>Результат</title><style>body{{font-family:Inter,Segoe UI,Arial,sans-serif;background:#0b1020;color:#e5e7eb;padding:30px}}a{{color:#38bdf8}}.card{{max-width:900px;background:#121a31;border:1px solid #334155;border-radius:16px;padding:20px}}</style></head><body><div class='card'><h1>Сканирование завершено</h1><h3>Отчёты</h3><ul>{report_items or '<li>Отчёты не созданы.</li>'}</ul><h3>Ошибки</h3><ul>{err_items or '<li>Ошибок нет.</li>'}</ul><p><a href='/'>← Вернуться на главную</a></p></div></body></html>"""


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

        targets = []
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
                    reports.append(collect_for_target(self.conn, item, "ui", self.report_dir))
            except Exception as exc:
                errors.append(f"{item}: {exc}")

        self.respond_html(render_scan_result(reports, errors))

    def log_message(self, format: str, *args) -> None:
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
    parser = argparse.ArgumentParser(description="Платформа пассивной разведки (OSINT) с БД, отчётами и web UI.")
    parser.add_argument("--target", help="Один домен или поддомен для анализа.")
    parser.add_argument("--file", type=Path, help="Файл со списком доменов/поддоменов (по одному на строку).")
    parser.add_argument("--db", type=Path, default=Path("passive_osint.db"), help="Путь к SQLite БД.")
    parser.add_argument("--report-dir", type=Path, default=Path("reports"), help="Каталог для HTML отчётов.")
    parser.add_argument("--ui", action="store_true", help="Запустить красивый web UI.")
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
