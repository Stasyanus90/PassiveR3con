# PassiveR3con

`PassiveR3con` — русскоязычный инструмент для **пассивной OSINT-разведки** с минималистичным UI в стиле RedTeam.

## Что важно

- Запуск из CLI (`--target` / `--file`) и через web UI (`--ui`).
- Реальный запуск инструментов: `whois`, `dig`, `nslookup`, `host`.
- Дополнительные источники: `socket.getaddrinfo`, `crt.sh`.
- Сохранение всех данных в SQLite (`scans`, `findings`).
- Отчёт в HTML содержит **обработанные выводы**, оценку уровня риска, метрики и рекомендации (а не только сырой вывод).

## Быстрый запуск

### CLI

```bash
python3 passive_osint_ru.py --target example.com
```

или

```bash
python3 passive_osint_ru.py --file targets.txt
```

### Web UI (минималистичный RedTeam)

```bash
python3 passive_osint_ru.py --ui --host 127.0.0.1 --port 8080
```

Откройте: `http://127.0.0.1:8080`

## Аргументы

- `--target` — один домен/поддомен
- `--file` — файл со списком целей
- `--db` — путь к SQLite БД (по умолчанию `passive_osint.db`)
- `--report-dir` — каталог отчётов (по умолчанию `reports`)
- `--ui` — запуск web UI
- `--host` — хост web UI
- `--port` — порт web UI
