#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTF «Тёмный архив „Мнемозина“» — задание 2 (порт 5051).
OWASP Top 10: A01:2021 — Broken Access Control (Path Traversal).

Легенда: хранилище документов «Лета». Интерфейс выдаёт файлы описи из
каталога docs/ по имени. Архивариус поставил фильтр от `..`, но забыл,
что браузеры и прокси дважды кодируют URL — а его «нормализатор»
раскодирует имя лишний раз. Это классический Path Traversal.

Флаг зашит в secret_flag.py; чтобы его получить, нужно выйти за пределы
docs/ и прочитать исходники приложения (/app/secret_flag.py).
"""

import os
import sqlite3
import time
from urllib.parse import unquote

from flask import Flask, request, Response, abort

from secret_flag import FLAG  # noqa: F401  (мастер-ключ «Мнемозины»)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(APP_DIR, "docs")
AUDIT_DB = os.environ.get("AUDIT_DB", "/data/audit.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = "mnemozina-dark-archive"


# ---------------------------------------------------------------------------
# База аудита: пишем ЛЮБЫЕ действия пользователя в SQLite на volume /data
# ---------------------------------------------------------------------------
def _db():
    d = os.path.dirname(AUDIT_DB)
    if d:
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(AUDIT_DB, timeout=5)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS actions (
               id      INTEGER PRIMARY KEY AUTOINCREMENT,
               ts      TEXT,
               ip      TEXT,
               method  TEXT,
               path    TEXT,
               query   TEXT,
               form    TEXT,
               headers TEXT,
               body    TEXT,
               ua      TEXT
           )"""
    )
    return conn


@app.before_request
def audit_everything():
    try:
        raw_body = request.get_data(cache=True, parse_form_data=False) or b""
        conn = _db()
        conn.execute(
            "INSERT INTO actions (ts, ip, method, path, query, form,"
            " headers, body, ua) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                request.headers.get("X-Forwarded-For", request.remote_addr),
                request.method,
                request.path,
                request.query_string.decode("utf-8", "replace"),
                str(dict(request.form)),
                str(dict(request.headers)),
                raw_body[:2048].decode("utf-8", "replace"),
                request.headers.get("User-Agent", ""),
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


@app.route("/audit/recent")
def audit_recent():
    """«Журнал читателей архива» — игроки видят собственные запросы."""
    conn = _db()
    rows = conn.execute(
        "SELECT ts, method, path, query FROM actions ORDER BY id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    out = "<h2>Журнал читателей (последние записи)</h2><pre>"
    for r in rows:
        out += " | ".join(str(x) for x in r) + "\n"
    return Response(out + "</pre>", mimetype="text/html")


# ---------------------------------------------------------------------------
# Оформление
# ---------------------------------------------------------------------------
PAGE_TITLE = "Тёмный архив «Мнемозина» — хранилище документов «Лета»"


def layout(inner: str) -> str:
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>{PAGE_TITLE}</title>
<style>
 body{{background:#101418;color:#c9d1d9;font-family:'Courier New',monospace;margin:4em auto;max-width:820px}}
 a{{color:#58a6ff}} h1,h2{{color:#58a6ff}} .content{{background:#161b22;padding:1em;border:1px solid #30363d}}
 pre{{white-space:pre-wrap}} table{{border-collapse:collapse}} td,th{{border:1px solid #30363d;padding:.3em .7em}}
</style></head><body>
<h1>📁 Хранилище документов «Лета»</h1>
<div class="nav">
 <a href="/">Опись</a> ·
 <a href="/files/readme.txt">Правила чтения</a> ·
 <a href="/audit/recent">Журнал читателей</a>
</div><hr>
<div class="content">{inner}</div>
<hr><small>Mnemozina Corp. — внутренний контур «Лета». Все обращения к документам протоколируются.</small>
</body></html>"""


# ---------------------------------------------------------------------------
# Опись
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    try:
        names = sorted(os.listdir(DOCS_DIR))
    except OSError:
        names = []
    rows = "".join(
        f"<tr><td><a href='/files/{n}'>{n}</a></td><td>опись №{i+1}</td></tr>"
        for i, n in enumerate(names)
    )
    return Response(layout(
        "<h2>Публичная опись документов</h2>"
        "<p>Выберите документ — хранилище выдаст его по имени. "
        "Система контроля доступа следит, чтобы читатели не выходили "
        "за пределы публичной описи <code>docs/</code>.</p>"
        f"<table><tr><th>Документ</th><th>Рег. номер</th></tr>{rows}</table>"
        "<p><small>Админ-заметка: фильтр имён работает, проверено. "
        "Двойное кодирование? Не слышали.</small></p>"),
        mimetype="text/html")


# ---------------------------------------------------------------------------
# «Защита»: чёрный список подстрок. Обход — двойное URL-кодирование,
# потому что ниже имя раскодируется ЕЩЁ РАЗ (unquote).
# ---------------------------------------------------------------------------
FORBIDDEN = ["..", "\\", "%2e", "%2E", "%2f", "%2F", "~"]
# ВНИМАНИЕ (для жюри): слэш "/" в список НЕ включён — «вежливый»
# ?name=/app/secret_flag.py проходит фильтр. А двойное кодирование
# (%252e%252e) обходит запрет на ".." через повторный unquote.


def is_blocked(name: str) -> bool:
    low = name.lower()
    return any(f in low for f in FORBIDDEN)


@app.route("/files/<path:filename>", defaults={"direct": None})
@app.route("/files")
def get_file(filename=None, direct=None):
    # имя документа можно передать и «вежливым» параметром ?name=
    raw = direct if direct else (request.args.get("name") or filename or "")

    # «Нормализация для пользователей с кириллицей»: добрый сервис
    # раскодирует URL ещё РАЗ. Именно это двойное декодирование и
    # обходит чёрный список: %252e%252e -> (Werkzeug) -> %2e%2e ->
    # (unquote ниже) -> '..'  — классический Path Traversal (A01).
    name = unquote(raw)

    if is_blocked(name):
        return Response(layout(
            "<h2>⛔ Доступ запрещён</h2>"
            "<p>Контроль доступа «Леты» обнаружил попытку выхода за пределы "
            "описи. Инцидент занесён в журнал.</p>"),
            status=403, mimetype="text/html")

    # «Удобство для ссылок филиалов»: абсолютный путь берётся как есть.
    # Чёрный список не содержит символа "/" целиком для параметра ?name=,
    # поэтому /app/secret_flag.py проходит свободно — второй вектор A01.
    if os.path.isabs(name):
        target = name
    else:
        target = os.path.join(DOCS_DIR, name)

    if not os.path.isfile(target):
        abort(404, description="Документ отсутствует в описи.")
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        abort(404, description="Документ отсутствует в описи.")
    from jinja2 import Environment
    env = Environment(autoescape=False)  # legacy-рендерер выдаваемых страниц
    page = env.from_string(
        "<h2>Документ: {{ name }}</h2><pre>{{ content }}</pre>"
        "<p><small>выдача остановлена на границе описи docs/</small></p>"
    ).render(name=name, content=content)
    return Response(layout(page), mimetype="text/html")


@app.errorhandler(404)
def nf(e):
    return Response(layout(f"<h2>404</h2><p>{e.description}</p>"),
                    status=404, mimetype="text/html")


@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\nDisallow: /audit/recent\n"
        "# выдача документов: /files/<имя>; границы описи под защитой фильтра\n",
        mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5051)),
            debug=False, threaded=True)
