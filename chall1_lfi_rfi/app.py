#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTF «Тёмный архив „Мнемозина“» — задание 1 (порт 5050).
OWASP Top 10: A03:2021 — Injection (LFI / RFI с исполнением шаблона).

Легенда: внутренний портал шаблонов корпорации. Страницы рендерятся из
файлов каталога templates/ по параметру ?page=. Администратор добавил
«синхронизацию с филиалом» — загрузку удалённых шаблонов по URL (/fetch),
и именно эта функция стала второй дверью.

Флаг зашит в secret_flag.py (импортируется на старте, поэтому его можно
получить только через LFI/RFI -> исполнение кода или чтение исходников).
"""

import os
import sqlite3
import time
from urllib.parse import unquote
from urllib.request import urlopen

from flask import Flask, request, abort, Response

from secret_flag import FLAG  # noqa: F401  (мастер-ключ «Мнемозины»)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(APP_DIR, "templates")
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
    """Каждый запрос — одна запись в базу аудита."""
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
        # аудит не должен ронять приложение
        pass


@app.route("/audit/recent")
def audit_recent():
    """Игроки могут взглянуть на «журнал посетителей архива» (свои же шаги)."""
    conn = _db()
    rows = conn.execute(
        "SELECT ts, method, path, query FROM actions ORDER BY id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    out = "<h2>Журнал архива (последние записи)</h2><pre>"
    for r in rows:
        out += " | ".join(str(x) for x in r) + "\n"
    return Response(out + "</pre>", mimetype="text/html")


# ---------------------------------------------------------------------------
# Страницы портала
# ---------------------------------------------------------------------------
PAGE_TITLE = "Тёмный архив «Мнемозина» — портал шаблонов"


def layout(inner: str) -> str:
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>{PAGE_TITLE}</title>
<style>
 body{{background:#0d1117;color:#c9d1d9;font-family:Georgia,serif;margin:4em auto;max-width:760px}}
 a{{color:#e3b341}} h1,h2{{color:#e3b341}} .nav a{{margin-right:1em}}
 pre,.content{{background:#161b22;padding:1em;border:1px solid #30363d;white-space:pre-wrap}}
</style></head><body>
<h1>🗄 Тёмный архив «Мнемозина»</h1>
<div class="nav">
 <a href="/?page=home">Главная</a>
 <a href="/?page=about">Об архиве</a>
 <a href="/?page=contact">Архивариус</a>
 <a href="/sync">Синхронизация с филиалом</a>
</div><hr>
<div class="content">{inner}</div>
<hr><small>Mnemozina Corp. — внутренний контур. Все действия посетителей фиксируются.</small>
</body></html>"""


def render_template_file(path: str) -> str:
    """Уязвая часть задания: содержимое файла рендерится ДВИЖКОМ Jinja2.

    Путь формируется из пользовательского ввода без проверки границ
    каталога templates/ -> LFI. Удалённые шаблоны из /fetch доходят сюда
    же -> RFI. Так как файл исполняется как шаблон, игрок получает SSTI/RCE.
    """
    from jinja2 import Environment

    env = Environment(autoescape=False)  # «наследие legacy-портала»
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        tpl_src = fh.read()
    return env.from_string(tpl_src).render(page_title=PAGE_TITLE)


@app.route("/")
def index():
    page = request.args.get("page", "home")
    # «удобная» нормализация для пользователя… но путь НЕ ограничивается
    # каталогом templates/ — это и есть LFI-вектор.
    page = unquote(page)
    # «Вежливый» рендерер: если пользователь указал расширение — не дописываем.
    if not os.path.splitext(page)[1]:
        page += ".html"
    candidate = os.path.join(TEMPLATE_DIR, page)  # join проглатывает ../ и /abs!
    if not os.path.isfile(candidate):
        err = os.path.join(TEMPLATE_DIR, "error.html")
        if not os.path.isfile(err):
            abort(404)
        return Response(
            layout(render_template_file(err)
                   + f"<p><i>Страница «{page}» не найдена в описи архива.</i></p>"),
            status=404, mimetype="text/html",
        )
    return Response(layout(render_template_file(candidate)), mimetype="text/html")


# ---------------------------------------------------------------------------
# «Синхронизация с филиалом» — Remote File Inclusion
# ---------------------------------------------------------------------------
@app.route("/sync")
def sync_form():
    return Response(layout(
        "<h2>Загрузка шаблонов из филиала</h2>"
        "<p>Архивариус может импортировать страницу-шаблон с зеркального "
        "сервера филиала по HTTP. Введите URL шаблона:</p>"
        "<form method='POST' action='/fetch'>"
        "<input name='url' size='60' placeholder='http://mirror.mnemozina.local/tpl/welcome.tpl'>"
        "<button type='submit'>Импортировать</button></form>"),
        mimetype="text/html")


@app.route("/fetch", methods=["POST"])
def fetch_remote():
    url = (request.form.get("url") or request.args.get("url") or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        return Response(layout("<b>Ошибка:</b> разрешены только http(s)-зеркала."),
                        status=400, mimetype="text/html")
    try:
        req = urlopen(url, timeout=5)
        remote_tpl = req.read().decode("utf-8", "replace")
    except Exception as exc:
        return Response(layout(f"<b>Зеркало недоступно:</b> {exc}"),
                        status=502, mimetype="text/html")

    # RFI: удалённое содержимое сохраняется как локальный шаблон и тут же
    # рендерится движком — на сервере выполняется чужой код шаблона.
    safe_name = "remote_" + str(abs(hash(url)) % 10**8) + ".html"
    dest = os.path.join(TEMPLATE_DIR, safe_name)
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(remote_tpl)
    rendered = render_template_file(dest)
    return Response(
        layout(f"<h2>Импортированный шаблон</h2>{rendered}"
               f"<p><small>сохранён как {safe_name}</small></p>"),
        mimetype="text/html")


# ---------------------------------------------------------------------------
# Справочные страницы (атмосфера + намёки)
# ---------------------------------------------------------------------------
@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\nDisallow: /sync\nDisallow: /audit/recent\n"
        "# старый рендерер страниц всё ещё принимает ?page=...\n",
        mimetype="text/plain")


@app.errorhandler(500)
def boom(e):
    return Response(layout("<b>Внутренняя ошибка архива.</b>"), status=500,
                    mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5050)),
            debug=False, threaded=True)
