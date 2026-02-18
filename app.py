import base64
import hashlib
import hmac
import html
import json
import os
import secrets
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
STORE_PATH = DATA_DIR / 'store.json'
STATIC_STYLE = BASE_DIR / 'static' / 'style.css'
PORT = int(os.getenv('PORT', '3000'))
SESSION_SECRET = os.getenv('SESSION_SECRET', 'noteflux-change-this-secret')

memory_store = None


def default_store():
    return {'sitePassword': '1234', 'adminPassword': 'admin123', 'notes': []}


def normalize_store(store):
    if not isinstance(store, dict):
        return default_store()

    normalized = default_store()
    normalized['sitePassword'] = str(store.get('sitePassword', normalized['sitePassword']))
    normalized['adminPassword'] = str(store.get('adminPassword', normalized['adminPassword']))

    notes = store.get('notes', [])
    if not isinstance(notes, list):
        notes = []

    safe_notes = []
    for note in notes:
        if not isinstance(note, dict):
            continue
        safe_notes.append(
            {
                'id': str(note.get('id') or secrets.token_hex(6)),
                'title': str(note.get('title') or 'Без названия'),
                'content': str(note.get('content') or ''),
                'updatedAt': str(note.get('updatedAt') or datetime.now().isoformat()),
            }
        )

    normalized['notes'] = safe_notes
    return normalized


def ensure_store():
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if not STORE_PATH.exists():
            STORE_PATH.write_text(json.dumps(default_store(), ensure_ascii=False, indent=2), encoding='utf-8')
    except OSError:
        pass


def read_store():
    global memory_store
    ensure_store()

    try:
        if STORE_PATH.exists():
            data = json.loads(STORE_PATH.read_text(encoding='utf-8'))
            normalized = normalize_store(data)
            memory_store = normalized
            return normalized
    except (OSError, json.JSONDecodeError):
        pass

    if memory_store is None:
        memory_store = default_store()
    return normalize_store(memory_store)


def write_store(data):
    global memory_store
    normalized = normalize_store(data)
    memory_store = normalized

    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        STORE_PATH.write_text(json.dumps(normalized, ensure_ascii=False, indent=2), encoding='utf-8')
    except OSError:
        pass


def load_css():
    if STATIC_STYLE.exists():
        return STATIC_STYLE.read_text(encoding='utf-8')
    return ''


def page(title, body):
    styles = load_css()
    return f'''<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
  <style>{styles}</style>
</head>
<body>
  <main class="container">{body}</main>
  <footer>BySecret</footer>
</body>
</html>'''.encode('utf-8')


def parse_cookies(environ):
    cookie_header = environ.get('HTTP_COOKIE', '')
    pairs = [c.strip() for c in cookie_header.split(';') if '=' in c]
    return {k.strip(): v.strip() for k, v in (p.split('=', 1) for p in pairs)}


def b64_url_encode(raw):
    return base64.urlsafe_b64encode(raw).decode('utf-8').rstrip('=')


def b64_url_decode(value):
    padding = '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode('utf-8'))


def sign_payload(payload):
    return hmac.new(SESSION_SECRET.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()


def get_session(environ):
    raw = parse_cookies(environ).get('sid', '')
    if raw and '.' in raw:
        payload, signature = raw.split('.', 1)
        if hmac.compare_digest(sign_payload(payload), signature):
            try:
                data = json.loads(b64_url_decode(payload).decode('utf-8'))
                return {
                    'siteAuthed': bool(data.get('siteAuthed', False)),
                    'adminAuthed': bool(data.get('adminAuthed', False)),
                }
            except (json.JSONDecodeError, ValueError):
                pass
    return {'siteAuthed': False, 'adminAuthed': False}


def make_session_cookie(session_data):
    payload = b64_url_encode(json.dumps(session_data, separators=(',', ':')).encode('utf-8'))
    signature = sign_payload(payload)
    return f'sid={payload}.{signature}; HttpOnly; Path=/; SameSite=Lax'


def read_form(environ):
    try:
        length = int(environ.get('CONTENT_LENGTH') or 0)
    except ValueError:
        length = 0
    raw = environ['wsgi.input'].read(length).decode('utf-8')
    parsed = parse_qs(raw)
    return {k: (v[0] if v else '') for k, v in parsed.items()}


def response(start_response, body, status='200 OK', headers=None, content_type='text/html; charset=utf-8'):
    base_headers = [('Content-Type', content_type), ('Content-Length', str(len(body)))]
    if headers:
        base_headers.extend(headers)
    start_response(status, base_headers)
    return [body]


def redirect(start_response, location, session_data=None):
    headers = [('Location', location)]
    if session_data is not None:
        headers.append(('Set-Cookie', make_session_cookie(session_data)))
    start_response('302 Found', headers)
    return [b'']


def require_site(session_data, start_response):
    if not session_data.get('siteAuthed'):
        return redirect(start_response, '/', session_data)
    return None


def require_admin(session_data, start_response):
    if not session_data.get('siteAuthed'):
        return redirect(start_response, '/', session_data)
    if not session_data.get('adminAuthed'):
        return redirect(start_response, '/admin/login', session_data)
    return None


def as_local_datetime(iso_value):
    try:
        return datetime.fromisoformat(iso_value).strftime('%d.%m.%Y %H:%M:%S')
    except ValueError:
        return datetime.now().strftime('%d.%m.%Y %H:%M:%S')


def app(environ, start_response):
    try:
        path = environ.get('PATH_INFO', '/')
        method = environ.get('REQUEST_METHOD', 'GET').upper()
        query = parse_qs(environ.get('QUERY_STRING', ''))

        session_data = get_session(environ)
        cookie_header = [('Set-Cookie', make_session_cookie(session_data))]

        if path == '/static/style.css' and method == 'GET':
            if not STATIC_STYLE.exists():
                return response(start_response, b'Not found', '404 Not Found')
            content = STATIC_STYLE.read_bytes()
            return response(start_response, content, content_type='text/css; charset=utf-8')

        if path == '/' and method == 'GET':
            if session_data.get('siteAuthed'):
                return redirect(start_response, '/notes', session_data)
            error = '<p class="error">Неверный пароль сайта</p>' if 'error' in query else ''
            body = page(
                'Вход в NoteFlux',
                f'''<section class="card">
  <h1>Добро пожаловать в NoteFlux</h1>
  <p>Введите пароль сайта, чтобы открыть заметки.</p>
  {error}
  <form method="POST" action="/login" class="stack">
    <input type="password" name="password" placeholder="Пароль сайта" required />
    <button type="submit">Войти</button>
  </form>
</section>''',
            )
            return response(start_response, body, headers=cookie_header)

        if path == '/login' and method == 'POST':
            form = read_form(environ)
            if form.get('password') == read_store()['sitePassword']:
                session_data['siteAuthed'] = True
                return redirect(start_response, '/notes', session_data)
            return redirect(start_response, '/?error=1', session_data)

        if path == '/logout' and method == 'POST':
            session_data['siteAuthed'] = False
            session_data['adminAuthed'] = False
            return redirect(start_response, '/', session_data)

        if path == '/notes' and method == 'GET':
            blocked = require_site(session_data, start_response)
            if blocked:
                return blocked
            store = read_store()
            cards = []
            for note in store['notes']:
                cards.append(
                    f'''<article class="note-card">
  <form method="POST" action="/notes/{note['id']}/save" class="stack">
    <input name="title" value="{html.escape(note['title'])}" required />
    <textarea name="content" rows="8" placeholder="Текст заметки...">{html.escape(note['content'])}</textarea>
    <div class="between">
      <small>Обновлено: {as_local_datetime(note['updatedAt'])}</small>
      <button type="submit">Сохранить</button>
    </div>
  </form>
</article>'''
                )
            body = page(
                'Ваши заметки',
                f'''<section class="card">
  <div class="between top-controls">
    <h1>Ваши заметки</h1>
    <div class="actions-row">
      <a class="admin-entry" href="/admin/login">✨ Админ панель</a>
      <form method="POST" action="/logout"><button class="secondary" type="submit">Выйти</button></form>
    </div>
  </div>
  <form method="POST" action="/notes/new" class="stack inline-form">
    <input name="title" placeholder="Название новой заметки" required />
    <button type="submit">Открыть заметку</button>
  </form>
  <div class="notes-grid">{''.join(cards) if cards else '<p>Пока нет заметок. Создайте первую.</p>'}</div>
</section>''',
            )
            return response(start_response, body, headers=cookie_header)

        if path == '/notes/new' and method == 'GET':
            blocked = require_site(session_data, start_response)
            if blocked:
                return blocked
            return redirect(start_response, '/notes', session_data)

        if path == '/notes/new' and method == 'POST':
            blocked = require_site(session_data, start_response)
            if blocked:
                return blocked
            form = read_form(environ)
            store = read_store()
            store['notes'].append(
                {
                    'id': secrets.token_hex(6),
                    'title': form.get('title', '').strip() or 'Без названия',
                    'content': '',
                    'updatedAt': datetime.now().isoformat(),
                }
            )
            write_store(store)
            return redirect(start_response, '/notes', session_data)

        if path.startswith('/notes/') and path.endswith('/save') and method == 'POST':
            blocked = require_site(session_data, start_response)
            if blocked:
                return blocked
            note_id = path.split('/')[2]
            form = read_form(environ)
            store = read_store()
            for note in store['notes']:
                if note['id'] == note_id:
                    note['title'] = form.get('title', '').strip() or 'Без названия'
                    note['content'] = form.get('content', '')
                    note['updatedAt'] = datetime.now().isoformat()
                    break
            write_store(store)
            return redirect(start_response, '/notes', session_data)

        if path == '/admin/login' and method == 'GET':
            blocked = require_site(session_data, start_response)
            if blocked:
                return blocked
            if session_data.get('adminAuthed'):
                return redirect(start_response, '/admin', session_data)
            error = '<p class="error">Неверный пароль админ панели</p>' if 'error' in query else ''
            body = page(
                'Вход в админ панель',
                f'''<section class="card">
  <h1>Админ панель</h1>
  <p>Введите пароль админ панели.</p>
  {error}
  <form method="POST" action="/admin/login" class="stack">
    <input type="password" name="password" placeholder="Пароль админ панели" required />
    <button type="submit">Войти в админ панель</button>
  </form>
  <a class="link" href="/notes">Назад к заметкам</a>
</section>''',
            )
            return response(start_response, body, headers=cookie_header)

        if path == '/admin/login' and method == 'POST':
            blocked = require_site(session_data, start_response)
            if blocked:
                return blocked
            form = read_form(environ)
            if form.get('password') == read_store()['adminPassword']:
                session_data['adminAuthed'] = True
                return redirect(start_response, '/admin', session_data)
            return redirect(start_response, '/admin/login?error=1', session_data)

        if path == '/admin/logout' and method == 'POST':
            session_data['adminAuthed'] = False
            return redirect(start_response, '/admin/login', session_data)

        if path == '/admin' and method == 'GET':
            blocked = require_admin(session_data, start_response)
            if blocked:
                return blocked
            store = read_store()
            rows = []
            for note in store['notes']:
                rows.append(
                    f'''<tr>
  <td>{html.escape(note['title'])}</td>
  <td>{as_local_datetime(note['updatedAt'])}</td>
  <td>
    <form method="POST" action="/admin/delete/{note['id']}">
      <button class="danger" type="submit">Удалить</button>
    </form>
  </td>
</tr>'''
                )
            body = page(
                'Управление NoteFlux',
                f'''<section class="card">
  <div class="between">
    <h1>Админ панель</h1>
    <form method="POST" action="/admin/logout"><button class="secondary" type="submit">Выйти</button></form>
  </div>

  <h2>Открытые заметки</h2>
  <table>
    <thead><tr><th>Название</th><th>Обновлена</th><th>Действие</th></tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="3">Нет заметок</td></tr>'}</tbody>
  </table>

  <div class="admin-forms">
    <form method="POST" action="/admin/change-site-password" class="stack">
      <h2>Сменить пароль сайта</h2>
      <input type="password" name="newPassword" placeholder="Новый пароль сайта" required />
      <button type="submit">Сохранить пароль сайта</button>
    </form>

    <form method="POST" action="/admin/change-admin-password" class="stack">
      <h2>Сменить пароль админ панели</h2>
      <input type="password" name="newPassword" placeholder="Новый пароль админ панели" required />
      <button type="submit">Сохранить пароль админ панели</button>
    </form>
  </div>
</section>''',
            )
            return response(start_response, body, headers=cookie_header)

        if path.startswith('/admin/delete/') and method == 'POST':
            blocked = require_admin(session_data, start_response)
            if blocked:
                return blocked
            note_id = path.split('/')[-1]
            store = read_store()
            store['notes'] = [n for n in store['notes'] if n['id'] != note_id]
            write_store(store)
            return redirect(start_response, '/admin', session_data)

        if path == '/admin/change-site-password' and method == 'POST':
            blocked = require_admin(session_data, start_response)
            if blocked:
                return blocked
            form = read_form(environ)
            value = form.get('newPassword', '').strip()
            if value:
                store = read_store()
                store['sitePassword'] = value
                write_store(store)
            return redirect(start_response, '/admin', session_data)

        if path == '/admin/change-admin-password' and method == 'POST':
            blocked = require_admin(session_data, start_response)
            if blocked:
                return blocked
            form = read_form(environ)
            value = form.get('newPassword', '').strip()
            if value:
                store = read_store()
                store['adminPassword'] = value
                write_store(store)
            return redirect(start_response, '/admin', session_data)

        return response(start_response, b'Not found', '404 Not Found')

    except Exception:
        error_body = page(
            'Ошибка сервера',
            '<section class="card"><h1>Временная ошибка</h1><p>Обновите страницу и попробуйте снова.</p></section>',
        )
        return response(start_response, error_body, status='500 Internal Server Error')


if __name__ == '__main__':
    ensure_store()
    with make_server('0.0.0.0', PORT, app) as server:
        print(f'NoteFlux running on http://localhost:{PORT}')
        server.serve_forever()
