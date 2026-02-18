import html
import json
import os
import secrets
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
STORE_PATH = DATA_DIR / 'store.json'
STYLE_PATH = BASE_DIR / 'public' / 'style.css'
HOST = '0.0.0.0'
PORT = int(os.getenv('PORT', '3000'))

sessions = {}


def ensure_store():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (BASE_DIR / 'public').mkdir(parents=True, exist_ok=True)
    if not STORE_PATH.exists():
        STORE_PATH.write_text(
            json.dumps(
                {
                    'sitePassword': '1234',
                    'adminPassword': 'admin123',
                    'notes': [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding='utf-8',
        )


def read_store():
    ensure_store()
    return json.loads(STORE_PATH.read_text(encoding='utf-8'))


def write_store(data):
    STORE_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


def page(title, body, footer='BySecret'):
    return f'''<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
  <link rel="stylesheet" href="/style.css" />
</head>
<body>
  <main class="container">{body}</main>
  <footer>{footer}</footer>
</body>
</html>'''.encode('utf-8')


class NoteFluxHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/style.css':
            return self.serve_style()
        if parsed.path == '/':
            return self.login_page(parsed)
        if parsed.path == '/notes':
            return self.notes_page()
        if parsed.path == '/admin/login':
            return self.admin_login_page(parsed)
        if parsed.path == '/admin':
            return self.admin_page()
        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        form = self.parse_form()

        if parsed.path == '/login':
            return self.login_action(form)
        if parsed.path == '/logout':
            return self.logout_action()
        if parsed.path == '/notes/new':
            return self.new_note_action(form)
        if parsed.path.startswith('/notes/') and parsed.path.endswith('/save'):
            return self.save_note_action(parsed.path, form)
        if parsed.path == '/admin/login':
            return self.admin_login_action(form)
        if parsed.path == '/admin/logout':
            return self.admin_logout_action()
        if parsed.path.startswith('/admin/delete/'):
            return self.admin_delete_note_action(parsed.path)
        if parsed.path == '/admin/change-site-password':
            return self.admin_change_site_password(form)
        if parsed.path == '/admin/change-admin-password':
            return self.admin_change_admin_password(form)
        self.send_error(404)

    def serve_style(self):
        if not STYLE_PATH.exists():
            self.send_error(404)
            return
        content = STYLE_PATH.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', 'text/css; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def parse_form(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8')
        parsed = parse_qs(body)
        return {k: (v[0] if v else '') for k, v in parsed.items()}

    def get_session(self):
        jar = cookies.SimpleCookie(self.headers.get('Cookie'))
        sid = jar['sid'].value if 'sid' in jar else None
        if sid and sid in sessions:
            return sid, sessions[sid]
        sid = secrets.token_hex(16)
        sessions[sid] = {'siteAuthed': False, 'adminAuthed': False}
        return sid, sessions[sid]

    def send_html(self, content, sid=None, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        if sid:
            self.send_header('Set-Cookie', f'sid={sid}; HttpOnly; Path=/; SameSite=Lax')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def redirect(self, location, sid=None):
        self.send_response(302)
        self.send_header('Location', location)
        if sid:
            self.send_header('Set-Cookie', f'sid={sid}; HttpOnly; Path=/; SameSite=Lax')
        self.end_headers()

    def require_site_auth(self):
        sid, session = self.get_session()
        if not session.get('siteAuthed'):
            self.redirect('/', sid)
            return None, None
        return sid, session

    def require_admin_auth(self):
        sid, session = self.get_session()
        if not session.get('adminAuthed'):
            self.redirect('/admin/login', sid)
            return None, None
        return sid, session

    def login_page(self, parsed):
        sid, session = self.get_session()
        if session.get('siteAuthed'):
            return self.redirect('/notes', sid)

        params = parse_qs(parsed.query)
        error = '<p class="error">Неверный пароль сайта</p>' if 'error' in params else ''
        body = f'''
<section class="card">
  <h1>Добро пожаловать в NoteFlux</h1>
  <p>Введите пароль сайта, чтобы открыть заметки.</p>
  {error}
  <form method="POST" action="/login" class="stack">
    <input type="password" name="password" placeholder="Пароль сайта" required />
    <button type="submit">Войти</button>
  </form>
  <a class="link" href="/admin/login">Вход в админ панель</a>
</section>
'''
        self.send_html(page('Вход в NoteFlux', body), sid)

    def login_action(self, form):
        sid, session = self.get_session()
        store = read_store()
        if form.get('password', '') == store['sitePassword']:
            session['siteAuthed'] = True
            self.redirect('/notes', sid)
            return
        self.redirect('/?error=1', sid)

    def logout_action(self):
        sid, session = self.get_session()
        session['siteAuthed'] = False
        self.redirect('/', sid)

    def notes_page(self):
        sid, _ = self.require_site_auth()
        if not sid:
            return

        store = read_store()
        notes_html = []
        for note in store['notes']:
            title = html.escape(note['title'])
            content = html.escape(note['content'])
            updated = datetime.fromisoformat(note['updatedAt']).strftime('%d.%m.%Y %H:%M:%S')
            notes_html.append(f'''
<article class="note-card">
  <form method="POST" action="/notes/{note['id']}/save" class="stack">
    <input name="title" value="{title}" required />
    <textarea name="content" rows="8" placeholder="Текст заметки...">{content}</textarea>
    <div class="between">
      <small>Обновлено: {updated}</small>
      <button type="submit">Сохранить</button>
    </div>
  </form>
</article>
''')

        body = f'''
<section class="card">
  <div class="between">
    <h1>Ваши заметки</h1>
    <form method="POST" action="/logout"><button class="secondary" type="submit">Выйти</button></form>
  </div>
  <form method="POST" action="/notes/new" class="stack inline-form">
    <input name="title" placeholder="Название новой заметки" required />
    <button type="submit">Открыть заметку</button>
  </form>
  <div class="notes-grid">{''.join(notes_html) if notes_html else '<p>Пока нет заметок. Создайте первую.</p>'}</div>
</section>
'''
        self.send_html(page('Ваши заметки', body), sid)

    def new_note_action(self, form):
        sid, _ = self.require_site_auth()
        if not sid:
            return

        title = form.get('title', '').strip() or 'Без названия'
        store = read_store()
        store['notes'].append(
            {
                'id': secrets.token_hex(6),
                'title': title,
                'content': '',
                'updatedAt': datetime.now().isoformat(),
            }
        )
        write_store(store)
        self.redirect('/notes', sid)

    def save_note_action(self, path, form):
        sid, _ = self.require_site_auth()
        if not sid:
            return

        note_id = path.split('/')[2]
        store = read_store()
        for note in store['notes']:
            if note['id'] == note_id:
                note['title'] = (form.get('title', '').strip() or 'Без названия')
                note['content'] = form.get('content', '')
                note['updatedAt'] = datetime.now().isoformat()
                break
        write_store(store)
        self.redirect('/notes', sid)

    def admin_login_page(self, parsed):
        sid, session = self.get_session()
        if session.get('adminAuthed'):
            return self.redirect('/admin', sid)

        params = parse_qs(parsed.query)
        error = '<p class="error">Неверный пароль админ панели</p>' if 'error' in params else ''
        body = f'''
<section class="card">
  <h1>Админ панель</h1>
  <p>Введите пароль админ панели.</p>
  {error}
  <form method="POST" action="/admin/login" class="stack">
    <input type="password" name="password" placeholder="Пароль админ панели" required />
    <button type="submit">Войти в админ панель</button>
  </form>
  <a class="link" href="/">Назад ко входу</a>
</section>
'''
        self.send_html(page('Вход в админ панель', body), sid)

    def admin_login_action(self, form):
        sid, session = self.get_session()
        store = read_store()
        if form.get('password', '') == store['adminPassword']:
            session['adminAuthed'] = True
            self.redirect('/admin', sid)
            return
        self.redirect('/admin/login?error=1', sid)

    def admin_logout_action(self):
        sid, session = self.get_session()
        session['adminAuthed'] = False
        self.redirect('/admin/login', sid)

    def admin_page(self):
        sid, _ = self.require_admin_auth()
        if not sid:
            return

        store = read_store()
        rows = []
        for note in store['notes']:
            title = html.escape(note['title'])
            updated = datetime.fromisoformat(note['updatedAt']).strftime('%d.%m.%Y %H:%M:%S')
            rows.append(f'''
<tr>
  <td>{title}</td>
  <td>{updated}</td>
  <td>
    <form method="POST" action="/admin/delete/{note['id']}">
      <button class="danger" type="submit">Удалить</button>
    </form>
  </td>
</tr>''')

        body = f'''
<section class="card">
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
</section>
'''
        self.send_html(page('Управление NoteFlux', body), sid)

    def admin_delete_note_action(self, path):
        sid, _ = self.require_admin_auth()
        if not sid:
            return

        note_id = path.split('/')[-1]
        store = read_store()
        store['notes'] = [n for n in store['notes'] if n['id'] != note_id]
        write_store(store)
        self.redirect('/admin', sid)

    def admin_change_site_password(self, form):
        sid, _ = self.require_admin_auth()
        if not sid:
            return
        value = form.get('newPassword', '').strip()
        if value:
            store = read_store()
            store['sitePassword'] = value
            write_store(store)
        self.redirect('/admin', sid)

    def admin_change_admin_password(self, form):
        sid, _ = self.require_admin_auth()
        if not sid:
            return
        value = form.get('newPassword', '').strip()
        if value:
            store = read_store()
            store['adminPassword'] = value
            write_store(store)
        self.redirect('/admin', sid)

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    ensure_store()
    print(f'NoteFlux running on http://localhost:{PORT}')
    print('Site password: 1234 | Admin password: admin123')
    server = ThreadingHTTPServer((HOST, PORT), NoteFluxHandler)
    server.serve_forever()
