"""Verify teacher certificates on a disposable synthetic local MySQL 8 schema.

This program accepts only an explicit local Unix socket. It never reads the
application database configuration or private backups. The only DDL applied is
synthetic baseline DDL and the certificate migration. Credentials and fixtures
belong to this QA server. By default the schema is removed even on failure.

Development-only dependencies: Pillow, zxing-cpp (QR decoding).
Example: .venv/bin/python scripts/verify_teacher_certificates_mysql.py \
    --socket /tmp/roboman-certificates-qa.sock --artifacts ../outputs/certificates-qa
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from datetime import datetime
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import sys
import uuid
from unittest.mock import patch
import zipfile

import pymupdf as fitz
import mysql.connector
from PIL import Image
import zxingcpp

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.apply_migrations import _statements


# Own synthetic dependency definitions; no schema/data extracted from production.
BASELINE_SQL = """
CREATE TABLE owners (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, full_name VARCHAR(255) NOT NULL
);
CREATE TABLE teachers (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, full_name VARCHAR(255) NOT NULL,
 color CHAR(7) NOT NULL DEFAULT '#008060', status ENUM('working','vacation','fired') NOT NULL DEFAULT 'working',
 is_salary_free TINYINT(1) NOT NULL DEFAULT 0, phone VARCHAR(100), note TEXT,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
CREATE TABLE departments (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255) NOT NULL
);
CREATE TABLE department_owners (
 department_id BIGINT UNSIGNED NOT NULL, owner_id BIGINT UNSIGNED NOT NULL,
 PRIMARY KEY(department_id,owner_id)
);
CREATE TABLE branches (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, department_id BIGINT UNSIGNED NOT NULL,
 name VARCHAR(255) NOT NULL, address VARCHAR(500), metro VARCHAR(100),
 is_active TINYINT(1) NOT NULL DEFAULT 1, price_per_child DECIMAL(10,2) NOT NULL DEFAULT 300,
 teacher_base_rate INT, phone VARCHAR(100), contact_person VARCHAR(255), note TEXT
);
CREATE TABLE branch_teachers (
 branch_id BIGINT UNSIGNED NOT NULL, teacher_id BIGINT UNSIGNED NOT NULL,
 PRIMARY KEY(branch_id,teacher_id),
 FOREIGN KEY(branch_id) REFERENCES branches(id), FOREIGN KEY(teacher_id) REFERENCES teachers(id)
);
CREATE TABLE auf_users (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, login VARCHAR(100) NOT NULL UNIQUE,
 password_hash VARCHAR(255) NOT NULL, role ENUM('OWNER','TEACHER','BRANCH') NOT NULL,
 owner_id BIGINT UNSIGNED, teacher_id BIGINT UNSIGNED, branch_id BIGINT UNSIGNED,
 is_active TINYINT(1) NOT NULL DEFAULT 1, crm_access TINYINT(1) NOT NULL DEFAULT 0,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
CREATE TABLE auth_sessions (
 token_hash CHAR(64) NOT NULL PRIMARY KEY, user_id BIGINT UNSIGNED NOT NULL,
 expires_at DATETIME NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES auf_users(id)
);
CREATE TABLE lessons (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, branch_id BIGINT UNSIGNED NOT NULL,
 teacher_id BIGINT UNSIGNED NOT NULL, starts_at DATETIME NOT NULL,
 paid_children INT NOT NULL DEFAULT 1, trial_children INT NOT NULL DEFAULT 0,
 price_snapshot DECIMAL(10,2) NOT NULL DEFAULT 300, teacher_salary DECIMAL(10,2) NOT NULL DEFAULT 99999,
 private_note TEXT
);
"""

PUBLIC_KEYS = {
    'teacher_name', 'number', 'status', 'university', 'study_program', 'description',
    'has_photo', 'photo_url', 'qr_url', 'public_url', 'public_path', 'issued_at', 'branches',
}
PASSWORD = 'Certificates-demo-2026'
CANARY = 'PRIVATE_CERTIFICATE_QA_CANARY'


def image_bytes(format='PNG', size=(240, 320)):
    image = Image.new('RGB', size, '#caeee1')
    # Synthetic illustration rather than a real person's photograph.
    from PIL import ImageDraw
    draw = ImageDraw.Draw(image)
    draw.ellipse((72, 36, 168, 132), fill='#146d54')
    draw.rounded_rectangle((42, 150, 198, 285), radius=45, fill='#146d54')
    data = BytesIO()
    image.save(data, format=format)
    return data.getvalue()


class CertificateQA:
    def __init__(self, socket, artifacts, user='root', password=''):
        socket_path = Path(socket).resolve()
        if not socket_path.is_socket():
            raise ValueError('An existing local Unix socket is required')
        self.socket = str(socket_path)
        self.user = user
        self.password = password
        self.artifacts = Path(artifacts).resolve()
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.schema = 'roboman_certificates_qa_' + uuid.uuid4().hex
        self.checks = []
        self.api_probes = 0
        self.pdf_documents = 0
        self.pdf_pages = 0
        self.pdf_layout_words = 0
        self.qr_decodings = 0
        self.constraint_rejections = 0
        self.tokens = {}
        self.connection = self.connect()
        self.cursor = self.connection.cursor(dictionary=True, buffered=True)

    def connect(self, schema=None):
        return mysql.connector.connect(unix_socket=self.socket, user=self.user,
            password=self.password, database=schema, autocommit=False, connection_timeout=10)

    def check(self, condition, label):
        if not condition:
            raise AssertionError(label)
        self.checks.append(label)

    def execute(self, sql, values=()):
        self.cursor.execute(sql, values)
        self.connection.commit()
        return self.cursor.lastrowid

    def reject_sql(self, sql, values=()):
        try:
            self.cursor.execute(sql, values)
        except mysql.connector.Error as error:
            self.connection.rollback()
            self.check(error.errno in (1062, 1451, 1452, 3819, 1265, 1048),
                       'MySQL rejected invalid certificate data: ' + str(error.errno))
            self.constraint_rejections += 1
        else:
            self.connection.rollback()
            raise AssertionError('MySQL accepted invalid certificate data: ' + sql)

    @contextmanager
    def database(self, *, dictionary=True):
        connection = self.connect(self.schema)
        cursor = connection.cursor(dictionary=dictionary, buffered=True)
        try:
            yield connection, cursor
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            cursor.close()
            connection.close()

    def baseline(self):
        self.execute(f'CREATE DATABASE `{self.schema}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
        self.execute(f'USE `{self.schema}`')
        for statement in _statements(BASELINE_SQL):
            self.execute(statement)
        for full_name in ('Администратор QA', 'Другой администратор QA'):
            self.execute('INSERT INTO owners(full_name) VALUES(%s)', (full_name,))
        for index, full_name in enumerate(('Анна Сергеевна Примерова', 'Максим Игоревич Учебный',
                                          'Преподаватель без сертификата', 'Параллельная выдача'), 1):
            self.execute('INSERT INTO teachers(full_name,phone,note) VALUES(%s,%s,%s)',
                         (full_name, CANARY + '_teacher_phone', CANARY + '_teacher_note'))
        self.execute("INSERT INTO departments(name) VALUES('Синтетический отдел'),('Другой отдел')")
        self.execute('INSERT INTO department_owners VALUES(1,1),(2,2)')
        for name, active, dep in (('Сад «Ромашка»', 1, 1), ('Сад «Техноград»', 1, 2), ('Неактивный сад', 0, 1)):
            self.execute('INSERT INTO branches(department_id,name,address,is_active,phone,contact_person,note) VALUES(%s,%s,%s,%s,%s,%s,%s)',
                         (dep, name, 'Москва, учебная улица, 1', active, CANARY + '_branch_phone',
                          CANARY + '_contact', CANARY + '_branch_note'))
        self.execute('INSERT INTO branch_teachers VALUES(1,1),(2,1),(3,1),(2,2)')
        self.execute('INSERT INTO lessons(branch_id,teacher_id,starts_at,private_note) VALUES(1,1,%s,%s)',
                     ('2026-10-08 10:00:00', CANARY + '_lesson'))
        self.execute("INSERT INTO auf_users(login,password_hash,role,owner_id) VALUES('legacy-qa','synthetic-unused-password','OWNER',1)")
        self.execute('INSERT INTO auth_sessions(token_hash,user_id,expires_at) VALUES(%s,1,%s)',
                     ('0' * 64, '2026-01-01 00:00:00'))
        self.migration = next(iter(sorted(ROOT.glob('migrations/*teacher_certificate*.sql'))), None)
        if not self.migration:
            raise RuntimeError('Certificate migration is not available yet')
        before = self.snapshot()
        for statement in _statements(self.migration.read_text(encoding='utf-8')):
            self.execute(statement)
        self.check(before == self.snapshot(), 'Migration preserves every synthetic pre-existing row')

    def snapshot(self):
        result = {}
        for table in ('teachers', 'owners', 'departments', 'branches', 'branch_teachers', 'lessons', 'auf_users', 'auth_sessions'):
            self.cursor.execute(f'SELECT * FROM `{table}`')
            result[table] = self.cursor.fetchall()
        return result

    def load_app(self):
        # Explicitly override all remote defaults before importing application modules.
        self.cursor.execute('SELECT @@port AS port')
        self.port = int(self.cursor.fetchone()['port'])
        os.environ.update(DB_HOST='127.0.0.1', DB_PORT=str(self.port), DB_USER=self.user,
            DB_PASSWORD=self.password, DB_NAME=self.schema, PUBLIC_CERTIFICATE_BASE_URL='http://localhost:3027')
        import main
        import shared
        from blueprints import teacher_certificates
        self.main = main
        self.shared = shared
        self.certificates = teacher_certificates
        self.stack = ExitStack()
        for module in (main, shared, teacher_certificates):
            self.stack.enter_context(patch.object(module, 'db_cursor', self.database))
        self.client = main.app.test_client()
        actors = {
            'owner': ('OWNER', 1, None, None), 'foreign_owner': ('OWNER', 2, None, None),
            'teacher': ('TEACHER', None, 1, None), 'foreign_teacher': ('TEACHER', None, 2, None),
            'no_certificate_teacher': ('TEACHER', None, 3, None), 'branch': ('BRANCH', None, None, 1),
        }
        self.logins = {}
        for name, scope in actors.items():
            login = {'owner': 'owner-demo', 'teacher': 'teacher-demo', 'branch': 'branch-demo'}.get(name, name + '-demo')
            self.logins[name] = login
            self.execute('INSERT INTO auf_users(login,password_hash,role,owner_id,teacher_id,branch_id) VALUES(%s,%s,%s,%s,%s,%s)',
                         (login, shared.hash_password(PASSWORD), *scope))
            result = self.request('POST', '/auth/login', actor=None,
                                  data={'login': login, 'password': PASSWORD})
            self.tokens[name] = result['token']
            self.check('password_hash' not in result['user'], name + ' login hides password hash')
            self.cursor.execute('SELECT token_hash FROM auth_sessions WHERE user_id=%s', (result['user']['id'],))
            self.check(self.cursor.fetchone()['token_hash'] == hashlib.sha256(result['token'].encode()).hexdigest(),
                       name + ' login stores only token digest')

    def request(self, method, path, data=None, actor='owner', status=200, files=None, headers=None, binary=False):
        request_headers = dict(headers or {})
        if actor is not None:
            request_headers['Authorization'] = 'Bearer ' + self.tokens.get(actor, actor)
        kwargs = {'method': method, 'headers': request_headers}
        if files is not None:
            kwargs['data'] = files
            kwargs['content_type'] = 'multipart/form-data'
        elif data is not None:
            kwargs['json'] = data
        response = self.client.open('/api' + path, **kwargs)
        self.api_probes += 1
        payload = response.get_json(silent=True)
        self.check(response.status_code == status,
            f'{actor or "public"} {method} {path} expected {status}, got {response.status_code}: {payload if not binary else response.mimetype}')
        return response if binary else (payload or {}).get('data')

    def upload(self, certificate, image=None, filename='portrait.png', status=200, actor='owner'):
        return self.request('PUT', f"/teacher-certificates/{certificate['id']}/photo", actor=actor, status=status,
            files={'revision': str(certificate['revision']), 'photo': (BytesIO(image if image is not None else image_bytes()), filename)})

    def create(self, teacher_id, **values):
        return self.request('POST', '/teacher-certificates', {'teacher_id': teacher_id, **values})

    def update(self, certificate, **values):
        return self.request('PUT', f"/teacher-certificates/{certificate['id']}", {'revision': certificate['revision'], **values})

    def action(self, certificate, action, status=200):
        return self.request('POST', f"/teacher-certificates/{certificate['id']}/{action}", {'revision': certificate['revision']}, status=status)

    def public_path(self, certificate, suffix=''):
        return '/public/teacher-certificates/' + certificate['public_path'].rsplit('/', 1)[-1] + suffix

    def private_path(self, certificate, suffix=''):
        return f"/teacher-certificates/{certificate['id']}" + suffix

    def qr(self, response, expected_url, label):
        self.check(response.mimetype == 'image/png', label + ' QR MIME')
        codes = zxingcpp.read_barcodes(Image.open(BytesIO(response.data)))
        self.check(any(code.text == expected_url for code in codes), label + ' QR decodes to canonical frontend URL')
        self.qr_decodings += 1

    def pdf(self, response, certificate, filename, expected_text=()):
        self.check(response.mimetype == 'application/pdf' and response.data.startswith(b'%PDF'), 'Real PDF content and MIME')
        self.check('attachment' in response.headers.get('Content-Disposition', ''), 'PDF is delivered as an attachment')
        path = self.artifacts / filename
        path.write_bytes(response.data)
        for old_png in self.artifacts.glob(Path(filename).stem + '-page-*.png'):
            old_png.unlink()
        document = fitz.open(stream=response.data, filetype='pdf')
        text = '\n'.join(page.get_text() for page in document)
        compact_text = ''.join(text.split())
        for value in (certificate['teacher_name'], certificate['number'], certificate['university'], certificate['study_program'], *expected_text):
            self.check(''.join(value.split()) in compact_text, 'PDF preserves text: ' + value[:80])
        qr_found = False
        links = []
        for index, page in enumerate(document):
            pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
            png = pix.tobytes('png')
            (self.artifacts / (Path(filename).stem + f'-page-{index + 1}.png')).write_bytes(png)
            qr_found |= any(code.text == certificate['public_url'] for code in zxingcpp.read_barcodes(Image.open(BytesIO(png))))
            links.extend(link.get('uri') for link in page.get_links())
            words = page.get_text('words')
            self.pdf_layout_words += len(words)
            self.check(all(word[0] >= -0.1 and word[1] >= -0.1 and word[2] <= page.rect.width + 0.1 and word[3] <= page.rect.height + 0.1
                           for word in words), 'Every PDF text bounding box stays on page ' + str(index + 1))
        self.check(qr_found, 'QR decodes from the rendered PDF')
        self.qr_decodings += 1
        self.check(certificate['public_url'] in links, 'PDF contains a clickable canonical verification link')
        count = document.page_count
        self.pdf_documents += 1
        self.pdf_pages += count
        document.close()
        return count

    def run_checks(self):
        self.request('GET', '/teacher-certificates', actor=None, status=401)
        self.request('GET', '/teacher-certificates', actor='1', status=401)
        self.request('POST', '/auth/login', actor=None, data={'login': 'owner-demo', 'password': 'incorrect'}, status=401)
        for actor in ('teacher', 'foreign_teacher', 'branch'):
            self.request('GET', '/teacher-certificates', actor=actor, status=403)
            self.request('POST', '/teacher-certificates', {'teacher_id': 1}, actor=actor, status=403)
        self.check(self.request('GET', '/teacher-certificates/me', actor='no_certificate_teacher') is None,
                   'Teacher without certificate has a safe empty personal result')
        first = self.create(1, description='Преподаватель робототехники. Помогаю детям исследовать механизмы.',
                            university='Московский технический университет', study_program='Прикладная информатика')
        second = self.create(2, description='Разработка конструкторов и занятия робототехникой.')
        self.first = first
        self.second = second
        self.check(first['status'] == 'draft' and first['revision'] == 1, 'New certificate is draft revision 1')
        self.check(first['number'] != second['number'] and first['public_path'] != second['public_path'],
                   'Certificate numbers and public tokens are unique')
        self.check(first['public_url'] == 'http://localhost:3027' + first['public_path'], 'Canonical URL matches frontend path')
        self.check(len(first['public_path'].rsplit('/', 1)[-1]) == 43, 'Public token has 256-bit random length')
        self.check(self.request('GET', self.private_path(first), actor='foreign_owner')['id'] == first['id'],
                   'Every OWNER retains the existing global teacher administration scope')
        self.request('POST', '/teacher-certificates', {'teacher_id': 1}, status=409)
        self.request('POST', '/teacher-certificates', {'teacher_id': 999999}, status=404)
        for invalid_teacher in (None, True, 'abc', -1):
            self.request('POST', '/teacher-certificates', {'teacher_id': invalid_teacher}, status=400)
        self.request('GET', self.public_path(first), actor=None, status=404)
        self.request('GET', self.public_path(first, '/photo'), actor=None, status=404)
        self.request('GET', self.public_path(first, '/qr'), actor=None, status=404)
        self.request('GET', self.private_path(first, '/pdf'), status=409)
        self.action(first, 'publish', status=400)
        self.request('PUT', self.private_path(first), {'revision': first['revision'], 'teacher_id': 2}, status=400)
        for field, invalid_value in (('description', 'x' * 3001), ('university', 'x' * 251),
                                     ('study_program', 'x' * 251), ('description', 42)):
            self.request('PUT', self.private_path(first), {'revision': first['revision'], field: invalid_value}, status=400)
        for revision in (None, 0, True, 'abc'):
            self.request('PUT', self.private_path(first), {'revision': revision, 'description': 'Заполнение'}, status=400)
        # DB constraints provide a second boundary independent of the API.
        self.reject_sql('UPDATE teacher_certificates SET revision=0 WHERE id=%s', (first['id'],))
        self.reject_sql('UPDATE teacher_certificates SET public_token=%s WHERE id=%s', ('short', first['id']))
        self.reject_sql('UPDATE teacher_certificates SET description=%s WHERE id=%s', ('x' * 3001, first['id']))
        self.reject_sql('UPDATE teacher_certificates SET number=%s WHERE id=%s', (first['number'], second['id']))
        self.reject_sql('UPDATE teacher_certificates SET teacher_id=999999 WHERE id=%s', (first['id'],))
        self.reject_sql('UPDATE teacher_certificates SET teacher_id=1 WHERE id=%s', (second['id'],))
        self.reject_sql('UPDATE teacher_certificates SET status=\'published\' WHERE id=%s', (first['id'],))
        self.reject_sql('DELETE FROM teachers WHERE id=2')
        self.upload(first, image=b'<svg onload="alert(1)"></svg>', filename='fake.jpg', status=400)
        self.upload(first, image=image_bytes() + b'x' * (5 * 1024 * 1024), status=413)
        self.upload(first, image=image_bytes(size=(5000, 5000)), status=400)
        for fmt in ('PNG', 'JPEG', 'WEBP'):
            first = self.upload(first, image=image_bytes(fmt), filename='portrait.' + fmt.lower())
            photo = self.request('GET', self.private_path(first, '/photo'), binary=True)
            self.check(photo.mimetype == 'image/jpeg', 'Decoded ' + fmt + ' photo is normalized to JPEG')
            Image.open(BytesIO(photo.data)).verify()
        self.reject_sql('UPDATE teacher_certificates SET photo_mime=NULL WHERE id=%s', (first['id'],))
        self.reject_sql('UPDATE teacher_certificates SET photo_blob=%s WHERE id=%s', (b'', first['id']))
        self.reject_sql('UPDATE teacher_certificates SET public_token=(SELECT token FROM (SELECT public_token AS token FROM teacher_certificates WHERE id=%s) source) WHERE id=%s',
                        (first['id'], second['id']))
        self.qr(self.request('GET', self.private_path(first, '/qr'), binary=True), first['public_url'], 'Private draft preview')
        old = first.copy()
        first = self.update(first, university='Московский университет', study_program='Робототехника')
        self.request('PUT', self.private_path(first), {'revision': old['revision'], 'description': 'Устаревшие данные'}, status=409)
        self.upload(old, status=409)
        self.request('DELETE', self.private_path(first, '/photo'), {'revision': old['revision']}, status=409)
        first = self.action(first, 'publish')
        self.check(first['status'] == 'published' and first['issued_at'], 'Publication stores status and first issue date')
        stable = (first['number'], first['public_path'], first['issued_at'])
        public = self.request('GET', self.public_path(first), actor=None)
        self.check(set(public) <= PUBLIC_KEYS, 'Public certificate uses only allowed fields')
        self.check(all(set(branch) == {'name', 'address'} for branch in public['branches']), 'Public branches expose only name and address')
        self.check(CANARY not in json.dumps(public), 'Public certificate contains no private contact, payroll or lesson canary')
        public_response = self.request('GET', self.public_path(first), actor=None, binary=True)
        self.check('no-store' in public_response.headers.get('Cache-Control', ''), 'Public profile cannot retain cached personal data after revocation')
        self.check({branch['name'] for branch in public['branches']} == {'Сад «Ромашка»', 'Сад «Техноград»'},
                   'Public certificate derives active current assignments across departments')
        self.request('GET', self.public_path(first), actor='expired-session')
        hostile = self.request('GET', self.public_path(first), actor=None,
            headers={'Host': 'hostile.example', 'Origin': 'https://hostile.example'})
        self.check(hostile['public_url'] == first['public_url'], 'Host and Origin cannot alter the QR verification URL')
        self.qr(self.request('GET', self.public_path(first, '/qr'), actor=None, binary=True), first['public_url'], 'Public')
        self.request('GET', self.public_path(first, '/photo'), actor=None, binary=True)
        self.check(self.request('GET', '/teacher-certificates/me', actor='teacher')['id'] == first['id'],
                   'Teacher personal endpoint returns their linked certificate')
        for suffix in ('', '/photo', '/qr', '/pdf'):
            self.request('GET', self.private_path(first, suffix), actor='foreign_teacher', status=404)
            self.request('GET', self.private_path(first, suffix), actor='branch', status=403)
        for method, suffix, data in (
            ('PUT', '', {'revision': first['revision'], 'description': 'Forbidden edit'}),
            ('POST', '/publish', {'revision': first['revision']}),
            ('POST', '/revoke', {'revision': first['revision']}),
            ('DELETE', '/photo', {'revision': first['revision']}),
        ):
            self.request(method, self.private_path(first, suffix), data, actor='teacher', status=403)
        self.request('POST', '/teacher-certificates/export', {'certificate_ids': [first['id']]}, actor='teacher', status=403)
        self.request('DELETE', self.private_path(first, '/photo'), {'revision': first['revision']}, status=409)
        self.request('PUT', self.private_path(first), {'revision': first['revision'], 'description': ''}, status=400)
        # Every PDF reflects current names and current active assignments.
        self.execute('UPDATE teachers SET full_name=%s WHERE id=1', ('Анна Петровна Новая-Фамилия',))
        self.execute('UPDATE branches SET is_active=0 WHERE id=2')
        public = self.request('GET', self.public_path(first), actor=None)
        self.check(public['teacher_name'] == 'Анна Петровна Новая-Фамилия' and len(public['branches']) == 1,
                   'Name and kindergarten activity changes are visible immediately')
        first = self.request('GET', self.private_path(first))
        self.pdf(self.request('GET', '/teacher-certificates/me/pdf', actor='teacher', binary=True),
                 first, 'certificate-standard.pdf', expected_text=('Сад «Ромашка»',))
        self.execute('DELETE FROM branch_teachers WHERE teacher_id=1')
        self.check(self.request('GET', self.public_path(first), actor=None)['branches'] == [],
                   'Past lessons never become current kindergarten assignments')
        first = self.request('GET', self.private_path(first))
        self.pdf(self.request('GET', self.private_path(first, '/pdf'), binary=True), first, 'certificate-no-branches.pdf')
        self.execute("UPDATE teachers SET status='vacation' WHERE id=1")
        self.request('GET', self.public_path(first), actor=None)
        self.execute("UPDATE teachers SET status='fired' WHERE id=1")
        inactive = self.request('GET', self.public_path(first), actor=None, status=410)
        self.check(inactive == {'number': first['number'], 'status': 'revoked'}, 'Fired teacher public result contains no personal details')
        for suffix in ('/photo', '/qr'):
            self.request('GET', self.public_path(first, suffix), actor=None, status=410)
        self.request('GET', '/teacher-certificates/me/pdf', actor='teacher', status=409)
        self.execute("UPDATE teachers SET status='working' WHERE id=1")
        self.request('GET', self.public_path(first), actor=None)
        first = self.action(first, 'revoke')
        revoked = self.request('GET', self.public_path(first), actor=None, status=410)
        self.check(revoked == {'number': first['number'], 'status': 'revoked'}, 'Revoked result is minimal and contains no person')
        self.request('GET', self.public_path(first, '/photo'), actor=None, status=410)
        self.request('GET', self.public_path(first, '/qr'), actor=None, status=410)
        self.request('GET', self.private_path(first, '/pdf'), status=409)
        first = self.action(first, 'publish')
        self.check((first['number'], first['public_path'], first['issued_at']) == stable,
                   'Republishing preserves number, URL and first issue date')
        # Exercise allowed boundary lengths, unbroken words and multipage branch lists.
        marker = ' КОНЕЦ_ПОЛНОГО_ОПИСАНИЯ'
        description = ('Описание с кириллицей, символами <>& и инженерными интересами. ' * 60)[:3000 - len(marker)] + marker
        university = 'Университет ' + 'У' * (250 - len('Университет '))
        study_program = 'Направление ' + 'Н' * (250 - len('Направление '))
        first = self.update(first, description=description, university=university, study_program=study_program)
        self.execute('UPDATE teachers SET full_name=%s WHERE id=1',
                     (('Анна ' + 'ОченьДлиннаяФамилияБезПробела' * 12)[:255],))
        for index in range(1, 51):
            branch_id = self.execute('INSERT INTO branches(department_id,name,address) VALUES(1,%s,%s)',
                (f'Длинное название сада {index:02d} ' + 'Конструктор ' * 15,
                 'Москва, длинный адрес, учебная улица, корпус ' + str(index)))
            self.execute('INSERT INTO branch_teachers VALUES(%s,1)', (branch_id,))
        first = self.request('GET', self.private_path(first))
        pages = self.pdf(self.request('GET', self.private_path(first, '/pdf'), binary=True),
            first, 'certificate-long.pdf', expected_text=('КОНЕЦ_ПОЛНОГО_ОПИСАНИЯ', 'Длинное название сада 50'))
        self.check(pages > 1, 'Long description and kindergarten list continue across pages')
        second = self.upload(second)
        second = self.action(second, 'publish')
        exported = self.request('POST', '/teacher-certificates/export', {'certificate_ids': [first['id'], second['id']]}, binary=True)
        self.check(exported.mimetype in ('application/zip', 'application/x-zip-compressed'), 'Bulk certificate export is ZIP')
        archive = zipfile.ZipFile(BytesIO(exported.data))
        expected_names = {first['number'] + '.pdf', second['number'] + '.pdf'}
        self.check(set(archive.namelist()) == expected_names, 'ZIP contains exactly the selected certificates named by unique number')
        for certificate in (first, second):
            content = archive.read(certificate['number'] + '.pdf')
            with fitz.open(stream=content, filetype='pdf') as document:
                compact_text = ''.join(''.join(page.get_text() for page in document).split())
                self.check(''.join(certificate['teacher_name'].split()) in compact_text, 'ZIP PDF has selected teacher content')
        (self.artifacts / 'certificates-selected.zip').write_bytes(exported.data)
        draft = self.create(3)
        self.execute('UPDATE teacher_certificates SET created_by_user_id=1 WHERE id=%s', (draft['id'],))
        self.execute('DELETE FROM auth_sessions WHERE user_id=1')
        self.execute('DELETE FROM auf_users WHERE id=1')
        self.cursor.execute('SELECT created_by_user_id FROM teacher_certificates WHERE id=%s', (draft['id'],))
        self.check(self.cursor.fetchone()['created_by_user_id'] is None, 'Deleting a creator account preserves the certificate with NULL creator')
        for selection, status in (([], 400), ([first['id']] * 101, 400), ([999999], 404),
                                  ([first['id'], draft['id']], 409), ([first['id'], first['id']], 400), ('all', 400)):
            self.request('POST', '/teacher-certificates/export', {'certificate_ids': selection}, status=status)
        self.request('GET', '/public/teacher-certificates/unknown', actor=None, status=404)
        self.execute("UPDATE teachers SET status='fired' WHERE id=3")
        self.request('GET', self.public_path(draft), actor=None, status=404)
        # Optimistic revisions and uniqueness also survive simultaneous requests.
        def concurrent_create(_):
            with self.main.app.test_client() as client:
                response = client.post('/api/teacher-certificates', json={'teacher_id': 4},
                    headers={'Authorization': 'Bearer ' + self.tokens['owner']})
                return response.status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(concurrent_create, range(2)))
        self.check(sorted(statuses) == [200, 409], 'Concurrent creation produces one certificate and one duplicate conflict')
        self.cursor.execute('SELECT COUNT(*) AS count FROM teacher_certificates WHERE teacher_id=4')
        self.check(self.cursor.fetchone()['count'] == 1, 'Concurrent creation preserves the one-certificate-per-teacher invariant')
        parallel_revision = first['revision']
        def concurrent_update(index):
            with self.main.app.test_client() as client:
                response = client.put('/api' + self.private_path(first), json={
                    'revision': parallel_revision, 'description': 'Параллельная правка ' + str(index)},
                    headers={'Authorization': 'Bearer ' + self.tokens['owner']})
                return response.status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(concurrent_update, range(2)))
        self.check(sorted(statuses) == [200, 409], 'Concurrent edits accept one revision and reject the stale writer')
        first = self.request('GET', self.private_path(first))
        self.check(first['revision'] == parallel_revision + 1, 'Concurrent edits increment the revision only once')
        # A missing configuration must not derive a canonical URL from the client.
        with patch.dict(os.environ, {'PUBLIC_CERTIFICATE_BASE_URL': ''}):
            self.request('GET', self.private_path(first, '/pdf'), status=503)
            self.action(second, 'publish', status=503)
        self.first, self.second = first, second

    def cleanup(self, drop_schema=True):
        if hasattr(self, 'stack'):
            self.stack.close()
        if drop_schema:
            self.execute(f'DROP DATABASE IF EXISTS `{self.schema}`')
        self.cursor.close()
        self.connection.close()


def create_demo(arguments):
    """Create a separate persistent, wholly synthetic schema for local browser QA."""
    demo = CertificateQA(arguments.socket, arguments.artifacts, arguments.user, arguments.password)
    try:
        demo.baseline()
        demo.load_app()
        first = demo.create(1, university='Московский технический университет',
            study_program='Прикладная информатика и робототехника',
            description='Я учусь на направлении прикладной информатики и провожу занятия робототехникой. '
                        'Помогаю детям понять, как работают механизмы, придумывать собственные модели '
                        'и уверенно пробовать новые решения. Люблю объяснять сложное через игру и эксперименты.')
        first = demo.upload(first)
        first = demo.action(first, 'publish')
        second = demo.create(2, university='Университет технологий', study_program='Инженерное проектирование',
            description='Изучаю конструирование и программирование. На занятиях мы собираем модели, '
                        'проверяем идеи и учимся работать в команде.')
        second = demo.upload(second, image=image_bytes('WEBP'), filename='portrait.webp')
        second = demo.action(second, 'publish')
        draft = demo.create(3, description='Черновик: фотография и учебное заведение ещё не добавлены.')
        descriptor = {
            'synthetic_only': True, 'database': demo.schema, 'mysql_host': '127.0.0.1',
            'mysql_port': demo.port, 'mysql_socket': demo.socket, 'mysql_user': demo.user,
            'backend_port': 5027, 'frontend_url': 'http://localhost:3027',
            'logins': {key: value for key, value in demo.logins.items() if key in ('owner', 'teacher', 'branch')},
            'password': PASSWORD, 'certificates': [first, second, draft],
            'created_at': datetime.now().isoformat(),
        }
        (demo.artifacts / 'demo.json').write_text(json.dumps(descriptor, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        launcher = '''"""Local certificate demo; explicit synthetic-only loopback configuration."""
import json
import os
from pathlib import Path
import re
import sys
descriptor = json.loads((Path(__file__).parent / 'demo.json').read_text())
assert descriptor['synthetic_only'] is True
assert descriptor['mysql_host'] == '127.0.0.1'
assert re.fullmatch(r'roboman_certificates_qa_[a-f0-9]{32}', descriptor['database'])
os.environ.update(DB_HOST=descriptor['mysql_host'], DB_PORT=str(descriptor['mysql_port']),
    DB_USER=descriptor['mysql_user'], DB_PASSWORD='', DB_NAME=descriptor['database'],
    PUBLIC_CERTIFICATE_BASE_URL=descriptor['frontend_url'])
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'roboman_back-main'))
import main
main.app.run(host='127.0.0.1', port=descriptor['backend_port'], debug=False, use_reloader=False)
'''
        (demo.artifacts / 'run_ui_backend.py').write_text(launcher, encoding='utf-8')
        print('Persistent synthetic browser demo:', demo.schema)
    except BaseException:
        demo.cleanup()
        raise
    else:
        demo.cleanup(drop_schema=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--user', default='root')
    parser.add_argument('--password', default='', help='Isolated local QA credentials only')
    parser.add_argument('--artifacts', default=str(ROOT.parent / 'outputs/certificates-qa'))
    parser.add_argument('--demo', action='store_true', help='After successful verification create a separate synthetic browser demo schema')
    arguments = parser.parse_args()
    qa = CertificateQA(arguments.socket, arguments.artifacts, arguments.user, arguments.password)
    report = {'server_socket': qa.socket, 'schema': qa.schema, 'synthetic_only': True, 'passed': False}
    try:
        qa.baseline()
        qa.load_app()
        qa.run_checks()
        report.update(passed=True, checks=len(qa.checks), migration=qa.migration.name,
                      migration_sha256=hashlib.sha256(qa.migration.read_bytes()).hexdigest(),
                      api_probes=qa.api_probes, mysql_constraint_rejections=qa.constraint_rejections,
                      pdf_documents=qa.pdf_documents, pdf_pages=qa.pdf_pages,
                      pdf_layout_words=qa.pdf_layout_words, qr_decodings=qa.qr_decodings)
        print(f'Passed {qa.api_probes} API probes, {qa.constraint_rejections} MySQL constraint rejections, '
              f'{qa.pdf_documents} PDFs/{qa.pdf_pages} rendered pages and {qa.qr_decodings} QR decodings '
              f'({len(qa.checks)} grouped assertions).')
    except BaseException as error:
        report.update(error=str(error), checks=len(qa.checks))
        raise
    finally:
        qa.cleanup()
        report['schema_removed'] = True
        (qa.artifacts / 'verification-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print('Disposable synthetic schema removed; application databases were not used.')
    if arguments.demo:
        create_demo(arguments)


if __name__ == '__main__':
    main()
