"""Certificate HTTP invariants and real PDF rendering, using temporary local SQLite only."""
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from io import BytesIO
from unittest.mock import patch
from zipfile import ZipFile

import pymupdf
from flask import request
from PIL import Image

import main
from blueprints import teacher_certificates as certificates
from shared import CurrentUser

SCHEMA = '''
CREATE TABLE teachers(id INTEGER PRIMARY KEY,full_name TEXT,status TEXT);
CREATE TABLE branches(id INTEGER PRIMARY KEY,name TEXT,address TEXT,is_active INTEGER);
CREATE TABLE branch_teachers(branch_id INTEGER,teacher_id INTEGER);
CREATE TABLE teacher_certificates(
 id INTEGER PRIMARY KEY AUTOINCREMENT,teacher_id INTEGER NOT NULL UNIQUE REFERENCES teachers(id) ON DELETE RESTRICT,
 number TEXT NOT NULL UNIQUE,public_token TEXT NOT NULL UNIQUE,status TEXT NOT NULL DEFAULT 'draft',
 university TEXT NOT NULL DEFAULT '',study_program TEXT NOT NULL DEFAULT '',description TEXT NOT NULL,
 photo_blob BLOB,photo_mime TEXT,photo_filename TEXT,revision INTEGER NOT NULL DEFAULT 1,
 issued_at TIMESTAMP,revoked_at TIMESTAMP,created_by_user_id INTEGER,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
INSERT INTO teachers VALUES(1,'Анна Иванова','working'),(2,'Борис Петров','working'),(3,'Без сертификата','working');
INSERT INTO branches VALUES(1,'Ромашка','Москва, улица Первая, 1',1),(2,'Закрытый сад','Не показывать',0);
INSERT INTO branch_teachers VALUES(1,1),(2,1);
'''


class Cursor:
    def __init__(self,db):self.cursor=db.cursor()
    def execute(self,sql,params=()):self.cursor.execute(sql.replace('%s','?').replace(' FOR UPDATE',''),params)
    def fetchone(self):
        value=self.cursor.fetchone()
        return dict(value) if value else None
    def fetchall(self):return [dict(row) for row in self.cursor.fetchall()]
    @property
    def lastrowid(self):return self.cursor.lastrowid


class TeacherCertificateTests(unittest.TestCase):
    def setUp(self):
        handle,self.path=tempfile.mkstemp(suffix='.sqlite')
        os.close(handle)
        with sqlite3.connect(self.path) as db:db.executescript(SCHEMA)
        self.client=main.app.test_client()
        self.patches=[patch.object(certificates,'db_cursor',self.database),
            patch('shared.get_current_user',self.current_user),
            patch.dict(os.environ,{'PUBLIC_CERTIFICATE_BASE_URL':'https://certificates.example'})]
        for p in self.patches:p.start()

    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        os.unlink(self.path)

    @contextmanager
    def database(self):
        db=sqlite3.connect(self.path,timeout=10,detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory=sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db,Cursor(db)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:db.close()

    def current_user(self):
        who=request.headers.get('X-Test-User','owner')
        if who=='branch':return CurrentUser(4,'BRANCH',None,None,'branch',1)
        if who.startswith('teacher'):
            teacher_id=int(who.removeprefix('teacher'))
            return CurrentUser(10+teacher_id,'TEACHER',None,teacher_id,who)
        return CurrentUser(1 if who=='owner' else 2,'OWNER',1 if who=='owner' else 2,None,who)

    def call(self,method,path,data=None,user='owner',code=200,headers=None,client=None):
        result=(client or self.client).open('/api'+path,method=method,json=data,
            headers={'X-Test-User':user,**(headers or {})})
        self.addCleanup(result.close)
        self.assertEqual(result.status_code,code,result.get_data(as_text=True)[:1500] if result.is_json else result.status)
        return result

    def json(self,method,path,data=None,user='owner',code=200):
        return self.call(method,path,data,user,code).get_json().get('data')

    def draft(self,teacher_id=1,**values):
        return self.json('POST','/teacher-certificates',dict(teacher_id=teacher_id,**values))

    def upload(self,row,content=None,filename='photo.png',code=200):
        if content is None:
            output=BytesIO()
            image=Image.new('RGBA',(320,440),(90,140,170,200))
            image.save(output,format='PNG',pnginfo=None)
            content=output.getvalue()
        result=self.client.put(f"/api/teacher-certificates/{row['id']}/photo",
            data={'revision':str(row['revision']),'photo':(BytesIO(content),filename)},content_type='multipart/form-data')
        self.addCleanup(result.close)
        self.addCleanup(result.request.environ['wsgi.input'].close)
        self.assertEqual(result.status_code,code,result.get_json())
        return result.get_json().get('data')

    def issued(self,teacher_id=1,**values):
        row=self.upload(self.draft(teacher_id,description='Ведёт занятия по робототехнике.',**values))
        return self.json('POST',f"/teacher-certificates/{row['id']}/publish",{'revision':row['revision']})

    def action(self,row,action,**values):
        return self.json('POST',f"/teacher-certificates/{row['id']}/{action}",{'revision':row['revision'],**values})

    def test_lifecycle_constants_revision_and_current_assignments(self):
        row=self.issued(university='МГУ',study_program='Информатика')
        identity=(row['number'],row['public_token'],row['issued_at'],row['public_url'])
        self.assertRegex(row['number'],r'^RM-20\d{2}-[A-F0-9]{12}$')
        self.assertEqual(row['public_url'],'https://certificates.example'+row['public_path'])
        self.assertEqual(row['branches'],[{'name':'Ромашка','address':'Москва, улица Первая, 1'}])
        self.json('PUT',f"/teacher-certificates/{row['id']}",{'revision':1,'description':'Старая правка'},code=409)
        row=self.json('PUT',f"/teacher-certificates/{row['id']}",{'revision':row['revision'],'description':'Новое описание'})
        with self.database() as (_,cur):
            cur.execute("UPDATE teachers SET full_name='Анна Новая' WHERE id=1")
            cur.execute('UPDATE branches SET is_active=0 WHERE id=1')
            cur.execute('UPDATE branches SET is_active=1 WHERE id=2')
        visible=self.json('GET','/public/teacher-certificates/'+row['public_token'])
        self.assertEqual(visible['teacher_name'],'Анна Новая')
        self.assertEqual(visible['branches'],[{'name':'Закрытый сад','address':'Не показывать'}])
        row=self.action(row,'revoke')
        for suffix in ('','/photo','/qr'):
            response=self.call('GET','/public/teacher-certificates/'+row['public_token']+suffix,code=410)
            self.assertEqual(response.get_json()['data'],{'number':row['number'],'status':'revoked'})
            self.assertNotIn('Анна',response.get_data(as_text=True))
            self.assertIn('no-store',response.headers['Cache-Control'])
        self.json('GET',f"/teacher-certificates/{row['id']}/pdf",code=409)
        row=self.action(row,'publish')
        self.assertEqual(identity,(row['number'],row['public_token'],row['issued_at'],row['public_url']))

    def test_public_never_reads_auth_or_leaks_internal_projection(self):
        row=self.issued()
        with patch('shared.get_current_user',side_effect=AssertionError('public auth lookup')):
            response=self.call('GET','/public/teacher-certificates/'+row['public_token'],
                headers={'Authorization':'Bearer expired-session'})
        data=response.get_json()['data']
        self.assertEqual(set(data),{'teacher_name','number','status','university','study_program','description',
            'has_photo','photo_url','qr_url','public_url','public_path','issued_at','branches'})
        self.assertNotIn('id',data['branches'][0])
        self.json('GET','/public/teacher-certificates/RM-2026-000001',code=404)
        self.json('GET','/public/teacher-certificates/'+'x'*43,code=404)

    def test_roles_teacher_own_media_and_absent_certificate(self):
        row=self.issued()
        second=self.upload(self.draft(2,description='Описание второго преподавателя'))
        self.assertIsNone(self.json('GET','/teacher-certificates/me',user='teacher3'))
        self.assertEqual(self.json('GET','/teacher-certificates/me',user='teacher1')['id'],row['id'])
        self.assertEqual(self.json('GET','/teacher-certificates/me',user='teacher2')['status'],'draft')
        for suffix in ('','/photo','/qr','/pdf'):
            self.call('GET',f"/teacher-certificates/{row['id']}"+suffix,user='teacher2',code=404)
        self.call('GET',f"/teacher-certificates/{second['id']}/photo",user='teacher2')
        self.call('GET',f"/teacher-certificates/{second['id']}/qr",user='teacher2')
        self.call('GET','/teacher-certificates/me/pdf',user='teacher2',code=409)
        self.call('GET','/teacher-certificates/me/pdf',user='teacher3',code=404)
        self.call('GET','/teacher-certificates/me/pdf',user='teacher1')
        for user in ('teacher1','branch'):
            self.call('POST','/teacher-certificates',{'teacher_id':3},user=user,code=403)
            self.call('GET','/teacher-certificates',user=user,code=403)
            self.call('POST','/teacher-certificates/export',{'certificate_ids':[row['id']]},user=user,code=403)
            self.call('POST',f"/teacher-certificates/{row['id']}/revoke",{'revision':row['revision']},user=user,code=403)
        # OWNER certificates match the existing global teacher-management model.
        self.call('GET',f"/teacher-certificates/{row['id']}",user='owner2')

    def test_mandatory_publication_fields_duplicate_and_protected_fields(self):
        row=self.draft()
        response=self.call('POST','/teacher-certificates',{'teacher_id':1},code=409)
        self.assertEqual(response.get_json()['error']['code'],'CERTIFICATE_EXISTS')
        self.call('POST',f"/teacher-certificates/{row['id']}/publish",{'revision':1},code=400)
        row=self.upload(row)
        self.call('POST',f"/teacher-certificates/{row['id']}/publish",{'revision':row['revision']},code=400)
        row=self.json('PUT',f"/teacher-certificates/{row['id']}",{'revision':row['revision'],'description':'Описание'})
        row=self.action(row,'publish')
        self.call('PUT',f"/teacher-certificates/{row['id']}",{'revision':row['revision'],'description':'  '},code=400)
        self.call('DELETE',f"/teacher-certificates/{row['id']}/photo",{'revision':row['revision']},code=409)
        self.call('PUT',f"/teacher-certificates/{row['id']}",{'revision':row['revision'],'teacher_id':2},code=400)
        self.call('PUT',f"/teacher-certificates/{row['id']}",{'revision':row['revision'],'status':'draft'},code=400)
        self.call('POST',f"/teacher-certificates/{row['id']}/publish",{'revision':row['revision']},code=409)
        row=self.action(row,'revoke')
        row=self.json('DELETE',f"/teacher-certificates/{row['id']}/photo",{'revision':row['revision']})
        self.assertFalse(row['has_photo'])
        self.call('POST',f"/teacher-certificates/{row['id']}/publish",{'revision':row['revision']},code=400)

    def test_fired_vacation_and_missing_name_effective_validity(self):
        row=self.issued()
        with self.database() as (_,cur):cur.execute("UPDATE teachers SET status='vacation' WHERE id=1")
        self.call('GET','/public/teacher-certificates/'+row['public_token'])
        with self.database() as (_,cur):cur.execute("UPDATE teachers SET status='fired' WHERE id=1")
        own=self.json('GET','/teacher-certificates/me',user='teacher1')
        self.assertFalse(own['is_valid'])
        self.assertEqual(own['effective_status'],'revoked')
        for suffix in ('','/photo','/qr'):
            self.call('GET','/public/teacher-certificates/'+row['public_token']+suffix,code=410)
        self.call('GET','/teacher-certificates/me/pdf',user='teacher1',code=409)
        draft=self.draft(2)
        with self.database() as (_,cur):cur.execute("UPDATE teachers SET status='fired' WHERE id=2")
        for suffix in ('','/photo','/qr'):
            self.call('GET','/public/teacher-certificates/'+draft['public_token']+suffix,code=404)
        with self.database() as (_,cur):cur.execute("UPDATE teachers SET status='working',full_name='' WHERE id=1")
        self.call('GET','/public/teacher-certificates/'+row['public_token'],code=410)
        self.call('GET',f"/teacher-certificates/{row['id']}/pdf",code=409)

    def test_photo_validation_normalization_and_stale_upload(self):
        row=self.draft()
        self.upload(row,b'<svg xmlns="http://www.w3.org/2000/svg"></svg>',code=400)
        self.upload(row,b'<html>fake</html>',filename='photo.jpg',code=400)
        self.upload(row,b'x'*(certificates.MAX_PHOTO_BYTES+1),code=413)
        valid=self.upload(row)
        self.upload(row,code=409)
        response=self.call('GET',f"/teacher-certificates/{valid['id']}/photo")
        self.assertEqual(response.mimetype,'image/jpeg')
        with Image.open(BytesIO(response.data)) as image:
            self.assertEqual(image.mode,'RGB')
            self.assertFalse(image.getexif())
        with patch.object(certificates,'MAX_PHOTO_PIXELS',100):self.upload(valid,code=400)

    def test_configuration_must_be_explicit_not_host_or_origin(self):
        row=self.upload(self.draft(description='Описание'))
        for value in ('','javascript:alert(1)','https://name:password@example.com','https://example.com/path?query=1',
            'https://example.com/#fragment','https://example.com:invalid','https://example.com/../path','https://example.com/app'):
            with patch.dict(os.environ,{'PUBLIC_CERTIFICATE_BASE_URL':value}):
                response=self.call('POST',f"/teacher-certificates/{row['id']}/publish",{'revision':row['revision']},code=503,
                    headers={'Host':'attacker.test','Origin':'https://attacker.test'})
                self.assertEqual(response.get_json()['error']['code'],'CERTIFICATE_URL_NOT_CONFIGURED')
        row=self.action(row,'publish')
        with patch.object(certificates,'qr_png',return_value=b'PNG') as renderer:
            self.call('GET','/public/teacher-certificates/'+row['public_token']+'/qr',
                headers={'Host':'attacker.test','Origin':'https://attacker.test'})
            renderer.assert_called_once_with('https://certificates.example'+row['public_path'])
        with patch.dict(os.environ,{'PUBLIC_CERTIFICATE_BASE_URL':''}):
            self.call('GET',f"/teacher-certificates/{row['id']}/pdf",code=503)

    def test_input_types_lengths_search_and_export_atomicity(self):
        for value in (None,False,0,'1.2',[],{}):
            self.call('POST','/teacher-certificates',{'teacher_id':value},code=400)
        self.call('POST','/teacher-certificates',[],code=400)
        for key,value in (('description','x'*3001),('university','x'*251),('study_program',False)):
            self.call('POST','/teacher-certificates',{'teacher_id':1,key:value},code=400)
        row=self.issued()
        draft=self.draft(2)
        response=self.json('GET','/teacher-certificates?q='+row['number']+'&status=published')
        self.assertEqual([x['id'] for x in response['items']],[row['id']])
        for query in ('status=bad','limit=201','offset=-1'):
            self.call('GET','/teacher-certificates?'+query,code=400)
        for ids in ([],[row['id']]*101,[row['id'],row['id']],[True]):
            self.call('POST','/teacher-certificates/export',{'certificate_ids':ids},code=400)
        self.call('POST','/teacher-certificates/export',{'certificate_ids':[row['id'],draft['id']]},code=409)
        self.call('POST','/teacher-certificates/export',{'certificate_ids':[row['id'],99999]},code=404)

    def test_pdf_cyrillic_escaping_multi_page_and_zip(self):
        row=self.issued(university='МГУ <xml> & текст',study_program='Прикладная информатика')
        long_text=('Опыт преподавателя и робототехника. '*80)+' КОНЕЦ ОПИСАНИЯ'
        row=self.json('PUT',f"/teacher-certificates/{row['id']}",{'revision':row['revision'],'description':long_text})
        with self.database() as (_,cur):
            for index in range(3,68):
                cur.execute('INSERT INTO branches VALUES(%s,%s,%s,1)',(index,f'Сад {index:03d}','Адрес для проверяемого переноса на следующую страницу'))
                cur.execute('INSERT INTO branch_teachers VALUES(%s,1)',(index,))
        response=self.call('GET',f"/teacher-certificates/{row['id']}/pdf")
        self.assertTrue(response.data.startswith(b'%PDF-'))
        self.assertEqual(response.mimetype,'application/pdf')
        with pymupdf.open(stream=response.data,filetype='pdf') as pdf:
            self.assertGreater(len(pdf),1)
            text=''.join(page.get_text() for page in pdf)
            self.assertIn('Анна Иванова',text)
            self.assertIn('МГУ <xml> & текст',text)
            self.assertIn('КОНЕЦ ОПИСАНИЯ',text)
            self.assertIn('Сад 067',text)
            self.assertTrue(any(link.get('uri')==row['public_url'] for page in pdf for link in page.get_links()))
            self.assertGreaterEqual(len(pdf[0].get_images()),2)
        second=self.issued(2)
        archive=self.call('POST','/teacher-certificates/export',{'certificate_ids':[row['id'],second['id']]})
        with ZipFile(BytesIO(archive.data)) as zip_file:
            self.assertEqual(set(zip_file.namelist()),{row['number']+'.pdf',second['number']+'.pdf'})
            for name in zip_file.namelist():self.assertTrue(zip_file.read(name).startswith(b'%PDF-'))

    def test_typical_profile_with_two_gardens_fits_one_pdf_page(self):
        row=self.issued(university='Московский технический университет',
            study_program='Прикладная информатика и робототехника')
        description=('Помогаю детям собирать роботов и объясняю работу механизмов через игру и эксперименты. '*6)[:500]
        row=self.json('PUT',f"/teacher-certificates/{row['id']}",{'revision':row['revision'],'description':description})
        with self.database() as (_,cur):
            cur.execute("UPDATE teachers SET full_name='Анна Сергеевна Примерова' WHERE id=1")
            cur.execute("UPDATE branches SET is_active=1,name='Сад «Техноград»',address='Москва, учебная улица, 2' WHERE id=2")
        response=self.call('GET',f"/teacher-certificates/{row['id']}/pdf")
        with pymupdf.open(stream=response.data,filetype='pdf') as pdf:
            self.assertEqual(len(pdf),1)
            text=pdf[0].get_text()
            self.assertIn('Анна Сергеевна',text)
            self.assertIn('Примерова',text)
            self.assertIn('Сад «Техноград»',text)
            self.assertIn('Сертификат подтверждает профиль преподавателя в IT Club.',text)
            self.assertGreaterEqual(len(pdf[0].get_images()),2)

    def test_concurrent_edits_do_not_overwrite(self):
        row=self.draft(description='Исходный текст')
        def write(description):
            with main.app.test_client() as client:
                return client.put(f"/api/teacher-certificates/{row['id']}",json={'revision':row['revision'],'description':description}).status_code
        with ThreadPoolExecutor(max_workers=2) as workers:
            statuses=list(workers.map(write,['Первый текст','Второй текст']))
        self.assertEqual(sorted(statuses),[200,409])
        self.assertEqual(self.json('GET',f"/teacher-certificates/{row['id']}")['revision'],2)


if __name__=='__main__':unittest.main()
