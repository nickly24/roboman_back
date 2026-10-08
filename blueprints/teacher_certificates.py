"""Teacher certificate lifecycle, public profile, photos and genuine PDF exports."""
from __future__ import annotations

import os
import re
import secrets
import warnings
from datetime import datetime
from io import BytesIO
from urllib.parse import urlsplit
from zipfile import ZIP_DEFLATED, ZipFile
from zoneinfo import ZoneInfo

from flask import Blueprint, Response, abort, g, request, send_file, url_for
from mysql.connector import IntegrityError
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.exceptions import HTTPException

from certificate_pdf import qr_png, render_certificate_pdf
from shared import db_cursor, exec_one, fetch_all, fetch_one, require_auth, require_role, _err, _jsonify, _ok

bp = Blueprint('teacher_certificates', __name__)
public_bp = Blueprint('public_teacher_certificates', __name__)
MAX_PHOTO_BYTES = 5 * 1024 * 1024
MAX_PHOTO_PIXELS = 20_000_000
TOKEN_PATTERN = re.compile(r'[A-Za-z0-9_-]{43}')
FIELDS = {'university':250, 'study_program':250, 'description':3000}
SELECT = '''SELECT c.id,c.teacher_id,c.number,c.public_token,c.status,c.university,c.study_program,
    c.description,c.revision,c.issued_at,c.revoked_at,c.created_at,c.updated_at,
    (c.photo_blob IS NOT NULL) AS has_photo,t.full_name AS teacher_name,t.status AS teacher_status
    FROM teacher_certificates c JOIN teachers t ON t.id=c.teacher_id'''


@bp.errorhandler(HTTPException)
@public_bp.errorhandler(HTTPException)
def http_error(error):
    return _err(error.description, status=error.code,
        code='CERTIFICATE_URL_NOT_CONFIGURED' if error.code==503 else None)


@bp.errorhandler(IntegrityError)
def integrity_error(error):
    if error.errno == 1062:
        return _err('У преподавателя уже есть сертификат. Обновите список.', status=409, code='CERTIFICATE_EXISTS')
    return _err('Не удалось сохранить сертификат. Проверьте выбранного преподавателя.', status=400)


@bp.after_request
@public_bp.after_request
def response_headers(response):
    # Revocation must immediately remove both public JSON and previously fetched media.
    response.headers['Cache-Control'] = 'no-store, private, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


def now():
    return datetime.now(ZoneInfo('Europe/Moscow')).replace(tzinfo=None, microsecond=0)


def json_body(allowed):
    data = request.get_json(silent=True)
    if not isinstance(data,dict):
        abort(400, description='Ожидается JSON-объект')
    if set(data)-set(allowed):
        abort(400, description='Запрос содержит неподдерживаемые поля')
    return data


def integer(value, label='Идентификатор'):
    if isinstance(value,bool) or not re.fullmatch(r'[1-9]\d{0,17}',str(value)):
        abort(400, description=f'{label}: укажите положительное целое число')
    return int(value)


def text_fields(data):
    result={}
    for name,limit in FIELDS.items():
        if name in data:
            value=data[name]
            if value is None:
                value=''
            if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 and c not in '\n\r\t' for c in value):
                abort(400, description=f'{name}: текст не более {limit} символов')
            result[name]=value.strip()
    return result


def public_base(required=False):
    raw=os.environ.get('PUBLIC_CERTIFICATE_BASE_URL','').strip().rstrip('/')
    try:
        parts=urlsplit(raw)
        valid=(bool(raw) and len(raw)<=512 and parts.scheme in ('http','https') and bool(parts.hostname)
            and not parts.username and not parts.password and not parts.query and not parts.fragment
            and parts.path in ('','/') and not re.search(r'[\s\\]',raw))
        _=parts.port  # Invalid port strings are configuration errors, too.
    except ValueError:
        valid=False
    if valid:
        return raw
    if required:
        abort(503, description='Не настроен публичный адрес сертификатов. Задайте PUBLIC_CERTIFICATE_BASE_URL.')
    return None


def configured_url(row,required=False):
    base=public_base(required)
    return base+public_path(row) if base else None


def public_path(row):
    return '/certificates/'+row['public_token']


def certificate_row(cur,certificate_id=None,token=None,lock=False,teacher_id=None):
    if token is not None:
        if not TOKEN_PATTERN.fullmatch(token):
            abort(404,description='Сертификат не найден')
        clause,params='c.public_token=%s',(token,)
    elif teacher_id is not None:
        clause,params='c.teacher_id=%s',(teacher_id,)
    else:
        clause,params='c.id=%s',(certificate_id,)
    row=fetch_one(cur,SELECT+' WHERE '+clause+(' FOR UPDATE' if lock else ''),params)
    if not row:
        if teacher_id is not None:
            return None
        abort(404,description='Сертификат не найден')
    if token is None and g.current_user.role=='TEACHER' and row['teacher_id']!=g.current_user.teacher_id:
        abort(404,description='Сертификат не найден')
    return row


def branches_for(cur,teacher_ids):
    if not teacher_ids:
        return {}
    placeholders=','.join(['%s']*len(teacher_ids))
    rows=fetch_all(cur,f'''SELECT bt.teacher_id,b.name,b.address FROM branch_teachers bt
        JOIN branches b ON b.id=bt.branch_id WHERE bt.teacher_id IN ({placeholders}) AND b.is_active=1
        ORDER BY b.name,b.id''',tuple(teacher_ids))
    grouped={}
    for branch in rows:
        grouped.setdefault(branch['teacher_id'],[]).append({'name':branch['name'],'address':branch['address']})
    return grouped


def is_valid(row):
    return (row['status']=='published' and row['teacher_status']!='fired' and bool(row['has_photo'])
        and bool(str(row['teacher_name'] or '').strip()) and bool(row['description'].strip()))


def profile(cur,row,public=False,branches=None):
    if branches is None:
        branches=branches_for(cur,[row['teacher_id']]).get(row['teacher_id'],[])
    media_endpoint='public_teacher_certificates' if public else 'teacher_certificates'
    media_args={'token':row['public_token']} if public else {'certificate_id':row['id']}
    issued_at=row['issued_at']
    if isinstance(issued_at,datetime):
        issued_at=issued_at.replace(tzinfo=ZoneInfo('Europe/Moscow')).isoformat()
    result={
        'teacher_name':row['teacher_name'],'number':row['number'],'status':row['status'],
        'university':row['university'],'study_program':row['study_program'],'description':row['description'],
        'has_photo':bool(row['has_photo']),'photo_url':url_for(media_endpoint+'.photo',**media_args) if row['has_photo'] else None,
        'qr_url':url_for(media_endpoint+'.qr',**media_args), 'public_url':configured_url(row),
        'public_path':public_path(row),'issued_at':issued_at,'branches':branches,
    }
    if not public:
        result.update(id=row['id'],teacher_id=row['teacher_id'],public_token=row['public_token'],
            teacher_status=row['teacher_status'],revision=row['revision'],
            effective_status='revoked' if row['teacher_status']=='fired' or (row['status']=='published' and not is_valid(row)) else row['status'],
            is_valid=is_valid(row),created_at=row['created_at'],updated_at=row['updated_at'])
    return result


def check_revision(row,value):
    revision=integer(value,'Версия сертификата')
    if row['revision']!=revision:
        return _err('Сертификат уже изменился. Обновите данные и повторите действие.',status=409,code='REVISION_CONFLICT')
    return None


def ensure_publishable(row,values=None,allow_fired=False):
    data=dict(row,**(values or {}))
    if data['teacher_status']=='fired' and not allow_fired:
        abort(409,description='Уволенному преподавателю нельзя выдать действующий сертификат')
    if not str(data['teacher_name'] or '').strip() or not data['has_photo'] or not data['description'].strip():
        abort(400,description='Для публикации нужны имя, фотография и описание преподавателя')


def require_valid_pdf(row):
    if not is_valid(row):
        abort(409,description='PDF доступен только для опубликованного сертификата действующего преподавателя')
    public_base(required=True)


def public_validity(row):
    if row['status']=='draft':
        abort(404,description='Сертификат не найден')
    if row['teacher_status']=='fired' or row['status']=='revoked' or (row['status']=='published' and not is_valid(row)):
        return _jsonify({'ok':False,'error':{'message':'Сертификат недействителен','code':'CERTIFICATE_INVALID'},
            'data':{'number':row['number'],'status':'revoked'}},status=410)
    return None


def read_photo(cur,row):
    photo=fetch_one(cur,'SELECT photo_blob FROM teacher_certificates WHERE id=%s',(row['id'],))
    if not photo or not photo['photo_blob']:
        abort(404,description='Фотография не найдена')
    return bytes(photo['photo_blob'])


def normalize_photo(upload):
    content=upload.read(MAX_PHOTO_BYTES+1)
    if not content:
        abort(400,description='Выберите фотографию')
    if len(content)>MAX_PHOTO_BYTES:
        abort(413,description='Фотография должна быть не больше 5 МБ')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error',Image.DecompressionBombWarning)
            with Image.open(BytesIO(content)) as source:
                if source.format not in ('JPEG','PNG','WEBP') or getattr(source,'n_frames',1)!=1:
                    raise ValueError('format')
                if source.width*source.height>MAX_PHOTO_PIXELS:
                    raise ValueError('pixels')
                source.verify()
            with Image.open(BytesIO(content)) as source:
                image=ImageOps.exif_transpose(source)
                image.thumbnail((1200,1200),Image.Resampling.LANCZOS)
                if image.mode in ('RGBA','LA') or (image.mode=='P' and 'transparency' in image.info):
                    rgba=image.convert('RGBA')
                    background=Image.new('RGB',image.size,'white')
                    background.paste(rgba,mask=rgba.getchannel('A'))
                    image=background
                else:
                    image=image.convert('RGB')
                result=BytesIO()
                image.save(result,format='JPEG',quality=90,optimize=True)
                return result.getvalue()
    except (UnidentifiedImageError,OSError,ValueError,Image.DecompressionBombError,Image.DecompressionBombWarning):
        abort(400,description='Нужна корректная фотография JPEG, PNG или WebP, до 20 миллионов пикселей')


@bp.get('')
@require_auth
@require_role('OWNER')
def listing():
    q=request.args.get('q','').strip()
    status=request.args.get('status','')
    if len(q)>250 or status not in ('','draft','published','revoked'):
        abort(400,description='Некорректные фильтры сертификатов')
    limit=integer(request.args.get('limit','100'),'Размер списка')
    if limit>200:
        abort(400,description='Размер списка не более 200')
    raw_offset=request.args.get('offset','0')
    if not re.fullmatch(r'\d{1,9}',raw_offset):
        abort(400,description='Некорректное смещение списка')
    offset=int(raw_offset)
    where,params=['1=1'],[]
    if status:
        where.append('c.status=%s'); params.append(status)
    if q:
        where.append('(t.full_name LIKE %s OR c.number LIKE %s)');params.extend(['%'+q+'%','%'+q+'%'])
    clause=' WHERE '+' AND '.join(where)
    with db_cursor() as (_,cur):
        total=fetch_one(cur,'SELECT COUNT(*) AS total FROM teacher_certificates c JOIN teachers t ON t.id=c.teacher_id'+clause,tuple(params))['total']
        rows=fetch_all(cur,SELECT+clause+' ORDER BY c.id DESC LIMIT %s OFFSET %s',tuple(params+[limit,offset]))
        assignments=branches_for(cur,[row['teacher_id'] for row in rows])
        items=[profile(cur,row,branches=assignments.get(row['teacher_id'],[])) for row in rows]
    return _ok({'items':items,'total':total,'limit':limit,'offset':offset})


@bp.post('')
@require_auth
@require_role('OWNER')
def create():
    data=json_body({'teacher_id',*FIELDS})
    teacher_id=integer(data.get('teacher_id'),'Преподаватель')
    values={'university':'','study_program':'','description':'',**text_fields(data)}
    token=secrets.token_urlsafe(32)
    number=f'RM-{now().year}-{secrets.token_hex(6).upper()}'
    with db_cursor() as (_,cur):
        if not fetch_one(cur,'SELECT id FROM teachers WHERE id=%s',(teacher_id,)):
            abort(404,description='Преподаватель не найден')
        existing=fetch_one(cur,'SELECT id FROM teacher_certificates WHERE teacher_id=%s',(teacher_id,))
        if existing:
            return _err('У преподавателя уже есть сертификат.',status=409,code='CERTIFICATE_EXISTS',details={'certificate_id':existing['id']})
        certificate_id=exec_one(cur,'''INSERT INTO teacher_certificates(teacher_id,number,public_token,
            university,study_program,description,created_by_user_id) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
            (teacher_id,number,token,values['university'],values['study_program'],values['description'],g.current_user.id))
        result=profile(cur,certificate_row(cur,certificate_id))
    return _ok(result)


@bp.get('/me')
@require_auth
@require_role('TEACHER')
def mine():
    with db_cursor() as (_,cur):
        row=certificate_row(cur,teacher_id=g.current_user.teacher_id or 0)
        result=profile(cur,row) if row else None
    return _ok(result)


@bp.get('/<int:certificate_id>')
@require_auth
@require_role('OWNER','TEACHER')
def detail(certificate_id):
    with db_cursor() as (_,cur):
        result=profile(cur,certificate_row(cur,certificate_id))
    return _ok(result)


@bp.put('/<int:certificate_id>')
@require_auth
@require_role('OWNER')
def update(certificate_id):
    data=json_body({'revision',*FIELDS})
    values=text_fields(data)
    if not values:
        abort(400,description='Нет полей для сохранения')
    with db_cursor() as (_,cur):
        row=certificate_row(cur,certificate_id,lock=True)
        conflict=check_revision(row,data.get('revision'))
        if conflict:return conflict
        if row['status']=='published':ensure_publishable(row,values,allow_fired=True)
        fields=','.join(name+'=%s' for name in values)
        cur.execute('UPDATE teacher_certificates SET '+fields+',revision=revision+1 WHERE id=%s',tuple(values.values())+(certificate_id,))
        result=profile(cur,certificate_row(cur,certificate_id))
    return _ok(result)


@bp.post('/<int:certificate_id>/publish')
@require_auth
@require_role('OWNER')
def publish(certificate_id):
    data=json_body({'revision'})
    with db_cursor() as (_,cur):
        row=certificate_row(cur,certificate_id,lock=True)
        conflict=check_revision(row,data.get('revision'))
        if conflict:return conflict
        ensure_publishable(row)
        public_base(required=True)
        if row['status']=='published':
            return _err('Сертификат уже опубликован.',status=409,code='CERTIFICATE_ALREADY_PUBLISHED')
        cur.execute("UPDATE teacher_certificates SET status='published',issued_at=COALESCE(issued_at,%s),revoked_at=NULL,revision=revision+1 WHERE id=%s",(now(),certificate_id))
        result=profile(cur,certificate_row(cur,certificate_id))
    return _ok(result)


@bp.post('/<int:certificate_id>/revoke')
@require_auth
@require_role('OWNER')
def revoke(certificate_id):
    data=json_body({'revision'})
    with db_cursor() as (_,cur):
        row=certificate_row(cur,certificate_id,lock=True)
        conflict=check_revision(row,data.get('revision'))
        if conflict:return conflict
        if row['status']!='published':
            return _err('Отозвать можно только опубликованный сертификат.',status=409,code='CERTIFICATE_NOT_PUBLISHED')
        cur.execute("UPDATE teacher_certificates SET status='revoked',revoked_at=%s,revision=revision+1 WHERE id=%s",(now(),certificate_id))
        result=profile(cur,certificate_row(cur,certificate_id))
    return _ok(result)


@bp.route('/<int:certificate_id>/photo',methods=['PUT','DELETE'])
@require_auth
@require_role('OWNER')
def change_photo(certificate_id):
    if request.method=='PUT':
        upload=request.files.get('photo')
        if upload is None:abort(400,description='Выберите фотографию')
        value=request.form.get('revision')
        photo_bytes=normalize_photo(upload)
    else:
        data=json_body({'revision'})
        value=data.get('revision')
        photo_bytes=None
    with db_cursor() as (_,cur):
        row=certificate_row(cur,certificate_id,lock=True)
        conflict=check_revision(row,value)
        if conflict:return conflict
        if photo_bytes is None and row['status']=='published':
            abort(409,description='Сначала отзовите сертификат, чтобы удалить обязательную фотографию')
        cur.execute('UPDATE teacher_certificates SET photo_blob=%s,photo_mime=%s,photo_filename=%s,revision=revision+1 WHERE id=%s',
            (photo_bytes,'image/jpeg' if photo_bytes else None,'certificate-photo.jpg' if photo_bytes else None,certificate_id))
        result=profile(cur,certificate_row(cur,certificate_id))
    return _ok(result)


@bp.get('/<int:certificate_id>/photo')
@require_auth
@require_role('OWNER','TEACHER')
def photo(certificate_id):
    with db_cursor() as (_,cur):
        row=certificate_row(cur,certificate_id)
        content=read_photo(cur,row)
    return Response(content,mimetype='image/jpeg')


@bp.get('/<int:certificate_id>/qr')
@require_auth
@require_role('OWNER','TEACHER')
def qr(certificate_id):
    with db_cursor() as (_,cur):
        row=certificate_row(cur,certificate_id)
        address=configured_url(row,required=True)
    return Response(qr_png(address),mimetype='image/png')


def pdf_data(cur,row):
    require_valid_pdf(row)
    return profile(cur,row,public=True),read_photo(cur,row)


def pdf_response(profile_data,photo_bytes):
    return send_file(BytesIO(render_certificate_pdf(profile_data,photo_bytes)),mimetype='application/pdf',
        as_attachment=True,download_name=profile_data['number']+'.pdf',max_age=0)


@bp.get('/<int:certificate_id>/pdf')
@require_auth
@require_role('OWNER','TEACHER')
def pdf(certificate_id):
    with db_cursor() as (_,cur):
        payload,content=pdf_data(cur,certificate_row(cur,certificate_id))
    return pdf_response(payload,content)


@bp.get('/me/pdf')
@require_auth
@require_role('TEACHER')
def my_pdf():
    with db_cursor() as (_,cur):
        row=certificate_row(cur,teacher_id=g.current_user.teacher_id or 0)
        if row is None:abort(404,description='Сертификат ещё не создан')
        payload,content=pdf_data(cur,row)
    return pdf_response(payload,content)


@bp.post('/export')
@require_auth
@require_role('OWNER')
def export():
    data=json_body({'certificate_ids'})
    ids=data.get('certificate_ids')
    if not isinstance(ids,list) or not 1<=len(ids)<=100:
        abort(400,description='Выберите от 1 до 100 сертификатов')
    ids=[integer(value,'Сертификат') for value in ids]
    if len(ids)!=len(set(ids)):
        abort(400,description='Сертификаты в выгрузке не должны повторяться')
    # Validate every document before rendering any; errors never return a partial archive.
    with db_cursor() as (_,cur):
        rows=[certificate_row(cur,certificate_id) for certificate_id in ids]
        for row in rows:require_valid_pdf(row)
        payloads=[pdf_data(cur,row) for row in rows]
    output=BytesIO()
    with ZipFile(output,'w',compression=ZIP_DEFLATED) as archive:
        for payload,content in payloads:
            archive.writestr(payload['number']+'.pdf',render_certificate_pdf(payload,content))
    output.seek(0)
    return send_file(output,mimetype='application/zip',as_attachment=True,
        download_name='IT-Club-certificates.zip',max_age=0)


@public_bp.get('/<token>')
def public_detail(token):
    with db_cursor() as (_,cur):
        row=certificate_row(cur,token=token)
        invalid=public_validity(row)
        if invalid:return invalid
        result=profile(cur,row,public=True)
    return _ok(result)


@public_bp.get('/<token>/photo')
def photo(token):
    with db_cursor() as (_,cur):
        row=certificate_row(cur,token=token)
        invalid=public_validity(row)
        if invalid:return invalid
        content=read_photo(cur,row)
    return Response(content,mimetype='image/jpeg')


@public_bp.get('/<token>/qr')
def qr(token):
    with db_cursor() as (_,cur):
        row=certificate_row(cur,token=token)
        invalid=public_validity(row)
        if invalid:return invalid
        address=configured_url(row,required=True)
    return Response(qr_png(address),mimetype='image/png')
