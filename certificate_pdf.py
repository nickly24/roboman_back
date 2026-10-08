"""Portable PDF/QR renderer for the same current profile as the public page."""
from __future__ import annotations

from datetime import datetime
from html import escape
from io import BytesIO
from pathlib import Path
from threading import Lock

import qrcode
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import CondPageBreak, Image, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

_FONT_LOCK = Lock()
_FONTS_READY = False
GREEN = colors.HexColor('#145b49')
MUTED = colors.HexColor('#5a7067')


def qr_png(public_url: str) -> bytes:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    qr.add_data(public_url)
    qr.make(fit=True)
    output = BytesIO()
    qr.make_image(fill_color='black', back_color='white').save(output, format='PNG')
    return output.getvalue()


def _register_fonts():
    global _FONTS_READY
    with _FONT_LOCK:
        if not _FONTS_READY:
            folder = Path(__file__).resolve().parent / 'assets' / 'fonts'
            pdfmetrics.registerFont(TTFont('CertificateSans', str(folder / 'LiberationSans-Regular.ttf')))
            pdfmetrics.registerFont(TTFont('CertificateSansBold', str(folder / 'LiberationSans-Bold.ttf')))
            pdfmetrics.registerFontFamily('CertificateSans', normal='CertificateSans', bold='CertificateSansBold')
            _FONTS_READY = True


def _markup(value):
    # Paragraph is an XML parser: user text must never become document markup.
    return escape(str(value or '')).replace('\r\n', '\n').replace('\r', '\n').replace('\n', '<br/>')


def _issued_date(value):
    if isinstance(value, datetime):
        return value.strftime('%d.%m.%Y')
    try:
        return datetime.fromisoformat(str(value)).strftime('%d.%m.%Y')
    except (ValueError, TypeError):
        return str(value or '')


def render_certificate_pdf(profile: dict, photo: bytes) -> bytes:
    """Allow long paragraphs and lists to split across pages instead of clipping."""
    _register_fonts()
    output = BytesIO()
    document = SimpleDocTemplate(output, pagesize=A4, rightMargin=22*mm, leftMargin=22*mm,
        topMargin=28*mm, bottomMargin=24*mm, title=f"Сертификат {profile['number']}", author='IT Club')
    body = ParagraphStyle('body', fontName='CertificateSans', fontSize=10.5, leading=15,
        textColor=colors.HexColor('#253e34'), spaceAfter=6, splitLongWords=True)
    label = ParagraphStyle('label', parent=body, fontName='CertificateSansBold', fontSize=10,
        textColor=GREEN, spaceBefore=8, spaceAfter=6, keepWithNext=True)
    bio_label = ParagraphStyle('bio_label', parent=label, keepWithNext=False)
    small = ParagraphStyle('small', parent=body, fontSize=8.5, leading=12, textColor=MUTED)
    title = ParagraphStyle('title', parent=body, fontName='CertificateSansBold', fontSize=24,
        leading=29, textColor=GREEN, spaceAfter=12)
    name = ParagraphStyle('name', parent=body, fontName='CertificateSansBold', fontSize=20,
        leading=26, spaceAfter=12)
    badge = ParagraphStyle('badge', parent=small, textColor=GREEN)
    center = ParagraphStyle('center', parent=small, alignment=TA_CENTER)

    def page_frame(canvas, doc):
        canvas.saveState()
        width, height = A4
        canvas.setFillColor(GREEN)
        canvas.rect(0, height-17*mm, width, 17*mm, fill=1, stroke=0)
        canvas.setFont('CertificateSansBold', 11)
        canvas.setFillColor(colors.white)
        canvas.drawString(22*mm, height-11*mm, 'IT CLUB / ROBOMAN')
        canvas.setStrokeColor(colors.HexColor('#d6e4dc'))
        canvas.line(22*mm, 18*mm, width-22*mm, 18*mm)
        canvas.setFillColor(MUTED)
        canvas.setFont('CertificateSans', 8)
        canvas.drawString(22*mm, 12*mm, profile['number'])
        canvas.drawRightString(width-22*mm, 12*mm, f'Страница {doc.page}')
        canvas.restoreState()

    image = Image(BytesIO(photo), width=30*mm, height=40*mm, kind='proportional', hAlign='LEFT')
    qr_image = Image(BytesIO(qr_png(profile['public_url'])), width=34*mm, height=34*mm)
    identity = [Paragraph(_markup(profile['teacher_name']), name), Paragraph('Преподаватель IT Club', body)]
    media = Table([[image, identity, [qr_image, Paragraph('Проверить актуальность', center)]]],
        colWidths=[34*mm,document.width-76*mm,42*mm], hAlign='LEFT')
    media.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),0),
        ('RIGHTPADDING',(0,0),(-1,-1),0),('TOPPADDING',(0,0),(-1,-1),0),('BOTTOMPADDING',(0,0),(-1,-1),0)]))
    story = [Paragraph('Цифровой сертификат', title),
        Paragraph(f"№ {_markup(profile['number'])} · Выдан {_markup(_issued_date(profile['issued_at']))}", badge),
        Spacer(1,8*mm), media, Spacer(1,8*mm),
        CondPageBreak(3*body.leading), Paragraph('О преподавателе', bio_label),
        Paragraph(_markup(profile['description']), body)]
    if profile.get('university') or profile.get('study_program'):
        story.append(Paragraph('Образование', label))
        if profile.get('university'):
            story.append(Paragraph(_markup(profile['university']), body))
        if profile.get('study_program'):
            story.append(Paragraph(_markup(profile['study_program']), body))
    story.append(Paragraph('Закреплённые сады', label))
    if profile.get('branches'):
        for branch in profile['branches']:
            block=[Paragraph('<b>'+_markup(branch['name'])+'</b>', body)]
            if branch.get('address'):
                block.append(Paragraph(_markup(branch['address']), small))
            story.append(KeepTogether(block))
    else:
        story.append(Paragraph('Сады пока не назначены.', body))
    url = escape(profile['public_url'], quote=True)
    story.extend([Spacer(1,6*mm), Paragraph('Проверка сертификата', label),
        Paragraph(f'<link href="{url}" color="#145b49">{_markup(profile["public_url"])}</link>', small),
        Paragraph('Данные актуальны на момент скачивания. Текущее состояние сертификата и назначения '
            'проверяйте по QR-коду или ссылке.', small),
        Paragraph('Сертификат подтверждает профиль преподавателя в IT Club.', small)])
    document.build(story, onFirstPage=page_frame, onLaterPages=page_frame)
    return output.getvalue()
