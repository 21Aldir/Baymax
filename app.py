import os
import json
import uuid
import re
import hashlib
import html
from datetime import datetime
from pathlib import Path
import io

from flask import Flask, request, jsonify, render_template, send_file
from dotenv import load_dotenv
from google import genai
from google.genai import types as genai_types
from pypdf import PdfReader
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER

load_dotenv()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
FRAMEWORKS_DIR = Path(__file__).parent / 'frameworks'

FRAMEWORK_FILES = {
    'nist_csf':  'nist_csf.json',
    'iso_27001': 'iso_27001.json',
    'soc2':      'soc2.json',
}

# {doc_hash: True/False}  — resultado de validación
_validation_cache: dict[str, bool] = {}
# {doc_hash + framework_key: full analysis dict}  — resultado de análisis
_analysis_cache:   dict[str, dict] = {}


# ─── Document extraction ──────────────────────────────────────────────────────

def pdf_to_markdown(filepath: str) -> str:
    reader = PdfReader(filepath)
    pages_md = []
    for page in reader.pages:
        raw = page.extract_text() or ''
        lines = raw.split('\n')
        md = []
        for line in lines:
            s = line.strip()
            if not s:
                md.append('')
                continue
            if len(s) < 80 and s.isupper() and len(s) > 3:
                md.append(f'## {s}')
            elif len(s) < 60 and not s.endswith('.') and s.istitle():
                md.append(f'### {s}')
            elif re.match(r'^[•·\-\*]\s', s):
                md.append(f'- {s[2:]}')
            elif re.match(r'^\d+[\.\)]\s', s):
                md.append(s)
            else:
                md.append(s)
        pages_md.append('\n'.join(md))
    return '\n\n---\n\n'.join(pages_md)


def extract_text(filepath: str, ext: str) -> str:
    if ext == '.pdf':
        return pdf_to_markdown(filepath)
    with open(filepath, encoding='utf-8', errors='ignore') as f:
        return f.read()


# ─── Framework helpers ────────────────────────────────────────────────────────

def load_framework(key: str) -> dict:
    with open(FRAMEWORKS_DIR / FRAMEWORK_FILES[key]) as f:
        return json.load(f)


def normalize_controls(key: str, data: dict) -> list:
    out = []
    if key == 'nist_csf':
        for func in data.get('functions', []):
            fn = func.get('name', '')
            for cat in func.get('categories', []):
                label = f"{fn} › {cat.get('name', '')}"
                for sub in cat.get('subcategories', []):
                    out.append({
                        'id':       sub['id'],
                        'name':     sub.get('statement', sub.get('name', '')),
                        'category': label,
                    })
    elif key == 'iso_27001':
        for c in data.get('controls', []):
            out.append({
                'id':          c['id'],
                'name':        c.get('control_name', ''),
                'description': c.get('description', ''),
                'category':    c.get('category', ''),
            })
    elif key == 'soc2':
        for c in data.get('criteria', []):
            out.append({
                'id':          c['id'],
                'name':        c.get('criteria_name', ''),
                'description': c.get('description', ''),
                'category':    c.get('category', ''),
            })
    return out


# ─── Gemini helpers ───────────────────────────────────────────────────────────

def is_compliance_document(doc_text: str, client) -> bool:
    snippet = doc_text[:1500]
    prompt  = (
        "Does the following document relate to any of these topics: "
        "information security, cybersecurity, IT governance, risk management, "
        "compliance, data protection, access control, audit, privacy, or "
        "organizational security controls?\n"
        "Answer only YES or NO.\n\n"
        f"DOCUMENT:\n---\n{snippet}\n---"
    )
    resp = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt,
        config=genai_types.GenerateContentConfig(
            temperature=0.0,
            max_output_tokens=5,
        ),
    )
    text = resp.text or ''
    return text.strip().upper().startswith('YES')


def build_prompt(doc_text: str, fw_name: str, controls: list) -> str:
    excerpt = doc_text[:12000]
    slim    = [{'id': c['id'], 'name': c['name']} for c in controls]
    return (
        f"You are a senior GRC analyst specializing in cybersecurity compliance.\n\n"
        f"TASK: Analyze the policy document (formatted as Markdown) against the {fw_name} framework controls.\n\n"
        f"POLICY DOCUMENT:\n---\n{excerpt}\n---\n\n"
        f"CONTROLS TO ASSESS ({len(controls)} total):\n"
        f"{json.dumps(slim)}\n\n"
        "Assessment rules:\n"
        '- "status": "met" | "partial" | "missing"\n'
        '- "compliance_level": integer 0-100 (100 = fully compliant)\n'
        '- "evidence_found": direct quote from the document (<=150 chars) or "none"\n'
        '- "recommendation": specific actionable remediation step, or "none" if met\n'
        '- "confidence_score": float 0.0-1.0 reflecting certainty of your assessment\n'
        '- "priority": "high" | "medium" | "low"\n\n'
        "IMPORTANT: SKIP controls where no evidence or findings exist (zero evidence). "
        "Only include controls where you found something relevant in the document.\n\n"
        "Return ONLY a raw JSON array with no markdown, no code fences, no explanation:\n"
        '[{"control_id":"...","control_name":"...","status":"met|partial|missing",'
        '"compliance_level":0,"evidence_found":"...","recommendation":"...","confidence_score":0.0,"priority":"high|medium|low"},...]\n\n'
        "Return the array now:"
    )


def parse_gemini(raw: str) -> list:
    text = raw.strip()
    # quita bloques de código markdown
    text = re.sub(r'```json\s*', '', text)
    text = re.sub(r'```\s*',     '', text)
    text = text.strip()
    # extrae solo el array JSON (ignora thinking/preamble de Gemini 2.5)
    s = text.find('[')
    e = text.rfind(']') + 1
    if s == -1 or e <= s:
        raise json.JSONDecodeError('No JSON array found', text, 0)
    return json.loads(text[s:e])


def compute_score(results: list) -> tuple:
    n = len(results)
    if not n:
        return 0, 0, 0, 0
    met     = sum(1 for c in results if c.get('status') == 'met')
    partial = sum(1 for c in results if c.get('status') == 'partial')
    missing = sum(1 for c in results if c.get('status') == 'missing')
    score   = round((met + partial * 0.5) / n * 100, 1)
    return score, met, partial, missing


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'document' not in request.files:
        return jsonify({'error': 'No document provided'}), 400

    file = request.files['document']
    key  = request.form.get('framework', '').strip()

    if not file or not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    if key not in FRAMEWORK_FILES:
        return jsonify({'error': 'Invalid framework selection'}), 400

    ext = Path(file.filename).suffix.lower()
    if ext not in ('.pdf', '.txt'):
        return jsonify({'error': 'Only PDF and TXT files are supported'}), 400

    if not GEMINI_API_KEY:
        return jsonify({'error': 'GEMINI_API_KEY is not configured in .env'}), 500

    tmp = Path(app.config['UPLOAD_FOLDER']) / f"{uuid.uuid4()}{ext}"
    try:
        file.save(str(tmp))

        doc_text = extract_text(str(tmp), ext)
        if not doc_text.strip():
            return jsonify({
                'error': 'Could not extract text. Is the PDF scanned / image-based?'
            }), 400

        doc_hash     = hashlib.sha256(doc_text.encode()).hexdigest()
        analysis_key = f"{doc_hash}:{key}"

        # ── Cache hit: análisis completo ya existe ────────────────────────────
        if analysis_key in _analysis_cache:
            app.logger.info('Cache hit: %s', analysis_key[:16])
            cached = _analysis_cache[analysis_key]
            return jsonify({**cached, 'document_name': file.filename, 'cached': True})

        client = genai.Client(api_key=GEMINI_API_KEY)

        # ── Cache hit: ya sabemos que NO es compliance ────────────────────────
        if doc_hash in _validation_cache and not _validation_cache[doc_hash]:
            return jsonify({
                'error': 'The document does not appear to be a security policy or compliance document.'
            }), 400

        # ── Validación (solo si no está en cache) ─────────────────────────────
        if doc_hash not in _validation_cache:
            _validation_cache[doc_hash] = is_compliance_document(doc_text, client)

        if not _validation_cache[doc_hash]:
            return jsonify({
                'error': 'The document does not appear to be a security policy or compliance document.'
            }), 400

        fw_data  = load_framework(key)
        fw_name  = fw_data.get('framework', {}).get('name', key)
        controls = normalize_controls(key, fw_data)
        cat_map  = {c['id']: c.get('category', '') for c in controls}

        prompt = build_prompt(doc_text, fw_name, controls)
        resp   = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                temperature=0,
                max_output_tokens=32768,
            ),
        )

        results = parse_gemini(resp.text)

        for ctrl in results:
            ctrl['category'] = cat_map.get(ctrl.get('control_id', ''), '')

        score, met, partial, missing = compute_score(results)

        analysis_result = {
            'success':        True,
            'framework_name': fw_name,
            'framework_key':  key,
            'analysis_date':  datetime.now().strftime('%B %d, %Y at %H:%M'),
            'score':          score,
            'met':            met,
            'partial':        partial,
            'missing':        missing,
            'total':          len(results),
            'controls':       results,
        }
        _analysis_cache[analysis_key] = analysis_result

        return jsonify({
            'success':        True,
            'framework_name': fw_name,
            'framework_key':  key,
            'document_name':  file.filename,
            'analysis_date':  datetime.now().strftime('%B %d, %Y at %H:%M'),
            'score':          score,
            'met':            met,
            'partial':        partial,
            'missing':        missing,
            'total':          len(results),
            'controls':       results,
            'cached':         False,
        })

    except json.JSONDecodeError as e:
        app.logger.error('Gemini raw response: %s', getattr(e, 'doc', str(e)))
        return jsonify({'error': 'AI returned unparseable JSON. Please try again.'}), 500
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
    finally:
        if tmp.exists():
            tmp.unlink()


@app.route('/export-pdf', methods=['POST'])
def export_pdf():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=0.7*inch, rightMargin=0.7*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch,
    )

    base = getSampleStyleSheet()
    DARK = colors.HexColor('#0d1b2a')
    BLUE = colors.HexColor('#003580')
    GREY = colors.HexColor('#555555')

    _ps_cache = {}
    def ps(name, **kw):
        key = name + str(kw)
        if key not in _ps_cache:
            _ps_cache[key] = ParagraphStyle(name, parent=base['Normal'], **kw)
        return _ps_cache[key]

    def safe_str(v):
        return html.escape(str(v)) if v is not None else ''

    story = []



    # Meta table
    def mcell(txt, bold=False, col=None):
        kw = {'fontSize': 9}
        if bold: kw['fontName'] = 'Helvetica-Bold'
        if col:  kw['textColor'] = col
        return Paragraph(txt, ps('Meta_' + txt[:8].replace(' ', '_'), **kw))

    meta_rows = [
        [mcell('Framework', bold=True), mcell(safe_str(data.get('framework_name', ''))),
         mcell('Date',  bold=True),     mcell(safe_str(data.get('analysis_date', '')))],
        [mcell('Document', bold=True),  mcell(safe_str(data.get('document_name', ''))),
         mcell('Score', bold=True, col=BLUE),
         mcell(f"{data.get('score', 0)}%", bold=True, col=BLUE)],
    ]
    mt = Table(meta_rows, colWidths=[1.0*inch, 2.9*inch, 0.85*inch, 1.85*inch])
    mt.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), colors.HexColor('#f8f9fa')),
        ('BOX',           (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('INNERGRID',     (0,0), (-1,-1), 0.3, colors.HexColor('#eeeeee')),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
    ]))
    story += [mt, Spacer(1, 14)]

    # Summary
    story.append(Paragraph("Executive Summary",
        ps('H1', fontSize=13, fontName='Helvetica-Bold',
           textColor=DARK, spaceAfter=8)))

    total = data.get('total', 1) or 1
    met   = data.get('met',     0)
    part  = data.get('partial', 0)
    miss  = data.get('missing', 0)
    score = data.get('score',   0)
    pct   = lambda n: f"{round(n / total * 100, 1)}%"

    sum_rows = [
        ['Status',                  'Controls',  'Percentage'],
        ['Met (Compliant)',          str(met),    pct(met)],
        ['Partial (Needs Work)',     str(part),   pct(part)],
        ['Missing (Gap)',            str(miss),   pct(miss)],
        ['Total Assessed',           str(total),  '100%'],
        ['Overall Compliance Score', '',          f'{score}%'],
    ]
    st = Table(sum_rows, colWidths=[2.6*inch, 1.1*inch, 1.5*inch])
    st.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  DARK),
        ('TEXTCOLOR',     (0,0), (-1,0),  colors.white),
        ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 9),
        ('ALIGN',         (1,0), (-1,-1), 'CENTER'),
        ('GRID',          (0,0), (-1,-1), 0.4, colors.HexColor('#cccccc')),
        ('BACKGROUND',    (0,1), (-1,1),  colors.HexColor('#e8f5e9')),
        ('BACKGROUND',    (0,2), (-1,2),  colors.HexColor('#fffde7')),
        ('BACKGROUND',    (0,3), (-1,3),  colors.HexColor('#ffebee')),
        ('BACKGROUND',    (0,4), (-1,4),  colors.HexColor('#f5f5f5')),
        ('BACKGROUND',    (0,5), (-1,5),  colors.HexColor('#e3f2fd')),
        ('FONTNAME',      (0,5), (-1,5),  'Helvetica-Bold'),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
    ]))
    story += [st, Spacer(1, 14)]

    # Controls detail
    story.append(Paragraph("Controls Assessment Detail",
        ps('H2', fontSize=13, fontName='Helvetica-Bold',
           textColor=DARK, spaceAfter=8)))

    hdr_s = ps('Hdr', fontSize=8, fontName='Helvetica-Bold',
               textColor=colors.white, leading=10)
    cel_s = ps('Cel', fontSize=7.5, leading=10)
    ev_s  = ps('Ev',  fontSize=7, leading=9.5,
               textColor=colors.HexColor('#444444'))

    STATUS_BG = {
        'met':     colors.HexColor('#e8f5e9'),
        'partial': colors.HexColor('#fffde7'),
        'missing': colors.HexColor('#ffebee'),
    }
    STATUS_FG = {
        'met':     colors.HexColor('#1b5e20'),
        'partial': colors.HexColor('#795548'),
        'missing': colors.HexColor('#b71c1c'),
    }
    PRIO_FG = {
        'high':   colors.HexColor('#b71c1c'),
        'medium': colors.HexColor('#e65100'),
        'low':    colors.HexColor('#2e7d32'),
    }

    rows = [[
        Paragraph('ID',       hdr_s),
        Paragraph('Control',  hdr_s),
        Paragraph('Status',   hdr_s),
        Paragraph('Priority', hdr_s),
        Paragraph('Evidence / Recommendation', hdr_s),
    ]]
    row_styles = []

    for i, c in enumerate(data.get('controls', []), 1):
        st_v = c.get('status',         'missing')
        pr_v = c.get('priority',       'low')
        ev   = c.get('evidence_found',  'none') or 'none'
        rec  = c.get('recommendation', 'none') or 'none'

        note = ev if ev != 'none' else ''
        if rec != 'none':
            note += (' | ' if note else '') + f'→ {rec}'
        if len(note) > 120:
            note = note[:120] + '…'

        rows.append([
            Paragraph(safe_str(c.get('control_id', '')),
                ps(f'ID{i}', fontSize=7.5, fontName='Courier')),
            Paragraph(safe_str(c.get('control_name', ''))[:70], cel_s),
            Paragraph(safe_str(st_v).upper(),
                ps(f'ST{i}', fontSize=7.5, fontName='Helvetica-Bold',
                   textColor=STATUS_FG.get(st_v, colors.black))),
            Paragraph(safe_str(pr_v).upper(),
                ps(f'PR{i}', fontSize=7.5,
                   textColor=PRIO_FG.get(pr_v, colors.black))),
            Paragraph(safe_str(note) or '—', ev_s),
        ])
        row_styles.append(
            ('BACKGROUND', (0, i), (-1, i), STATUS_BG.get(st_v, colors.white))
        )

    cw = [0.65*inch, 1.85*inch, 0.72*inch, 0.72*inch, 2.7*inch]
    ct = Table(rows, colWidths=cw, repeatRows=1)
    ct.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  DARK),
        ('FONTSIZE',      (0,0), (-1,-1), 7.5),
        ('GRID',          (0,0), (-1,-1), 0.3, colors.HexColor('#cccccc')),
        ('TOPPADDING',    (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING',   (0,0), (-1,-1), 5),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
    ] + row_styles))
    story.append(ct)

    # Recommendations
    action = [
        c for c in data.get('controls', [])
        if c.get('status') in ('partial', 'missing')
        and c.get('recommendation', 'none') not in ('none', '', None)
    ]
    if action:
        action.sort(
            key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(
                x.get('priority', 'low'), 2)
        )
        story += [
            Spacer(1, 14),
            Paragraph("Remediation Recommendations",
                ps('H3', fontSize=13, fontName='Helvetica-Bold',
                   textColor=DARK, spaceAfter=8)),
        ]
        PRIO_HEX = {'high': 'b71c1c', 'medium': 'e65100', 'low': '2e7d32'}
        for idx, c in enumerate(action):
            pr   = c.get('priority', 'low')
            stat = c.get('status',   'missing')
            hex_ = PRIO_HEX.get(pr, '333333')
            cid  = c.get('control_id', '')
            hdr  = Paragraph(
                f"<b>[{safe_str(cid)}]</b> {safe_str(c.get('control_name',''))[:80]} "
                f"— <font color='#{hex_}'>{safe_str(pr).upper()}</font> ({safe_str(stat)})",
                ps(f'RH{idx}', fontSize=8.5, fontName='Helvetica-Bold', spaceAfter=2))
            body = Paragraph(
                f"→ {safe_str(c.get('recommendation', ''))}",
                ps(f'RB{idx}', fontSize=8, leftIndent=12, spaceAfter=7,
                   textColor=colors.HexColor('#333333')))
            story.append(KeepTogether([hdr, body]))

    # Footer
    story += [
        Spacer(1, 20),
        HRFlowable(width='100%', thickness=0.5,
                    color=colors.HexColor('#aaaaaa'), spaceAfter=5),
        Paragraph(
            safe_str(data.get('analysis_date', '')),
            ps('Ft', fontSize=10, textColor=GREY, alignment=TA_CENTER)),
    ]

    doc.build(story)
    buf.seek(0)
    fname = f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return send_file(buf, mimetype='application/pdf',
                     as_attachment=True, download_name=fname)


if __name__ == '__main__':
    Path('uploads').mkdir(exist_ok=True)
    app.run(debug=False, port=5000)
