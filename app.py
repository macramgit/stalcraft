from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
import os
import json
import uuid
import hashlib
import hmac
import secrets
import boto3
from botocore.client import Config
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

# Lokalne .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024 * 10  # 250 MB max na cały request (10 zdjęć x 25MB)

# ─── Config ───────────────────────────────────────────────
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_FILES_PER_PROJECT = 10
DATA_FILE = os.path.join(os.path.dirname(__file__), 'data.json')

SESSION_LIFETIME = timedelta(hours=2)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
_RAW_PASSWORD = os.environ.get('ADMIN_PASSWORD')
if not ADMIN_USERNAME or not _RAW_PASSWORD:
    raise RuntimeError("Ustaw zmienne ADMIN_USERNAME i ADMIN_PASSWORD!")

# ─── Cloudflare R2 ────────────────────────────────────────
R2_ACCOUNT_ID     = os.environ.get('R2_ACCOUNT_ID')
R2_ACCESS_KEY_ID  = os.environ.get('R2_ACCESS_KEY_ID')
R2_SECRET_KEY     = os.environ.get('R2_SECRET_ACCESS_KEY')
R2_BUCKET_NAME    = os.environ.get('R2_BUCKET_NAME', 'baluxstal')
R2_PUBLIC_URL     = os.environ.get('R2_PUBLIC_URL', '').rstrip('/')

USE_R2 = all([R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_KEY])

def get_r2_client():
    return boto3.client(
        's3',
        endpoint_url=f'https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com',
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_KEY,
        config=Config(signature_version='s3v4'),
        region_name='auto'
    )

def upload_to_r2(file_obj, filename):
    """Wysyla plik do R2, zwraca publiczny URL."""
    client = get_r2_client()
    client.upload_fileobj(
        file_obj,
        R2_BUCKET_NAME,
        filename,
        ExtraArgs={'ContentType': file_obj.content_type or 'image/jpeg'}
    )
    return f'{R2_PUBLIC_URL}/{filename}'

def delete_from_r2(filename):
    """Usuwa plik z R2."""
    try:
        client = get_r2_client()
        client.delete_object(Bucket=R2_BUCKET_NAME, Key=filename)
    except Exception:
        pass

# Lokalny fallback (development bez R2)
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def save_image(file) -> str:
    """Zapisuje zdjecie - do R2 lub lokalnie. Zwraca sciezke/URL do zapisania w data.json."""
    filename = str(uuid.uuid4()) + '_' + secure_filename(file.filename)
    if USE_R2:
        url = upload_to_r2(file, filename)
        return url  # pelny URL np. https://pub.r2.dev/xyz.jpg
    else:
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return filename  # lokalna nazwa pliku

def delete_image(image_ref):
    """Usuwa zdjecie z R2 lub lokalnie."""
    if image_ref.startswith('http'):
        # To jest URL z R2 - wyciagnij nazwe pliku
        filename = image_ref.split('/')[-1]
        delete_from_r2(filename)
    else:
        img_path = os.path.join(UPLOAD_FOLDER, image_ref)
        if os.path.exists(img_path):
            os.remove(img_path)

def image_url(image_ref) -> str:
    """Zwraca URL do wyswietlenia zdjecia w szablonie."""
    if image_ref.startswith('http'):
        return image_ref  # juz jest pelny URL z R2
    return url_for('static', filename='uploads/' + image_ref)

app.jinja_env.globals['image_url'] = image_url

# ─── Password hashing ─────────────────────────────────────
def _hash_password(password: str) -> str:
    return hmac.new(
        app.secret_key.encode(),
        password.encode(),
        hashlib.sha256
    ).hexdigest()

ADMIN_PASSWORD_HASH = _hash_password(_RAW_PASSWORD)

# ─── Brute-force tracker ──────────────────────────────────
_login_tracker: dict = {}

def _get_tracker(ip):
    if ip not in _login_tracker:
        _login_tracker[ip] = {'attempts': 0, 'locked_until': None}
    return _login_tracker[ip]

def _is_locked(ip):
    t = _get_tracker(ip)
    if t['locked_until'] and datetime.now() < t['locked_until']:
        return True
    if t['locked_until'] and datetime.now() >= t['locked_until']:
        t['attempts'] = 0
        t['locked_until'] = None
    return False

def _record_failed(ip):
    t = _get_tracker(ip)
    t['attempts'] += 1
    if t['attempts'] >= MAX_LOGIN_ATTEMPTS:
        t['locked_until'] = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)

def _record_success(ip):
    _login_tracker.pop(ip, None)

def _remaining_lockout(ip):
    t = _get_tracker(ip)
    if t['locked_until']:
        delta = t['locked_until'] - datetime.now()
        return max(1, int(delta.total_seconds() // 60))
    return 0

# ─── CSRF ─────────────────────────────────────────────────
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf(token):
    return hmac.compare_digest(session.get('csrf_token', ''), token or '')

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# ─── Session expiry ───────────────────────────────────────
@app.before_request
def check_session_expiry():
    if session.get('logged_in'):
        last_active = session.get('last_active')
        if last_active:
            last_dt = datetime.fromisoformat(last_active)
            if datetime.now() - last_dt > SESSION_LIFETIME:
                session.clear()
                flash('Sesja wygasla. Zaloguj sie ponownie.', 'error')
                return redirect(url_for('login'))
        session['last_active'] = datetime.now().isoformat()

# ─── Data helpers ─────────────────────────────────────────
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ─── Data helpers ─────────────────────────────────────────
DEFAULT_DATA = {
    'projects': [],
    'categories': ['Schody', 'Balustrady', 'Bramy', 'Ogrodzenia', 'Zadaszenia tarasow', 'Pergole i mala architektura', 'Meble stalowe', 'Inne']
}
DATA_R2_KEY = 'data.json'

def load_data():
    # Najpierw próbuj z R2
    if USE_R2:
        try:
            client = get_r2_client()
            obj = client.get_object(Bucket=R2_BUCKET_NAME, Key=DATA_R2_KEY)
            return json.loads(obj['Body'].read().decode('utf-8'))
        except Exception as e:
            # Plik nie istnieje jeszcze w R2 lub inny błąd - zwróć domyślne dane
            if '404' in str(e) or 'NoSuchKey' in str(e):
                return dict(DEFAULT_DATA)
            # Inny błąd - spróbuj lokalnie
            pass

    # Lokalny fallback
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return dict(DEFAULT_DATA)

def save_data(data):
    # Zapisz do R2
    if USE_R2:
        try:
            client = get_r2_client()
            body = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
            client.put_object(
                Bucket=R2_BUCKET_NAME,
                Key=DATA_R2_KEY,
                Body=body,
                ContentType='application/json'
            )
            return
        except Exception:
            pass  # fallback do lokalnego pliku

    # Lokalny fallback
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def is_logged_in():
    return session.get('logged_in', False)

# ─── Routes ───────────────────────────────────────────────
@app.route('/o-nas')
def o_nas():
    return render_template('o_nas.html', is_admin=is_logged_in())

@app.route('/')
def index():
    data = load_data()
    category = request.args.get('category', '')
    projects = data['projects']
    if category:
        projects = [p for p in projects if p.get('category') == category]
    return render_template('index.html',
                           projects=projects,
                           categories=data['categories'],
                           active_category=category,
                           is_admin=is_logged_in())

@app.route('/project/<project_id>')
def project_detail(project_id):
    data = load_data()
    project = next((p for p in data['projects'] if p['id'] == project_id), None)
    if not project:
        return redirect(url_for('index'))
    return render_template('project_detail.html', project=project, is_admin=is_logged_in())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('admin'))
    ip = request.remote_addr
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            abort(403)
        if _is_locked(ip):
            mins = _remaining_lockout(ip)
            flash(f'Za duzo prob. Sprobuj za {mins} min.', 'error')
            return render_template('login.html')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        username_ok = hmac.compare_digest(username, ADMIN_USERNAME)
        password_ok = hmac.compare_digest(_hash_password(password), ADMIN_PASSWORD_HASH)
        if username_ok and password_ok:
            _record_success(ip)
            session.clear()
            session['logged_in'] = True
            session['last_active'] = datetime.now().isoformat()
            session.permanent = True
            app.permanent_session_lifetime = SESSION_LIFETIME
            flash('Zalogowano pomyslnie!', 'success')
            return redirect(url_for('admin'))
        else:
            _record_failed(ip)
            remaining = MAX_LOGIN_ATTEMPTS - _get_tracker(ip)['attempts']
            if remaining > 0:
                flash(f'Nieprawidlowe dane. Pozostalo prob: {remaining}', 'error')
            else:
                flash(f'Konto zablokowane na {LOCKOUT_MINUTES} minut.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if not is_logged_in():
        return redirect(url_for('login'))
    data = load_data()
    return render_template('admin.html', projects=data['projects'], categories=data['categories'])

@app.route('/admin/add', methods=['GET', 'POST'])
def add_project():
    if not is_logged_in():
        return redirect(url_for('login'))
    data = load_data()
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            abort(403)
        title = request.form.get('title', '').strip()[:200]
        description = request.form.get('description', '').strip()[:2000]
        category = request.form.get('category', '').strip()
        location = request.form.get('location', '').strip()[:100]
        year = request.form.get('year', '').strip()[:4]
        if category not in data['categories']:
            flash('Nieprawidlowa kategoria.', 'error')
            return render_template('add_project.html', categories=data['categories'])
        if not title:
            flash('Tytul jest wymagany.', 'error')
            return render_template('add_project.html', categories=data['categories'])
        images = []
        files = request.files.getlist('images')
        for file in files[:MAX_FILES_PER_PROJECT]:
            if not file or not file.filename:
                continue
            if not allowed_file(file.filename):
                flash(f'Niedozwolony format: {file.filename}', 'error')
                continue
            file.seek(0, 2)
            size = file.tell()
            file.seek(0)
            if size > MAX_FILE_SIZE:
                flash(f'Plik {file.filename} za duzy (max 8 MB).', 'error')
                continue
            ref = save_image(file)
            images.append(ref)
        project = {
            'id': str(uuid.uuid4()),
            'title': title,
            'description': description,
            'category': category,
            'location': location,
            'year': year,
            'images': images,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M')
        }
        data['projects'].insert(0, project)
        save_data(data)
        flash('Projekt dodany pomyslnie!', 'success')
        return redirect(url_for('admin'))
    return render_template('add_project.html', categories=data['categories'])

@app.route('/admin/delete/<project_id>', methods=['POST'])
def delete_project(project_id):
    if not is_logged_in():
        abort(403)
    if not validate_csrf(request.form.get('csrf_token')):
        abort(403)
    data = load_data()
    project = next((p for p in data['projects'] if p['id'] == project_id), None)
    if project:
        for img in project.get('images', []):
            delete_image(img)
        data['projects'] = [p for p in data['projects'] if p['id'] != project_id]
        save_data(data)
        flash('Projekt usuniety.', 'success')
    return redirect(url_for('admin'))

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https:; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response

if __name__ == '__main__':
    app.run(debug=False, port=5000)
