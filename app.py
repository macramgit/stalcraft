from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import json
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'stalcraft-secret-key-2024-change-in-production'

# Config
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
DATA_FILE = os.path.join(os.path.dirname(__file__), 'data.json')

# Admin credentials (in production use env vars / DB)
ADMIN_USERNAME = 'brat'
ADMIN_PASSWORD = 'stal2024'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {'projects': [], 'categories': ['Schody', 'Balustrady', 'Bramy', 'Ogrodzenia', 'Meble stalowe', 'Inne']}

def save_data(data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def is_logged_in():
    return session.get('logged_in', False)

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
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            flash('Zalogowano pomyślnie!', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Nieprawidłowe dane logowania.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
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
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        location = request.form.get('location', '').strip()
        year = request.form.get('year', '').strip()
        
        images = []
        files = request.files.getlist('images')
        for file in files:
            if file and allowed_file(file.filename):
                filename = str(uuid.uuid4()) + '_' + secure_filename(file.filename)
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                images.append(filename)
        
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
        flash('Projekt dodany pomyślnie!', 'success')
        return redirect(url_for('admin'))
    
    return render_template('add_project.html', categories=data['categories'])

@app.route('/admin/delete/<project_id>', methods=['POST'])
def delete_project(project_id):
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    data = load_data()
    project = next((p for p in data['projects'] if p['id'] == project_id), None)
    if project:
        # Delete images
        for img in project.get('images', []):
            img_path = os.path.join(UPLOAD_FOLDER, img)
            if os.path.exists(img_path):
                os.remove(img_path)
        data['projects'] = [p for p in data['projects'] if p['id'] != project_id]
        save_data(data)
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
