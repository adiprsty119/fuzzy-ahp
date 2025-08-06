from flask import Flask, request, render_template, request as flask_request, redirect, url_for, flash, session, jsonify
from flask_session import Session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from app import create_app, db
from app.models import Users, Notification
from flask_mail import Mail, Message
from twilio.rest import Client
from authlib.integrations.flask_client import OAuth
from markupsafe import escape
from datetime import datetime, timedelta
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError 
from forms import LoginForm, RegisterForm
from config import Config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import random, string
import logging
import secrets
import time
import os
import re
from dotenv import load_dotenv

load_dotenv()

app = create_app()
app.config['SESSION_FILE_DIR'] = os.path.join(app.root_path, 'flask_session')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.secret_key = os.getenv("APP_SECRET_KEY")
Session(app)

csrf = CSRFProtect(app)
app.config.from_object(Config)
limiter = Limiter(get_remote_address, app=app)
logging.basicConfig(filename='login.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s:%(message)s')

# Buat folder uploads jika belum ada
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
    
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Configure Flask-Mail OTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'adip98816@gmail.com'
app.config['MAIL_PASSWORD'] = 'aiacumtbxgiyssuc'
mail = Mail(app)

# Whatsapp OTP
load_dotenv()
account_sid = os.getenv("TWILIO_ACCOUNT_SID")
auth_token = os.getenv("TWILIO_AUTH_TOKEN")
client = Client(account_sid, auth_token)

def send_whatsapp_code(phone, code):
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    client = Client(account_sid, auth_token)
    message_body = f"Kode verifikasi Anda adalah: *{code}*.\nJangan bagikan kode ini kepada siapa pun."
    try:
        message = client.messages.create(
            body=message_body,
            from_='whatsapp:+14155238886',
            to=f'whatsapp:{phone}'
        )
        print("Pesan berhasil dikirim:", message.sid)
    except Exception as e:
        print("Gagal mengirim pesan:", e)

def normalize_phone_number(phone):
    phone = phone.strip()
    if phone.startswith('0'):
        return '+62' + phone[1:]
    elif phone.startswith('+62'):
        return phone
    elif phone.startswith('62'):
        return '+' + phone
    else:
        return phone
    
def generate_username(email):
    name_part = email.split('@')[0]
    random_suffix = ''.join(random.choices(string.digits, k=4))
    return f"{name_part}_{random_suffix}"

# Google OAuth Config
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)

# Fungsi untuk mengecek keberadaan username, nomor hp, email dan password serta untuk menghasilkan kode verifikasi 6 digit
def check_username_in_db(username):
    user = Users.query.filter_by(username=username).first()
    return user is not None

def check_phone_in_db(phone):
    user = Users.query.filter_by(nomor_hp=phone).first()
    return user is not None


def check_email_in_db(email):
    user = Users.query.filter_by(email=email).first()
    return user is not None

def check_password_in_db(username, password):
    user = Users.query.filter_by(username=username).first()
    if user:
        return check_password_hash(user.password, password)
    return False

def generate_verification_code():
    return random.randint(100000, 999999)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("429.html", message="Terlalu banyak percobaan login. Silakan coba lagi nanti."), 429

@app.context_processor
def inject_notifications():
    user = None
    unread_count = 0
    if session.get('username'):
        user = Users.query.filter_by(username=session.get('username')).first()
    elif session.get('user'):
        user = Users.query.filter_by(username=session['user'].get('username')).first()
    if user:
        unread_count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
    return dict(notification_count=unread_count)

# Endpoint login
@app.route('/login/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Query user dari database
        user = Users.query.filter_by(username=username).first()
        
        if not user:
            logging.warning(f"Login gagal: username '{username}' tidak ditemukan.")
            flash("Username salah!", "danger")
        elif not check_password_hash(user.password, password):
            logging.warning(f"Login gagal: password salah untuk user '{username}'.")
            flash("Password salah!", "danger")
        else:
            session['username'] = username  
            safe_username = escape(username)
            logging.info(f"User '{username}' berhasil login.")
            flash(f"Login berhasil! Selamat datang, {safe_username}.", "success")
            session['first_time_login'] = True
            return redirect(url_for('index')) 
    return render_template('login.html', form=form)

# Endpoint login with Google
@app.route('/login/google/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login_google():
    redirect_uri = url_for('login_google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

# Endpoint Callback Login With Google
@app.route('/login/google/callback/')
def login_google_callback():
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')  
        resp.raise_for_status()  
        user_info = resp.json()
    except Exception as e:
        logging.warning(f"Login Google gagal: {e}") 
        flash("Gagal login dengan Google. Silakan coba lagi.", "danger")
        return redirect(url_for('login'))
    
    # Proses lanjut jika data user berhasil diambil
    email = user_info.get('email')
    username = user_info.get('name') or "Pengguna"
    picture = user_info.get('picture') or "img/default-user.png"
    
    if not email:
        flash("Email dari akun Google tidak ditemukan.", "danger")
        return redirect(url_for('login'))
    
    # ✅ Validasi hanya email Gmail
    if not email.endswith('@gmail.com'):
        flash("Login hanya diizinkan dengan akun Gmail.", "danger")
        return redirect(url_for('login'))
    
    user = Users.query.filter_by(email=email).first()
    if user:
        # Update foto dari Google jika belum tersimpan
        if not user.foto or user.foto == "img/default-user.png":
            user.foto = user_info.get('picture') or "img/default-user.png"
            db.session.commit()
            
        session['username'] = user.username
        session['user'] = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'nama_lengkap': user.nama_lengkap,
            'foto': user.foto,
            'level': user.level
        }
        session['first_time_login'] = True
        session.modified = True 
        print("✅ Session set:", session.get('user'))
        logging.info(f"User '{user.username}' berhasil login via Google.")
        flash(f"Login berhasil! Selamat datang, {escape(user.nama_lengkap)}.", "success")
        return redirect(url_for('index'))
    else:
        # Jika belum ada, arahkan ke konfirmasi registrasi
        session['pending_user'] = user_info
        logging.warning(f"Percobaan login Google dari email '{email}' belum terdaftar.")
        flash("Akun Google Anda belum terdaftar. Lanjutkan registrasi?", "warning")
        return redirect(url_for('confirm_register'))
    
# Endpoint Fisrt Confirm Register With Google
@app.route('/confirm-register/')
def confirm_register():
    user_info = session.get('pending_user')
    if not user_info:
        flash("Data user tidak ditemukan. Silakan login ulang.", "danger")
        return redirect(url_for('login'))
    form = RegisterForm()
    return render_template("confirm_register.html", user=user_info, form=form)

# Endpoint Confirm Register With Google
@app.route('/confirm-register', methods=['POST'])
def do_register():
    user_info = session.get('pending_user')
    if not user_info:
        flash("Data user tidak ditemukan. Silakan login ulang.", "danger")
        return redirect(url_for('login'))
    
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = user_info['email']
        
    # Validasi apakah username atau email sudah digunakan
        if Users.query.filter_by(email=email).first():
            flash("Email sudah digunakan. Silakan login.", "warning")
            return redirect(url_for('login'))
        if Users.query.filter_by(username=username).first():
            flash("Username sudah digunakan.", "warning")
            return redirect(url_for('confirm_register'))
    
        # Simpan ke database
        new_user = Users(
                username=username,
                password=generate_password_hash(secrets.token_urlsafe(12), method='pbkdf2:sha256'),
                nama_lengkap=user_info['name'],
                email=user_info['email'],
                jenis_kelamin=None,
                usia=None,
                foto=user_info['picture'],
                nomor_hp=None,
                level='user',
                reset_token=None,
                token_exp=None
        )
        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(f"Gagal menyimpan user Google baru: {e}")
            flash("Terjadi kesalahan saat registrasi. Coba lagi.", "danger")
            return redirect(url_for('confirm_register'))

        # Set session
        session['user'] = {
            'id': new_user.id,
            'username': new_user.username,
            'email': new_user.email,
            'nama_lengkap': new_user.nama_lengkap,
            'foto': new_user.foto,
            'level': new_user.level
        }
        print("Session setelah login Google:", dict(session))
        logging.info(f"User baru '{username}' berhasil registrasi dan login via Google.")
        flash("Registrasi berhasil! Anda sudah login untuk pertama kali.", "welcome")
        session['username'] = new_user.username
        session['first_time_login'] = True
        return redirect(url_for('index'))
    return render_template("confirm_register.html", user=user_info, form=form)

# Endpoint register
@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['fullName']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        level = 'user'  
        
        # Validasi password dengan regex
        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        if not re.match(password_pattern, password):
            flash("Password must have at least 8 characters, including uppercase, lowercase, number, and special character.", "danger")
            return redirect(url_for('register'))
        # Validasi apakah password dan confirmPassword cocok
        if password != confirm_password:
            flash("Password and Confirm Password must match!", "danger")
            return redirect(url_for('register'))
        # Cek keberadaan username dan email di database
        user_exists = check_username_in_db(username)
        email_exists = check_email_in_db(email)
        if not user_exists and not email_exists:
           # Enkripsi password
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16) 
            # Masukkan data ke database
            try:
                new_user = Users(
                    username=username,
                    password=hashed_password,
                    nama_lengkap=full_name,
                    email=email,
                    level=level
                )
                db.session.add(new_user)
                db.session.commit()
                flash("Registrasi berhasil! Selamat datang di sistem kami. Silakan login untuk mulai menggunakan fitur.", "welcome")
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                logging.error(f"Error during registration: {e}")
                flash("An error occurred during registration.Please try again.", "danger")
                print(e)
        elif user_exists and email_exists:
            flash("Username dan email Anda telah terdaftar.", "danger")
        elif user_exists:
            flash("Username Anda telah terdaftar.", "danger")
        elif email_exists:
            flash("Email Anda telah terdaftar.", "danger")
        return redirect(url_for('register'))
    return render_template('register.html')

# Endpoint Register With Google
@app.route('/register/google/', methods=['GET', 'POST'])
def register_google():
    redirect_uri = url_for('register_google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

# Endpoint Callback Register With Google
@app.route('/register/google/callback/')
def register_google_callback():
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        resp.raise_for_status() 
        user_info = resp.json()
    except Exception as e:
        print(f"Google registrasi error: {e}") 
        flash("Gagal melakukan registrasi dengan Google. Silakan coba lagi.", "danger")
        return redirect(url_for('register'))
    
    email = user_info['email']
    username = generate_username(email)
    
    # Simpan ke database
    new_user = Users(
            username=username,
            password=generate_password_hash(secrets.token_urlsafe(12), method='pbkdf2:sha256'),
            nama_lengkap=user_info['name'],
            email=user_info['email'],
            jenis_kelamin=None,
            usia=None,
            foto=user_info['picture'],
            nomor_hp=None,
            level='user',
            reset_token=None,
            token_exp=None
    )
    if Users.query.filter_by(email=email).first():
        flash("Email sudah digunakan. Silakan login.", "warning")
        return redirect(url_for('login'))
    db.session.add(new_user)
    db.session.commit()
    
    # Login langsung setelah registrasi
    session['username'] = new_user.username
    session['user'] = {
        'id': new_user.id,
        'username': new_user.username,
        'email': new_user.email,
        'nama_lengkap': new_user.nama_lengkap,
        'foto': new_user.foto,
        'level': new_user.level
    }
    flash("Registrasi berhasil! Selamat datang pengguna baru. Anda sekarang login untuk pertama kali.", "welcome")
    return redirect(url_for('index'))

# Endpoint Find Account
@app.route('/find_account/', methods=['GET', 'POST'])
def find_account():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('no-hp')
        # Pastikan username diisi
        if not username:
            flash('Username wajib diisi.', 'danger')
            return redirect(url_for('find_account'))

        # ===== Kondisi 1: Username + Email =====
        if email and not phone:
            # Validasi format email
            email_pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
            if not re.match(email_pattern, email):
                flash('Alamat email tidak valid.', 'danger')
                return redirect(url_for('find_account'))
            user_exists = check_username_in_db(username)
            email_exists = check_email_in_db(email)

            if user_exists and email_exists:
                verification_code = generate_verification_code()
                session['verification_code'] = verification_code
                session['verification_code_expiry'] = time.time() + 180
                session['username'] = username
                # Kirim kode via email
                msg = Message('Verifikasi Akun Anda',
                              sender='adip98816@gmail.com',
                              recipients=[email])
                safe_code = escape(verification_code)
                msg.html = f"""
                <p>Halo,</p>
                <p>Berikut adalah kode verifikasi 6 digit untuk mengakses akun Anda:</p>
                <h2>{safe_code}</h2>
                <p>Atau klik <a href="{url_for('verify_code', _external=True)}" style="color: blue;">link ini</a> untuk melanjutkan.</p>
                """
                mail.send(msg)
                flash(f'Kode verifikasi telah dikirim ke email {escape(email)}', 'success')
                return redirect(url_for('verify_code'))
            elif not user_exists and not email_exists:
                flash('Username dan email tidak ditemukan.', 'danger')
            elif not user_exists:
                flash('Username tidak ditemukan.', 'danger')
            elif not email_exists:
                flash('Email tidak ditemukan.', 'danger')
    
        # ===== Kondisi 2: Username + Nomor HP =====
        elif phone and not email:
            normalized_phone = normalize_phone_number(phone)
            phone_pattern = r'^\+628\d{7,12}$'
            if not re.match(phone_pattern, normalized_phone):
                flash('Format nomor HP tidak valid. Gunakan nomor Indonesia.', 'danger')
                return redirect(url_for('find_account'))
            # Cek keberadaan username dan nomor HP di database
            user_exists = check_username_in_db(username)
            hp_exists = check_phone_in_db(normalized_phone)
            if user_exists and hp_exists:
                verification_code = generate_verification_code()
                session['verification_code'] = verification_code
                session['verification_code_expiry'] = time.time() + 180  # berlaku 3 menit
                session['username'] = username
                session['phone'] = normalized_phone
                send_whatsapp_code(normalized_phone, verification_code)
                flash(f'Kode verifikasi telah dikirim ke nomor WhatsApp {normalized_phone}', 'success')
                return redirect(url_for('verify_code'))
            # Penanganan error spesifik
            if not user_exists and not hp_exists:
                flash('Username dan nomor HP tidak ditemukan.', 'danger')
            elif not user_exists:
                flash('Username tidak ditemukan.', 'danger')
            elif not hp_exists:
                flash('Nomor HP tidak ditemukan.', 'danger')
            return redirect(url_for('find_account'))
        else:
            flash('Harap isi email atau nomor HP.', 'danger')
        return redirect(url_for('find_account'))
    return render_template('find_account.html')

# Endpoint untuk verify_code
@app.route('/verify_code/', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'GET':
        expiry_time = session.get('verification_code_expiry', 0)
        return render_template('verify_code.html', expiry_time=int(expiry_time))
    # Metode untuk memproses data JSON
    expiry_time = session.get('verification_code_expiry', 0)
    data = request.get_json()
    if not data or 'verification_code' not in data:
        return jsonify({'message': 'Verification code is required.'}), 400
    code = data['verification_code']
    if time.time() > expiry_time:
        return jsonify({'message': 'Verification code has expired.'}), 400
    if 'verification_code' in session and session['verification_code'] == int(code):
        # Generate reset token dan set waktu kedaluwarsa
        reset_token = secrets.token_hex(16)
        expiry_time = datetime.now() + timedelta(minutes=10)
        username = session.get('username')
        user = Users.query.filter_by(username=username).first()
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        # Simpan token dan waktu kedaluwarsa di database lalu sertakan URL reset password dengan token
        user.reset_token = reset_token
        user.token_exp = expiry_time
        db.session.commit()
        reset_password_url = escape(url_for('reset_password', token=reset_token, _external=True))
        return jsonify({
            'message': 'Verification successful.',
            'redirect_url': reset_password_url
        }), 200
    else:
        return jsonify({'message': 'Incorrect verification code.'}), 400
    
# Endpoint Reset Password
@app.route('/reset_password/', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        reset_token = request.args.get('token')
        if not reset_token:
            return jsonify({'error': "Token tidak ditemukan."}), 400
        # Validasi token
        user = Users.query.filter_by(reset_token=reset_token).first()
        if not user or datetime.now() > user.token_exp:
            if user:
                user.reset_token = None
                user.token_exp = None
                db.session.commit()
            return jsonify({'error': "Token tidak valid atau telah kedaluwarsa."}), 400
        # Jika token valid, arahkan ke halaman reset password
        return render_template('reset_password.html', token=escape(reset_token))
    if request.method == 'POST':
        data = request.get_json()
        reset_token = data.get('reset_token')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        # Debug input
        print(f"Reset token: {reset_token}, Password baru: {new_password}")
        # Validasi input
        if not reset_token or not new_password or not confirm_password:
            return jsonify({'error': "Semua data harus diisi."}), 400
        # Validasi pola password
        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        if not re.match(password_pattern, new_password):
            return jsonify({'error': "Password harus terdiri dari minimal 8 karakter, termasuk huruf besar, kecil, angka, dan simbol."}), 400
        if new_password != confirm_password:
            return jsonify({'error': "Password dan konfirmasi password tidak cocok."}), 400
        # Validasi token
        user = Users.query.filter_by(reset_token=reset_token).first()
        if not user:
            return jsonify({'error': "Token reset password tidak valid."}), 400
        if datetime.now() > user.token_exp:
            user.reset_token = None
            user.token_exp = None
            db.session.commit()
            return jsonify({'error': "Token reset password telah kedaluwarsa."}), 400
        # Update password
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
        user.password = hashed_password
        user.reset_token = None
        user.token_exp = None
        db.session.commit()
        print("Password berhasil diubah.")
        return jsonify({'message': "Password Anda telah berhasil diubah!"}), 200
    
# Route Index
@app.route("/")
@app.route("/index/")
def index():
    username = None
    user_data = None
    notification_count = 0
    profile_picture = None
    
    print("session keys:", session.keys())
    print("first_time_login:", session.get("first_time_login"))
    print("Session di /index/:", dict(session))
    first_time = session.get('first_time_login', None)

    # Cek login via session username (manual)
    if 'username' in session:
        username = session['username']
        user = Users.query.filter_by(username=username).first()
        if user:
            notification_count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
            profile_picture = user.foto
        else:
            session.pop('username', None)

    # Cek login via session user (Google OAuth)
    elif 'user' in session:
        user_data = session['user'] 
        username = user_data.get('username')
        profile_picture = user_data.get('foto')
        user_id = user_data.get('id')
        if user_id:
            notification_count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
    return render_template('index.html', username=username, profile_picture=profile_picture, notification_count=notification_count, user_data=user_data, first_time_login=first_time, debug_theme=session.get("theme"))

@app.route("/clear-first-login-flag", methods=["POST"])
@csrf.exempt
def clear_first_login_flag():
    session.pop('first_time_login', None)
    return '', 204

@app.before_request
def check_session():
    print("Session sekarang:", dict(session))
    
@app.route('/set-language/<lang_code>')
def set_language(lang_code):
    if lang_code in ['id', 'en']:
        session['lang'] = lang_code
    return redirect(request.referrer or url_for('index'))

@app.context_processor
def inject_current_lang():
    return dict(current_lang=session.get('lang', 'id'))

@app.route('/set-theme/<theme>', methods=['POST'])
def set_theme(theme):
    if theme in ['light', 'dark']:
        session['theme'] = theme
        session.modified = True
        return '', 204
    return 'Invalid theme', 400

@app.context_processor
def inject_theme():
    return dict(current_theme=session.get('theme', 'light'))

@app.route('/logout/')
def logout():
    session.clear()
    session.pop('username', None)
    flash("Anda telah logout.", "info")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
