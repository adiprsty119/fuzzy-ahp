# 🚀 Panduan Menjalankan Projek Flask Fuzzy AHP

## 📋 Persyaratan Sistem

- **Python 3.8 atau lebih tinggi** (disarankan Python 3.10+)
- **MySQL Server** (XAMPP, WAMP, atau MySQL standalone)
- **pip** (Python package manager)
- **Git** (opsional, untuk clone repository)

## 📦 Langkah-langkah Instalasi

### 1. Setup Database MySQL

1. **Pastikan MySQL Server sudah berjalan**
   - Jika menggunakan XAMPP, jalankan MySQL dari Control Panel
   - Atau pastikan MySQL service berjalan di Windows Services

2. **Buat database baru:**
   ```sql
   CREATE DATABASE fuzzy_ahp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```

3. **Atau sesuaikan koneksi database di `config.py`:**
   ```python
   SQLALCHEMY_DATABASE_URI = "mysql+pymysql://username:password@localhost:3306/fuzzy_ahp"
   ```
   - Ganti `username` dengan username MySQL Anda (default: `root`)
   - Ganti `password` dengan password MySQL Anda (kosongkan jika tidak ada password)
   - Pastikan port MySQL adalah `3306` (default)

### 2. Setup Virtual Environment (Opsional tapi Disarankan)

Virtual environment sudah tersedia di folder `venv`. Aktifkan dengan:

**Windows (PowerShell):**
```powershell
.\venv\Scripts\Activate.ps1
```

**Windows (CMD):**
```cmd
venv\Scripts\activate.bat
```

**Jika virtual environment belum ada, buat baru:**
```bash
python -m venv venv
```

### 3. Install Dependencies

Install semua package yang diperlukan:

```bash
pip install -r requirements.txt
```

**Jika ada error, install package secara manual:**
```bash
pip install Flask Flask-Session Flask-Mail Flask-Login Flask-SQLAlchemy Flask-WTF Flask-Limiter
pip install pymysql openpyxl pandas python-dotenv
pip install Twilio Authlib Werkzeug
```

### 4. Setup Environment Variables

Buat file `.env` di root directory projek (satu folder dengan `run.py`) dengan isi:

```env
APP_SECRET_KEY=your-secret-key-here-change-this-to-random-string
SECRET_KEY=your-secret-key-here-change-this-to-random-string
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password-here
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

**Catatan:**
- Ganti semua nilai dengan kredensial Anda sendiri
- Untuk `APP_SECRET_KEY` dan `SECRET_KEY`, gunakan string acak yang aman (minimal 32 karakter)
- Jika tidak menggunakan fitur email/WhatsApp/Google OAuth, gunakan nilai dummy untuk sementara
- File `.env` tidak akan di-commit ke repository (sudah ada di .gitignore)

**Cara membuat Secret Key:**
```python
import secrets
print(secrets.token_hex(32))
```

### 5. Inisialisasi Database

Jalankan aplikasi untuk pertama kali untuk membuat tabel-tabel database secara otomatis:

```bash
python run.py
```

Aplikasi akan membuat tabel-tabel yang diperlukan secara otomatis saat pertama kali dijalankan (melalui `db.create_all()` di `app/__init__.py`).

**Atau buat tabel secara manual:**
```python
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
    print("Database tables created successfully!")
```

### 6. Menjalankan Aplikasi

Jalankan aplikasi dengan perintah:

```bash
python run.py
```

Aplikasi akan berjalan di:
- **URL:** http://localhost:5000
- **URL:** http://127.0.0.1:5000

**Atau menggunakan Flask CLI:**
```bash
flask run
```

### 7. Akses Aplikasi

Buka browser dan akses:
- **Halaman Utama:** http://localhost:5000
- **Halaman Login:** http://localhost:5000/login/
- **Halaman Register:** http://localhost:5000/register/

## 🔧 Troubleshooting

### Error: Module not found
**Solusi:**
```bash
pip install nama-package-yang-hilang
```

Atau install ulang semua dependencies:
```bash
pip install -r requirements.txt --upgrade
```

### Error: Database connection failed
**Solusi:**
1. Pastikan MySQL Server berjalan
2. Periksa kredensial database di `config.py`
3. Pastikan database `fuzzy_ahp` sudah dibuat
4. Pastikan port MySQL adalah `3306` (default)
5. Pastikan `pymysql` sudah terinstall: `pip install pymysql`

### Error: Port 5000 already in use
**Solusi:**
Ubah port di `run.py`:
```python
if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Ganti dengan port lain
```

Atau matikan aplikasi yang menggunakan port 5000:
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### Error: Environment variables not found
**Solusi:**
1. Pastikan file `.env` sudah dibuat di root directory
2. Pastikan file `.env` berisi semua variabel yang diperlukan
3. Pastikan `python-dotenv` sudah terinstall: `pip install python-dotenv`

### Error: Cannot connect to MySQL
**Solusi:**
1. Pastikan MySQL Server berjalan
2. Periksa kredensial di `config.py`
3. Pastikan database `fuzzy_ahp` sudah dibuat
4. Uji koneksi MySQL:
   ```python
   import pymysql
   connection = pymysql.connect(
       host='localhost',
       user='root',
       password='',
       database='fuzzy_ahp'
   )
   print("Connection successful!")
   connection.close()
   ```

### Error: CSRF token missing
**Solusi:**
1. Pastikan `SECRET_KEY` sudah di-set di file `.env`
2. Pastikan `Flask-WTF` sudah terinstall
3. Clear browser cache dan cookies
4. Restart aplikasi

## 📁 Struktur Projek

```
fuzzy-ahp/
├── app/                    # Folder aplikasi utama
│   ├── __init__.py        # Inisialisasi Flask app
│   ├── models.py          # Model database
│   ├── fuzzy_ahp.py       # Logika Fuzzy AHP
│   ├── routes/            # Route handlers
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   └── main.py
│   ├── templates/         # Template HTML
│   ├── static/            # File statis (CSS, JS, images)
│   │   ├── css/
│   │   ├── js/
│   │   └── images/
│   ├── utils/             # Utility functions
│   │   └── utils.py
│   └── flask_session/     # Session files
├── config.py              # Konfigurasi aplikasi
├── forms.py               # Form definitions
├── run.py                 # File utama untuk menjalankan aplikasi
├── requirements.txt       # Dependencies Python
├── .env                   # Environment variables (buat sendiri)
└── README.md             # Dokumentasi
```

## 🎯 Fitur Aplikasi

- ✅ Sistem autentikasi (Login/Register)
- ✅ Login dengan Google OAuth
- ✅ Manajemen pengguna (Admin)
- ✅ Manajemen seleksi
- ✅ Sistem penilaian dengan Fuzzy AHP
- ✅ Dashboard untuk Admin, Penilai, dan Peserta
- ✅ Notifikasi sistem
- ✅ Log aktivitas
- ✅ Import/Export data Excel
- ✅ Reset password via email/WhatsApp

## 📝 Catatan Penting

1. **Database:** Pastikan database `fuzzy_ahp` sudah dibuat sebelum menjalankan aplikasi
2. **Environment Variables:** File `.env` diperlukan untuk konfigurasi aplikasi
3. **Dependencies:** Pastikan semua dependencies sudah terinstall
4. **Mode Debug:** Mode debug aktif secara default (untuk development)
5. **Secret Key:** Gunakan secret key yang aman dan unik untuk production

## 🚀 Menjalankan di Production

Untuk production, disarankan:
1. Nonaktifkan mode debug: `app.run(debug=False)`
2. Gunakan web server seperti Gunicorn atau uWSGI
3. Setup reverse proxy dengan Nginx
4. Gunakan HTTPS
5. Setup environment variables di server
6. Backup database secara rutin

## 📞 Support

Jika ada masalah atau pertanyaan, silakan:
1. Periksa file `README.md`
2. Periksa error log di console
3. Periksa file `login.log` untuk log aktivitas
4. Hubungi developer atau buat issue di repository

---

**Selamat mencoba! 🎉**

