# Panduan Menjalankan Projek Fuzzy AHP

Projek ini adalah aplikasi web berbasis Flask untuk sistem pendukung keputusan menggunakan metode Fuzzy AHP (Analytic Hierarchy Process).

## Persyaratan Sistem

- Python 3.8 atau lebih tinggi
- MySQL Server
- pip (Python package manager)

## Langkah-langkah Instalasi dan Menjalankan

### 1. Clone atau Download Projek

Pastikan Anda sudah memiliki projek ini di komputer Anda.

### 2. Setup Database MySQL

1. Pastikan MySQL Server sudah terinstall dan berjalan
2. Buat database baru dengan nama `fuzzy_ahp`:
   ```sql
   CREATE DATABASE fuzzy_ahp;
   ```
3. Atau sesuaikan konfigurasi database di file `config.py` sesuai dengan setup MySQL Anda:
   ```python
   SQLALCHEMY_DATABASE_URI = "mysql+pymysql://username:password@localhost:3306/fuzzy_ahp"
   ```

### 3. Setup Virtual Environment (Opsional tapi Disarankan)

Jika virtual environment belum aktif:

**Windows:**
```bash
venv\Scripts\activate
```

**Linux/Mac:**
```bash
source venv/bin/activate
```

### 4. Install Dependencies

Install semua package yang diperlukan:

```bash
pip install -r requirements.txt
```

Jika ada error, install package tambahan yang mungkin diperlukan:
```bash
pip install Flask-Login pymysql openpyxl pandas
```

### 5. Setup Environment Variables

Buat file `.env` di root directory projek dengan isi berikut:

```env
APP_SECRET_KEY=your-secret-key-here
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-email-password
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
SECRET_KEY=your-secret-key-here
```

**Catatan:** 
- Ganti nilai-nilai di atas dengan kredensial Anda sendiri
- Jika tidak menggunakan fitur email/WhatsApp/Google OAuth, Anda bisa menggunakan nilai dummy untuk sementara

### 6. Inisialisasi Database

Jalankan aplikasi sekali untuk membuat tabel-tabel database secara otomatis:

```bash
python run.py
```

Aplikasi akan membuat tabel-tabel yang diperlukan secara otomatis saat pertama kali dijalankan.

### 7. Menjalankan Aplikasi

Jalankan aplikasi dengan perintah:

```bash
python run.py
```

Atau:

```bash
flask run
```

Aplikasi akan berjalan di `http://localhost:5000` atau `http://127.0.0.1:5000`

### 8. Akses Aplikasi

Buka browser dan akses:
- **URL:** http://localhost:5000
- **Halaman Login:** http://localhost:5000/login/

## Struktur Projek

```
fuzzy-ahp/
├── app/                    # Folder aplikasi utama
│   ├── __init__.py        # Inisialisasi Flask app
│   ├── models.py          # Model database
│   ├── fuzzy_ahp.py       # Logika Fuzzy AHP
│   ├── routes/            # Route handlers
│   ├── templates/         # Template HTML
│   ├── static/            # File statis (CSS, JS, images)
│   └── utils/             # Utility functions
├── config.py              # Konfigurasi aplikasi
├── forms.py               # Form definitions
├── run.py                 # File utama untuk menjalankan aplikasi
├── requirements.txt       # Dependencies Python
└── README.md             # File ini
```

## Troubleshooting

### Error: Module not found
Jika ada error module tidak ditemukan, install package yang hilang:
```bash
pip install nama-package
```

### Error: Database connection failed
1. Pastikan MySQL Server berjalan
2. Periksa kredensial database di `config.py`
3. Pastikan database `fuzzy_ahp` sudah dibuat

### Error: Port already in use
Jika port 5000 sudah digunakan, ubah di `run.py`:
```python
app.run(debug=True, port=5001)
```

### Error: Environment variables not found
Pastikan file `.env` sudah dibuat dan berisi semua variabel yang diperlukan.

## Fitur Aplikasi

- Sistem autentikasi (Login/Register)
- Manajemen pengguna (Admin)
- Manajemen seleksi
- Sistem penilaian dengan Fuzzy AHP
- Dashboard untuk Admin, Penilai, dan Peserta
- Notifikasi sistem
- Log aktivitas

## Catatan Penting

- Pastikan semua dependencies sudah terinstall
- Database harus sudah dibuat sebelum menjalankan aplikasi
- File `.env` diperlukan untuk konfigurasi aplikasi
- Mode debug aktif secara default (untuk development)

## Support

Jika ada masalah atau pertanyaan, silakan hubungi developer atau buat issue di repository projek.


