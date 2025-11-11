# 🔧 Konfigurasi Database MySQL

## 📍 Lokasi File Konfigurasi

Settingan username dan password database ada di file **`config.py`** (baris 13-17).

## 🔐 Cara Mengubah Username dan Password Database

### **Cara 1: Menggunakan File `.env` (DISARANKAN)** ✅

Tambahkan konfigurasi database di file `.env`:

```env
# Konfigurasi Database MySQL
DB_USERNAME=root
DB_PASSWORD=password_anda
DB_HOST=localhost
DB_PORT=3306
DB_NAME=fuzzy_ahp
```

**Contoh:**
- Jika username: `root` dan password: `123456`
  ```env
  DB_USERNAME=root
  DB_PASSWORD=123456
  ```

- Jika username: `admin` dan password: `mypassword123`
  ```env
  DB_USERNAME=admin
  DB_PASSWORD=mypassword123
  ```

- Jika tidak ada password (kosong):
  ```env
  DB_USERNAME=root
  DB_PASSWORD=
  ```

### **Cara 2: Langsung Edit File `config.py`** 

Edit file `config.py` dan ubah nilai default:

```python
DB_USERNAME = os.environ.get("DB_USERNAME") or "root"          # Ganti "root" dengan username Anda
DB_PASSWORD = os.environ.get("DB_PASSWORD") or "password123"   # Ganti "password123" dengan password Anda
DB_HOST = os.environ.get("DB_HOST") or "localhost"             # Ganti jika host berbeda
DB_PORT = os.environ.get("DB_PORT") or "3306"                  # Ganti jika port berbeda
DB_NAME = os.environ.get("DB_NAME") or "fuzzy_ahp"             # Ganti jika nama database berbeda
```

## 📋 Format Connection String

Format connection string MySQL:
```
mysql+pymysql://username:password@host:port/database_name
```

**Contoh:**
- Username: `root`, Password: `123456`, Host: `localhost`, Port: `3306`, Database: `fuzzy_ahp`
  ```
  mysql+pymysql://root:123456@localhost:3306/fuzzy_ahp
  ```

- Username: `admin`, Password: `mypass`, Host: `localhost`, Port: `3307`, Database: `fuzzy_ahp`
  ```
  mysql+pymysql://admin:mypass@localhost:3307/fuzzy_ahp
  ```

- Username: `root`, Tidak ada password, Host: `localhost`, Port: `3306`, Database: `fuzzy_ahp`
  ```
  mysql+pymysql://root:@localhost:3306/fuzzy_ahp
  ```

## 🔍 Contoh Konfigurasi

### **Contoh 1: XAMPP (Default)**
```env
DB_USERNAME=root
DB_PASSWORD=
DB_HOST=localhost
DB_PORT=3306
DB_NAME=fuzzy_ahp
```

### **Contoh 2: MySQL dengan Password**
```env
DB_USERNAME=root
DB_PASSWORD=MySecurePassword123
DB_HOST=localhost
DB_PORT=3306
DB_NAME=fuzzy_ahp
```

### **Contoh 3: Remote Database**
```env
DB_USERNAME=admin
DB_PASSWORD=SecurePassword
DB_HOST=192.168.1.100
DB_PORT=3306
DB_NAME=fuzzy_ahp
```

### **Contoh 4: Port Custom**
```env
DB_USERNAME=root
DB_PASSWORD=password123
DB_HOST=localhost
DB_PORT=3307
DB_NAME=fuzzy_ahp
```

## ✅ Langkah-langkah Setup

1. **Pastikan MySQL Server berjalan**
   - XAMPP: Jalankan MySQL dari Control Panel
   - WAMP: Pastikan MySQL service running
   - MySQL Standalone: Pastikan MySQL service running

2. **Buat database `fuzzy_ahp`**
   ```sql
   CREATE DATABASE fuzzy_ahp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```

3. **Tambahkan konfigurasi di file `.env`**
   ```env
   DB_USERNAME=root
   DB_PASSWORD=password_anda
   DB_HOST=localhost
   DB_PORT=3306
   DB_NAME=fuzzy_ahp
   ```

4. **Test koneksi database**
   ```python
   from app import create_app, db
   app = create_app()
   with app.app_context():
       try:
           db.engine.connect()
           print("✅ Koneksi database berhasil!")
       except Exception as e:
           print(f"❌ Error: {e}")
   ```

## 🐛 Troubleshooting

### **Error: Access denied for user**
**Penyebab:** Username atau password salah
**Solusi:** 
- Periksa username dan password di file `.env`
- Pastikan user MySQL memiliki akses ke database

### **Error: Can't connect to MySQL server**
**Penyebab:** MySQL server tidak berjalan atau host/port salah
**Solusi:**
- Pastikan MySQL server berjalan
- Periksa host dan port di file `.env`
- Test koneksi dengan:
  ```bash
  mysql -u root -p -h localhost -P 3306
  ```

### **Error: Unknown database 'fuzzy_ahp'**
**Penyebab:** Database belum dibuat
**Solusi:**
```sql
CREATE DATABASE fuzzy_ahp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### **Error: Module 'pymysql' not found**
**Solusi:**
```bash
pip install pymysql
```

## 📝 Catatan Penting

1. **Jangan commit file `.env` ke repository** (sudah ada di `.gitignore`)
2. **Gunakan environment variables** untuk konfigurasi yang sensitif
3. **Pastikan database sudah dibuat** sebelum menjalankan aplikasi
4. **Test koneksi database** setelah mengubah konfigurasi
5. **Backup database** secara rutin

## 🔒 Keamanan

- ✅ Gunakan password yang kuat untuk database
- ✅ Jangan hardcode password di file `config.py`
- ✅ Gunakan file `.env` untuk menyimpan kredensial
- ✅ Jangan commit file `.env` ke repository
- ✅ Gunakan user database dengan privileges yang terbatas (bukan root) untuk production

---

**Selamat mengkonfigurasi database! 🎉**

