# app/models.py
from app import db
from sqlalchemy.dialects.mysql import ENUM
from flask_login import UserMixin
    
# Access to table users
class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column('id', db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    nama_lengkap = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    jenis_kelamin = db.Column(ENUM('Laki-laki', 'Perempuan', name='jenis_kelamin'), nullable=True, default="")
    usia = db.Column(db.String(255), nullable=True, default="0")
    foto = db.Column(db.String(255), default="img/default-user.png")
    nomor_hp = db.Column(db.String(255), nullable=True, default="")
    level = db.Column(ENUM('admin', 'penilai', 'peserta', name='user_level'), nullable=False)
    reset_token = db.Column(db.String(255), nullable=True, default="")
    token_exp = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    login_method = db.Column(db.String(100), nullable=False, default="manual")
    sidebar_state = db.Column(db.String(10), nullable=True, default='expanded')
    status = db.Column(ENUM('aktif', 'non-aktif', name='user_status'), nullable=False, default='aktif', server_default='aktif')
    
    def to_dict(self):
        return {
            'id': self.id,
            'nama_lengkap': self.nama_lengkap,
            'email': self.email,
            'username': self.username,
            'level': self.level,
            'status': self.status,
            'foto': self.foto
        }


# Access to table tb_kegiatan
class Event(db.Model):
    __tablename__ = 'tb_kegiatan'
    id_kegiatan = db.Column(db.Integer, primary_key=True, autoincrement=True)
    jenis_kegiatan = db.Column(db.Enum('siaga','penggalang','penegak','pandega','penegak dan pandega'), nullable=False)
    nama_kegiatan = db.Column(db.String(255), nullable=False)
    waktu_pelaksanaan = db.Column(db.Date, nullable=False)
    tempat_pelaksanaan = db.Column(db.String(100), nullable=False)
    skala_kegiatan = db.Column(db.Enum('ranting','cabang','daerah','nasional','internasional'), nullable=False)
    kwartir_penyelenggara = db.Column(db.String(255), nullable=False)
    mulai = db.Column(db.Date, nullable=False)
    selesai = db.Column(db.Date, nullable=False)
    kuota = db.relationship("Kuota", backref="event", lazy=True, cascade="all, delete-orphan")
    kriteria = db.relationship("Criteria", backref="event", lazy=True, cascade="all, delete-orphan")

class Kuota(db.Model):
    __tablename__ = 'tb_kuota'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("tb_kegiatan.id_kegiatan"), nullable=False, unique=True)
    putra = db.Column(db.Integer, default=0)
    putri = db.Column(db.Integer, default=0)   

# Access to table tb_kriteria
class Criteria(db.Model):
    __tablename__ = 'tb_kriteria'
    id_kriteria = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("tb_kegiatan.id_kegiatan"), nullable=False)
    nama_kriteria = db.Column(db.String(255), nullable=False)
    aspek = db.Column(db.String(255), nullable=True)  
    bobot = db.Column(db.Float, nullable=False)
    deskripsi = db.Column(db.Text, nullable=False)
    jenis_kriteria = db.Column(db.String(255), nullable=False)
    jumlah_soal = db.Column(db.Integer, nullable=True)
    
# Access to table notifications
class Notification(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_read = db.Column(db.Boolean, default=False)
    message = db.Column(db.String(255))

# Access to table participants
class Participants(db.Model):
    __tablename__ = 'participants'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nama_lengkap = db.Column(db.String(100), nullable=True)
    tanggal_lahir = db.Column(db.Date, nullable=False)
    alamat_tinggal = db.Column(db.String(255), nullable=False)
    golongan = db.Column(db.Enum('siaga', 'penggalang', 'penegak', 'pandega', name='golongan_enum'), nullable=False)
    tingkatan = db.Column(db.Enum('siaga mula', 'siaga tata', 'siaga bantu', 'siaga garuda', 'penggalang ramu', 'penggalang rakit', 'penggalang terap', 'penggalang garuda', 'penegak bantara', 'penegak laksana', 'penegak garuda', 'pandega', 'pandega garuda', name='tingkatan_enum'), nullable=False)
    asal_gudep = db.Column(db.String(100), nullable=False)
    asal_kwarran = db.Column(db.String(100), nullable=False)
    asal_kwarcab = db.Column(db.String(100), nullable=False)
    asal_kwarda = db.Column(db.String(100), nullable=False)
    usia = db.Column(db.Integer, nullable=False)
    jenis_kelamin = db.Column(
        db.Enum('laki-laki', 'perempuan', '', '', name='jenis_kelamin_enum'),
        nullable=False)
    email = db.Column(db.String(255), nullable=False)
    nomor_hp = db.Column(db.String(100), nullable=False)
    foto = db.Column(db.String(100), nullable=False)

    # kolom yang selalu berisi "peserta"
    level = db.Column(db.String(50), nullable=False, default="peserta", server_default="peserta")

    def __repr__(self):
        return f"<Participant {self.nama_lengkap}>"

# Access to table himpunan_kriteria
class HimpunanKriteria(db.Model):
    __tablename__ = 'himpunan_kriteria'
    id_himpunan = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_kriteria = db.Column(db.Integer, db.ForeignKey('tb_kriteria.id_kriteria'), nullable=False)
    nama_himpunan = db.Column(db.String(255), nullable=False)
    nilai_himpunan = db.Column(db.Float, nullable=False)

# Access to table tb_penilaian
class Penilaian(db.Model):
    __tablename__ = 'tb_penilaian'
    id_penilaian = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_users = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    id_kriteria = db.Column(db.Integer, db.ForeignKey('tb_kriteria.id_kriteria'), nullable=False)
    nilai = db.Column(db.Float, nullable=False)


# Access to table tb_hasil_seleksi
class HasilSeleksi(db.Model):
    __tablename__ = 'tb_hasil_seleksi'
    id_hasil = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_users = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    skor_akhir = db.Column(db.Float, nullable=False)
    ranking = db.Column(db.Integer, nullable=False)

# Access to table tb_log_aktivitas
class LogAktivitas(db.Model):
    __tablename__ = 'tb_log_aktivitas'
    id_log = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    aktivitas = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    
    user = db.relationship('Users', backref='logs')

# Access to table tb_informasi
class Informasi(db.Model):
    __tablename__ = 'tb_informasi'
    id_informasi = db.Column(db.Integer, primary_key=True, autoincrement=True)
    judul = db.Column(db.String(255), nullable=False)
    isi = db.Column(db.Text, nullable=False)
    tanggal = db.Column(db.Date, server_default=db.func.current_date())
