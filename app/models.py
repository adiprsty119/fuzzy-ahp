# app/models.py
from app import db
from sqlalchemy.dialects.mysql import ENUM
    
# Access to table users
class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column('id', db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    nama_lengkap = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    jenis_kelamin = db.Column(db.String(255), nullable=False)
    usia = db.Column(db.String(255), nullable=False)
    foto = db.Column(db.String(255), default="img/default-user.png")
    nomor_hp = db.Column(db.String(255), nullable=False)
    level = db.Column(ENUM('admin', 'user', name='user_level'), nullable=False)
    reset_token = db.Column(db.String(255), nullable=True, default="")
    token_exp = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    login_method = db.Column(db.String(100), nullable=False)

# Access to table notifications
class Notification(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_read = db.Column(db.Boolean, default=False)
    message = db.Column(db.String(255))