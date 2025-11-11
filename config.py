# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "secret-key-123"
    
    # Konfigurasi Database MySQL
    # Format: mysql+pymysql://username:password@host:port/database_name
    # Jika tidak menggunakan environment variables, gunakan nilai default di bawah
    DB_USERNAME = os.environ.get("DB_USERNAME") or "root"
    DB_PASSWORD = os.environ.get("DB_PASSWORD") or "rahasia"
    DB_HOST = os.environ.get("DB_HOST") or "localhost"
    DB_PORT = os.environ.get("DB_PORT") or "3306"
    DB_NAME = os.environ.get("DB_NAME") or "fuzzy_ahp"
    
    # Membuat connection string
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False