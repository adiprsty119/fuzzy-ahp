# config.py
import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "secret-key-123"
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:@localhost:3306/fuzzy_ahp"
    SQLALCHEMY_TRACK_MODIFICATIONS = False