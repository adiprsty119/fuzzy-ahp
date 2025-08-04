import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

db = SQLAlchemy()

def create_app():
    basedir = os.path.abspath(os.path.dirname(__file__))
    template_dir = os.path.join(basedir, "templates")
    static_dir = os.path.join(basedir, "static")

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config.from_object(Config)

    db.init_app(app)

    with app.app_context():
        from app import models
        db.create_all()

    return app
