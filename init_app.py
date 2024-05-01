import os
import sqlite3
from flask import Flask, g
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
# from flask_migrate import Migrate

from config import config

APP_SECRET_KEY = os.getenv('APP_SECRET_KEY', '')
SQLLITE_DB_PATH = os.getenv('SQLLITE_DB_PATH', '')

db = SQLAlchemy()
# migrate = Migrate()

def init_app(config_mode):
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})
    app.secret_key = APP_SECRET_KEY  # Set a secret key for security purposes
    app.config.from_object(config["development"])
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_SECURE'] = True
    db.init_app(app)
    # migrate.init_app(app, db)

    return app

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(SQLLITE_DB_PATH)
        # This enables column access by name: row['column_name']
        db.row_factory = sqlite3.Row
    return db