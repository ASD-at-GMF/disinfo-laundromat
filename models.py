from datetime import datetime
from flask_login import UserMixin

from init_app import get_db, db


class Query(db.Model):
    __tablename__ = 'content_queries'

    # Auto Generated Fields:
    id           = db.Column(db.Integer, primary_key=True,  autoincrement=True)
    created      = db.Column(db.DateTime(timezone=True), default=datetime.now)
    updated      = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Input by Query Fields:
    title        = db.Column(db.String(100), nullable=False, unique=False)
    content      = db.Column(db.String(100), nullable=False, unique=False)
    combine_operator = db.Column(db.String(100), nullable=True, unique=False)
    language     = db.Column(db.String(100), nullable=True, unique=False)
    country      = db.Column(db.String(100), nullable=True, unique=False)


class Result(db.Model):
    __tablename__ = 'content_queries_results'

    # Auto Generated Fields:
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created      = db.Column(db.DateTime(timezone=True), default=datetime.now)
    updated      = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Input by Query Fields:
    domain       = db.Column(db.String(100), nullable=False, unique=False)
    occurrences  = db.Column(db.Integer(), nullable=False, unique=False)
    title        = db.Column(db.String(100), nullable=True, unique=False)
    link         = db.Column(db.String(100), nullable=True, unique=False)
    link_occurrences      = db.Column(db.Integer(), nullable=True, unique=False)
    engines      = db.Column(db.String(100), nullable=True, unique=False)
    cq_id        = db.Column(db.String(100), nullable=True, unique=False)

class SiteIndicator(db.Model):
    __tablename__ = 'site_fingerprint'

    # Auto Generated Fields:
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created      = db.Column(db.DateTime(timezone=True), default=datetime.now)
    updated      = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Input by Query Fields:
    indicator_type        = db.Column(db.String(100), nullable=False, unique=False)
    indicator_content     = db.Column(db.String(100), nullable=False, unique=False)
    domain        = db.Column(db.String(100), nullable=False, unique=False)

class SiteBase(db.Model):
    __tablename__ = 'sites_base'

    # Auto Generated Fields:
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created      = db.Column(db.DateTime(timezone=True), default=datetime.now)
    updated      = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Input by Query Fields:
    domain       = db.Column(db.String(100), nullable=False, unique=False)
    source       = db.Column(db.String(100), nullable=False, unique=False)

class SiteUser(db.Model):
    __tablename__ = 'sites_user'

    # Auto Generated Fields:
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created      = db.Column(db.DateTime(timezone=True), default=datetime.now)
    updated      = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Input by Query Fields:
    domain       = db.Column(db.String(100), nullable=False, unique=False)
    source       = db.Column(db.String(100), nullable=False, unique=False)

class User(UserMixin):
    __tablename__ = 'users'

    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password


    @classmethod
    def get(cls, id):
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (id,))
        user = cursor.fetchone()
        if user:
            return cls(id=user[0], username=user[1], password=user[2])
        return None