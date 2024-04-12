from ..app import db
from datetime import datetime
from flask_login import UserMixin
from modules.db.utils import get_db

class Query(db.Model):
    # Auto Generated Fields:
    id           = db.Column(db.String(50), primary_key=True, nullable=False, unique=True)
    created      = db.Column(db.DateTime(timezone=True), default=datetime.now)
    updated      = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Input by Query Fields:
    title        = db.Column(db.String(100), nullable=False, unique=False)
    content      = db.Column(db.String(100), nullable=False, unique=False)
    combine_operator = db.Column(db.String(100), nullable=True, unique=False)
    language     = db.Column(db.String(100), nullable=True, unique=False)
    country      = db.Column(db.String(100), nullable=True, unique=False)


class Result(db.Model):
    # Auto Generated Fields:
    id           = db.Column(db.String(50), primary_key=True, nullable=False, unique=True)
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
    # Auto Generated Fields:
    id           = db.Column(db.String(50), primary_key=True, nullable=False, unique=True)
    created      = db.Column(db.DateTime(timezone=True), default=datetime.now)
    updated      = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Input by Query Fields:
    indicator_type        = db.Column(db.String(100), nullable=False, unique=False)
    indicator_content     = db.Column(db.String(100), nullable=False, unique=False)
    domain        = db.Column(db.String(100), nullable=False, unique=False)

class SiteBase(db.Model):
    # Auto Generated Fields:
    id           = db.Column(db.String(50), primary_key=True, nullable=False, unique=True)
    created      = db.Column(db.DateTime(timezone=True), default=datetime.now)
    updated      = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Input by Query Fields:
    domain       = db.Column(db.String(100), nullable=False, unique=False)
    source       = db.Column(db.String(100), nullable=False, unique=False)

class SiteUser(db.Model):
    # Auto Generated Fields:
    id           = db.Column(db.String(50), primary_key=True, nullable=False, unique=True)
    created      = db.Column(db.DateTime(timezone=True), default=datetime.now)
    updated      = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Input by Query Fields:
    domain       = db.Column(db.String(100), nullable=False, unique=False)
    source       = db.Column(db.String(100), nullable=False, unique=False)

class User(UserMixin):
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