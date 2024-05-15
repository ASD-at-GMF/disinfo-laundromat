from datetime import datetime
from flask_login import UserMixin

from init_app import db


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


class RegistrationKey(db.Model):
    __tablename__ = 'registration_keys'

    registration_keys    = db.Column(db.String(100), primary_key=True, nullable=False, unique=True)

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

class Site(db.Model):
    __tablename__ = 'sites'

    # Auto Generated Fields:
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created      = db.Column(db.DateTime(timezone=True), default=datetime.now)
    updated      = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    # Input by Query Fields:
    domain       = db.Column(db.String(100), nullable=False, unique=False)
    source       = db.Column(db.String(100), nullable=False, unique=False)
    is_base    = db.Column(db.Boolean, nullable=False, unique=False, default=False)

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password = db.Column(db.String(255), nullable=False, default='')