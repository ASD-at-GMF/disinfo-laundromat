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
    title        = db.Column(db.String(300), nullable=True, unique=False)
    content      = db.Column(db.String(300), nullable=True, unique=False)
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
    domain       = db.Column(db.String(255), nullable=True, unique=False)
    url          = db.Column(db.String(255), nullable=True, unique=False)
    title        = db.Column(db.String(255), nullable=True, unique=False)
    snippet      = db.Column(db.Text, nullable=True, unique=False)
    engine       = db.Column(db.String(255), nullable=True, unique=False)
    link_count   = db.Column(db.Integer, nullable=True, unique=False)
    domain_count = db.Column(db.Integer, nullable=True, unique=False)
    engines      = db.Column(db.String(255), nullable=True, unique=False)
    score        = db.Column(db.Float, nullable=True, unique=False)
    query_id     = db.Column(db.Integer, db.ForeignKey('content_queries.id'), nullable=False)


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
    indicator_content     = db.Column(db.Text, nullable=True, unique=False)
    domain        = db.Column(db.String(100), nullable=False, unique=False)
    indicator_annotation  = db.Column(db.String(100), nullable=True, unique=False)

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

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password = db.Column(db.String(255), nullable=False, default='')