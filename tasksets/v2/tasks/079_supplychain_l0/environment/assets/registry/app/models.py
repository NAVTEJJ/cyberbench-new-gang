from . import db
from datetime import datetime


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), default='reader')
    packages = db.relationship('Package', backref='owner', lazy=True)


class Package(db.Model):
    __tablename__ = 'packages'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    version = db.Column(db.String(32), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(16), default='unverified')   # unverified, verified, revoked
    checksum = db.Column(db.String(128), nullable=True)
    manifest = db.Column(db.Text, default='{}')
    build_output = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class BuildLog(db.Model):
    __tablename__ = 'build_logs'
    id = db.Column(db.Integer, primary_key=True)
    package_name = db.Column(db.String(128))
    version = db.Column(db.String(32))
    log = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CollectedData(db.Model):
    __tablename__ = 'collected_data'
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(256))
    payload = db.Column(db.Text)
    received_at = db.Column(db.DateTime, default=datetime.utcnow)
