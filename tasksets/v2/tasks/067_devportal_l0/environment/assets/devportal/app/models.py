from . import db
from datetime import datetime


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    api_keys = db.relationship('ApiKey', backref='user', lazy=True)
    projects = db.relationship('Project', backref='owner', lazy=True)


class ApiKey(db.Model):
    __tablename__ = 'api_keys'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(128), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    label = db.Column(db.String(64), nullable=False)
    permissions = db.Column(db.String(128), default='read')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, nullable=True)


class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    repo_url = db.Column(db.String(256), nullable=False)
    deploy_hook = db.Column(db.String(256), nullable=True)
    webhook_secret = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
