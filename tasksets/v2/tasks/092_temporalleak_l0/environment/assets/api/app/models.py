from . import db
from datetime import datetime


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), default='operator')
    workflows = db.relationship('Workflow', backref='owner', lazy=True)


class Workflow(db.Model):
    __tablename__ = 'workflows'
    id = db.Column(db.Integer, primary_key=True)
    workflow_id = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(128), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(16), default='pending')
    definition = db.Column(db.Text, default='{}')
    tasks = db.relationship('Task', backref='workflow', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(64), nullable=False)
    workflow_id = db.Column(db.Integer, db.ForeignKey('workflows.id'), nullable=False)
    task_type = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(16), default='pending')
    position = db.Column(db.Integer, default=0)
    parameters = db.Column(db.Text, default='{}')
    execution_history = db.Column(db.Text, default='[]')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
