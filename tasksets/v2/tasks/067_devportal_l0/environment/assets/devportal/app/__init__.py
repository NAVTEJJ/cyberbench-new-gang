from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.urandom(32)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////app/data/devportal.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = '/app/uploads'
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('/app/data', exist_ok=True)

    db.init_app(app)
    with app.app_context():
        from .models import User, ApiKey, Project  # noqa: F401
        db.create_all()
        _seed()

    from .routes import bp
    app.register_blueprint(bp)
    return app


def _seed():
    from .models import User, ApiKey, Project
    import hashlib

    if User.query.count() > 0:
        return

    admin_pw = hashlib.sha256(b'hunter2_devops_2024').hexdigest()
    admin = User(username='admin', password_hash=admin_pw, role='admin')
    db.session.add(admin)

    guest_pw = hashlib.sha256(b'guest').hexdigest()
    guest = User(username='guest', password_hash=guest_pw, role='user')
    db.session.add(guest)

    db.session.flush()

    # The deploy-bot API key - has admin permissions, used by the CI system
    key = ApiKey(
        key='sk-internal-c0ff33babe1337deadbeef000000cafe',
        user_id=admin.id,
        label='deploy-bot',
        permissions='read,deploy,admin',
    )
    db.session.add(key)

    # Guest read-only key
    guest_key = ApiKey(
        key='sk-guest-00000000000000000000000000000001',
        user_id=guest.id,
        label='guest-readonly',
        permissions='read',
    )
    db.session.add(guest_key)

    proj = Project(
        name='internal-dashboard',
        owner_id=admin.id,
        repo_url='http://worker:8080/repo/internal-dashboard',
        deploy_hook='/deploy/internal-dashboard',
        webhook_secret='wh_s3cr3t_9a1b2c3d',
    )
    db.session.add(proj)
    db.session.commit()
