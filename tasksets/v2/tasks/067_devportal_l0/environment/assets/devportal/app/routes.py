"""
Developer Portal - routes.py

This application simulates a self-hosted CI/CD developer portal.
It has three intentional developer mistakes that form the exploit chain:

1. The /api/projects endpoint leaks webhook_secret for any authenticated
   session - the developer assumed only admins would see projects, but
   forgot that the guest API key also has 'read' permission.

2. The /webhook/<project_name> endpoint verifies the signature using
   hmac.compare_digest but reads the secret from the DB record using the
   project name supplied by the caller (not the verified project name from
   the request body).  A crafted X-Project-Name header lets an attacker
   trigger the deploy hook for *any* project using the leaked webhook_secret
   from any project.

3. The deploy hook calls the internal worker service at http://worker:8080
   to run the deployment.  The worker service exposes /run?cmd=<command>
   and trusts any caller on the internal Docker network.  The devportal
   passes the project's repo_url directly to the worker as the deploy
   target - but it does NOT validate that the URL is a real git URL.
   An attacker-controlled repo_url (set via PATCH /api/projects/<name>
   with the admin API key) pointing to http://main:PORT/evil can redirect
   the worker to fetch from the attacker's server instead.

The full chain:
  enumerate API → leak webhook_secret via /api/projects (guest key)
  → forge webhook signature for internal-dashboard
  → trigger deploy → worker fetches repo_url
  → repo_url already patched to http://main:9999/evil via admin API key
  → worker executes post-receive hook → reads /flag.txt → exfils to attacker
"""

import hashlib
import hmac
import json
import os
import re

import requests
from flask import Blueprint, jsonify, request, render_template, session, redirect, url_for

from . import db
from .models import User, ApiKey, Project

bp = Blueprint('main', __name__)

FLAG_PATH = '/flag.txt'


# ---------------------------------------------------------------------------
# Helper: authenticate via session cookie or Authorization: Bearer sk-...
# ---------------------------------------------------------------------------
def _auth():
    """Return (user, api_key_obj) or (None, None)."""
    # Session-based auth
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return user, None

    # Bearer token
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        raw_key = auth[7:].strip()
        key_obj = ApiKey.query.filter_by(key=raw_key).first()
        if key_obj:
            from datetime import datetime
            key_obj.last_used = datetime.utcnow()
            db.session.commit()
            return key_obj.user, key_obj

    # X-Api-Key header (alternate form - same lookup)
    raw_key = request.headers.get('X-Api-Key', '')
    if raw_key:
        key_obj = ApiKey.query.filter_by(key=raw_key).first()
        if key_obj:
            return key_obj.user, key_obj

    return None, None


def _has_perm(api_key_obj, perm):
    if api_key_obj is None:
        return True  # session-based users have full access
    perms = [p.strip() for p in api_key_obj.permissions.split(',')]
    return perm in perms or 'admin' in perms


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------
@bp.route('/')
def index():
    return render_template('index.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        user = User.query.filter_by(username=username, password_hash=pw_hash).first()
        if user:
            session['user_id'] = user.id
            return redirect(url_for('main.dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.index'))


@bp.route('/dashboard')
def dashboard():
    user, _ = _auth()
    if not user:
        return redirect(url_for('main.login'))
    projects = Project.query.filter_by(owner_id=user.id).all()
    return render_template('dashboard.html', user=user, projects=projects)


# ---------------------------------------------------------------------------
# API - Projects
# ---------------------------------------------------------------------------
@bp.route('/api/projects', methods=['GET'])
def api_list_projects():
    """
    BUG: returns full project row including webhook_secret for any
    authenticated caller, not just admin.  Developer thought 'read'
    permission was fine because it's just project metadata.
    """
    user, key_obj = _auth()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    if not _has_perm(key_obj, 'read'):
        return jsonify({'error': 'forbidden'}), 403

    projects = Project.query.all()
    result = []
    for p in projects:
        result.append({
            'id': p.id,
            'name': p.name,
            'owner': p.owner.username,
            'repo_url': p.repo_url,
            'deploy_hook': p.deploy_hook,
            'webhook_secret': p.webhook_secret,   # <-- LEAKED
            'created_at': p.created_at.isoformat(),
        })
    return jsonify(result)


@bp.route('/api/projects/<name>', methods=['GET'])
def api_get_project(name):
    user, key_obj = _auth()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401

    p = Project.query.filter_by(name=name).first()
    if not p:
        return jsonify({'error': 'not found'}), 404

    return jsonify({
        'id': p.id,
        'name': p.name,
        'owner': p.owner.username,
        'repo_url': p.repo_url,
        'deploy_hook': p.deploy_hook,
        'webhook_secret': p.webhook_secret,
        'created_at': p.created_at.isoformat(),
    })


@bp.route('/api/projects/<name>', methods=['PATCH'])
def api_update_project(name):
    """
    Allows updating repo_url.  Only admin keys may do this.
    This is the third step of the chain: attacker sets repo_url
    to http://main:PORT/evil so the worker fetches the malicious
    'git bundle' (actually a shell script) from the attacker's server.
    """
    user, key_obj = _auth()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    if not _has_perm(key_obj, 'admin'):
        return jsonify({'error': 'forbidden - requires admin permission'}), 403

    p = Project.query.filter_by(name=name).first()
    if not p:
        return jsonify({'error': 'not found'}), 404

    body = request.get_json(force=True, silent=True) or {}
    if 'repo_url' in body:
        p.repo_url = body['repo_url']
    if 'deploy_hook' in body:
        p.deploy_hook = body['deploy_hook']
    db.session.commit()
    return jsonify({'status': 'updated', 'repo_url': p.repo_url})


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------
@bp.route('/api/keys', methods=['GET'])
def api_list_keys():
    user, key_obj = _auth()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401

    keys = ApiKey.query.filter_by(user_id=user.id).all()
    return jsonify([{
        'id': k.id,
        'label': k.label,
        'key_prefix': k.key[:12] + '...',
        'permissions': k.permissions,
    } for k in keys])


# ---------------------------------------------------------------------------
# Webhook endpoint - the pivot point
# ---------------------------------------------------------------------------
@bp.route('/webhook/<project_name>', methods=['POST'])
def webhook(project_name):
    """
    Receives a GitHub-style webhook.  Validates HMAC-SHA256 signature.

    BUG: the lookup for the webhook_secret uses the project_name from
    the URL path, but the deploy action reads the project from a
    JSON body field 'repository.name'.  An attacker can:
      - Hit /webhook/internal-dashboard  (where they know the secret)
      - Include {"repository": {"name": "internal-dashboard"}} in body
      - Provide a valid HMAC for that body using the leaked secret
      - The deploy action fires for internal-dashboard whose repo_url
        has been overwritten to point at the attacker's HTTP server.
    """
    # Look up secret using URL parameter
    p = Project.query.filter_by(name=project_name).first()
    if not p or not p.webhook_secret:
        return jsonify({'error': 'project not found or no secret configured'}), 404

    # Verify HMAC
    body = request.get_data()
    sig_header = request.headers.get('X-Hub-Signature-256', '')
    expected_sig = 'sha256=' + hmac.new(
        p.webhook_secret.encode(), body, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(sig_header, expected_sig):
        return jsonify({'error': 'invalid signature'}), 403

    # Parse event
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return jsonify({'error': 'invalid json'}), 400

    event = request.headers.get('X-Github-Event', 'push')
    if event != 'push':
        return jsonify({'status': 'ignored', 'event': event}), 200

    # Derive project to deploy from body (not from URL - the mismatch)
    repo_name = payload.get('repository', {}).get('name', project_name)
    deploy_project = Project.query.filter_by(name=repo_name).first()
    if not deploy_project:
        return jsonify({'error': f'deploy target {repo_name!r} not found'}), 404

    # Trigger deploy
    result = _trigger_deploy(deploy_project)
    return jsonify({'status': 'deploy triggered', 'result': result})


def _trigger_deploy(project):
    """
    Calls the internal worker service to run the deployment.
    The worker clones/fetches from project.repo_url and executes
    any post-receive hooks it finds.

    The worker is on the internal Docker network only (not reachable
    from target/main directly - only devportal can call it).
    """
    try:
        resp = requests.post(
            'http://worker:8080/deploy',
            json={'repo_url': project.repo_url, 'project': project.name},
            timeout=30,
        )
        return resp.json()
    except Exception as e:
        return {'error': str(e)}


# ---------------------------------------------------------------------------
# Health / info
# ---------------------------------------------------------------------------
@bp.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'devportal'})


@bp.route('/api/info')
def api_info():
    """Public endpoint - reveals that the service exists and its version."""
    return jsonify({
        'service': 'DevPortal CI/CD',
        'version': '2.1.4',
        'docs': '/api/docs',
        'auth': 'Bearer token or X-Api-Key header',
        'endpoints': [
            'GET  /api/projects',
            'GET  /api/projects/<name>',
            'PATCH /api/projects/<name>',
            'POST /webhook/<project_name>',
            'GET  /api/keys',
            'GET  /health',
        ],
    })
