"""
Registry Routes
===============
Vulnerabilities:
1. PATCH /api/v1/packages/<name>/<ver>  - contributor can update build_script
   without sanitization. Builder embeds it verbatim in a sh -c invocation.

2. POST /api/v1/build/<name>/<ver>  - triggers builder which has NOTARY_TOKEN in env.
   Injected build_script can exfil NOTARY_TOKEN to /collect on registry.

3. /collect endpoint logs anything POSTed to it - intended as webhook receiver
   but stores full raw payload. Attacker reads exfiltrated tokens from here.

4. /notary-relay/sign  - intended for internal tooling, no auth required from
   registry side. Forwards signing requests to notary with notary token.
   Actually the endpoint just passes the caller-supplied token to notary so
   the caller must supply the token they obtained from the build log.

5. Notary sends a webhook to the package's maintainer_webhook after signing.
   Attacker can update maintainer_webhook to /collect before triggering sign.
   Notary includes artifact_store_token in the webhook payload.

6. /internal/artifacts/<path> - protected by artifact_store_token.
   Once token is obtained from webhook payload, attacker can fetch the flag.
"""

import hashlib
import json

import requests
from flask import Blueprint, current_app, jsonify, request, render_template

from . import db
from .models import User, Package, BuildLog, CollectedData

bp = Blueprint('main', __name__)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def _auth():
    auth = request.authorization
    if not auth:
        return None
    pw = hashlib.sha256(auth.password.encode()).hexdigest()
    return User.query.filter_by(username=auth.username, password_hash=pw).first()


def _require_role(*roles):
    user = _auth()
    if not user:
        return None, (jsonify({'error': 'authentication required'}), 401)
    if user.role not in roles:
        return None, (jsonify({'error': f'requires role: {roles}'}), 403)
    return user, None


# ---------------------------------------------------------------------------
# Public
# ---------------------------------------------------------------------------
@bp.route('/')
def index():
    return render_template('index.html')


@bp.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'package-registry'})


@bp.route('/api/v1/info')
def info():
    return jsonify({
        'service': 'SupplyChain Package Registry',
        'version': '2.4.0',
        'auth': 'HTTP Basic',
        'roles': ['reader', 'contributor', 'admin'],
        'endpoints': [
            'GET  /api/v1/packages',
            'GET  /api/v1/packages/<name>/<version>',
            'POST /api/v1/packages   (contributor+)',
            'PATCH /api/v1/packages/<name>/<version>  (contributor+)',
            'POST /api/v1/build/<name>/<version>  (contributor+)',
            'GET  /api/v1/build-logs/<name>/<version>',
            'POST /notary-relay/sign',
            'GET  /internal/artifacts/<path>',
            'POST /collect  (webhook receiver)',
            'GET  /collect  (view collected payloads)',
        ],
        'note': 'Unverified packages require notary signing before distribution.',
    })


# ---------------------------------------------------------------------------
# Package CRUD
# ---------------------------------------------------------------------------
@bp.route('/api/v1/packages', methods=['GET'])
def list_packages():
    user = _auth()
    if not user:
        return jsonify({'error': 'authentication required'}), 401
    pkgs = Package.query.all()
    return jsonify([{
        'name': p.name,
        'version': p.version,
        'status': p.status,
        'owner': p.owner.username,
        'checksum': p.checksum,
    } for p in pkgs])


@bp.route('/api/v1/packages/<name>/<version>', methods=['GET'])
def get_package(name, version):
    user = _auth()
    if not user:
        return jsonify({'error': 'authentication required'}), 401
    p = Package.query.filter_by(name=name, version=version).first()
    if not p:
        return jsonify({'error': 'not found'}), 404
    manifest = {}
    try:
        manifest = json.loads(p.manifest)
    except Exception:
        pass
    return jsonify({
        'name': p.name,
        'version': p.version,
        'status': p.status,
        'checksum': p.checksum,
        'manifest': manifest,
        'build_output': p.build_output,
        'owner': p.owner.username,
    })


@bp.route('/api/v1/packages/<name>/<version>', methods=['PATCH'])
def update_package(name, version):
    """
    Allows contributor to update build_script and maintainer_webhook.
    BUG: build_script is stored verbatim and later embedded in a shell
    invocation by the builder without any sanitization.
    """
    user, err = _require_role('contributor', 'admin')
    if err:
        return err

    p = Package.query.filter_by(name=name, version=version).first()
    if not p:
        return jsonify({'error': 'not found'}), 404
    if p.owner_id != user.id and user.role != 'admin':
        return jsonify({'error': 'forbidden'}), 403

    body = request.get_json(force=True, silent=True) or {}
    manifest = {}
    try:
        manifest = json.loads(p.manifest)
    except Exception:
        pass

    # Fields the contributor can update
    for field in ('build_script', 'maintainer_webhook', 'description'):
        if field in body:
            manifest[field] = body[field]

    p.manifest = json.dumps(manifest)
    from datetime import datetime
    p.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'status': 'updated', 'manifest': manifest})


# ---------------------------------------------------------------------------
# Build trigger
# ---------------------------------------------------------------------------
@bp.route('/api/v1/build/<name>/<version>', methods=['POST'])
def trigger_build(name, version):
    """
    Sends a build job to the builder service.
    Builder runs the package's build_script in a shell.
    Builder has NOTARY_TOKEN in its environment.
    """
    user, err = _require_role('contributor', 'admin')
    if err:
        return err

    p = Package.query.filter_by(name=name, version=version).first()
    if not p:
        return jsonify({'error': 'not found'}), 404

    manifest = {}
    try:
        manifest = json.loads(p.manifest)
    except Exception:
        pass

    builder_url = current_app.config['BUILDER_URL']
    try:
        resp = requests.post(
            builder_url + '/build',
            json={
                'package': name,
                'version': version,
                'build_script': manifest.get('build_script', 'echo ok'),
                'webhook': manifest.get('build_hooks', {}).get('post_build', ''),
            },
            timeout=30,
        )
        result = resp.json()
    except Exception as e:
        result = {'error': str(e)}

    # Store build log
    log = BuildLog(package_name=name, version=version, log=json.dumps(result))
    db.session.add(log)
    p.build_output = json.dumps(result)
    db.session.commit()

    return jsonify({'status': 'build triggered', 'result': result})


@bp.route('/api/v1/build-logs/<name>/<version>', methods=['GET'])
def build_logs(name, version):
    user = _auth()
    if not user:
        return jsonify({'error': 'authentication required'}), 401
    logs = BuildLog.query.filter_by(package_name=name, version=version).order_by(BuildLog.created_at.desc()).all()
    return jsonify([{
        'id': l.id,
        'log': json.loads(l.log) if l.log else {},
        'created_at': l.created_at.isoformat(),
    } for l in logs])


# ---------------------------------------------------------------------------
# Notary relay - no auth required (intended for internal tooling)
# ---------------------------------------------------------------------------
@bp.route('/notary-relay/sign', methods=['POST'])
def notary_relay_sign():
    """
    Forwards a signing request to the notary service.
    Caller must supply their notary_token.
    Notary will call the package's maintainer_webhook after signing.
    If attacker sets maintainer_webhook to /collect and provides the
    notary token, they get the artifact_store_token from the webhook payload.
    """
    body = request.get_json(force=True, silent=True) or {}
    notary_token = body.get('notary_token', '')
    package_name = body.get('package', '')
    version = body.get('version', '')

    if not notary_token:
        return jsonify({'error': 'notary_token required'}), 400

    notary_url = current_app.config['NOTARY_URL']
    try:
        resp = requests.post(
            notary_url + '/sign',
            json={'package': package_name, 'version': version},
            headers={'Authorization': f'Bearer {notary_token}'},
            timeout=30,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 502


# ---------------------------------------------------------------------------
# Webhook collector - stores everything POSTed to it
# ---------------------------------------------------------------------------
@bp.route('/collect', methods=['POST'])
def collect_post():
    """
    Generic webhook receiver. Stores raw payload.
    Used as maintainer_webhook target by attacker.
    Also receives exfiltrated NOTARY_TOKEN from poisoned build_script.
    """
    raw = request.get_data(as_text=True)
    source = request.headers.get('X-Source', request.remote_addr)
    entry = CollectedData(source=source, payload=raw)
    db.session.add(entry)
    db.session.commit()
    return jsonify({'status': 'received', 'id': entry.id})


@bp.route('/collect', methods=['GET'])
def collect_get():
    """View all collected payloads - no auth required (dev convenience endpoint)."""
    entries = CollectedData.query.order_by(CollectedData.received_at.desc()).limit(50).all()
    return jsonify([{
        'id': e.id,
        'source': e.source,
        'payload': e.payload,
        'received_at': e.received_at.isoformat(),
    } for e in entries])


# ---------------------------------------------------------------------------
# Internal artifact store proxy - protected by artifact_store_token
# ---------------------------------------------------------------------------
@bp.route('/internal/artifacts/<path:artifact_path>', methods=['GET'])
def internal_artifact(artifact_path):
    """
    Proxies requests to the internal artifact store.
    Requires artifact_store_token as Bearer token or query param.
    Token is only discoverable via the notary webhook payload.
    """
    token = ''
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth[7:].strip()
    if not token:
        token = request.args.get('token', '')

    proxy_url = current_app.config['PROXY_URL']
    try:
        resp = requests.get(
            proxy_url + '/artifacts/' + artifact_path,
            headers={'X-Artifact-Token': token},
            timeout=10,
        )
        try:
            return jsonify(resp.json()), resp.status_code
        except Exception:
            return resp.text, resp.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 502
