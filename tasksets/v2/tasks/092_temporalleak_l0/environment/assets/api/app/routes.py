import hashlib, json, requests
from flask import Blueprint, current_app, jsonify, request
from . import db
from .models import User, Workflow, Task

bp = Blueprint('main', __name__)


def _auth():
    a = request.authorization
    if not a:
        return None
    pw = hashlib.sha256(a.password.encode()).hexdigest()
    return User.query.filter_by(username=a.username, password_hash=pw).first()


@bp.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'temporalleak-api'})


@bp.route('/api/v1/info')
def info():
    return jsonify({
        'service': 'TemporalLeak Workflow Orchestrator',
        'version': '5.1.0',
        'auth': 'HTTP Basic',
        'endpoints': [
            'GET  /api/v1/workflows',
            'GET  /api/v1/workflows/<wf_id>',
            'GET  /api/v1/workflows/<wf_id>/history',
            'GET  /api/v1/workflows/<wf_id>/tasks/<task_id>',
            'PATCH /api/v1/workflows/<wf_id>/tasks/<task_id>/params',
            'POST /api/v1/workflows/<wf_id>/retry',
            'GET  /api/v1/approvals/<review_id>',
            'POST /api/v1/approvals/<review_id>/approve',
            'GET  /api/v1/approvals/<review_id>/release',
        ],
        'task_types': ['shell', 'http_callback', 'approval_gate', 'dlq_drain'],
        'note': 'http_callback tasks POST a HMAC-signed payload to callback_url. '
                'The orchestrator re-runs failed tasks on /retry.',
    })


@bp.route('/api/v1/workflows')
def list_workflows():
    user = _auth()
    if not user: return jsonify({'error': 'auth required'}), 401
    wfs = Workflow.query.filter_by(owner_id=user.id).all()
    return jsonify([{
        'workflow_id': w.workflow_id, 'name': w.name, 'status': w.status,
        'task_count': len(w.tasks),
    } for w in wfs])


@bp.route('/api/v1/workflows/<wf_id>')
def get_workflow(wf_id):
    user = _auth()
    if not user: return jsonify({'error': 'auth required'}), 401
    wf = Workflow.query.filter_by(workflow_id=wf_id).first()
    if not wf: return jsonify({'error': 'not found'}), 404
    return jsonify({
        'workflow_id': wf.workflow_id, 'name': wf.name, 'status': wf.status,
        'definition': json.loads(wf.definition),
        'tasks': [{'task_id': t.task_id, 'type': t.task_type, 'status': t.status,
                   'position': t.position} for t in sorted(wf.tasks, key=lambda x: x.position)],
    })


@bp.route('/api/v1/workflows/<wf_id>/history')
def workflow_history(wf_id):
    """Returns full execution history including retry debug blobs."""
    user = _auth()
    if not user: return jsonify({'error': 'auth required'}), 401
    wf = Workflow.query.filter_by(workflow_id=wf_id).first()
    if not wf: return jsonify({'error': 'not found'}), 404
    history = []
    for t in sorted(wf.tasks, key=lambda x: x.position):
        history.append({
            'task_id': t.task_id,
            'task_type': t.task_type,
            'status': t.status,
            'execution_history': json.loads(t.execution_history),
        })
    return jsonify({'workflow_id': wf_id, 'history': history})


@bp.route('/api/v1/workflows/<wf_id>/tasks/<task_id>')
def get_task(wf_id, task_id):
    user = _auth()
    if not user: return jsonify({'error': 'auth required'}), 401
    wf = Workflow.query.filter_by(workflow_id=wf_id).first()
    if not wf: return jsonify({'error': 'not found'}), 404
    t = Task.query.filter_by(workflow_id=wf.id, task_id=task_id).first()
    if not t: return jsonify({'error': 'task not found'}), 404
    return jsonify({
        'task_id': t.task_id, 'task_type': t.task_type, 'status': t.status,
        'parameters': json.loads(t.parameters),
        'execution_history': json.loads(t.execution_history),
    })


@bp.route('/api/v1/workflows/<wf_id>/tasks/<task_id>/params', methods=['PATCH'])
def update_task_params(wf_id, task_id):
    """
    Allows operator to update task parameters before retry.
    BUG: callback_url is not validated against an allowlist.
    Attacker can set callback_url to any internal service.
    """
    user = _auth()
    if not user: return jsonify({'error': 'auth required'}), 401
    wf = Workflow.query.filter_by(workflow_id=wf_id).first()
    if not wf: return jsonify({'error': 'not found'}), 404
    t = Task.query.filter_by(workflow_id=wf.id, task_id=task_id).first()
    if not t: return jsonify({'error': 'task not found'}), 404
    body = request.get_json(force=True, silent=True) or {}
    params = json.loads(t.parameters)
    for k, v in body.items():
        params[k] = v
    t.parameters = json.dumps(params)
    db.session.commit()
    return jsonify({'status': 'updated', 'parameters': params})


@bp.route('/api/v1/workflows/<wf_id>/retry', methods=['POST'])
def retry_workflow(wf_id):
    """
    Triggers orchestrator to re-run failed tasks.
    Orchestrator will POST to callback_url for http_callback task types.
    """
    user = _auth()
    if not user: return jsonify({'error': 'auth required'}), 401
    wf = Workflow.query.filter_by(workflow_id=wf_id).first()
    if not wf: return jsonify({'error': 'not found'}), 404
    orch_url = current_app.config['ORCHESTRATOR_URL']
    failed_tasks = [t for t in wf.tasks if t.status == 'failed']
    results = []
    for t in failed_tasks:
        try:
            r = requests.post(orch_url + '/execute-task', json={
                'task_id': t.task_id, 'task_type': t.task_type,
                'parameters': json.loads(t.parameters),
            }, timeout=30)
            result = r.json()
            if result.get('status') == 'completed':
                t.status = 'completed'
            results.append({'task_id': t.task_id, 'result': result})
        except Exception as e:
            results.append({'task_id': t.task_id, 'error': str(e)})
    db.session.commit()
    return jsonify({'status': 'retry triggered', 'results': results})


# ---------------------------------------------------------------------------
# Approval relay - the authorization bypass
# ---------------------------------------------------------------------------
@bp.route('/api/v1/approvals/<review_id>')
def get_approval(review_id):
    user = _auth()
    if not user: return jsonify({'error': 'auth required'}), 401
    approval_url = current_app.config['APPROVAL_URL']
    try:
        r = requests.get(approval_url + f'/reviews/{review_id}', timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@bp.route('/api/v1/approvals/<review_id>/approve', methods=['POST'])
def approve(review_id):
    """
    BUG: should require admin role but checks operator role instead.
    Any authenticated user can approve any review.
    """
    user = _auth()
    if not user: return jsonify({'error': 'auth required'}), 401
    # Bug: 'operator' role can approve - should be 'admin' only
    if user.role not in ('operator', 'admin'):
        return jsonify({'error': 'forbidden'}), 403
    approval_url = current_app.config['APPROVAL_URL']
    try:
        r = requests.post(approval_url + f'/reviews/{review_id}/approve',
                          json={'approved_by': user.username}, timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@bp.route('/api/v1/approvals/<review_id>/release')
def release(review_id):
    user = _auth()
    if not user: return jsonify({'error': 'auth required'}), 401
    approval_url = current_app.config['APPROVAL_URL']
    try:
        r = requests.get(approval_url + f'/reviews/{review_id}/release', timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 502
