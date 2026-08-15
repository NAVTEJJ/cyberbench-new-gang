from flask import Flask, request, jsonify
from flask_cors import CORS
from graphene import ObjectType, String, List, Schema, resolve_only_args, Field
from threading import Lock
import time
import json
from functools import wraps

app = Flask(__name__)
CORS(app)

# Global rate limiting
rate_limit_data = {}
rate_limit_lock = Lock()
RATE_LIMIT = 5  # requests per minute per IP
WINDOW = 60  # seconds

# Flag data
ADMIN_FLAG = "cyberbench{gr4phql_b4tch_r4t3l1m1t_byp4ss}"

def rate_limiter(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr or 'unknown'
        current_time = time.time()
        
        with rate_limit_lock:
            if client_ip not in rate_limit_data:
                rate_limit_data[client_ip] = []
            
            # Remove old requests outside the window
            rate_limit_data[client_ip] = [
                req_time for req_time in rate_limit_data[client_ip]
                if current_time - req_time < WINDOW
            ]
            
            # Check if rate limit exceeded
            if len(rate_limit_data[client_ip]) >= RATE_LIMIT:
                return jsonify({"error": "Rate limit exceeded"}), 429
            
            # Add current request
            rate_limit_data[client_ip].append(current_time)
        
        return f(*args, **kwargs)
    return decorated_function

class User(ObjectType):
    id = String()
    name = String()
    email = String()
    role = String()

class Query(ObjectType):
    users = Field(List(User))
    user = Field(User, id=String(required=True))
    admin_secret = Field(String)
    
    @resolve_only_args
    def resolve_users(self):
        if request.headers.get('X-Batch-Query') == 'true':
            # Hidden functionality that reveals all users including admin
            return [
                User(id="1", name="John Doe", email="john@example.com", role="user"),
                User(id="2", name="Jane Smith", email="jane@example.com", role="user"),
                User(id="admin", name="Administrator", email="admin@system.local", role="admin"),
            ]
        # Only return non-admin users for regular queries
        return [
            User(id="1", name="John Doe", email="john@example.com", role="user"),
            User(id="2", name="Jane Smith", email="jane@example.com", role="user"),
        ]
    
    @resolve_only_args
    def resolve_user(self, id):
        if id == "admin" and request.headers.get('X-Batch-Query') == 'true':
            return User(id="admin", name="Administrator", email="admin@system.local", role="admin")
        return None
    
    @resolve_only_args
    def resolve_admin_secret(self):
        if request.headers.get('X-Batch-Query') == 'true':
            return ADMIN_FLAG
        return None

# Note: The admin flag is actually stored in an environment variable
# It can be accessed by batching queries which bypass rate limiting

schema = Schema(query=Query)

@app.route('/graphql', methods=['POST'])
@rate_limiter
def graphql():
    try:
        data = request.get_json()
        
        # Check if this is a batch query
        if isinstance(data, list):
            # Rate limiting applies to the entire batch, allowing enumeration
            results = []
            for query_data in data:
                result = schema.execute(query_data.get('query', ''))
                results.append(result.data)
            return jsonify({"data": results})
        else:
            # Single query
            result = schema.execute(data.get('query', ''))
            return jsonify({"data": result.data})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)