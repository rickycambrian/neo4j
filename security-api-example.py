#!/usr/bin/env python3
"""
REST API Security Wrapper for Neo4j
Provides user authentication and node-level access control
"""

from flask import Flask, request, jsonify, g
from functools import wraps
from neo4j import GraphDatabase
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'

# Neo4j connection
driver = GraphDatabase.driver(
    "bolt://localhost:7687", 
    auth=("neo4j", "neo4j123")
)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            g.current_user = data['username']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

@app.route('/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token"""
    auth = request.get_json()
    username = auth.get('username')
    password = auth.get('password')
    
    # In production, verify password properly
    # For demo, we just check if user exists in graph
    with driver.session() as session:
        result = session.run(
            "MATCH (u:User {name: $username}) RETURN u",
            username=username
        )
        if not result.single():
            return jsonify({'message': 'Invalid credentials'}), 401
    
    # Generate token
    token = jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    
    return jsonify({'token': token})

@app.route('/query', methods=['POST'])
@token_required
def secure_query():
    """Execute a Cypher query with security filters"""
    data = request.get_json()
    query = data.get('query')
    params = data.get('params', {})
    
    # Get user's allowed node types
    with driver.session() as session:
        result = session.run("""
            MATCH (u:User {name: $username})-[:CAN_READ]->(nt:NodeType)
            RETURN collect(nt.name) as allowed_types
        """, username=g.current_user)
        
        record = result.single()
        allowed_types = record["allowed_types"] if record else []
    
    if not allowed_types:
        return jsonify({'results': []})
    
    # Apply security filter to query
    # Note: This is simplified - in production, use proper query parsing
    secure_query = f"""
    WITH {allowed_types} as allowed_labels
    {query}
    WHERE all(label in labels(n) WHERE label IN allowed_labels)
    """
    
    # Execute query
    with driver.session() as session:
        result = session.run(secure_query, **params)
        results = [dict(record) for record in result]
    
    return jsonify({'results': results})

@app.route('/grant-access', methods=['POST'])
@token_required
def grant_access():
    """Grant access to node types (admin only)"""
    # In production, check if current user is admin
    data = request.get_json()
    target_user = data.get('user')
    node_types = data.get('node_types', [])
    
    with driver.session() as session:
        for node_type in node_types:
            session.run("""
                MATCH (u:User {name: $username})
                MERGE (nt:NodeType {name: $node_type})
                MERGE (u)-[:CAN_READ]->(nt)
            """, username=target_user, node_type=node_type)
    
    return jsonify({'message': 'Access granted'})

@app.route('/my-permissions', methods=['GET'])
@token_required
def my_permissions():
    """Get current user's permissions"""
    with driver.session() as session:
        result = session.run("""
            MATCH (u:User {name: $username})-[:CAN_READ]->(nt:NodeType)
            RETURN collect(nt.name) as allowed_types
        """, username=g.current_user)
        
        record = result.single()
        allowed_types = record["allowed_types"] if record else []
    
    return jsonify({
        'username': g.current_user,
        'allowed_node_types': allowed_types
    })

if __name__ == '__main__':
    # Set up example data
    with driver.session() as session:
        session.run("""
            // Create users
            MERGE (u1:User {name: 'alice'})
            MERGE (u2:User {name: 'bob'})
            
            // Create node types
            MERGE (nt1:NodeType {name: 'Person'})
            MERGE (nt2:NodeType {name: 'Company'})
            MERGE (nt3:NodeType {name: 'Secret'})
            
            // Grant permissions
            MERGE (u1)-[:CAN_READ]->(nt1)
            MERGE (u1)-[:CAN_READ]->(nt2)
            MERGE (u2)-[:CAN_READ]->(nt1)
            
            // Create test data
            CREATE (p1:Person {name: 'John Doe'})
            CREATE (p2:Person {name: 'Jane Smith'})
            CREATE (c1:Company {name: 'Acme Corp'})
            CREATE (s1:Secret {data: 'Confidential'})
        """)
    
    print("Security API running on http://localhost:5000")
    print("\nExample usage:")
    print("1. Login: POST /login {'username': 'alice', 'password': 'pass'}")
    print("2. Query: POST /query {'query': 'MATCH (n) RETURN n.name'}")
    print("   (Include Authorization header with token)")
    
    app.run(debug=True)