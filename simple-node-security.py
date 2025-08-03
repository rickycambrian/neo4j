#!/usr/bin/env python3
"""
Simple Node-Level Security for Neo4j Community Edition
This provides user-based access control to specific node types
"""

from neo4j import GraphDatabase
from typing import List, Dict, Any

class NodeSecurityManager:
    def __init__(self, uri: str, auth: tuple):
        self.driver = GraphDatabase.driver(uri, auth=auth)
        
    def setup_security_schema(self):
        """Create the security schema in Neo4j"""
        with self.driver.session() as session:
            session.run("""
                // Create unique constraints
                CREATE CONSTRAINT user_name IF NOT EXISTS 
                FOR (u:User) REQUIRE u.name IS UNIQUE;
                
                CREATE CONSTRAINT node_type_name IF NOT EXISTS 
                FOR (nt:NodeType) REQUIRE nt.name IS UNIQUE;
            """)
            
    def create_user(self, username: str, password: str = None):
        """Create a user in the graph (not a Neo4j user)"""
        with self.driver.session() as session:
            session.run("""
                MERGE (u:User {name: $username})
                SET u.created = datetime()
            """, username=username)
    
    def grant_node_access(self, username: str, node_labels: List[str]):
        """Grant user access to specific node types"""
        with self.driver.session() as session:
            for label in node_labels:
                session.run("""
                    MATCH (u:User {name: $username})
                    MERGE (nt:NodeType {name: $label})
                    MERGE (u)-[:CAN_READ]->(nt)
                """, username=username, label=label)
    
    def revoke_node_access(self, username: str, node_labels: List[str]):
        """Revoke user access to specific node types"""
        with self.driver.session() as session:
            for label in node_labels:
                session.run("""
                    MATCH (u:User {name: $username})-[r:CAN_READ]->(nt:NodeType {name: $label})
                    DELETE r
                """, username=username, label=label)
    
    def get_user_permissions(self, username: str) -> List[str]:
        """Get list of node types user can access"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (u:User {name: $username})-[:CAN_READ]->(nt:NodeType)
                RETURN collect(nt.name) as allowed_types
            """, username=username)
            record = result.single()
            return record["allowed_types"] if record else []
    
    def secure_query(self, username: str, cypher: str, **params) -> List[Dict[str, Any]]:
        """Execute a query with security filters applied"""
        allowed_types = self.get_user_permissions(username)
        
        if not allowed_types:
            return []  # No permissions
        
        # Create a security filter
        # This is a simple implementation - you may need to parse the query for complex cases
        secure_cypher = f"""
        // Security filter
        WITH {allowed_types} as allowed_labels
        {cypher}
        // Add WHERE clause to filter nodes
        WHERE all(label in labels(n) WHERE label IN allowed_labels)
        """
        
        with self.driver.session() as session:
            result = session.run(secure_cypher, **params)
            return [dict(record) for record in result]
    
    def close(self):
        self.driver.close()

# Example usage
if __name__ == "__main__":
    # Connect to Neo4j
    security_mgr = NodeSecurityManager(
        "bolt://localhost:7687", 
        ("neo4j", "neo4j123")
    )
    
    # Set up security schema
    security_mgr.setup_security_schema()
    
    # Create users and permissions
    security_mgr.create_user("alice")
    security_mgr.create_user("bob")
    
    # Alice can read Person and Company nodes
    security_mgr.grant_node_access("alice", ["Person", "Company"])
    
    # Bob can only read Person nodes
    security_mgr.grant_node_access("bob", ["Person"])
    
    # Create test data
    with security_mgr.driver.session() as session:
        session.run("""
            CREATE (p1:Person {name: 'John Doe'})
            CREATE (p2:Person {name: 'Jane Smith'})
            CREATE (c1:Company {name: 'Acme Corp'})
            CREATE (s1:Secret {data: 'Confidential'})
        """)
    
    # Test secure queries
    print("Alice's view:")
    alice_results = security_mgr.secure_query("alice", "MATCH (n) RETURN n.name as name, labels(n) as labels")
    for record in alice_results:
        print(f"  - {record['name']} ({record['labels']})")
    
    print("\nBob's view:")
    bob_results = security_mgr.secure_query("bob", "MATCH (n) RETURN n.name as name, labels(n) as labels")
    for record in bob_results:
        print(f"  - {record['name']} ({record['labels']})")
    
    # Clean up
    security_mgr.close()