# Node-Level Security for Neo4j Community Edition

## Quick Solution: Plugin-Based Approach

Instead of modifying Neo4j core, create a security plugin that provides node-level access control.

### Option 1: Use a Security Plugin (Recommended)

```java
// SecurityPlugin.java
package com.example.neo4j.security;

import org.neo4j.graphdb.*;
import org.neo4j.procedure.*;
import org.neo4j.kernel.api.procedure.GlobalProcedures;
import org.neo4j.kernel.lifecycle.LifecycleAdapter;

public class SecurityProcedures {
    
    @Context
    public Transaction tx;
    
    @Context
    public SecurityContext securityContext;
    
    @Procedure(value = "security.canAccess", mode = Mode.READ)
    @Description("Check if current user can access a node")
    public Stream<BooleanResult> canAccess(@Name("nodeId") Long nodeId) {
        Node node = tx.getNodeById(nodeId);
        String username = securityContext.subject().executingUser();
        
        // Check user permissions stored in graph
        boolean hasAccess = checkUserAccess(username, node);
        
        return Stream.of(new BooleanResult(hasAccess));
    }
    
    @UserFunction(value = "security.filterNodes")
    @Description("Filter nodes based on user permissions")
    public List<Node> filterNodes(@Name("nodes") List<Node> nodes) {
        String username = securityContext.subject().executingUser();
        
        return nodes.stream()
            .filter(node -> checkUserAccess(username, node))
            .collect(Collectors.toList());
    }
    
    private boolean checkUserAccess(String username, Node node) {
        // Find user node
        Node userNode = tx.findNode(Label.label("User"), "name", username);
        if (userNode == null) return false;
        
        // Check if user has permission for this node's labels
        for (Label label : node.getLabels()) {
            if (!hasLabelAccess(userNode, label.name())) {
                return false;
            }
        }
        
        return true;
    }
    
    private boolean hasLabelAccess(Node userNode, String labelName) {
        // Check READ_LABEL relationships
        for (Relationship rel : userNode.getRelationships(
                RelationshipType.withName("CAN_READ_LABEL"), 
                Direction.OUTGOING)) {
            Node labelNode = rel.getEndNode();
            if (labelName.equals(labelNode.getProperty("name"))) {
                return true;
            }
        }
        return false;
    }
    
    public static class BooleanResult {
        public final boolean value;
        
        public BooleanResult(boolean value) {
            this.value = value;
        }
    }
}
```

### Option 2: Application-Level Security (Easiest)

Implement security in your application layer:

```python
# app_security.py
from neo4j import GraphDatabase

class SecureNeo4jClient:
    def __init__(self, uri, auth):
        self.driver = GraphDatabase.driver(uri, auth=auth)
        
    def get_user_permissions(self, username):
        with self.driver.session() as session:
            result = session.run("""
                MATCH (u:User {name: $username})-[:CAN_READ_LABEL]->(l:Label)
                RETURN collect(l.name) as readable_labels
            """, username=username)
            record = result.single()
            return record["readable_labels"] if record else []
    
    def secure_query(self, username, query, parameters=None):
        # Get user's allowed labels
        allowed_labels = self.get_user_permissions(username)
        
        # Add security filter to query
        secure_query = f"""
        WITH {allowed_labels} as allowed_labels
        {query}
        WHERE all(label in labels(n) WHERE label in allowed_labels)
        """
        
        with self.driver.session() as session:
            return list(session.run(secure_query, parameters or {}))

# Usage
client = SecureNeo4jClient("bolt://localhost:7687", ("neo4j", "password"))

# Set up permissions
with client.driver.session() as session:
    session.run("""
        // Create security structure
        CREATE (u:User {name: 'restricted_user'})
        CREATE (l1:Label {name: 'Public'})
        CREATE (l2:Label {name: 'Private'})
        CREATE (u)-[:CAN_READ_LABEL]->(l1)
        
        // Create test data
        CREATE (:Public {name: 'Public Data'})
        CREATE (:Private {name: 'Private Data'})
    """)

# Query with security
results = client.secure_query('restricted_user', 
    "MATCH (n) RETURN n.name as name")
# Will only return nodes with 'Public' label
```

### Option 3: Use Neo4j Enterprise Edition

If you need production-ready RBAC, consider Neo4j Enterprise Edition which includes:
- Native role-based access control
- Fine-grained security (property-level)
- Sub-graph access control
- Built-in security procedures

## Setting Up the Plugin Approach

1. **Create a plugin project**:
```bash
mkdir neo4j-security-plugin
cd neo4j-security-plugin

# Create Maven project structure
cat > pom.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.example</groupId>
    <artifactId>neo4j-security-plugin</artifactId>
    <version>1.0.0</version>
    
    <properties>
        <neo4j.version>5.26.0</neo4j.version>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
    </properties>
    
    <dependencies>
        <dependency>
            <groupId>org.neo4j</groupId>
            <artifactId>neo4j</artifactId>
            <version>${neo4j.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.neo4j</groupId>
            <artifactId>neo4j-procedure-api</artifactId>
            <version>${neo4j.version}</version>
            <scope>provided</scope>
        </dependency>
    </dependencies>
</project>
EOF
```

2. **Build and deploy**:
```bash
mvn clean package
cp target/neo4j-security-plugin-1.0.0.jar /path/to/neo4j/plugins/
```

3. **Use in Cypher**:
```cypher
// Check access before querying
MATCH (n:SensitiveData)
WHERE security.canAccess(id(n)).value
RETURN n

// Or filter collections
MATCH (n)
WITH collect(n) as nodes
RETURN security.filterNodes(nodes) as accessibleNodes
```

## Recommended Approach

For your use case (restricting access to certain node types), I recommend:

1. **Application-level security** (Option 2) if you control the client applications
2. **Plugin approach** (Option 1) if you need security within Neo4j
3. **Consider Enterprise Edition** if this is for production use

The application-level approach is the simplest and most maintainable, while still providing the security you need.