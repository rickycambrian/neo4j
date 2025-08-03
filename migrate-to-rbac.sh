#!/bin/bash

# Neo4j RBAC Migration Script
# Migrates existing Neo4j installations to use RBAC

set -e

echo "=================================================="
echo "Neo4j Role-Based Access Control Migration Tool"
echo "=================================================="
echo ""

# Check if Neo4j is running
if curl -s http://localhost:7474 > /dev/null 2>&1; then
    echo "ERROR: Neo4j is currently running!"
    echo "Please stop Neo4j before running migration."
    exit 1
fi

# Parse arguments
NEO4J_HOME="${1:-/usr/local/neo4j}"
BACKUP_DIR="${2:-./neo4j-backup-$(date +%Y%m%d-%H%M%S)}"

echo "Neo4j Home: $NEO4J_HOME"
echo "Backup Directory: $BACKUP_DIR"
echo ""

# Verify Neo4j installation
if [ ! -d "$NEO4J_HOME" ]; then
    echo "ERROR: Neo4j installation not found at $NEO4J_HOME"
    exit 1
fi

# Create backup
echo "Step 1: Creating backup..."
mkdir -p "$BACKUP_DIR"
cp -R "$NEO4J_HOME/data" "$BACKUP_DIR/"
cp -R "$NEO4J_HOME/conf" "$BACKUP_DIR/"
echo "Backup created at $BACKUP_DIR"

# Deploy RBAC patches
echo ""
echo "Step 2: Deploying RBAC components..."

# Copy configuration
cat >> "$NEO4J_HOME/conf/neo4j.conf" << 'EOF'

# RBAC Configuration
dbms.security.rbac.enabled=true
dbms.security.rbac.audit.enabled=true
dbms.security.rbac.default_role=reader
dbms.security.rbac.label_based_access.enabled=true
dbms.security.rbac.fail_closed=true
EOF

echo "Configuration updated"

# Create migration script
cat > "$NEO4J_HOME/scripts/rbac-migration.cypher" << 'EOF'
// RBAC Migration Script
// This script initializes RBAC in the system database

// Create default roles if they don't exist
MERGE (admin:Role {name: 'admin'})
ON CREATE SET admin.id = randomUUID()

MERGE (architect:Role {name: 'architect'})
ON CREATE SET architect.id = randomUUID()

MERGE (editor:Role {name: 'editor'})
ON CREATE SET editor.id = randomUUID()

MERGE (reader:Role {name: 'reader'})
ON CREATE SET reader.id = randomUUID()

MERGE (public:Role {name: 'PUBLIC'})
ON CREATE SET public.id = randomUUID()

// Ensure neo4j user has admin role
MATCH (u:User {name: 'neo4j'})
MATCH (r:Role {name: 'admin'})
MERGE (u)-[:HAS_ROLE]->(r)

// Create indexes for performance
CREATE INDEX role_name_idx IF NOT EXISTS FOR (r:Role) ON (r.name);
CREATE INDEX privilege_role_idx IF NOT EXISTS FOR (p:Privilege) ON (p.role);
CREATE INDEX user_name_idx IF NOT EXISTS FOR (u:User) ON (u.name);

RETURN "RBAC migration completed" as message;
EOF

# Create post-migration verification script
cat > "$NEO4J_HOME/scripts/verify-rbac.cypher" << 'EOF'
// Verify RBAC Installation
MATCH (r:Role)
RETURN r.name as role
ORDER BY role

UNION ALL

MATCH (u:User)-[:HAS_ROLE]->(r:Role)
RETURN u.name + " -> " + r.name as role
ORDER BY role;
EOF

echo ""
echo "Step 3: Migration Steps"
echo "======================"
echo ""
echo "1. Start Neo4j:"
echo "   $NEO4J_HOME/bin/neo4j start"
echo ""
echo "2. Run migration script:"
echo "   $NEO4J_HOME/bin/cypher-shell -u neo4j -p <password> \\
system 'CALL dbms.queryJmx.single(\"org.neo4j:instance=kernel#0,name=Kernel\", \"KernelVersion\") YIELD value RETURN value;'"
echo ""
echo "3. Verify migration:"
echo "   $NEO4J_HOME/bin/cypher-shell -u neo4j -p <password> \\
< $NEO4J_HOME/scripts/verify-rbac.cypher"
echo ""
echo "4. Test RBAC procedures:"
echo "   CALL dbms.security.listRoles();"
echo "   CALL dbms.security.createRole('test_role');"
echo ""
echo "=================================================="
echo "Migration preparation complete!"
echo ""
echo "IMPORTANT: Review the backup at $BACKUP_DIR"
echo "before starting Neo4j with RBAC enabled."
echo "=================================================="