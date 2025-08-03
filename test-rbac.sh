#!/bin/bash

# Neo4j RBAC Testing Script
# This script tests the RBAC implementation after building Neo4j

set -e

echo "=== Neo4j RBAC Testing Script ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NEO4J_HOME="${NEO4J_HOME:-./packaging/standalone/target/neo4j-community-*}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-neo4j123}"
CYPHER_SHELL="$NEO4J_HOME/bin/cypher-shell"

# Helper functions
success() {
    echo -e "${GREEN}✓ $1${NC}"
}

error() {
    echo -e "${RED}✗ $1${NC}"
    exit 1
}

info() {
    echo -e "${YELLOW}→ $1${NC}"
}

run_cypher() {
    local user=$1
    local pass=$2
    local query=$3
    echo "$query" | $CYPHER_SHELL -u "$user" -p "$pass" --format plain 2>/dev/null || return 1
}

run_cypher_expect_fail() {
    local user=$1
    local pass=$2
    local query=$3
    if echo "$query" | $CYPHER_SHELL -u "$user" -p "$pass" --format plain 2>/dev/null; then
        return 1
    else
        return 0
    fi
}

# Check if Neo4j is built
info "Checking Neo4j build..."
if [ ! -d $NEO4J_HOME ]; then
    error "Neo4j not found at $NEO4J_HOME. Please build Neo4j first with: mvn clean install -DskipTests"
fi
success "Neo4j build found"

# Start Neo4j if not running
info "Checking if Neo4j is running..."
if ! $NEO4J_HOME/bin/neo4j-admin server status >/dev/null 2>&1; then
    info "Starting Neo4j..."
    $NEO4J_HOME/bin/neo4j-admin server start
    sleep 10  # Wait for startup
fi
success "Neo4j is running"

# Change default password if needed
info "Setting up admin password..."
if run_cypher "neo4j" "neo4j" "RETURN 1" >/dev/null 2>&1; then
    run_cypher "neo4j" "neo4j" "ALTER CURRENT USER SET PASSWORD FROM 'neo4j' TO '$ADMIN_PASSWORD'" || error "Failed to change admin password"
fi
success "Admin password configured"

# Test 1: Verify default roles
info "Testing default roles..."
ROLES=$(run_cypher "neo4j" "$ADMIN_PASSWORD" "CALL dbms.security.listRoles() YIELD role RETURN role")
for role in admin reader editor architect PUBLIC; do
    if echo "$ROLES" | grep -q "$role"; then
        success "Found default role: $role"
    else
        error "Missing default role: $role"
    fi
done

# Test 2: Create test users and roles
info "Creating test users and roles..."
run_cypher "neo4j" "$ADMIN_PASSWORD" "CREATE ROLE IF NOT EXISTS analyst" || error "Failed to create analyst role"
run_cypher "neo4j" "$ADMIN_PASSWORD" "CREATE USER IF NOT EXISTS alice SET PASSWORD 'alice123' CHANGE NOT REQUIRED" || error "Failed to create user alice"
run_cypher "neo4j" "$ADMIN_PASSWORD" "CREATE USER IF NOT EXISTS bob SET PASSWORD 'bob123' CHANGE NOT REQUIRED" || error "Failed to create user bob"
success "Test users and roles created"

# Test 3: Assign roles
info "Assigning roles to users..."
run_cypher "neo4j" "$ADMIN_PASSWORD" "GRANT ROLE reader TO alice" || error "Failed to grant reader role to alice"
run_cypher "neo4j" "$ADMIN_PASSWORD" "GRANT ROLE editor TO bob" || error "Failed to grant editor role to bob"
success "Roles assigned to users"

# Test 4: Grant privileges
info "Testing privilege management..."
run_cypher "neo4j" "$ADMIN_PASSWORD" "CALL dbms.security.grantPrivilege('READ', 'neo4j', 'analyst')" || error "Failed to grant READ privilege"
run_cypher "neo4j" "$ADMIN_PASSWORD" "CALL dbms.security.grantPrivilege('TRAVERSE', 'neo4j', 'analyst')" || error "Failed to grant TRAVERSE privilege"
run_cypher "neo4j" "$ADMIN_PASSWORD" "GRANT ROLE analyst TO alice" || error "Failed to grant analyst role to alice"
success "Privileges granted successfully"

# Test 5: Test read access for alice
info "Testing read access for alice (reader + analyst)..."
run_cypher "alice" "alice123" "MATCH (n) RETURN count(n) as count" || error "Alice should be able to read"
success "Alice can read data"

# Test 6: Test write restriction for alice
info "Testing write restriction for alice..."
if run_cypher_expect_fail "alice" "alice123" "CREATE (n:TestNode {name: 'alice-test'})"; then
    success "Alice correctly denied write access"
else
    error "Alice should not be able to write"
fi

# Test 7: Test write access for bob
info "Testing write access for bob (editor)..."
run_cypher "bob" "bob123" "CREATE (n:TestNode {name: 'bob-test'})" || error "Bob should be able to write"
run_cypher "bob" "bob123" "MATCH (n:TestNode) DELETE n" || error "Bob should be able to delete"
success "Bob can write and delete data"

# Test 8: Test schema restriction for bob
info "Testing schema restriction for bob..."
if run_cypher_expect_fail "bob" "bob123" "CREATE INDEX test_idx FOR (n:TestNode) ON (n.name)"; then
    success "Bob correctly denied schema access"
else
    error "Bob should not be able to create indexes"
fi

# Test 9: Test role validation
info "Testing role validation..."
if run_cypher_expect_fail "neo4j" "$ADMIN_PASSWORD" "CREATE ROLE 'invalid role name'"; then
    success "Invalid role name correctly rejected"
else
    error "Should not allow invalid role names"
fi

if run_cypher_expect_fail "neo4j" "$ADMIN_PASSWORD" "DROP ROLE admin"; then
    success "System role deletion correctly prevented"
else
    error "Should not allow deletion of system roles"
fi

# Test 10: Show privileges
info "Testing privilege queries..."
run_cypher "neo4j" "$ADMIN_PASSWORD" "SHOW PRIVILEGES" || error "Failed to show privileges"
run_cypher "alice" "alice123" "SHOW USER PRIVILEGES" || error "Failed to show user privileges"
success "Privilege queries working"

# Summary
echo
echo "=== RBAC Testing Summary ==="
success "All RBAC tests passed!"
echo
echo "The RBAC implementation is working correctly. You can now:"
echo "1. Access Neo4j Browser at http://localhost:7474"
echo "2. Login with different users to test permissions"
echo "3. Use 'SHOW PROCEDURES' to see all RBAC procedures"
echo
echo "To stop Neo4j: $NEO4J_HOME/bin/neo4j-admin server stop"