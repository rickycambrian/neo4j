#!/bin/bash

# RBAC Functionality Test Script

echo "===================="
echo "Neo4j RBAC Test"
echo "===================="
echo ""

# Check if Neo4j is running
echo "Checking if Neo4j is running..."
if ! curl -s http://localhost:7474 > /dev/null; then
    echo "Neo4j is not running! Please start it first with ./start-neo4j-rbac.sh"
    exit 1
fi

echo "Neo4j is running!"
echo ""

# Default credentials
NEO4J_USER="neo4j"
NEO4J_PASS="neo4j"

echo "Testing RBAC procedures..."
echo ""

# Test 1: List roles
echo "1. Listing all roles:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 \
  "CALL dbms.security.listRoles() YIELD role RETURN role ORDER BY role"

echo ""
echo "2. Creating a test role:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 \
  "CALL dbms.security.createRole('test_role')"

echo ""
echo "3. Creating a test user:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 \
  "CALL dbms.security.createUser('test_user', 'test_password', false)"

echo ""
echo "4. Granting role to user:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 \
  "CALL dbms.security.grantRoleToUser('test_user', 'reader')"

echo ""
echo "5. Listing roles for test user:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 \
  "CALL dbms.security.listRolesForUser('test_user') YIELD role RETURN role"

echo ""
echo "===================="
echo "RBAC Test Complete"
echo "===================="