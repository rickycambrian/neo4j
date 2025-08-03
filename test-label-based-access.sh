#!/bin/bash

# Label-Based Access Control Test Script
# This script demonstrates how to restrict users to specific node labels (tables)

echo "===================================="
echo "Neo4j Label-Based Access Control Test"
echo "===================================="
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

echo "Setting up test scenario..."
echo ""

# Create test data
echo "1. Creating test data with different labels:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 <<'EOF'
// Create some Customer nodes
CREATE (c1:Customer {name: 'Alice', email: 'alice@example.com'})
CREATE (c2:Customer {name: 'Bob', email: 'bob@example.com'})
CREATE (c3:Customer {name: 'Charlie', email: 'charlie@example.com'})

// Create some Product nodes
CREATE (p1:Product {name: 'Laptop', price: 999.99})
CREATE (p2:Product {name: 'Phone', price: 599.99})
CREATE (p3:Product {name: 'Tablet', price: 399.99})

// Create some Order nodes
CREATE (o1:Order {id: '001', total: 999.99})
CREATE (o2:Order {id: '002', total: 599.99})
CREATE (o3:Order {id: '003', total: 1599.98})

RETURN "Created 3 Customers, 3 Products, and 3 Orders";
EOF

echo ""
echo "2. Creating a role with access to Customer label only:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 \
  "CALL dbms.security.createRole('customer_reader')"

echo ""
echo "3. Granting READ privilege on Customer label to the role:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 \
  "CALL dbms.security.grantPrivilege('customer_reader', 'READ', ['Customer'])"

echo ""
echo "4. Creating a role with access to Product and Order labels:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 \
  "CALL dbms.security.createRole('sales_user')"

echo ""
echo "5. Granting privileges on Product and Order labels:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 <<'EOF'
CALL dbms.security.grantPrivilege('sales_user', 'READ', ['Product', 'Order']);
CALL dbms.security.grantPrivilege('sales_user', 'WRITE', ['Order']);
EOF

echo ""
echo "6. Creating test users:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 <<'EOF'
CALL dbms.security.createUser('customer_service', 'password123', false);
CALL dbms.security.createUser('sales_person', 'password123', false);
EOF

echo ""
echo "7. Assigning roles to users:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 <<'EOF'
CALL dbms.security.grantRoleToUser('customer_service', 'customer_reader');
CALL dbms.security.grantRoleToUser('sales_person', 'sales_user');
EOF

echo ""
echo "8. Listing privileges for each role:"
echo "   Customer Reader privileges:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 \
  "CALL dbms.security.listPrivileges('customer_reader') YIELD action, labels, granted RETURN action, labels, granted"

echo ""
echo "   Sales User privileges:"
cypher-shell -u $NEO4J_USER -p $NEO4J_PASS -a bolt://localhost:7687 \
  "CALL dbms.security.listPrivileges('sales_user') YIELD action, labels, granted RETURN action, labels, granted"

echo ""
echo "===================================="
echo "Test Complete!"
echo ""
echo "What was demonstrated:"
echo "1. Created nodes with labels: Customer, Product, Order"
echo "2. Created 'customer_reader' role with READ access to Customer label only"
echo "3. Created 'sales_user' role with READ access to Product and Order, WRITE access to Order"
echo "4. Created users 'customer_service' and 'sales_person' with respective roles"
echo ""
echo "Expected behavior:"
echo "- customer_service user can only read Customer nodes"
echo "- sales_person user can read Product and Order nodes, and modify Order nodes"
echo "- Neither user can access labels they don't have permissions for"
echo "===================================="