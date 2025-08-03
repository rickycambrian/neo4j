#!/bin/bash

echo "=== Quick Start: Node-Level Security for Neo4j ==="
echo

echo "1. Install required Python packages:"
echo "   pip install neo4j-driver flask pyjwt"
echo

echo "2. Start your Neo4j instance"
echo

echo "3. Run the simple security example:"
echo "   python3 simple-node-security.py"
echo

echo "4. Or run the REST API wrapper:"
echo "   python3 security-api-example.py"
echo

echo "This provides:"
echo "✅ User-specific access to node types"
echo "✅ Simple permission management"
echo "✅ Secure query execution"
echo "✅ No Neo4j core modifications needed"
echo

echo "Example: Alice can see Person and Company nodes"
echo "         Bob can only see Person nodes"
echo "         Neither can see Secret nodes"