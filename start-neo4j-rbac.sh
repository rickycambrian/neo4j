#!/bin/bash

# Neo4j RBAC Testing Script
# This script starts Neo4j Community Edition with RBAC implementation

NEO4J_HOME="/Users/riccardoesclapon/Documents/github/neo4j/packaging/standalone/target/neo4j-community-5.26.0"

echo "Starting Neo4j Community Edition with RBAC..."
echo "Neo4j Home: $NEO4J_HOME"

# Start Neo4j
cd "$NEO4J_HOME"
./bin/neo4j console