#!/bin/bash

# Neo4j RBAC Patch Deployment Script
# This script creates JAR patches for the RBAC implementation

set -e

echo "Building Neo4j RBAC Patch..."

# Build directories
BUILD_DIR="./rbac-patch"
mkdir -p $BUILD_DIR

# Compile our RBAC classes
echo "Compiling RBAC classes..."

# Find Neo4j jars for classpath
NEO4J_HOME="/Users/riccardoesclapon/Documents/github/neo4j/packaging/standalone/target/neo4j-community-5.26.0"
CLASSPATH=$(find $NEO4J_HOME/lib -name "*.jar" | tr '\n' ':')

# Compile kernel-api classes
javac -cp "$CLASSPATH" -d $BUILD_DIR \
    community/kernel-api/src/main/java/org/neo4j/internal/kernel/api/security/RoleBasedAccessMode.java \
    community/kernel-api/src/main/java/org/neo4j/internal/kernel/api/security/LabelBasedAccessMode.java

# Compile security classes (need to handle dependencies)
javac -cp "$CLASSPATH:$BUILD_DIR" -d $BUILD_DIR \
    community/security/src/main/java/org/neo4j/server/security/systemgraph/DefaultRolesInitializer.java

# Compile procedure classes
javac -cp "$CLASSPATH:$BUILD_DIR" -d $BUILD_DIR \
    community/procedure/src/main/java/org/neo4j/procedure/builtin/RoleManagementProcedures.java

# Create patch JARs
echo "Creating patch JARs..."
cd $BUILD_DIR

# Create kernel-api patch
jar cf neo4j-kernel-api-rbac-patch.jar \
    org/neo4j/internal/kernel/api/security/RoleBasedAccessMode.class \
    org/neo4j/internal/kernel/api/security/LabelBasedAccessMode.class

# Create security patch
jar cf neo4j-security-rbac-patch.jar \
    org/neo4j/server/security/systemgraph/DefaultRolesInitializer.class

# Create procedure patch
jar cf neo4j-procedure-rbac-patch.jar \
    org/neo4j/procedure/builtin/RoleManagementProcedures*.class

cd ..

echo "Patch JARs created in $BUILD_DIR"
echo ""
echo "To apply patches:"
echo "1. Stop Neo4j"
echo "2. Copy patch JARs to Neo4j lib directory"
echo "3. Ensure patch JARs are loaded after original JARs (rename with z- prefix)"
echo "4. Start Neo4j"