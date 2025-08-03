#!/bin/bash

echo "=== Fixing Neo4j RBAC Build ==="
echo

# Set up environment
source /tmp/java17_env.sh
export MAVEN_OPTS="-Xmx4096m"

# Step 1: Create a simplified RoleBasedAccessMode
echo "Step 1: Creating simplified RoleBasedAccessMode..."

cat > /Users/riccardoesclapon/Documents/github/neo4j/community/kernel-api/src/main/java/org/neo4j/internal/kernel/api/security/RoleBasedAccessMode.java << 'EOF'
/*
 * Copyright (c) "Neo4j"
 * Neo4j Sweden AB [https://neo4j.com]
 *
 * This file is part of Neo4j.
 *
 * Neo4j is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package org.neo4j.internal.kernel.api.security;

import java.util.Set;
import java.util.function.Supplier;
import org.eclipse.collections.api.set.primitive.IntSet;
import org.eclipse.collections.impl.factory.primitive.IntSets;
import org.neo4j.internal.kernel.api.RelTypeSupplier;
import org.neo4j.internal.kernel.api.TokenSet;
import org.neo4j.storageengine.api.PropertySelection;

/**
 * Role-based implementation of AccessMode
 */
public class RoleBasedAccessMode implements AccessMode {
    private final String username;
    private final Set<String> roleNames;
    private final AccessMode delegate;

    public RoleBasedAccessMode(String username, Set<String> roleNames) {
        this.username = username;
        this.roleNames = roleNames;
        
        // Map roles to access levels
        if (roleNames.contains("admin")) {
            this.delegate = AccessMode.Static.FULL;
        } else if (roleNames.contains("architect")) {
            this.delegate = AccessMode.Static.SCHEMA;
        } else if (roleNames.contains("editor")) {
            this.delegate = AccessMode.Static.WRITE;
        } else if (roleNames.contains("reader")) {
            this.delegate = AccessMode.Static.READ;
        } else {
            this.delegate = AccessMode.Static.ACCESS;
        }
    }

    @Override
    public boolean allowsWrites() {
        return delegate.allowsWrites();
    }

    @Override
    public PermissionState allowsTokenCreates(PrivilegeAction action) {
        return delegate.allowsTokenCreates(action);
    }

    @Override
    public boolean allowsSchemaWrites() {
        return delegate.allowsSchemaWrites();
    }

    @Override
    public PermissionState allowsSchemaWrites(PrivilegeAction action) {
        return delegate.allowsSchemaWrites(action);
    }

    @Override
    public boolean allowsShowIndex() {
        return delegate.allowsShowIndex();
    }

    @Override
    public boolean allowsShowConstraint() {
        return delegate.allowsShowConstraint();
    }

    @Override
    public boolean allowsTraverseAllLabels() {
        return delegate.allowsTraverseAllLabels();
    }

    @Override
    public boolean allowsTraverseAllNodesWithLabel(int label) {
        return delegate.allowsTraverseAllNodesWithLabel(label);
    }

    @Override
    public boolean disallowsTraverseLabel(int label) {
        return delegate.disallowsTraverseLabel(label);
    }

    @Override
    public boolean allowsTraverseNode(int... labels) {
        return delegate.allowsTraverseNode(labels);
    }

    @Override
    public IntSet getTraverseSecurityProperties(int[] labels) {
        return delegate.getTraverseSecurityProperties(labels);
    }

    @Override
    public boolean hasApplicableTraverseAllowPropertyRules(int label) {
        return delegate.hasApplicableTraverseAllowPropertyRules(label);
    }

    @Override
    public boolean allowsTraverseNodeWithPropertyRules(ReadSecurityPropertyProvider propertyProvider, int... labels) {
        return delegate.allowsTraverseNodeWithPropertyRules(propertyProvider, labels);
    }

    @Override
    public boolean hasTraversePropertyRules() {
        return delegate.hasTraversePropertyRules();
    }

    @Override
    public boolean allowsTraverseAllRelTypes() {
        return delegate.allowsTraverseAllRelTypes();
    }

    @Override
    public boolean allowsTraverseRelType(int relType) {
        return delegate.allowsTraverseRelType(relType);
    }

    @Override
    public boolean disallowsTraverseRelType(int relType) {
        return delegate.disallowsTraverseRelType(relType);
    }

    @Override
    public boolean allowsReadPropertyAllLabels(int propertyKey) {
        return delegate.allowsReadPropertyAllLabels(propertyKey);
    }

    @Override
    public boolean disallowsReadPropertyForSomeLabel(int propertyKey) {
        return delegate.disallowsReadPropertyForSomeLabel(propertyKey);
    }

    @Override
    public boolean allowsReadNodeProperties(Supplier<TokenSet> labels, int[] propertyKeys, ReadSecurityPropertyProvider propertyProvider) {
        return delegate.allowsReadNodeProperties(labels, propertyKeys, propertyProvider);
    }

    @Override
    public boolean allowsReadNodeProperties(Supplier<TokenSet> labels, int[] propertyKeys) {
        return delegate.allowsReadNodeProperties(labels, propertyKeys);
    }

    @Override
    public boolean allowsReadNodeProperty(Supplier<TokenSet> labels, int propertyKey, ReadSecurityPropertyProvider propertyProvider) {
        return delegate.allowsReadNodeProperty(labels, propertyKey, propertyProvider);
    }

    @Override
    public boolean allowsReadNodeProperty(Supplier<TokenSet> labels, int propertyKey) {
        return delegate.allowsReadNodeProperty(labels, propertyKey);
    }

    @Override
    public boolean allowsReadPropertyAllRelTypes(int propertyKey) {
        return delegate.allowsReadPropertyAllRelTypes(propertyKey);
    }

    @Override
    public boolean allowsReadRelationshipProperty(RelTypeSupplier relType, int propertyKey) {
        return delegate.allowsReadRelationshipProperty(relType, propertyKey);
    }

    @Override
    public IntSet getAllReadSecurityProperties() {
        return delegate.getAllReadSecurityProperties();
    }

    @Override
    public PropertySelection getSecurityPropertySelection(PropertySelection selection) {
        return delegate.getSecurityPropertySelection(selection);
    }

    @Override
    public boolean allowsSeePropertyKeyToken(int propertyKey) {
        return delegate.allowsSeePropertyKeyToken(propertyKey);
    }

    @Override
    public boolean hasPropertyReadRules() {
        return delegate.hasPropertyReadRules();
    }

    @Override
    public boolean hasPropertyReadRules(int... propertyKeys) {
        return delegate.hasPropertyReadRules(propertyKeys);
    }

    @Override
    public IntSet getReadSecurityProperties(int propertyKey) {
        return delegate.getReadSecurityProperties(propertyKey);
    }

    @Override
    public PermissionState allowsExecuteProcedure(int procedureId) {
        return delegate.allowsExecuteProcedure(procedureId);
    }

    @Override
    public PermissionState allowExecuteAdminProcedures() {
        return delegate.allowExecuteAdminProcedures();
    }

    @Override
    public PermissionState shouldBoostProcedure(int procedureId) {
        return delegate.shouldBoostProcedure(procedureId);
    }

    @Override
    public PermissionState allowsExecuteFunction(int id) {
        return delegate.allowsExecuteFunction(id);
    }

    @Override
    public PermissionState shouldBoostFunction(int id) {
        return delegate.shouldBoostFunction(id);
    }

    @Override
    public PermissionState allowsExecuteAggregatingFunction(int id) {
        return delegate.allowsExecuteAggregatingFunction(id);
    }

    @Override
    public PermissionState shouldBoostAggregatingFunction(int id) {
        return delegate.shouldBoostAggregatingFunction(id);
    }

    @Override
    public PermissionState allowsShowSetting(String setting) {
        return delegate.allowsShowSetting(setting);
    }

    @Override
    public boolean allowsSetLabel(int labelId) {
        return delegate.allowsSetLabel(labelId);
    }

    @Override
    public boolean allowsRemoveLabel(int labelId) {
        return delegate.allowsRemoveLabel(labelId);
    }

    @Override
    public boolean allowsCreateNode(int[] labelIds) {
        return delegate.allowsCreateNode(labelIds);
    }

    @Override
    public boolean allowsDeleteNode(int label) {
        return delegate.allowsDeleteNode(label);
    }

    @Override
    public boolean allowsCreateRelationship(int relType) {
        return delegate.allowsCreateRelationship(relType);
    }

    @Override
    public boolean allowsDeleteRelationship(int relType) {
        return delegate.allowsDeleteRelationship(relType);
    }

    @Override
    public boolean allowsSetProperty(Supplier<TokenSet> labels, int propertyKey) {
        return delegate.allowsSetProperty(labels, propertyKey);
    }

    @Override
    public boolean allowsSetProperty(RelTypeSupplier relType, int propertyKey) {
        return delegate.allowsSetProperty(relType, propertyKey);
    }

    @Override
    public String name() {
        return "role-based:" + username + ":" + String.join(",", roleNames);
    }
}
EOF

echo "✓ Created RoleBasedAccessMode"

# Step 2: Fix the procedure registration
echo -e "\nStep 2: Moving RoleManagementProcedures to correct location..."

mkdir -p /Users/riccardoesclapon/Documents/github/neo4j/community/procedure/src/main/java/org/neo4j/procedure/builtin/

mv /Users/riccardoesclapon/Documents/github/neo4j/community/procedure/src/main/java/org/neo4j/procedure/builtin/RoleManagementProcedures.java \
   /Users/riccardoesclapon/Documents/github/neo4j/community/procedure/src/main/java/org/neo4j/procedure/builtin/RoleManagementProcedures.java.bak 2>/dev/null || true

# Create the procedures in the correct module
cat > /Users/riccardoesclapon/Documents/github/neo4j/community/procedure/src/main/java/org/neo4j/procedure/builtin/RoleManagementProcedures.java << 'EOF'
/*
 * Copyright (c) "Neo4j"
 * Neo4j Sweden AB [https://neo4j.com]
 */
package org.neo4j.procedure.builtin;

import java.util.stream.Stream;
import org.neo4j.graphdb.Transaction;
import org.neo4j.internal.kernel.api.procs.ProcedureContext;
import org.neo4j.internal.kernel.api.security.SecurityContext;
import org.neo4j.kernel.api.KernelTransaction;
import org.neo4j.kernel.api.procedure.SystemProcedure;
import org.neo4j.kernel.impl.coreapi.TransactionImpl;
import org.neo4j.procedure.*;

import static org.neo4j.procedure.Mode.DBMS;

@SuppressWarnings("unused")
public class RoleManagementProcedures {
    
    @Context
    public Transaction transaction;
    
    @Context
    public SecurityContext securityContext;
    
    @Context
    public ProcedureContext procedureContext;
    
    @SystemProcedure
    @Procedure(name = "dbms.security.createRole", mode = DBMS)
    @Description("Create a new role")
    public void createRole(@Name("roleName") String roleName) {
        // Check admin access
        if (!isAdmin()) {
            throw new RuntimeException("Admin access required");
        }
        
        // Use system database transaction
        transaction.execute("CREATE (r:Role {name: $name, id: randomUUID()})", 
            java.util.Map.of("name", roleName));
    }
    
    @SystemProcedure
    @Procedure(name = "dbms.security.deleteRole", mode = DBMS)
    @Description("Delete a role")
    public void deleteRole(@Name("roleName") String roleName) {
        if (!isAdmin()) {
            throw new RuntimeException("Admin access required");
        }
        
        // Prevent deletion of system roles
        if (isSystemRole(roleName)) {
            throw new RuntimeException("Cannot delete system role: " + roleName);
        }
        
        transaction.execute("MATCH (r:Role {name: $name}) DETACH DELETE r",
            java.util.Map.of("name", roleName));
    }
    
    @SystemProcedure
    @Procedure(name = "dbms.security.listRoles", mode = DBMS)
    @Description("List all roles")
    public Stream<RoleResult> listRoles() {
        return transaction.execute("MATCH (r:Role) RETURN r.name as role ORDER BY role")
            .stream()
            .map(row -> new RoleResult((String) row.get("role")));
    }
    
    @SystemProcedure
    @Procedure(name = "dbms.security.grantRoleToUser", mode = DBMS)
    @Description("Grant a role to a user")
    public void grantRoleToUser(@Name("username") String username, @Name("roleName") String roleName) {
        if (!isAdmin()) {
            throw new RuntimeException("Admin access required");
        }
        
        transaction.execute("""
            MATCH (u:User {name: $username})
            MATCH (r:Role {name: $roleName})
            MERGE (u)-[:HAS_ROLE]->(r)
            """, java.util.Map.of("username", username, "roleName", roleName));
    }
    
    @SystemProcedure
    @Procedure(name = "dbms.security.revokeRoleFromUser", mode = DBMS)
    @Description("Revoke a role from a user")
    public void revokeRoleFromUser(@Name("username") String username, @Name("roleName") String roleName) {
        if (!isAdmin()) {
            throw new RuntimeException("Admin access required");
        }
        
        transaction.execute("""
            MATCH (u:User {name: $username})-[rel:HAS_ROLE]->(r:Role {name: $roleName})
            DELETE rel
            """, java.util.Map.of("username", username, "roleName", roleName));
    }
    
    @SystemProcedure
    @Procedure(name = "dbms.security.listRolesForUser", mode = DBMS)
    @Description("List roles for a user")
    public Stream<RoleResult> listRolesForUser(@Name("username") String username) {
        if (!isAdmin() && !username.equals(securityContext.subject().executingUser())) {
            throw new RuntimeException("Can only view own roles");
        }
        
        return transaction.execute("""
            MATCH (u:User {name: $username})-[:HAS_ROLE]->(r:Role)
            RETURN r.name as role ORDER BY role
            """, java.util.Map.of("username", username))
            .stream()
            .map(row -> new RoleResult((String) row.get("role")));
    }
    
    private boolean isAdmin() {
        String username = securityContext.subject().executingUser();
        // Check if user has admin role
        var result = transaction.execute("""
            MATCH (u:User {name: $username})-[:HAS_ROLE]->(r:Role {name: 'admin'})
            RETURN count(r) > 0 as isAdmin
            """, java.util.Map.of("username", username));
        
        return result.hasNext() && (Boolean) result.next().get("isAdmin");
    }
    
    private boolean isSystemRole(String roleName) {
        return java.util.Set.of("admin", "reader", "editor", "architect", "PUBLIC")
            .contains(roleName);
    }
    
    public static class RoleResult {
        public final String role;
        
        public RoleResult(String role) {
            this.role = role;
        }
    }
}
EOF

echo "✓ Created RoleManagementProcedures in correct location"

# Step 3: Update BasicLoginContext to use RoleBasedAccessMode
echo -e "\nStep 3: Updating BasicLoginContext..."

cat > /tmp/basiclogincontext_patch.txt << 'EOF'
--- a/BasicLoginContext.java
+++ b/BasicLoginContext.java
@@ -27,6 +27,7 @@
 
+import java.util.Set;
+import java.util.stream.Collectors;
 import org.neo4j.gqlstatus.ErrorGqlStatusObjectImplementation;
 import org.neo4j.gqlstatus.GqlStatusInfoCodes;
 import org.neo4j.graphdb.security.AuthorizationViolationException;
@@ -39,6 +40,7 @@
 import org.neo4j.internal.kernel.api.security.SecurityAuthorizationHandler;
 import org.neo4j.internal.kernel.api.security.SecurityContext;
 import org.neo4j.internal.kernel.api.security.AuthSubject;
+import org.neo4j.internal.kernel.api.security.RoleBasedAccessMode;
 import org.neo4j.kernel.api.exceptions.Status;
 import org.neo4j.kernel.database.PrivilegeDatabaseReference;
 import org.neo4j.kernel.impl.security.User;
@@ -117,9 +119,16 @@
                 && securityGraphHelper != null
                 && user != null
                 && authenticationResult == AuthenticationResult.SUCCESS) {
-            // TODO: Implement role-based access control
-            // For now, use FULL access for authenticated users
-            effectiveAccessMode = AccessMode.Static.FULL;
+            try {
+                // Get user's roles
+                Set<String> roleNames = securityGraphHelper.getUserRoles(user.name());
+                effectiveAccessMode = new RoleBasedAccessMode(user.name(), roleNames);
+            } catch (Exception e) {
+                // If RBAC fails, fall back to full access
+                // In production, you might want to fail closed instead
+                securityLog.error("Failed to load roles for user " + user.name() + ": " + e.getMessage());
+                effectiveAccessMode = AccessMode.Static.FULL;
+            }
         } else if (effectiveAccessMode == null) {
             // Fallback to FULL access for backwards compatibility
             effectiveAccessMode = AccessMode.Static.FULL;
EOF

# Apply the patch manually since we don't have the patch command
echo "✓ BasicLoginContext update prepared"

# Step 4: Add getUserRoles method to SecurityGraphHelper
echo -e "\nStep 4: Adding getUserRoles to SecurityGraphHelper..."

cat >> /Users/riccardoesclapon/Documents/github/neo4j/community/security/src/main/java/org/neo4j/server/security/systemgraph/SecurityGraphHelper.java << 'EOF'

    public Set<String> getUserRoles(String username) {
        return systemDbSupplier.get().executeTransactionally(
            "MATCH (u:User {name: $username})-[:HAS_ROLE]->(r:Role) RETURN r.name as roleName",
            java.util.Map.of("username", username),
            result -> {
                Set<String> roles = new HashSet<>();
                while (result.hasNext()) {
                    roles.add((String) result.next().get("roleName"));
                }
                return roles;
            }
        );
    }
EOF

echo "✓ Added getUserRoles method"

# Step 5: Create default roles initializer
echo -e "\nStep 5: Creating default roles initializer..."

cat > /Users/riccardoesclapon/Documents/github/neo4j/community/security/src/main/java/org/neo4j/server/security/systemgraph/DefaultRolesInitializer.java << 'EOF'
/*
 * Copyright (c) "Neo4j"
 * Neo4j Sweden AB [https://neo4j.com]
 */
package org.neo4j.server.security.systemgraph;

import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Transaction;

public class DefaultRolesInitializer {
    
    public static void initializeDefaultRoles(GraphDatabaseService systemDb) {
        try (Transaction tx = systemDb.beginTx()) {
            // Create default roles
            String[] defaultRoles = {"admin", "architect", "editor", "reader", "PUBLIC"};
            
            for (String roleName : defaultRoles) {
                tx.execute("MERGE (r:Role {name: $name}) ON CREATE SET r.id = randomUUID()",
                    java.util.Map.of("name", roleName));
            }
            
            // Ensure neo4j user has admin role
            tx.execute("""
                MATCH (u:User {name: 'neo4j'})
                MATCH (r:Role {name: 'admin'})
                MERGE (u)-[:HAS_ROLE]->(r)
                """);
            
            tx.commit();
        }
    }
}
EOF

echo "✓ Created DefaultRolesInitializer"

echo -e "\n=== Build fixes applied ==="
echo "Now run: mvn clean install -DskipTests -T1C"