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
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
    
    @SystemProcedure
    @Procedure(name = "dbms.security.grantPrivilege", mode = DBMS)
    @Description("Grant a privilege on specific labels to a role")
    public void grantPrivilege(
            @Name("roleName") String roleName,
            @Name("privilege") String privilege,
            @Name("labels") java.util.List<String> labels) {
        if (!isAdmin()) {
            throw new RuntimeException("Admin access required");
        }
        
        // Store privilege in system graph
        String labelsStr = String.join(",", labels);
        transaction.execute("""
            MATCH (r:Role {name: $roleName})
            MERGE (p:Privilege {
                role: $roleName,
                action: $privilege,
                labels: $labels,
                granted: true
            })
            MERGE (r)-[:HAS_PRIVILEGE]->(p)
            """, java.util.Map.of(
                "roleName", roleName,
                "privilege", privilege,
                "labels", labelsStr
            ));
    }
    
    @SystemProcedure
    @Procedure(name = "dbms.security.denyPrivilege", mode = DBMS)
    @Description("Deny a privilege on specific labels to a role")
    public void denyPrivilege(
            @Name("roleName") String roleName,
            @Name("privilege") String privilege,
            @Name("labels") java.util.List<String> labels) {
        if (!isAdmin()) {
            throw new RuntimeException("Admin access required");
        }
        
        String labelsStr = String.join(",", labels);
        transaction.execute("""
            MATCH (r:Role {name: $roleName})
            MERGE (p:Privilege {
                role: $roleName,
                action: $privilege,
                labels: $labels,
                granted: false
            })
            MERGE (r)-[:HAS_PRIVILEGE]->(p)
            """, java.util.Map.of(
                "roleName", roleName,
                "privilege", privilege,
                "labels", labelsStr
            ));
    }
    
    @SystemProcedure
    @Procedure(name = "dbms.security.revokePrivilege", mode = DBMS)
    @Description("Revoke a privilege on specific labels from a role")
    public void revokePrivilege(
            @Name("roleName") String roleName,
            @Name("privilege") String privilege,
            @Name("labels") java.util.List<String> labels) {
        if (!isAdmin()) {
            throw new RuntimeException("Admin access required");
        }
        
        String labelsStr = String.join(",", labels);
        transaction.execute("""
            MATCH (r:Role {name: $roleName})-[rel:HAS_PRIVILEGE]->(p:Privilege {
                role: $roleName,
                action: $privilege,
                labels: $labels
            })
            DELETE rel, p
            """, java.util.Map.of(
                "roleName", roleName,
                "privilege", privilege,
                "labels", labelsStr
            ));
    }
    
    @SystemProcedure
    @Procedure(name = "dbms.security.listPrivileges", mode = DBMS)
    @Description("List privileges for a role")
    public Stream<PrivilegeResult> listPrivileges(@Name("roleName") String roleName) {
        return transaction.execute("""
            MATCH (r:Role {name: $roleName})-[:HAS_PRIVILEGE]->(p:Privilege)
            RETURN p.action as action, p.labels as labels, p.granted as granted
            ORDER BY action, labels
            """, java.util.Map.of("roleName", roleName))
            .stream()
            .map(row -> new PrivilegeResult(
                (String) row.get("action"),
                (String) row.get("labels"),
                (Boolean) row.get("granted")
            ));
    }
    
    public static class RoleResult {
        public final String role;
        
        public RoleResult(String role) {
            this.role = role;
        }
    }
    
    public static class PrivilegeResult {
        public final String action;
        public final String labels;
        public final boolean granted;
        
        public PrivilegeResult(String action, String labels, boolean granted) {
            this.action = action;
            this.labels = labels;
            this.granted = granted;
        }
    }
}
