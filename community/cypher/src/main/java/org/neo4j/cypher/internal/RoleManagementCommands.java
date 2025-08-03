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
package org.neo4j.cypher.internal;

import java.util.Map;
import java.util.Set;
import org.neo4j.kernel.impl.security.Privilege;
import org.neo4j.server.security.systemgraph.SecurityGraphHelper;

/**
 * Handler for RBAC commands in Cypher.
 * This provides a simplified implementation of GRANT/DENY/REVOKE commands.
 */
public class RoleManagementCommands {
    
    private final SecurityGraphHelper securityGraphHelper;
    
    public RoleManagementCommands(SecurityGraphHelper securityGraphHelper) {
        this.securityGraphHelper = securityGraphHelper;
    }
    
    /**
     * Execute a GRANT command.
     * Example: GRANT MATCH {*} ON GRAPH * NODE * TO role
     */
    public void executeGrant(GrantCommand command) {
        Privilege privilege = createPrivilege(command.action, command.scope, command.resource, true, command.immutable);
        
        for (String roleName : command.roles) {
            // This would need to be implemented in SecurityGraphHelper
            // securityGraphHelper.grantPrivilege(roleName, privilege);
        }
    }
    
    /**
     * Execute a DENY command.
     * Example: DENY WRITE ON GRAPH neo4j TO role
     */
    public void executeDeny(DenyCommand command) {
        Privilege privilege = createPrivilege(command.action, command.scope, command.resource, false, command.immutable);
        
        for (String roleName : command.roles) {
            // This would need to be implemented in SecurityGraphHelper
            // securityGraphHelper.denyPrivilege(roleName, privilege);
        }
    }
    
    /**
     * Execute a REVOKE command.
     * Example: REVOKE GRANT WRITE ON GRAPH * FROM role
     */
    public void executeRevoke(RevokeCommand command) {
        // For revoke, we need to know if we're revoking a grant or deny
        boolean granted = command.revokeType == RevokeType.GRANT;
        Privilege privilege = createPrivilege(command.action, command.scope, command.resource, granted, command.immutable);
        
        for (String roleName : command.roles) {
            // This would need to be implemented in SecurityGraphHelper
            // securityGraphHelper.revokePrivilege(roleName, privilege);
        }
    }
    
    /**
     * Execute a CREATE ROLE command.
     */
    public void executeCreateRole(String roleName) {
        securityGraphHelper.createRole(roleName);
    }
    
    /**
     * Execute a DROP ROLE command.
     */
    public void executeDropRole(String roleName) {
        securityGraphHelper.deleteRole(roleName);
    }
    
    /**
     * Execute a GRANT ROLE command.
     * Example: GRANT ROLE admin TO user
     */
    public void executeGrantRole(String roleName, Set<String> users) {
        for (String username : users) {
            securityGraphHelper.assignRoleToUser(username, roleName);
        }
    }
    
    /**
     * Execute a REVOKE ROLE command.
     * Example: REVOKE ROLE admin FROM user
     */
    public void executeRevokeRole(String roleName, Set<String> users) {
        for (String username : users) {
            securityGraphHelper.removeRoleFromUser(username, roleName);
        }
    }
    
    private Privilege createPrivilege(String action, String scope, ResourceSpecification resource, 
                                     boolean granted, boolean immutable) {
        // Parse action
        Privilege.PrivilegeAction privAction = parseAction(action);
        Privilege.PrivilegeScope privScope = parseScope(scope);
        
        // Create resource
        Privilege.PrivilegeResource privResource = new Privilege.PrivilegeResource(
                resource.graph,
                resource.labels,
                resource.relationshipTypes,
                resource.properties,
                resource.pattern
        );
        
        return new Privilege(privAction, privScope, privResource, granted, immutable);
    }
    
    private Privilege.PrivilegeAction parseAction(String action) {
        return switch (action.toUpperCase()) {
            case "TRAVERSE" -> Privilege.PrivilegeAction.TRAVERSE;
            case "READ" -> Privilege.PrivilegeAction.READ;
            case "MATCH" -> Privilege.PrivilegeAction.MATCH;
            case "WRITE" -> Privilege.PrivilegeAction.WRITE;
            case "CREATE" -> Privilege.PrivilegeAction.CREATE;
            case "DELETE" -> Privilege.PrivilegeAction.DELETE;
            case "SET LABEL" -> Privilege.PrivilegeAction.SET_LABEL;
            case "REMOVE LABEL" -> Privilege.PrivilegeAction.REMOVE_LABEL;
            case "SET PROPERTY" -> Privilege.PrivilegeAction.SET_PROPERTY;
            case "ACCESS" -> Privilege.PrivilegeAction.ACCESS;
            case "START" -> Privilege.PrivilegeAction.START;
            case "STOP" -> Privilege.PrivilegeAction.STOP;
            case "CREATE CONSTRAINT" -> Privilege.PrivilegeAction.CREATE_CONSTRAINT;
            case "DROP CONSTRAINT" -> Privilege.PrivilegeAction.DROP_CONSTRAINT;
            case "CREATE INDEX" -> Privilege.PrivilegeAction.CREATE_INDEX;
            case "DROP INDEX" -> Privilege.PrivilegeAction.DROP_INDEX;
            case "SHOW INDEX" -> Privilege.PrivilegeAction.SHOW_INDEX;
            case "SHOW CONSTRAINT" -> Privilege.PrivilegeAction.SHOW_CONSTRAINT;
            default -> throw new IllegalArgumentException("Unknown privilege action: " + action);
        };
    }
    
    private Privilege.PrivilegeScope parseScope(String scope) {
        return switch (scope.toUpperCase()) {
            case "GRAPH" -> Privilege.PrivilegeScope.GRAPH;
            case "DATABASE" -> Privilege.PrivilegeScope.DATABASE;
            case "DBMS" -> Privilege.PrivilegeScope.DBMS;
            case "ALL" -> Privilege.PrivilegeScope.ALL;
            default -> throw new IllegalArgumentException("Unknown privilege scope: " + scope);
        };
    }
    
    // Command classes
    
    public static class GrantCommand {
        public final String action;
        public final String scope;
        public final ResourceSpecification resource;
        public final Set<String> roles;
        public final boolean immutable;
        
        public GrantCommand(String action, String scope, ResourceSpecification resource, 
                           Set<String> roles, boolean immutable) {
            this.action = action;
            this.scope = scope;
            this.resource = resource;
            this.roles = roles;
            this.immutable = immutable;
        }
    }
    
    public static class DenyCommand extends GrantCommand {
        public DenyCommand(String action, String scope, ResourceSpecification resource, 
                          Set<String> roles, boolean immutable) {
            super(action, scope, resource, roles, immutable);
        }
    }
    
    public static class RevokeCommand extends GrantCommand {
        public final RevokeType revokeType;
        
        public RevokeCommand(String action, String scope, ResourceSpecification resource, 
                            Set<String> roles, boolean immutable, RevokeType revokeType) {
            super(action, scope, resource, roles, immutable);
            this.revokeType = revokeType;
        }
    }
    
    public enum RevokeType {
        GRANT, DENY, BOTH
    }
    
    public static class ResourceSpecification {
        public final String graph;
        public final Set<String> labels;
        public final Set<String> relationshipTypes;
        public final Set<String> properties;
        public final String pattern;
        
        public ResourceSpecification(String graph, Set<String> labels, Set<String> relationshipTypes,
                                   Set<String> properties, String pattern) {
            this.graph = graph;
            this.labels = labels;
            this.relationshipTypes = relationshipTypes;
            this.properties = properties;
            this.pattern = pattern;
        }
        
        public static ResourceSpecification allGraphs() {
            return new ResourceSpecification("*", Set.of("*"), Set.of("*"), Set.of("*"), null);
        }
        
        public static ResourceSpecification specificGraph(String graph) {
            return new ResourceSpecification(graph, Set.of("*"), Set.of("*"), Set.of("*"), null);
        }
    }
}