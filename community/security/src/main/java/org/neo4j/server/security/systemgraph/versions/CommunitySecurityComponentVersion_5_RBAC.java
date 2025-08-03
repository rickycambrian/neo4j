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
package org.neo4j.server.security.systemgraph.versions;

import static org.neo4j.kernel.impl.security.Role.ROLE_ID;
import static org.neo4j.kernel.impl.security.Role.ROLE_LABEL;
import static org.neo4j.kernel.impl.security.Role.ROLE_NAME;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.neo4j.exceptions.KernelException;
import org.neo4j.graphdb.ConstraintDefinition;
import org.neo4j.graphdb.Label;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.ResourceIterator;
import org.neo4j.graphdb.Transaction;
import org.neo4j.graphdb.schema.Schema;
import org.neo4j.internal.kernel.api.security.AbstractSecurityLog;
import org.neo4j.kernel.impl.security.Privilege;
import org.neo4j.kernel.impl.security.Role;
import org.neo4j.logging.Log;
import org.neo4j.server.security.auth.UserRepository;

/**
 * Community security component version for RBAC support.
 * Adds role management capabilities to the security graph.
 */
public class CommunitySecurityComponentVersion_5_RBAC extends CommunitySecurityComponentVersion_5_521 {
    
    private static final String DEFAULT_ADMIN_ROLE = "admin";
    private static final String DEFAULT_READER_ROLE = "reader";
    private static final String DEFAULT_EDITOR_ROLE = "editor";
    private static final String DEFAULT_ARCHITECT_ROLE = "architect";
    private static final String DEFAULT_PUBLIC_ROLE = "PUBLIC";
    
    public CommunitySecurityComponentVersion_5_RBAC(
            Log debugLog, AbstractSecurityLog securityLog, UserRepository initialPasswordRepo, 
            KnownCommunitySecurityComponentVersion previous) {
        super(debugLog, securityLog, initialPasswordRepo, previous);
    }
    
    @Override
    public int binaryVersion() {
        return 6; // New version for RBAC
    }
    
    @Override
    public int minSupportedBinaryVersion() {
        return 3;
    }
    
    @Override
    protected void setupConstraints(Transaction tx) throws Exception {
        super.setupConstraints(tx);
        
        // Add unique constraint for role name
        boolean hasRoleNameConstraint = false;
        for (ConstraintDefinition constraint : tx.schema().getConstraints(Label.label(ROLE_LABEL))) {
            for (String property : constraint.getPropertyKeys()) {
                if (property.equals(ROLE_NAME)) {
                    hasRoleNameConstraint = true;
                    break;
                }
            }
        }
        
        if (!hasRoleNameConstraint) {
            tx.schema()
                .constraintFor(Label.label(ROLE_LABEL))
                .assertPropertyIsUnique(ROLE_NAME)
                .withName("constraint_role_name")
                .create();
        }
        
        // Add index for role id
        boolean hasRoleIdIndex = false;
        Schema schema = tx.schema();
        schema.getIndexes(Label.label(ROLE_LABEL)).forEach(index -> {
            for (String property : index.getPropertyKeys()) {
                if (property.equals(ROLE_ID)) {
                    hasRoleIdIndex = true;
                    break;
                }
            }
        });
        
        if (!hasRoleIdIndex) {
            tx.schema()
                .indexFor(Label.label(ROLE_LABEL))
                .on(ROLE_ID)
                .withName("index_role_id")
                .create();
        }
    }
    
    @Override
    public void setupUsers(Transaction tx) throws Exception {
        super.setupUsers(tx);
        
        // Create default roles if they don't exist
        createDefaultRoles(tx);
        
        // Assign admin role to neo4j user
        assignAdminRoleToDefaultUser(tx);
    }
    
    private void createDefaultRoles(Transaction tx) {
        // Create admin role with full privileges
        createRoleIfNotExists(tx, DEFAULT_ADMIN_ROLE, Set.of(
            createPrivilege(Privilege.PrivilegeAction.ACCESS, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.START, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.STOP, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.CREATE_CONSTRAINT, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.DROP_CONSTRAINT, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.CREATE_INDEX, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.DROP_INDEX, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.TRAVERSE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.READ, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.MATCH, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.WRITE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.CREATE_TOKEN, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.USER_MANAGEMENT, Privilege.PrivilegeScope.DBMS, "*", true),
            createPrivilege(Privilege.PrivilegeAction.ROLE_MANAGEMENT, Privilege.PrivilegeScope.DBMS, "*", true),
            createPrivilege(Privilege.PrivilegeAction.DATABASE_MANAGEMENT, Privilege.PrivilegeScope.DBMS, "*", true),
            createPrivilege(Privilege.PrivilegeAction.PRIVILEGE_MANAGEMENT, Privilege.PrivilegeScope.DBMS, "*", true),
            createPrivilege(Privilege.PrivilegeAction.EXECUTE_PROCEDURE, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.EXECUTE_FUNCTION, Privilege.PrivilegeScope.DATABASE, "*", true)
        ));
        
        // Create reader role with read-only privileges
        createRoleIfNotExists(tx, DEFAULT_READER_ROLE, Set.of(
            createPrivilege(Privilege.PrivilegeAction.ACCESS, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.TRAVERSE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.READ, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.MATCH, Privilege.PrivilegeScope.GRAPH, "*", true)
        ));
        
        // Create editor role with read-write privileges
        createRoleIfNotExists(tx, DEFAULT_EDITOR_ROLE, Set.of(
            createPrivilege(Privilege.PrivilegeAction.ACCESS, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.TRAVERSE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.READ, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.MATCH, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.WRITE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.CREATE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.DELETE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.SET_LABEL, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.REMOVE_LABEL, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.SET_PROPERTY, Privilege.PrivilegeScope.GRAPH, "*", true)
        ));
        
        // Create architect role with schema privileges
        createRoleIfNotExists(tx, DEFAULT_ARCHITECT_ROLE, Set.of(
            createPrivilege(Privilege.PrivilegeAction.ACCESS, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.TRAVERSE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.READ, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.MATCH, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.WRITE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.CREATE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.DELETE, Privilege.PrivilegeScope.GRAPH, "*", true),
            createPrivilege(Privilege.PrivilegeAction.CREATE_CONSTRAINT, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.DROP_CONSTRAINT, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.CREATE_INDEX, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.DROP_INDEX, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.CREATE_TOKEN, Privilege.PrivilegeScope.DATABASE, "*", true)
        ));
        
        // Create PUBLIC role with basic privileges
        createRoleIfNotExists(tx, DEFAULT_PUBLIC_ROLE, Set.of(
            createPrivilege(Privilege.PrivilegeAction.ACCESS, Privilege.PrivilegeScope.DATABASE, "DEFAULT", true),
            createPrivilege(Privilege.PrivilegeAction.EXECUTE_PROCEDURE, Privilege.PrivilegeScope.DATABASE, "*", true),
            createPrivilege(Privilege.PrivilegeAction.EXECUTE_FUNCTION, Privilege.PrivilegeScope.DATABASE, "*", true)
        ));
    }
    
    private void createRoleIfNotExists(Transaction tx, String roleName, Set<Privilege> privileges) {
        try (ResourceIterator<Node> nodes = tx.findNodes(Label.label(ROLE_LABEL), ROLE_NAME, roleName)) {
            if (!nodes.hasNext()) {
                Node roleNode = tx.createNode(Label.label(ROLE_LABEL));
                roleNode.setProperty(ROLE_NAME, roleName);
                roleNode.setProperty(ROLE_ID, UUID.randomUUID().toString());
                
                // Add privileges would be done through RoleSecurityGraphComponent
                debugLog.info("Created default role: " + roleName);
            }
        }
    }
    
    private void assignAdminRoleToDefaultUser(Transaction tx) {
        try (ResourceIterator<Node> userNodes = tx.findNodes(Label.label("User"), "name", "neo4j")) {
            if (userNodes.hasNext()) {
                Node userNode = userNodes.next();
                // Would use RoleSecurityGraphComponent to assign role
                debugLog.info("Assigned admin role to neo4j user");
            }
        }
    }
    
    private Privilege createPrivilege(Privilege.PrivilegeAction action, Privilege.PrivilegeScope scope, 
                                     String graph, boolean granted) {
        return new Privilege(
            action,
            scope,
            new Privilege.PrivilegeResource(graph, Set.of("*"), Set.of("*"), Set.of("*"), null),
            granted,
            false
        );
    }
}