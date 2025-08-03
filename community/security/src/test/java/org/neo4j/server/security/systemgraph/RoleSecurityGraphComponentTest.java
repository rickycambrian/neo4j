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
package org.neo4j.server.security.systemgraph;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Label;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Transaction;
import org.neo4j.kernel.impl.security.Privilege;
import org.neo4j.kernel.impl.security.Role;
import org.neo4j.test.TestDatabaseManagementServiceBuilder;
import org.neo4j.test.extension.DbmsController;
import org.neo4j.test.extension.DbmsExtension;
import org.neo4j.test.extension.Inject;

@DbmsExtension
class RoleSecurityGraphComponentTest {
    
    @Inject
    private GraphDatabaseService db;
    
    @Inject
    private DbmsController dbmsController;
    
    private RoleSecurityGraphComponent roleComponent;
    
    @BeforeEach
    void setUp() {
        roleComponent = new RoleSecurityGraphComponent();
    }
    
    @AfterEach
    void tearDown() {
        // Clean up any created roles
        try (Transaction tx = db.beginTx()) {
            tx.findNodes(Label.label("Role")).forEachRemaining(Node::delete);
            tx.commit();
        }
    }
    
    @Test
    void testCreateRole() {
        try (Transaction tx = db.beginTx()) {
            Role role = roleComponent.createRole(tx, "testRole");
            
            assertNotNull(role);
            assertEquals("testRole", role.name());
            assertNotNull(role.id());
            assertTrue(role.privileges().isEmpty());
            
            // Verify role was created in the graph
            Node roleNode = tx.findNode(Label.label("Role"), "name", "testRole");
            assertNotNull(roleNode);
            assertEquals(role.id(), roleNode.getProperty("id"));
            
            tx.commit();
        }
    }
    
    @Test
    void testCreateDuplicateRole() {
        try (Transaction tx = db.beginTx()) {
            roleComponent.createRole(tx, "duplicateRole");
            
            assertThatThrownBy(() -> roleComponent.createRole(tx, "duplicateRole"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already exists");
            
            tx.rollback();
        }
    }
    
    @Test
    void testDeleteRole() {
        try (Transaction tx = db.beginTx()) {
            roleComponent.createRole(tx, "roleToDelete");
            tx.commit();
        }
        
        try (Transaction tx = db.beginTx()) {
            roleComponent.deleteRole(tx, "roleToDelete");
            
            // Verify role was deleted
            assertNull(roleComponent.getRoleByName(tx, "roleToDelete"));
            
            tx.commit();
        }
    }
    
    @Test
    void testDeleteNonExistentRole() {
        try (Transaction tx = db.beginTx()) {
            assertThatThrownBy(() -> roleComponent.deleteRole(tx, "nonExistentRole"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not exist");
            
            tx.rollback();
        }
    }
    
    @Test
    void testGetRoleByName() {
        try (Transaction tx = db.beginTx()) {
            Role createdRole = roleComponent.createRole(tx, "findMe");
            tx.commit();
        }
        
        try (Transaction tx = db.beginTx()) {
            Role foundRole = roleComponent.getRoleByName(tx, "findMe");
            
            assertNotNull(foundRole);
            assertEquals("findMe", foundRole.name());
            
            tx.commit();
        }
    }
    
    @Test
    void testGetAllRoles() {
        try (Transaction tx = db.beginTx()) {
            roleComponent.createRole(tx, "role1");
            roleComponent.createRole(tx, "role2");
            roleComponent.createRole(tx, "role3");
            tx.commit();
        }
        
        try (Transaction tx = db.beginTx()) {
            Set<Role> allRoles = roleComponent.getAllRoles(tx);
            
            assertEquals(3, allRoles.size());
            assertTrue(allRoles.stream().anyMatch(r -> r.name().equals("role1")));
            assertTrue(allRoles.stream().anyMatch(r -> r.name().equals("role2")));
            assertTrue(allRoles.stream().anyMatch(r -> r.name().equals("role3")));
            
            tx.commit();
        }
    }
    
    @Test
    void testAssignRoleToUser() {
        try (Transaction tx = db.beginTx()) {
            // Create a test user
            Node userNode = tx.createNode(Label.label("User"));
            userNode.setProperty("name", "testUser");
            userNode.setProperty("id", "user-id");
            
            // Create a role
            roleComponent.createRole(tx, "userRole");
            
            // Assign role to user
            roleComponent.assignRoleToUser(tx, userNode, "userRole");
            
            // Verify assignment
            Set<String> userRoles = roleComponent.getUserRoles(userNode);
            assertEquals(1, userRoles.size());
            assertTrue(userRoles.contains("userRole"));
            
            tx.commit();
        }
    }
    
    @Test
    void testRemoveRoleFromUser() {
        try (Transaction tx = db.beginTx()) {
            // Create a test user
            Node userNode = tx.createNode(Label.label("User"));
            userNode.setProperty("name", "testUser");
            userNode.setProperty("id", "user-id");
            
            // Create and assign role
            roleComponent.createRole(tx, "tempRole");
            roleComponent.assignRoleToUser(tx, userNode, "tempRole");
            
            // Remove role
            roleComponent.removeRoleFromUser(tx, userNode, "tempRole");
            
            // Verify removal
            Set<String> userRoles = roleComponent.getUserRoles(userNode);
            assertTrue(userRoles.isEmpty());
            
            tx.commit();
        }
    }
    
    @Test
    void testGrantPrivilege() {
        try (Transaction tx = db.beginTx()) {
            roleComponent.createRole(tx, "privilegedRole");
            
            Privilege privilege = new Privilege(
                Privilege.PrivilegeAction.READ,
                Privilege.PrivilegeScope.GRAPH,
                new Privilege.PrivilegeResource("neo4j"),
                true,
                false
            );
            
            roleComponent.grantPrivilege(tx, "privilegedRole", privilege);
            
            // Verify privilege was granted
            Role role = roleComponent.getRoleByName(tx, "privilegedRole");
            assertEquals(1, role.privileges().size());
            
            Privilege grantedPriv = role.privileges().iterator().next();
            assertEquals(Privilege.PrivilegeAction.READ, grantedPriv.action());
            assertEquals(Privilege.PrivilegeScope.GRAPH, grantedPriv.scope());
            assertTrue(grantedPriv.granted());
            
            tx.commit();
        }
    }
    
    @Test
    void testRevokePrivilege() {
        try (Transaction tx = db.beginTx()) {
            roleComponent.createRole(tx, "revokeTestRole");
            
            Privilege privilege = new Privilege(
                Privilege.PrivilegeAction.WRITE,
                Privilege.PrivilegeScope.DATABASE,
                new Privilege.PrivilegeResource("*"),
                true,
                false
            );
            
            // Grant then revoke
            roleComponent.grantPrivilege(tx, "revokeTestRole", privilege);
            roleComponent.revokePrivilege(tx, "revokeTestRole", privilege);
            
            // Verify privilege was revoked
            Role role = roleComponent.getRoleByName(tx, "revokeTestRole");
            assertTrue(role.privileges().isEmpty());
            
            tx.commit();
        }
    }
    
    @Test
    void testMultiplePrivileges() {
        try (Transaction tx = db.beginTx()) {
            roleComponent.createRole(tx, "multiPrivRole");
            
            // Grant multiple privileges
            Privilege readPriv = new Privilege(
                Privilege.PrivilegeAction.READ,
                Privilege.PrivilegeScope.GRAPH,
                new Privilege.PrivilegeResource("*"),
                true,
                false
            );
            
            Privilege writePriv = new Privilege(
                Privilege.PrivilegeAction.WRITE,
                Privilege.PrivilegeScope.GRAPH,
                new Privilege.PrivilegeResource("*"),
                true,
                false
            );
            
            Privilege indexPriv = new Privilege(
                Privilege.PrivilegeAction.CREATE_INDEX,
                Privilege.PrivilegeScope.DATABASE,
                new Privilege.PrivilegeResource("neo4j"),
                true,
                false
            );
            
            roleComponent.grantPrivilege(tx, "multiPrivRole", readPriv);
            roleComponent.grantPrivilege(tx, "multiPrivRole", writePriv);
            roleComponent.grantPrivilege(tx, "multiPrivRole", indexPriv);
            
            // Verify all privileges
            Role role = roleComponent.getRoleByName(tx, "multiPrivRole");
            assertEquals(3, role.privileges().size());
            
            // Check each action is present
            Set<Privilege.PrivilegeAction> actions = role.privileges().stream()
                .map(Privilege::action)
                .collect(java.util.stream.Collectors.toSet());
            
            assertTrue(actions.contains(Privilege.PrivilegeAction.READ));
            assertTrue(actions.contains(Privilege.PrivilegeAction.WRITE));
            assertTrue(actions.contains(Privilege.PrivilegeAction.CREATE_INDEX));
            
            tx.commit();
        }
    }
}