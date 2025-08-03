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
package org.neo4j.server.security.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.neo4j.exceptions.InvalidArgumentException;
import org.neo4j.internal.kernel.api.security.AccessMode;
import org.neo4j.internal.kernel.api.security.PermissionState;
import org.neo4j.kernel.impl.security.Privilege;
import org.neo4j.kernel.impl.security.Role;

class RBACTest {
    
    private Role adminRole;
    private Role readerRole;
    private Role editorRole;
    
    @BeforeEach
    void setUp() {
        // Create test roles with different privileges
        adminRole = new Role("admin", "admin-id", Set.of(
            createPrivilege(Privilege.PrivilegeAction.ACCESS, true),
            createPrivilege(Privilege.PrivilegeAction.READ, true),
            createPrivilege(Privilege.PrivilegeAction.WRITE, true),
            createPrivilege(Privilege.PrivilegeAction.CREATE_CONSTRAINT, true),
            createPrivilege(Privilege.PrivilegeAction.CREATE_INDEX, true),
            createPrivilege(Privilege.PrivilegeAction.USER_MANAGEMENT, true),
            createPrivilege(Privilege.PrivilegeAction.ROLE_MANAGEMENT, true)
        ));
        
        readerRole = new Role("reader", "reader-id", Set.of(
            createPrivilege(Privilege.PrivilegeAction.ACCESS, true),
            createPrivilege(Privilege.PrivilegeAction.READ, true),
            createPrivilege(Privilege.PrivilegeAction.TRAVERSE, true)
        ));
        
        editorRole = new Role("editor", "editor-id", Set.of(
            createPrivilege(Privilege.PrivilegeAction.ACCESS, true),
            createPrivilege(Privilege.PrivilegeAction.READ, true),
            createPrivilege(Privilege.PrivilegeAction.WRITE, true),
            createPrivilege(Privilege.PrivilegeAction.CREATE, true),
            createPrivilege(Privilege.PrivilegeAction.DELETE, true)
        ));
    }
    
    @Test
    void testRoleBasedAccessModeWithAdminRole() {
        RoleBasedAccessMode accessMode = new RoleBasedAccessMode("neo4j", Set.of(adminRole), true);
        
        assertTrue(accessMode.allowsWrites());
        assertTrue(accessMode.allowsSchemaWrites());
        assertEquals(PermissionState.EXPLICIT_GRANT, accessMode.allowsTokenCreates(null));
        assertEquals(PermissionState.EXPLICIT_GRANT, accessMode.allowsTraverseAllNodeLabels());
        assertEquals(PermissionState.EXPLICIT_GRANT, accessMode.allowsExecuteProcedure(0, "db", "labels"));
    }
    
    @Test
    void testRoleBasedAccessModeWithReaderRole() {
        RoleBasedAccessMode accessMode = new RoleBasedAccessMode("neo4j", Set.of(readerRole), true);
        
        assertFalse(accessMode.allowsWrites());
        assertFalse(accessMode.allowsSchemaWrites());
        assertEquals(PermissionState.NOT_GRANTED, accessMode.allowsTokenCreates(null));
        assertEquals(PermissionState.EXPLICIT_GRANT, accessMode.allowsTraverseAllNodeLabels());
        assertEquals(PermissionState.EXPLICIT_GRANT, accessMode.allowsReadNodeProperty(null));
    }
    
    @Test
    void testRoleBasedAccessModeWithEditorRole() {
        RoleBasedAccessMode accessMode = new RoleBasedAccessMode("neo4j", Set.of(editorRole), true);
        
        assertTrue(accessMode.allowsWrites());
        assertFalse(accessMode.allowsSchemaWrites());
        assertEquals(PermissionState.NOT_GRANTED, accessMode.allowsTokenCreates(null));
        assertEquals(PermissionState.EXPLICIT_GRANT, accessMode.allowsCreateNode(0));
        assertEquals(PermissionState.EXPLICIT_GRANT, accessMode.allowsDeleteNode(0, null));
    }
    
    @Test
    void testRoleBasedAccessModeWithMultipleRoles() {
        // User has both reader and editor roles
        RoleBasedAccessMode accessMode = new RoleBasedAccessMode("neo4j", Set.of(readerRole, editorRole), true);
        
        assertTrue(accessMode.allowsWrites()); // From editor role
        assertFalse(accessMode.allowsSchemaWrites()); // Neither role has this
        assertEquals(PermissionState.EXPLICIT_GRANT, accessMode.allowsTraverseAllNodeLabels()); // From reader role
        assertEquals(PermissionState.EXPLICIT_GRANT, accessMode.allowsCreateNode(0)); // From editor role
    }
    
    @Test
    void testRoleBasedAccessModeUnauthenticated() {
        RoleBasedAccessMode accessMode = new RoleBasedAccessMode("neo4j", Set.of(adminRole), false);
        
        assertFalse(accessMode.allowsWrites());
        assertFalse(accessMode.allowsSchemaWrites());
        assertEquals(PermissionState.NOT_GRANTED, accessMode.allowsTokenCreates(null));
        assertEquals(PermissionState.NOT_GRANTED, accessMode.allowsTraverseAllNodeLabels());
    }
    
    @Test
    void testRBACValidation() {
        // Test valid role names
        assertDoesNotThrow(() -> RBACValidation.validateRoleName("validRole"));
        assertDoesNotThrow(() -> RBACValidation.validateRoleName("role_with_underscore"));
        assertDoesNotThrow(() -> RBACValidation.validateRoleName("role123"));
        
        // Test invalid role names
        assertThatThrownBy(() -> RBACValidation.validateRoleName(null))
            .isInstanceOf(InvalidArgumentException.class)
            .hasMessageContaining("cannot be null");
            
        assertThatThrownBy(() -> RBACValidation.validateRoleName(""))
            .isInstanceOf(InvalidArgumentException.class)
            .hasMessageContaining("cannot be null or empty");
            
        assertThatThrownBy(() -> RBACValidation.validateRoleName("role with spaces"))
            .isInstanceOf(InvalidArgumentException.class)
            .hasMessageContaining("can only contain letters, numbers, and underscores");
            
        assertThatThrownBy(() -> RBACValidation.validateRoleName("PUBLIC"))
            .isInstanceOf(InvalidArgumentException.class)
            .hasMessageContaining("reserved role name");
    }
    
    @Test
    void testRoleDeletionValidation() {
        // Test that system roles cannot be deleted
        assertThatThrownBy(() -> RBACValidation.validateRoleDeletion("admin"))
            .isInstanceOf(InvalidArgumentException.class)
            .hasMessageContaining("Cannot delete system role");
            
        assertThatThrownBy(() -> RBACValidation.validateRoleDeletion("PUBLIC"))
            .isInstanceOf(InvalidArgumentException.class)
            .hasMessageContaining("Cannot delete reserved role");
            
        // Test that custom roles can be deleted
        assertDoesNotThrow(() -> RBACValidation.validateRoleDeletion("customRole"));
    }
    
    @Test
    void testPrivilegeValidation() {
        // Test valid privilege action
        assertDoesNotThrow(() -> RBACValidation.validatePrivilegeAction("READ"));
        assertDoesNotThrow(() -> RBACValidation.validatePrivilegeAction("WRITE"));
        assertDoesNotThrow(() -> RBACValidation.validatePrivilegeAction("CREATE_INDEX"));
        
        // Test invalid privilege action
        assertThatThrownBy(() -> RBACValidation.validatePrivilegeAction("INVALID_ACTION"))
            .isInstanceOf(InvalidArgumentException.class)
            .hasMessageContaining("Invalid privilege action");
            
        // Test valid privilege scope
        assertDoesNotThrow(() -> RBACValidation.validatePrivilegeScope("GRAPH"));
        assertDoesNotThrow(() -> RBACValidation.validatePrivilegeScope("DATABASE"));
        assertDoesNotThrow(() -> RBACValidation.validatePrivilegeScope("DBMS"));
        
        // Test invalid privilege scope
        assertThatThrownBy(() -> RBACValidation.validatePrivilegeScope("INVALID_SCOPE"))
            .isInstanceOf(InvalidArgumentException.class)
            .hasMessageContaining("Invalid privilege scope");
    }
    
    @Test
    void testDatabaseNameValidation() {
        // Test valid database names
        assertDoesNotThrow(() -> RBACValidation.validateDatabaseName("neo4j"));
        assertDoesNotThrow(() -> RBACValidation.validateDatabaseName("*"));
        assertDoesNotThrow(() -> RBACValidation.validateDatabaseName("my_database_123"));
        
        // Test invalid database names
        assertThatThrownBy(() -> RBACValidation.validateDatabaseName("database-with-dash"))
            .isInstanceOf(InvalidArgumentException.class)
            .hasMessageContaining("can only contain letters, numbers, and underscores");
    }
    
    @Test
    void testLabelValidation() {
        // Test valid labels
        assertDoesNotThrow(() -> RBACValidation.validateLabels(Set.of("Person", "Employee")));
        assertDoesNotThrow(() -> RBACValidation.validateLabels(Set.of("*")));
        assertDoesNotThrow(() -> RBACValidation.validateLabels(Set.of()));
        
        // Test invalid labels
        assertThatThrownBy(() -> RBACValidation.validateLabels(Set.of("Label:WithColon")))
            .isInstanceOf(InvalidArgumentException.class)
            .hasMessageContaining("Invalid label");
    }
    
    @Test
    void testPrivilegeMatching() {
        Privilege.PrivilegeResource resource = new Privilege.PrivilegeResource(
            "neo4j",
            Set.of("Person", "Employee"),
            Set.of("KNOWS", "WORKS_AT"),
            Set.of("name", "age"),
            null
        );
        
        // Test exact match
        assertTrue(resource.matchesResource("neo4j", "Person", null));
        assertTrue(resource.matchesResource("neo4j", "Employee", null));
        assertTrue(resource.matchesResource("neo4j", null, "KNOWS"));
        assertTrue(resource.matchesResource("neo4j", null, "WORKS_AT"));
        
        // Test non-match
        assertFalse(resource.matchesResource("system", "Person", null));
        assertFalse(resource.matchesResource("neo4j", "Company", null));
        assertFalse(resource.matchesResource("neo4j", null, "MANAGES"));
        
        // Test wildcard resource
        Privilege.PrivilegeResource wildcardResource = new Privilege.PrivilegeResource("*");
        assertTrue(wildcardResource.matchesResource("neo4j", "Person", null));
        assertTrue(wildcardResource.matchesResource("system", "User", null));
    }
    
    private Privilege createPrivilege(Privilege.PrivilegeAction action, boolean granted) {
        return new Privilege(
            action,
            Privilege.PrivilegeScope.GRAPH,
            new Privilege.PrivilegeResource("*"),
            granted,
            false
        );
    }
}