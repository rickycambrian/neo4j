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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.neo4j.graphdb.Result;
import org.neo4j.graphdb.Transaction;
import org.neo4j.internal.kernel.api.procs.ProcedureContext;
import org.neo4j.internal.kernel.api.security.AuthSubject;
import org.neo4j.internal.kernel.api.security.SecurityContext;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RoleManagementProceduresTest {
    
    @Mock
    private Transaction transaction;
    
    @Mock
    private SecurityContext securityContext;
    
    @Mock
    private AuthSubject authSubject;
    
    @Mock
    private Result result;
    
    private RoleManagementProcedures procedures;
    
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        procedures = new RoleManagementProcedures();
        procedures.transaction = transaction;
        procedures.securityContext = securityContext;
        
        when(securityContext.subject()).thenReturn(authSubject);
    }
    
    @Test
    void shouldCreateRole() {
        // Given
        when(authSubject.executingUser()).thenReturn("admin");
        mockAdminUser();
        
        // When
        procedures.createRole("test_role");
        
        // Then
        verify(transaction).execute(
            contains("CREATE (r:Role {name: $name"),
            argThat(params -> "test_role".equals(params.get("name")))
        );
    }
    
    @Test
    void shouldFailCreateRoleWithoutAdminAccess() {
        // Given
        when(authSubject.executingUser()).thenReturn("regular_user");
        mockNonAdminUser();
        
        // When/Then
        assertThrows(RuntimeException.class, () -> 
            procedures.createRole("test_role"),
            "Admin access required"
        );
    }
    
    @Test
    void shouldDeleteRole() {
        // Given
        mockAdminUser();
        
        // When
        procedures.deleteRole("test_role");
        
        // Then
        verify(transaction).execute(
            contains("DETACH DELETE r"),
            argThat(params -> "test_role".equals(params.get("name")))
        );
    }
    
    @Test
    void shouldNotDeleteSystemRole() {
        // Given
        mockAdminUser();
        
        // When/Then
        assertThrows(RuntimeException.class, () -> 
            procedures.deleteRole("admin"),
            "Cannot delete system role"
        );
    }
    
    @Test
    void shouldListRoles() {
        // Given
        Map<String, Object> row1 = Map.of("role", "admin");
        Map<String, Object> row2 = Map.of("role", "reader");
        when(transaction.execute(anyString())).thenReturn(result);
        when(result.stream()).thenReturn(Stream.of(row1, row2));
        
        // When
        List<RoleManagementProcedures.RoleResult> roles = 
            procedures.listRoles().collect(Collectors.toList());
        
        // Then
        assertEquals(2, roles.size());
        assertEquals("admin", roles.get(0).role);
        assertEquals("reader", roles.get(1).role);
    }
    
    @Test
    void shouldGrantPrivilege() {
        // Given
        mockAdminUser();
        List<String> labels = Arrays.asList("Customer", "Order");
        
        // When
        procedures.grantPrivilege("sales_role", "READ", labels);
        
        // Then
        verify(transaction).execute(
            contains("MERGE (p:Privilege"),
            argThat(params -> 
                "sales_role".equals(params.get("roleName")) &&
                "READ".equals(params.get("privilege")) &&
                "Customer,Order".equals(params.get("labels"))
            )
        );
    }
    
    @Test
    void shouldDenyPrivilege() {
        // Given
        mockAdminUser();
        List<String> labels = Arrays.asList("Employee");
        
        // When
        procedures.denyPrivilege("hr_role", "DELETE", labels);
        
        // Then
        verify(transaction).execute(
            contains("granted: false"),
            argThat(params -> 
                "hr_role".equals(params.get("roleName")) &&
                "DELETE".equals(params.get("privilege")) &&
                "Employee".equals(params.get("labels"))
            )
        );
    }
    
    @Test
    void shouldGrantRoleToUser() {
        // Given
        mockAdminUser();
        
        // When
        procedures.grantRoleToUser("john_doe", "editor");
        
        // Then
        verify(transaction).execute(
            contains("MERGE (u)-[:HAS_ROLE]->(r)"),
            argThat(params -> 
                "john_doe".equals(params.get("username")) &&
                "editor".equals(params.get("roleName"))
            )
        );
    }
    
    @Test
    void shouldListPrivileges() {
        // Given
        Map<String, Object> row = Map.of(
            "action", "READ",
            "labels", "Customer,Product",
            "granted", true
        );
        when(transaction.execute(anyString(), anyMap())).thenReturn(result);
        when(result.stream()).thenReturn(Stream.of(row));
        
        // When
        List<RoleManagementProcedures.PrivilegeResult> privileges = 
            procedures.listPrivileges("sales_role").collect(Collectors.toList());
        
        // Then
        assertEquals(1, privileges.size());
        assertEquals("READ", privileges.get(0).action);
        assertEquals("Customer,Product", privileges.get(0).labels);
        assertTrue(privileges.get(0).granted);
    }
    
    @Test
    void shouldListRolesForUser() {
        // Given
        when(authSubject.executingUser()).thenReturn("john_doe");
        Map<String, Object> row = Map.of("role", "editor");
        when(transaction.execute(anyString(), anyMap())).thenReturn(result);
        when(result.stream()).thenReturn(Stream.of(row));
        
        // When
        List<RoleManagementProcedures.RoleResult> roles = 
            procedures.listRolesForUser("john_doe").collect(Collectors.toList());
        
        // Then
        assertEquals(1, roles.size());
        assertEquals("editor", roles.get(0).role);
    }
    
    @Test
    void shouldNotListRolesForOtherUserWithoutAdmin() {
        // Given
        when(authSubject.executingUser()).thenReturn("john_doe");
        mockNonAdminUser();
        
        // When/Then
        assertThrows(RuntimeException.class, () -> 
            procedures.listRolesForUser("jane_doe").collect(Collectors.toList()),
            "Can only view own roles"
        );
    }
    
    private void mockAdminUser() {
        Result adminCheck = mock(Result.class);
        when(transaction.execute(contains("Role {name: 'admin'}"), anyMap()))
            .thenReturn(adminCheck);
        when(adminCheck.hasNext()).thenReturn(true);
        when(adminCheck.next()).thenReturn(Map.of("isAdmin", true));
    }
    
    private void mockNonAdminUser() {
        Result adminCheck = mock(Result.class);
        when(transaction.execute(contains("Role {name: 'admin'}"), anyMap()))
            .thenReturn(adminCheck);
        when(adminCheck.hasNext()).thenReturn(false);
    }
}