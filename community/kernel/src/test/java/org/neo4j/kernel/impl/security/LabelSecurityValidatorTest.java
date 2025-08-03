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
package org.neo4j.kernel.impl.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.neo4j.internal.kernel.api.NodeCursor;
import org.neo4j.internal.kernel.api.NodeLabelIndexCursor;
import org.neo4j.internal.kernel.api.security.AccessMode;
import org.neo4j.internal.kernel.api.security.LabelBasedAccessMode;
import org.neo4j.internal.kernel.api.security.SecurityContext;
import org.neo4j.token.TokenHolders;
import org.neo4j.token.api.TokenHolder;
import org.neo4j.token.api.TokenNotFoundException;
import org.neo4j.token.api.NamedToken;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class LabelSecurityValidatorTest {
    
    @Mock
    private TokenHolders tokenHolders;
    
    @Mock
    private TokenHolder labelTokens;
    
    @Mock
    private SecurityContext securityContext;
    
    @Mock
    private NodeCursor nodeCursor;
    
    @Mock
    private NodeLabelIndexCursor labelCursor;
    
    private LabelSecurityValidator validator;
    
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(tokenHolders.labelTokens()).thenReturn(labelTokens);
        validator = new LabelSecurityValidator(tokenHolders);
    }
    
    @Test
    void shouldAllowFullAccess() {
        // Given
        AccessMode fullAccess = mock(AccessMode.class);
        when(fullAccess.name()).thenReturn("FULL");
        when(securityContext.mode()).thenReturn(fullAccess);
        
        // When
        boolean canAccess = validator.canAccessNode(securityContext, new long[]{1, 2, 3});
        
        // Then
        assertTrue(canAccess);
    }
    
    @Test
    void shouldCheckLabelBasedAccess() throws TokenNotFoundException {
        // Given
        Map<String, Set<String>> permissions = Map.of(
            "Customer", Set.of("READ", "WRITE"),
            "Product", Set.of("READ")
        );
        LabelBasedAccessMode labelAccess = new LabelBasedAccessMode("user1", permissions, true);
        when(securityContext.mode()).thenReturn(labelAccess);
        
        // Mock label tokens
        when(labelTokens.getTokenById(1)).thenReturn(new NamedToken("Customer", 1));
        when(labelTokens.getTokenById(2)).thenReturn(new NamedToken("Order", 2));
        
        // When
        boolean canAccessCustomer = validator.canAccessNode(securityContext, new long[]{1});
        boolean canAccessOrder = validator.canAccessNode(securityContext, new long[]{2});
        
        // Then
        assertTrue(canAccessCustomer);
        assertFalse(canAccessOrder); // User doesn't have access to Order label
    }
    
    @Test
    void shouldAllowAccessToNodesWithoutLabels() {
        // Given
        when(nodeCursor.hasLabel()).thenReturn(false);
        
        // When
        boolean canRead = validator.canReadNode(securityContext, nodeCursor);
        
        // Then
        assertTrue(canRead);
    }
    
    @Test
    void shouldCheckWritePermissions() {
        // Given
        AccessMode readOnlyAccess = mock(AccessMode.class);
        when(readOnlyAccess.allowsWrites()).thenReturn(false);
        when(securityContext.mode()).thenReturn(readOnlyAccess);
        
        // When
        boolean canWrite = validator.canWriteNode(securityContext, nodeCursor);
        
        // Then
        assertFalse(canWrite);
    }
    
    @Test
    void shouldFilterLabelsBasedOnAccess() throws TokenNotFoundException {
        // Given
        Map<String, Set<String>> permissions = Map.of(
            "Customer", Set.of("READ"),
            "VIP", Set.of("READ")
        );
        LabelBasedAccessMode labelAccess = new LabelBasedAccessMode("user1", permissions, true);
        when(securityContext.mode()).thenReturn(labelAccess);
        
        // Mock label tokens
        when(labelTokens.getTokenById(1)).thenReturn(new NamedToken("Customer", 1));
        when(labelTokens.getTokenById(2)).thenReturn(new NamedToken("Product", 2));
        when(labelTokens.getTokenById(3)).thenReturn(new NamedToken("VIP", 3));
        
        // When
        long[] filtered = validator.filterAllowedLabels(securityContext, new long[]{1, 2, 3});
        
        // Then
        assertEquals(2, filtered.length);
        assertTrue(contains(filtered, 1)); // Customer
        assertTrue(contains(filtered, 3)); // VIP
        assertFalse(contains(filtered, 2)); // Product (not allowed)
    }
    
    @Test
    void shouldHandleTokenNotFound() throws TokenNotFoundException {
        // Given
        Map<String, Set<String>> permissions = Map.of("Customer", Set.of("READ"));
        LabelBasedAccessMode labelAccess = new LabelBasedAccessMode("user1", permissions, true);
        when(securityContext.mode()).thenReturn(labelAccess);
        
        when(labelTokens.getTokenById(1)).thenThrow(new TokenNotFoundException("Token not found", 1));
        
        // When
        boolean canAccess = validator.canAccessNode(securityContext, new long[]{1});
        
        // Then
        assertFalse(canAccess); // Fail closed on error
    }
    
    @Test
    void shouldClearCache() throws TokenNotFoundException {
        // Given
        when(labelTokens.getTokenById(1)).thenReturn(new NamedToken("Customer", 1));
        
        // Access to populate cache
        validator.canAccessNode(securityContext, new long[]{1});
        
        // When
        validator.clearCache();
        
        // Change the token name
        when(labelTokens.getTokenById(1)).thenReturn(new NamedToken("Client", 1));
        
        // Access again
        validator.canAccessNode(securityContext, new long[]{1});
        
        // Then
        verify(labelTokens, times(2)).getTokenById(1); // Should be called twice due to cache clear
    }
    
    private boolean contains(long[] array, long value) {
        for (long l : array) {
            if (l == value) return true;
        }
        return false;
    }
}