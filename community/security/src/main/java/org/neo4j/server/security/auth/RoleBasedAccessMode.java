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

import java.net.InetAddress;
import java.net.URI;
import java.util.HashSet;
import java.util.Set;
import java.util.function.IntPredicate;
import java.util.function.Supplier;
import org.eclipse.collections.api.set.primitive.IntSet;
import org.eclipse.collections.impl.factory.primitive.IntSets;
import org.neo4j.internal.kernel.api.RelTypeSupplier;
import org.neo4j.internal.kernel.api.TokenSet;
import org.neo4j.internal.kernel.api.security.AccessMode;
import org.neo4j.internal.kernel.api.security.PermissionState;
import org.neo4j.internal.kernel.api.security.PrivilegeAction;
import org.neo4j.kernel.impl.security.Privilege;
import org.neo4j.kernel.impl.security.Role;
import org.neo4j.storageengine.api.PropertySelection;

/**
 * AccessMode implementation that evaluates permissions based on roles and privileges.
 */
public class RoleBasedAccessMode implements AccessMode {
    private final String databaseName;
    private final Set<Role> userRoles;
    private final boolean isAuthenticated;
    private final Set<Privilege> allPrivileges;
    
    public RoleBasedAccessMode(String databaseName, Set<Role> userRoles, boolean isAuthenticated) {
        this.databaseName = databaseName;
        this.userRoles = userRoles;
        this.isAuthenticated = isAuthenticated;
        
        // Collect all privileges including inherited ones
        this.allPrivileges = new HashSet<>();
        for (Role role : userRoles) {
            this.allPrivileges.addAll(role.privileges());
        }
    }
    
    @Override
    public boolean allowsWrites() {
        return hasPrivilege(Privilege.PrivilegeAction.WRITE, Privilege.PrivilegeScope.GRAPH);
    }
    
    @Override
    public PermissionState allowsTokenCreates(PrivilegeAction action) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.CREATE_TOKEN, Privilege.PrivilegeScope.DATABASE);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public boolean allowsSchemaWrites() {
        return hasPrivilege(Privilege.PrivilegeAction.CREATE_CONSTRAINT, Privilege.PrivilegeScope.DATABASE) ||
               hasPrivilege(Privilege.PrivilegeAction.CREATE_INDEX, Privilege.PrivilegeScope.DATABASE);
    }
    
    @Override
    public boolean allowsSchemaWrites(PrivilegeAction action) {
        return switch (action) {
            case CREATE_CONSTRAINT -> hasPrivilege(Privilege.PrivilegeAction.CREATE_CONSTRAINT, Privilege.PrivilegeScope.DATABASE);
            case DROP_CONSTRAINT -> hasPrivilege(Privilege.PrivilegeAction.DROP_CONSTRAINT, Privilege.PrivilegeScope.DATABASE);
            case CREATE_INDEX -> hasPrivilege(Privilege.PrivilegeAction.CREATE_INDEX, Privilege.PrivilegeScope.DATABASE);
            case DROP_INDEX -> hasPrivilege(Privilege.PrivilegeAction.DROP_INDEX, Privilege.PrivilegeScope.DATABASE);
            default -> false;
        };
    }
    
    @Override
    public boolean allowsShowSchemas() {
        return hasPrivilege(Privilege.PrivilegeAction.SHOW_CONSTRAINT, Privilege.PrivilegeScope.DATABASE) ||
               hasPrivilege(Privilege.PrivilegeAction.SHOW_INDEX, Privilege.PrivilegeScope.DATABASE);
    }
    
    @Override
    public PermissionState allowsTraverseAllNodeLabels() {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.TRAVERSE, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsTraverseAllRelTypes() {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.TRAVERSE, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsTraverseNodeWithLabel(int label) {
        // In a full implementation, this would check label-specific privileges
        return allowsTraverseAllNodeLabels();
    }
    
    @Override
    public PermissionState allowsTraverseRelType(int relType) {
        // In a full implementation, this would check relationship-type-specific privileges  
        return allowsTraverseAllRelTypes();
    }
    
    @Override
    public IntPredicate allowedTraverseNodeLabelsPredicate() {
        return label -> allowsTraverseNodeWithLabel(label).allowsAccess();
    }
    
    @Override
    public PermissionState allowsTraverseNode(long node, Supplier<TokenSet> labels) {
        return allowsTraverseAllNodeLabels();
    }
    
    @Override
    public IntPredicate allowedTraverseRelTypesPredicate() {
        return relType -> allowsTraverseRelType(relType).allowsAccess();
    }
    
    @Override
    public PermissionState allowsTraverseRelationship(int relType, RelTypeSupplier relTypeSupplier) {
        return allowsTraverseRelType(relType);
    }
    
    @Override
    public PermissionState allowsReadNodeProperties(PropertySelection propertySelection, Supplier<TokenSet> labels) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.READ, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public IntSet getLabelsAccessibleForTraversal(IntSet labelSet) {
        if (allowsTraverseAllNodeLabels().allowsAccess()) {
            return labelSet;
        }
        // In a full implementation, filter based on specific label privileges
        return IntSets.immutable.empty();
    }
    
    @Override
    public PermissionState allowsReadNodeProperty(PropertySelection propertySelection) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.READ, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsReadRelationshipProperty(PropertySelection propertySelection) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.READ, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsProcedureWith(String[] allowed) {
        boolean hasPrivilege = hasPrivilege(Privilege.PrivilegeAction.EXECUTE_PROCEDURE, Privilege.PrivilegeScope.DATABASE);
        return PermissionState.fromAllowList(hasPrivilege);
    }
    
    @Override
    public PermissionState allowsExecuteFunction(int id, String schemaPart, String functionName) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.EXECUTE_FUNCTION, Privilege.PrivilegeScope.DATABASE);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsExecuteProcedure(int id, String schemaPart, String procedureName) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.EXECUTE_PROCEDURE, Privilege.PrivilegeScope.DATABASE);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsExecuteAggregatingFunction(int id, String schemaPart, String functionName) {
        return allowsExecuteFunction(id, schemaPart, functionName);
    }
    
    @Override
    public PermissionState allowsSetLabel(long node, int label) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.SET_LABEL, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsRemoveLabel(long node, int label) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.REMOVE_LABEL, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsCreateNode(int label) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.CREATE, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsDeleteNode(long node, Supplier<TokenSet> labels) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.DELETE, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsCreateRelationship(int relType) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.CREATE, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsDeleteRelationship(int relType) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.DELETE, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsSetProperty(long node, int propertyKey) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.SET_PROPERTY, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public PermissionState allowsSetProperty(long relationship, int propertyKey, RelTypeSupplier relTypeSupplier) {
        boolean allowed = hasPrivilege(Privilege.PrivilegeAction.SET_PROPERTY, Privilege.PrivilegeScope.GRAPH);
        return PermissionState.fromAllowList(allowed);
    }
    
    @Override
    public boolean allowsRunQueryInQueryCache() {
        return isAuthenticated;
    }
    
    @Override
    public boolean allowsCidr(InetAddress inetAddress) {
        return true; // CIDR restrictions not implemented in this basic version
    }
    
    @Override
    public boolean allowedDBMSActionsForProviders(Set<String> actions) {
        return false; // DBMS actions require specific privileges
    }
    
    @Override
    public String name() {
        return "role-based";
    }
    
    private boolean hasPrivilege(Privilege.PrivilegeAction action, Privilege.PrivilegeScope scope) {
        if (!isAuthenticated) {
            return false;
        }
        
        // Check all privileges (including inherited ones)
        for (Privilege privilege : allPrivileges) {
            if (privilege.granted() && 
                privilege.action() == action && 
                (privilege.scope() == scope || privilege.scope() == Privilege.PrivilegeScope.ALL) &&
                privilege.resource().matchesResource(databaseName, null, null)) {
                return true;
            }
        }
        
        return false;
    }
}