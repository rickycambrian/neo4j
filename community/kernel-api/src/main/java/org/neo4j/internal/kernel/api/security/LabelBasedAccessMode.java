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
package org.neo4j.internal.kernel.api.security;

import java.net.InetAddress;
import java.net.URI;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import org.eclipse.collections.api.set.primitive.IntSet;
import org.eclipse.collections.impl.factory.primitive.IntSets;
import org.neo4j.internal.kernel.api.RelTypeSupplier;
import org.neo4j.internal.kernel.api.TokenSet;
import org.neo4j.storageengine.api.PropertySelection;

/**
 * Label-based implementation of AccessMode that enforces permissions based on node labels
 */
public class LabelBasedAccessMode implements AccessMode {
    private final String username;
    private final Map<String, Set<String>> labelPermissions; // label -> allowed actions
    private final Set<String> allowedLabels;
    private final boolean defaultDeny;

    public LabelBasedAccessMode(String username, Map<String, Set<String>> labelPermissions, boolean defaultDeny) {
        this.username = username;
        this.labelPermissions = labelPermissions;
        this.allowedLabels = labelPermissions.keySet();
        this.defaultDeny = defaultDeny;
    }

    @Override
    public boolean allowsWrites() {
        // Check if any label has write permission
        return labelPermissions.values().stream()
                .anyMatch(actions -> actions.contains("WRITE") || actions.contains("ALL"));
    }

    @Override
    public PermissionState allowsTokenCreates(PrivilegeAction action) {
        return defaultDeny ? PermissionState.DENIED : PermissionState.ALLOWED;
    }

    @Override
    public boolean allowsSchemaWrites() {
        return false; // Label-based users typically shouldn't modify schema
    }

    @Override
    public PermissionState allowsSchemaWrites(PrivilegeAction action) {
        return PermissionState.DENIED;
    }

    @Override
    public boolean allowsShowIndex() {
        return true;
    }

    @Override
    public boolean allowsShowConstraint() {
        return true;
    }

    @Override
    public boolean allowsTraverseAllLabels() {
        return !defaultDeny && allowedLabels.isEmpty();
    }

    @Override
    public boolean allowsTraverseAllNodesWithLabel(int label) {
        // This would need to be mapped from label ID to label name
        // For now, allow if we have any permissions on labels
        return !allowedLabels.isEmpty();
    }

    @Override
    public boolean disallowsTraverseLabel(int label) {
        // Would need label ID to name mapping
        return defaultDeny && !allowedLabels.isEmpty();
    }

    @Override
    public boolean allowsTraverseNode(int... labels) {
        // Check if any of the node's labels are allowed
        // Would need label ID to name mapping
        return !defaultDeny || !allowedLabels.isEmpty();
    }

    @Override
    public IntSet getTraverseSecurityProperties(int[] labels) {
        return IntSets.immutable.empty();
    }

    @Override
    public boolean hasApplicableTraverseAllowPropertyRules(int label) {
        return false;
    }

    @Override
    public boolean allowsTraverseNodeWithPropertyRules(ReadSecurityPropertyProvider propertyProvider, int... labels) {
        return allowsTraverseNode(labels);
    }

    @Override
    public boolean hasTraversePropertyRules() {
        return false;
    }

    @Override
    public boolean allowsTraverseAllRelTypes() {
        return !defaultDeny;
    }

    @Override
    public boolean allowsTraverseRelType(int relType) {
        return !defaultDeny;
    }

    @Override
    public boolean disallowsTraverseRelType(int relType) {
        return defaultDeny;
    }

    @Override
    public boolean allowsReadPropertyAllLabels(int propertyKey) {
        return !defaultDeny && labelPermissions.values().stream()
                .anyMatch(actions -> actions.contains("READ") || actions.contains("ALL"));
    }

    @Override
    public boolean disallowsReadPropertyForSomeLabel(int propertyKey) {
        return defaultDeny;
    }

    @Override
    public boolean allowsReadNodeProperties(
            Supplier<TokenSet> labels, int[] propertyKeys, ReadSecurityPropertyProvider propertyProvider) {
        return allowsReadNodeProperties(labels, propertyKeys);
    }

    @Override
    public boolean allowsReadNodeProperties(Supplier<TokenSet> labels, int[] propertyKeys) {
        // Would need to check if the node's labels are in allowedLabels
        return !defaultDeny || !allowedLabels.isEmpty();
    }

    @Override
    public boolean allowsReadNodeProperty(
            Supplier<TokenSet> labels, int propertyKey, ReadSecurityPropertyProvider propertyProvider) {
        return allowsReadNodeProperty(labels, propertyKey);
    }

    @Override
    public boolean allowsReadNodeProperty(Supplier<TokenSet> labels, int propertyKey) {
        return !defaultDeny || !allowedLabels.isEmpty();
    }

    @Override
    public boolean allowsReadPropertyAllRelTypes(int propertyKey) {
        return !defaultDeny;
    }

    @Override
    public boolean allowsReadRelationshipProperty(RelTypeSupplier relType, int propertyKey) {
        return !defaultDeny;
    }

    @Override
    public IntSet getAllReadSecurityProperties() {
        return IntSets.immutable.empty();
    }

    @Override
    public PropertySelection getSecurityPropertySelection(PropertySelection selection) {
        return selection;
    }

    @Override
    public boolean allowsSeePropertyKeyToken(int propertyKey) {
        return true;
    }

    @Override
    public boolean hasPropertyReadRules() {
        return false;
    }

    @Override
    public boolean hasPropertyReadRules(int... propertyKeys) {
        return false;
    }

    @Override
    public IntSet getReadSecurityProperties(int propertyKey) {
        return IntSets.immutable.empty();
    }

    @Override
    public PermissionState allowsExecuteProcedure(int procedureId) {
        return defaultDeny ? PermissionState.DENIED : PermissionState.ALLOWED;
    }

    @Override
    public PermissionState allowExecuteAdminProcedures() {
        return PermissionState.DENIED;
    }

    @Override
    public PermissionState shouldBoostProcedure(int procedureId) {
        return PermissionState.DENIED;
    }

    @Override
    public PermissionState allowsExecuteFunction(int id) {
        return PermissionState.ALLOWED;
    }

    @Override
    public PermissionState shouldBoostFunction(int id) {
        return PermissionState.DENIED;
    }

    @Override
    public PermissionState allowsExecuteAggregatingFunction(int id) {
        return PermissionState.ALLOWED;
    }

    @Override
    public PermissionState shouldBoostAggregatingFunction(int id) {
        return PermissionState.DENIED;
    }

    @Override
    public PermissionState allowsShowSetting(String setting) {
        return PermissionState.ALLOWED;
    }

    @Override
    public boolean allowsSetLabel(int labelId) {
        // Would need label ID to name mapping
        return !defaultDeny && labelPermissions.values().stream()
                .anyMatch(actions -> actions.contains("SET_LABEL") || actions.contains("WRITE") || actions.contains("ALL"));
    }

    @Override
    public boolean allowsRemoveLabel(int labelId) {
        return !defaultDeny && labelPermissions.values().stream()
                .anyMatch(actions -> actions.contains("REMOVE_LABEL") || actions.contains("WRITE") || actions.contains("ALL"));
    }

    @Override
    public boolean allowsCreateNode(int[] labelIds) {
        return !defaultDeny && labelPermissions.values().stream()
                .anyMatch(actions -> actions.contains("CREATE") || actions.contains("WRITE") || actions.contains("ALL"));
    }

    @Override
    public boolean allowsDeleteNode(Supplier<TokenSet> labelSupplier) {
        return !defaultDeny && labelPermissions.values().stream()
                .anyMatch(actions -> actions.contains("DELETE") || actions.contains("WRITE") || actions.contains("ALL"));
    }

    @Override
    public boolean allowsCreateRelationship(int relType) {
        return !defaultDeny && labelPermissions.values().stream()
                .anyMatch(actions -> actions.contains("CREATE") || actions.contains("WRITE") || actions.contains("ALL"));
    }

    @Override
    public boolean allowsDeleteRelationship(int relType) {
        return !defaultDeny && labelPermissions.values().stream()
                .anyMatch(actions -> actions.contains("DELETE") || actions.contains("WRITE") || actions.contains("ALL"));
    }

    @Override
    public boolean allowsSetProperty(Supplier<TokenSet> labels, int propertyKey) {
        return !defaultDeny && labelPermissions.values().stream()
                .anyMatch(actions -> actions.contains("SET_PROPERTY") || actions.contains("WRITE") || actions.contains("ALL"));
    }

    @Override
    public boolean allowsSetProperty(RelTypeSupplier relType, int propertyKey) {
        return !defaultDeny;
    }

    @Override
    public PermissionState allowsLoadUri(URI uri, InetAddress inetAddress) {
        return PermissionState.DENIED;
    }

    @Override
    public PermissionState allowsLoadAllData() {
        return PermissionState.DENIED;
    }

    @Override
    public String name() {
        return "label-based:" + username + ":" + String.join(",", allowedLabels);
    }
}