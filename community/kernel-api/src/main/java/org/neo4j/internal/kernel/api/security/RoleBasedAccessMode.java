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

import java.util.Set;
import java.util.function.Supplier;
import org.eclipse.collections.api.set.primitive.IntSet;
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
    public boolean allowsReadNodeProperties(
            Supplier<TokenSet> labels, int[] propertyKeys, ReadSecurityPropertyProvider propertyProvider) {
        return delegate.allowsReadNodeProperties(labels, propertyKeys, propertyProvider);
    }

    @Override
    public boolean allowsReadNodeProperties(Supplier<TokenSet> labels, int[] propertyKeys) {
        return delegate.allowsReadNodeProperties(labels, propertyKeys);
    }

    @Override
    public boolean allowsReadNodeProperty(
            Supplier<TokenSet> labels, int propertyKey, ReadSecurityPropertyProvider propertyProvider) {
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
    public boolean allowsDeleteNode(Supplier<TokenSet> labelSupplier) {
        return delegate.allowsDeleteNode(labelSupplier);
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
    public PermissionState allowsLoadUri(java.net.URI uri, java.net.InetAddress inetAddress) {
        return delegate.allowsLoadUri(uri, inetAddress);
    }

    @Override
    public PermissionState allowsLoadAllData() {
        return delegate.allowsLoadAllData();
    }

    @Override
    public String name() {
        return "role-based:" + username + ":" + String.join(",", roleNames);
    }
}
