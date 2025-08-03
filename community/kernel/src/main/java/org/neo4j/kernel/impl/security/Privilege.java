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

import java.util.Set;

/**
 * Represents a privilege in the RBAC system.
 * Privileges control access to specific graph operations and resources.
 */
public record Privilege(
        PrivilegeAction action, PrivilegeScope scope, PrivilegeResource resource, boolean granted, boolean immutable) {

    public enum PrivilegeAction {
        // Graph privileges
        TRAVERSE,
        READ,
        MATCH,
        WRITE,
        CREATE,
        DELETE,
        SET_LABEL,
        REMOVE_LABEL,
        SET_PROPERTY,

        // Database privileges
        ACCESS,
        START,
        STOP,

        // Schema privileges
        CREATE_CONSTRAINT,
        DROP_CONSTRAINT,
        CREATE_INDEX,
        DROP_INDEX,
        SHOW_INDEX,
        SHOW_CONSTRAINT,

        // Token privileges
        CREATE_TOKEN,

        // Procedure privileges
        EXECUTE_PROCEDURE,
        EXECUTE_FUNCTION,
        EXECUTE_BOOSTED_PROCEDURE,
        EXECUTE_BOOSTED_FUNCTION,

        // Admin privileges
        USER_MANAGEMENT,
        ROLE_MANAGEMENT,
        DATABASE_MANAGEMENT,
        PRIVILEGE_MANAGEMENT,
        IMPERSONATE,

        // Transaction privileges
        SHOW_TRANSACTION,
        TERMINATE_TRANSACTION
    }

    public enum PrivilegeScope {
        GRAPH,
        DATABASE,
        DBMS,
        ALL
    }

    public static class PrivilegeResource {
        private final String graph;
        private final Set<String> labels;
        private final Set<String> relationshipTypes;
        private final Set<String> properties;
        private final String pattern;

        public PrivilegeResource(String graph) {
            this(graph, Set.of("*"), Set.of("*"), Set.of("*"), null);
        }

        public PrivilegeResource(
                String graph,
                Set<String> labels,
                Set<String> relationshipTypes,
                Set<String> properties,
                String pattern) {
            this.graph = graph;
            this.labels = labels;
            this.relationshipTypes = relationshipTypes;
            this.properties = properties;
            this.pattern = pattern;
        }

        public String graph() {
            return graph;
        }

        public Set<String> labels() {
            return labels;
        }

        public Set<String> relationshipTypes() {
            return relationshipTypes;
        }

        public Set<String> properties() {
            return properties;
        }

        public String pattern() {
            return pattern;
        }

        public boolean matchesResource(String targetGraph, String targetLabel, String targetType) {
            if (!graph.equals("*") && !graph.equals(targetGraph)) {
                return false;
            }

            if (targetLabel != null && !labels.contains("*") && !labels.contains(targetLabel)) {
                return false;
            }

            if (targetType != null && !relationshipTypes.contains("*") && !relationshipTypes.contains(targetType)) {
                return false;
            }

            return true;
        }
    }
}
