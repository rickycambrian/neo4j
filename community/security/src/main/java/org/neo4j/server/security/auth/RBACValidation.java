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

import java.util.Set;
import java.util.regex.Pattern;
import org.neo4j.exceptions.InvalidArgumentException;
import org.neo4j.kernel.impl.security.Privilege;

/**
 * Validation utilities for RBAC operations.
 */
public class RBACValidation {

    // Role name constraints
    private static final int MIN_ROLE_NAME_LENGTH = 1;
    private static final int MAX_ROLE_NAME_LENGTH = 256;
    private static final Pattern ROLE_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]+$");

    // Reserved role names that cannot be created/deleted
    private static final Set<String> RESERVED_ROLES = Set.of("PUBLIC", "SYSTEM", "ANONYMOUS");

    // System roles that cannot be deleted but can be modified
    private static final Set<String> SYSTEM_ROLES = Set.of("admin", "reader", "editor", "architect", "publisher");

    /**
     * Validates a role name for creation.
     */
    public static void validateRoleName(String roleName) {
        if (roleName == null || roleName.isBlank()) {
            throw new InvalidArgumentException("Role name cannot be null or empty");
        }

        if (roleName.length() < MIN_ROLE_NAME_LENGTH || roleName.length() > MAX_ROLE_NAME_LENGTH) {
            throw new InvalidArgumentException(String.format(
                    "Role name must be between %d and %d characters", MIN_ROLE_NAME_LENGTH, MAX_ROLE_NAME_LENGTH));
        }

        if (!ROLE_NAME_PATTERN.matcher(roleName).matches()) {
            throw new InvalidArgumentException("Role name can only contain letters, numbers, and underscores");
        }

        if (RESERVED_ROLES.contains(roleName.toUpperCase())) {
            throw new InvalidArgumentException(String.format("'%s' is a reserved role name", roleName));
        }
    }

    /**
     * Validates if a role can be deleted.
     */
    public static void validateRoleDeletion(String roleName) {
        if (RESERVED_ROLES.contains(roleName.toUpperCase())) {
            throw new InvalidArgumentException(String.format("Cannot delete reserved role '%s'", roleName));
        }

        if (SYSTEM_ROLES.contains(roleName)) {
            throw new InvalidArgumentException(String.format("Cannot delete system role '%s'", roleName));
        }
    }

    /**
     * Validates if a role can be modified.
     */
    public static void validateRoleModification(String roleName) {
        if (RESERVED_ROLES.contains(roleName.toUpperCase())) {
            throw new InvalidArgumentException(String.format("Cannot modify reserved role '%s'", roleName));
        }
    }

    /**
     * Validates a username.
     */
    public static void validateUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new InvalidArgumentException("Username cannot be null or empty");
        }

        if (username.length() > 256) {
            throw new InvalidArgumentException("Username cannot exceed 256 characters");
        }
    }

    /**
     * Validates a privilege action.
     */
    public static void validatePrivilegeAction(String action) {
        if (action == null || action.isBlank()) {
            throw new InvalidArgumentException("Privilege action cannot be null or empty");
        }

        try {
            Privilege.PrivilegeAction.valueOf(action.toUpperCase().replace(" ", "_"));
        } catch (IllegalArgumentException e) {
            throw new InvalidArgumentException(String.format("Invalid privilege action: '%s'", action));
        }
    }

    /**
     * Validates a privilege scope.
     */
    public static void validatePrivilegeScope(String scope) {
        if (scope == null || scope.isBlank()) {
            throw new InvalidArgumentException("Privilege scope cannot be null or empty");
        }

        try {
            Privilege.PrivilegeScope.valueOf(scope.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new InvalidArgumentException(String.format("Invalid privilege scope: '%s'", scope));
        }
    }

    /**
     * Validates a database/graph name.
     */
    public static void validateDatabaseName(String dbName) {
        if (dbName == null || dbName.isBlank()) {
            throw new InvalidArgumentException("Database name cannot be null or empty");
        }

        if (!dbName.equals("*") && !dbName.matches("^[a-zA-Z0-9_]+$")) {
            throw new InvalidArgumentException(
                    "Database name can only contain letters, numbers, and underscores, or be '*' for all databases");
        }
    }

    /**
     * Validates labels for privileges.
     */
    public static void validateLabels(Set<String> labels) {
        if (labels == null || labels.isEmpty()) {
            return; // Empty is valid, means all labels
        }

        for (String label : labels) {
            if (label == null || label.isBlank()) {
                throw new InvalidArgumentException("Label cannot be null or empty");
            }

            if (!label.equals("*") && !label.matches("^[a-zA-Z0-9_]+$")) {
                throw new InvalidArgumentException(String.format(
                        "Invalid label: '%s'. Labels can only contain letters, numbers, and underscores", label));
            }
        }
    }

    /**
     * Validates relationship types for privileges.
     */
    public static void validateRelationshipTypes(Set<String> types) {
        if (types == null || types.isEmpty()) {
            return; // Empty is valid, means all types
        }

        for (String type : types) {
            if (type == null || type.isBlank()) {
                throw new InvalidArgumentException("Relationship type cannot be null or empty");
            }

            if (!type.equals("*") && !type.matches("^[a-zA-Z0-9_]+$")) {
                throw new InvalidArgumentException(String.format(
                        "Invalid relationship type: '%s'. Types can only contain letters, numbers, and underscores",
                        type));
            }
        }
    }

    /**
     * Validates properties for privileges.
     */
    public static void validateProperties(Set<String> properties) {
        if (properties == null || properties.isEmpty()) {
            return; // Empty is valid, means all properties
        }

        for (String property : properties) {
            if (property == null || property.isBlank()) {
                throw new InvalidArgumentException("Property name cannot be null or empty");
            }

            if (!property.equals("*") && !property.matches("^[a-zA-Z0-9_]+$")) {
                throw new InvalidArgumentException(String.format(
                        "Invalid property: '%s'. Properties can only contain letters, numbers, and underscores",
                        property));
            }
        }
    }

    /**
     * Validates a complete privilege specification.
     */
    public static void validatePrivilege(Privilege privilege) {
        if (privilege == null) {
            throw new InvalidArgumentException("Privilege cannot be null");
        }

        if (privilege.action() == null) {
            throw new InvalidArgumentException("Privilege action cannot be null");
        }

        if (privilege.scope() == null) {
            throw new InvalidArgumentException("Privilege scope cannot be null");
        }

        if (privilege.resource() == null) {
            throw new InvalidArgumentException("Privilege resource cannot be null");
        }

        validateDatabaseName(privilege.resource().graph());
        validateLabels(privilege.resource().labels());
        validateRelationshipTypes(privilege.resource().relationshipTypes());
        validateProperties(privilege.resource().properties());
    }

    /**
     * Checks if a user has the required privilege to perform an operation.
     */
    public static void requirePrivilege(
            Set<Privilege> userPrivileges, Privilege.PrivilegeAction requiredAction, String errorMessage) {
        boolean hasPrivilege = userPrivileges.stream().anyMatch(p -> p.granted() && p.action() == requiredAction);

        if (!hasPrivilege) {
            throw new InvalidArgumentException(errorMessage);
        }
    }
}
