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

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.neo4j.configuration.Config;
import org.neo4j.kernel.api.exceptions.InvalidArgumentsException;

/**
 * Validates RBAC operations and inputs
 */
public class RbacValidator {
    private static final Pattern VALID_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");
    private static final int MAX_NAME_LENGTH = 256;
    private static final int MIN_NAME_LENGTH = 1;
    
    private static final Set<String> VALID_ACTIONS = Set.of(
        "READ", "WRITE", "CREATE", "DELETE", 
        "SET_LABEL", "REMOVE_LABEL", "SET_PROPERTY",
        "ALL", "TRAVERSE", "MATCH",
        "ACCESS", "START", "STOP",
        "CREATE_CONSTRAINT", "DROP_CONSTRAINT",
        "CREATE_INDEX", "DROP_INDEX",
        "SHOW_INDEX", "SHOW_CONSTRAINT",
        "CREATE_TOKEN", "EXECUTE_PROCEDURE",
        "EXECUTE_FUNCTION", "USER_MANAGEMENT",
        "ROLE_MANAGEMENT", "DATABASE_MANAGEMENT",
        "PRIVILEGE_MANAGEMENT", "IMPERSONATE",
        "SHOW_TRANSACTION", "TERMINATE_TRANSACTION"
    );
    
    private static final Set<String> RESERVED_ROLE_NAMES = Set.of(
        "neo4j", "system", "root", "superuser", "anonymous", "authenticated"
    );
    
    private static final Set<String> RESERVED_LABEL_NAMES = Set.of(
        "User", "Role", "Privilege", "_", "__"
    );
    
    private final int maxRolesPerUser;
    private final int maxPrivilegesPerRole;
    
    public RbacValidator(Config config) {
        this.maxRolesPerUser = config.get(RbacSettings.rbac_max_roles_per_user);
        this.maxPrivilegesPerRole = config.get(RbacSettings.rbac_max_privileges_per_role);
    }
    
    /**
     * Validate role name
     */
    public void validateRoleName(String roleName) throws InvalidArgumentsException {
        if (roleName == null || roleName.trim().isEmpty()) {
            throw new InvalidArgumentsException("Role name cannot be empty");
        }
        
        if (roleName.length() < MIN_NAME_LENGTH || roleName.length() > MAX_NAME_LENGTH) {
            throw new InvalidArgumentsException(
                String.format("Role name must be between %d and %d characters", 
                    MIN_NAME_LENGTH, MAX_NAME_LENGTH)
            );
        }
        
        if (!VALID_NAME_PATTERN.matcher(roleName).matches()) {
            throw new InvalidArgumentsException(
                "Role name can only contain letters, numbers, underscores, and hyphens"
            );
        }
        
        if (RESERVED_ROLE_NAMES.contains(roleName.toLowerCase())) {
            throw new InvalidArgumentsException(
                String.format("'%s' is a reserved role name", roleName)
            );
        }
    }
    
    /**
     * Validate username
     */
    public void validateUsername(String username) throws InvalidArgumentsException {
        if (username == null || username.trim().isEmpty()) {
            throw new InvalidArgumentsException("Username cannot be empty");
        }
        
        if (username.length() < MIN_NAME_LENGTH || username.length() > MAX_NAME_LENGTH) {
            throw new InvalidArgumentsException(
                String.format("Username must be between %d and %d characters", 
                    MIN_NAME_LENGTH, MAX_NAME_LENGTH)
            );
        }
        
        if (!VALID_NAME_PATTERN.matcher(username).matches()) {
            throw new InvalidArgumentsException(
                "Username can only contain letters, numbers, underscores, and hyphens"
            );
        }
    }
    
    /**
     * Validate privilege action
     */
    public void validatePrivilegeAction(String action) throws InvalidArgumentsException {
        if (action == null || action.trim().isEmpty()) {
            throw new InvalidArgumentsException("Privilege action cannot be empty");
        }
        
        String upperAction = action.toUpperCase();
        if (!VALID_ACTIONS.contains(upperAction)) {
            throw new InvalidArgumentsException(
                String.format("Invalid privilege action: '%s'. Valid actions are: %s", 
                    action, String.join(", ", VALID_ACTIONS))
            );
        }
    }
    
    /**
     * Validate label names
     */
    public void validateLabels(List<String> labels) throws InvalidArgumentsException {
        if (labels == null || labels.isEmpty()) {
            throw new InvalidArgumentsException("Label list cannot be empty");
        }
        
        for (String label : labels) {
            validateLabel(label);
        }
    }
    
    /**
     * Validate single label
     */
    public void validateLabel(String label) throws InvalidArgumentsException {
        if (label == null || label.trim().isEmpty()) {
            throw new InvalidArgumentsException("Label name cannot be empty");
        }
        
        if (label.length() > MAX_NAME_LENGTH) {
            throw new InvalidArgumentsException(
                String.format("Label name cannot exceed %d characters", MAX_NAME_LENGTH)
            );
        }
        
        if (!VALID_NAME_PATTERN.matcher(label).matches()) {
            throw new InvalidArgumentsException(
                "Label name can only contain letters, numbers, underscores, and hyphens"
            );
        }
        
        if (RESERVED_LABEL_NAMES.contains(label)) {
            throw new InvalidArgumentsException(
                String.format("'%s' is a reserved label name", label)
            );
        }
    }
    
    /**
     * Validate role assignment limits
     */
    public void validateRoleAssignment(String username, int currentRoleCount) 
            throws InvalidArgumentsException {
        if (currentRoleCount >= maxRolesPerUser) {
            throw new InvalidArgumentsException(
                String.format("User '%s' already has maximum number of roles (%d)", 
                    username, maxRolesPerUser)
            );
        }
    }
    
    /**
     * Validate privilege assignment limits
     */
    public void validatePrivilegeAssignment(String roleName, int currentPrivilegeCount) 
            throws InvalidArgumentsException {
        if (currentPrivilegeCount >= maxPrivilegesPerRole) {
            throw new InvalidArgumentsException(
                String.format("Role '%s' already has maximum number of privileges (%d)", 
                    roleName, maxPrivilegesPerRole)
            );
        }
    }
    
    /**
     * Validate that operation is not on system role
     */
    public void validateNotSystemRole(String roleName) throws InvalidArgumentsException {
        Set<String> systemRoles = Set.of("admin", "reader", "editor", "architect", "PUBLIC");
        if (systemRoles.contains(roleName)) {
            throw new InvalidArgumentsException(
                String.format("Cannot modify system role: %s", roleName)
            );
        }
    }
    
    /**
     * Check if role name exists (for create operations)
     */
    public void validateRoleDoesNotExist(Set<String> existingRoles, String roleName) 
            throws InvalidArgumentsException {
        if (existingRoles.contains(roleName)) {
            throw new InvalidArgumentsException(
                String.format("Role '%s' already exists", roleName)
            );
        }
    }
    
    /**
     * Check if role name exists (for update/delete operations)
     */
    public void validateRoleExists(Set<String> existingRoles, String roleName) 
            throws InvalidArgumentsException {
        if (!existingRoles.contains(roleName)) {
            throw new InvalidArgumentsException(
                String.format("Role '%s' does not exist", roleName)
            );
        }
    }
    
    /**
     * Validate password requirements
     */
    public void validatePassword(String password) throws InvalidArgumentsException {
        if (password == null || password.isEmpty()) {
            throw new InvalidArgumentsException("Password cannot be empty");
        }
        
        if (password.length() < 8) {
            throw new InvalidArgumentsException("Password must be at least 8 characters long");
        }
        
        // Add more password complexity rules as needed
    }
    
    /**
     * Sanitize input to prevent injection
     */
    public static String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }
        
        // Remove any potential Cypher injection characters
        return input.replaceAll("[\"'`\\\\]", "");
    }
}