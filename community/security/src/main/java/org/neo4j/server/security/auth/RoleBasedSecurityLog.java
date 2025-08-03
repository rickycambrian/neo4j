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

import org.neo4j.internal.kernel.api.security.AbstractSecurityLog;
import org.neo4j.internal.kernel.api.security.SecurityContext;
import org.neo4j.kernel.impl.security.Privilege;
import org.neo4j.logging.Log;

/**
 * Security log for RBAC operations with audit capabilities.
 */
public class RoleBasedSecurityLog {

    private final AbstractSecurityLog securityLog;
    private final Log auditLog;

    public RoleBasedSecurityLog(AbstractSecurityLog securityLog, Log auditLog) {
        this.securityLog = securityLog;
        this.auditLog = auditLog;
    }

    // Role operations logging

    public void logRoleCreated(SecurityContext context, String roleName) {
        String message = String.format(
                "Role '%s' created by user '%s'", roleName, context.subject().executingUser());
        securityLog.info(context, message);
        auditLog.info(message);
    }

    public void logRoleDeleted(SecurityContext context, String roleName) {
        String message = String.format(
                "Role '%s' deleted by user '%s'", roleName, context.subject().executingUser());
        securityLog.info(context, message);
        auditLog.info(message);
    }

    public void logRoleRenamed(SecurityContext context, String oldName, String newName) {
        String message = String.format(
                "Role '%s' renamed to '%s' by user '%s'",
                oldName, newName, context.subject().executingUser());
        securityLog.info(context, message);
        auditLog.info(message);
    }

    // User-Role assignment logging

    public void logRoleGrantedToUser(SecurityContext context, String username, String roleName) {
        String message = String.format(
                "Role '%s' granted to user '%s' by '%s'",
                roleName, username, context.subject().executingUser());
        securityLog.info(context, message);
        auditLog.info(message);
    }

    public void logRoleRevokedFromUser(SecurityContext context, String username, String roleName) {
        String message = String.format(
                "Role '%s' revoked from user '%s' by '%s'",
                roleName, username, context.subject().executingUser());
        securityLog.info(context, message);
        auditLog.info(message);
    }

    // Privilege operations logging

    public void logPrivilegeGranted(SecurityContext context, String roleName, Privilege privilege) {
        String message = String.format(
                "Privilege '%s' on '%s' granted to role '%s' by user '%s'",
                privilege.action(),
                privilege.resource().graph(),
                roleName,
                context.subject().executingUser());
        securityLog.info(context, message);
        auditLog.info(message);
    }

    public void logPrivilegeDenied(SecurityContext context, String roleName, Privilege privilege) {
        String message = String.format(
                "Privilege '%s' on '%s' denied to role '%s' by user '%s'",
                privilege.action(),
                privilege.resource().graph(),
                roleName,
                context.subject().executingUser());
        securityLog.info(context, message);
        auditLog.info(message);
    }

    public void logPrivilegeRevoked(SecurityContext context, String roleName, Privilege privilege) {
        String message = String.format(
                "Privilege '%s' on '%s' revoked from role '%s' by user '%s'",
                privilege.action(),
                privilege.resource().graph(),
                roleName,
                context.subject().executingUser());
        securityLog.info(context, message);
        auditLog.info(message);
    }

    // Access control logging

    public void logAccessGranted(SecurityContext context, String resource, String action) {
        String message = String.format(
                "Access granted: user '%s' performed '%s' on '%s'",
                context.subject().executingUser(), action, resource);
        securityLog.debug(context, message);
    }

    public void logAccessDenied(SecurityContext context, String resource, String action, String reason) {
        String message = String.format(
                "Access denied: user '%s' attempted '%s' on '%s' - %s",
                context.subject().executingUser(), action, resource, reason);
        securityLog.warn(context, message);
        auditLog.warn(message);
    }

    // Authentication logging

    public void logRoleBasedAuthSuccess(SecurityContext context, String username, int roleCount) {
        String message = String.format("User '%s' authenticated successfully with %d roles", username, roleCount);
        securityLog.info(context, message);
        auditLog.info(message);
    }

    public void logRoleBasedAuthFailure(String username, String reason) {
        String message = String.format("Authentication failed for user '%s': %s", username, reason);
        // No context available for failed auth
        auditLog.warn(message);
    }

    // Error logging

    public void logRoleOperationError(SecurityContext context, String operation, String details, Exception e) {
        String message = String.format(
                "Role operation error: %s - %s by user '%s'",
                operation, details, context.subject().executingUser());
        securityLog.error(context, message);
        auditLog.error(message, e);
    }

    public void logPrivilegeOperationError(SecurityContext context, String operation, String details, Exception e) {
        String message = String.format(
                "Privilege operation error: %s - %s by user '%s'",
                operation, details, context.subject().executingUser());
        securityLog.error(context, message);
        auditLog.error(message, e);
    }

    // System events

    public void logRBACSystemInitialized(int roleCount, int userCount) {
        String message = String.format("RBAC system initialized with %d roles and %d users", roleCount, userCount);
        auditLog.info(message);
    }

    public void logRBACSystemShutdown() {
        auditLog.info("RBAC system shutdown");
    }

    // Migration and upgrade events

    public void logSecurityGraphMigration(String fromVersion, String toVersion) {
        String message = String.format("Security graph migrated from version %s to %s", fromVersion, toVersion);
        auditLog.info(message);
    }

    public void logDefaultRolesCreated(int count) {
        String message = String.format("Created %d default roles during initialization", count);
        auditLog.info(message);
    }
}
