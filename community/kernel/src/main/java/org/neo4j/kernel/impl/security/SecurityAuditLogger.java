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

import java.time.Clock;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import org.neo4j.internal.kernel.api.security.SecurityContext;
import org.neo4j.logging.Log;
import org.neo4j.logging.LogProvider;

/**
 * Audit logger for security events
 */
public class SecurityAuditLogger {
    private final Log auditLog;
    private final Clock clock;
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
    
    public SecurityAuditLogger(LogProvider logProvider) {
        this(logProvider, Clock.systemUTC());
    }
    
    public SecurityAuditLogger(LogProvider logProvider, Clock clock) {
        this.auditLog = logProvider.getLog("neo4j.security.audit");
        this.clock = clock;
    }
    
    /**
     * Log a successful authentication
     */
    public void logAuthentication(String username, String authMethod, boolean success) {
        String timestamp = ZonedDateTime.now(clock).format(TIMESTAMP_FORMAT);
        String status = success ? "SUCCESS" : "FAILURE";
        
        auditLog.info(String.format(
            "[%s] AUTH %s user=%s method=%s",
            timestamp, status, username, authMethod
        ));
    }
    
    /**
     * Log a role assignment
     */
    public void logRoleAssignment(SecurityContext context, String targetUser, String role, String action) {
        String timestamp = ZonedDateTime.now(clock).format(TIMESTAMP_FORMAT);
        String admin = context.subject().executingUser();
        
        auditLog.info(String.format(
            "[%s] ROLE %s admin=%s user=%s role=%s",
            timestamp, action, admin, targetUser, role
        ));
    }
    
    /**
     * Log a privilege change
     */
    public void logPrivilegeChange(SecurityContext context, String role, String privilege, String labels, String action) {
        String timestamp = ZonedDateTime.now(clock).format(TIMESTAMP_FORMAT);
        String admin = context.subject().executingUser();
        
        auditLog.info(String.format(
            "[%s] PRIVILEGE %s admin=%s role=%s privilege=%s labels=%s",
            timestamp, action, admin, role, privilege, labels
        ));
    }
    
    /**
     * Log an access denial
     */
    public void logAccessDenied(SecurityContext context, String operation, long resourceId, String reason) {
        String timestamp = ZonedDateTime.now(clock).format(TIMESTAMP_FORMAT);
        String user = context.subject().executingUser();
        
        auditLog.warn(String.format(
            "[%s] ACCESS_DENIED user=%s operation=%s resource=%d reason=%s",
            timestamp, user, operation, resourceId, reason
        ));
    }
    
    /**
     * Log a security configuration change
     */
    public void logConfigChange(SecurityContext context, String setting, String oldValue, String newValue) {
        String timestamp = ZonedDateTime.now(clock).format(TIMESTAMP_FORMAT);
        String admin = context.subject().executingUser();
        
        auditLog.info(String.format(
            "[%s] CONFIG_CHANGE admin=%s setting=%s old=%s new=%s",
            timestamp, admin, setting, oldValue, newValue
        ));
    }
    
    /**
     * Log a user management action
     */
    public void logUserManagement(SecurityContext context, String action, String targetUser) {
        String timestamp = ZonedDateTime.now(clock).format(TIMESTAMP_FORMAT);
        String admin = context.subject().executingUser();
        
        auditLog.info(String.format(
            "[%s] USER_%s admin=%s user=%s",
            timestamp, action.toUpperCase(), admin, targetUser
        ));
    }
    
    /**
     * Log a security violation attempt
     */
    public void logSecurityViolation(SecurityContext context, String violationType, String details) {
        String timestamp = ZonedDateTime.now(clock).format(TIMESTAMP_FORMAT);
        String user = context.subject().executingUser();
        
        auditLog.error(String.format(
            "[%s] SECURITY_VIOLATION user=%s type=%s details=%s",
            timestamp, user, violationType, details
        ));
    }
    
    /**
     * Log procedure execution
     */
    public void logProcedureExecution(SecurityContext context, String procedureName, boolean allowed) {
        String timestamp = ZonedDateTime.now(clock).format(TIMESTAMP_FORMAT);
        String user = context.subject().executingUser();
        String status = allowed ? "ALLOWED" : "DENIED";
        
        auditLog.info(String.format(
            "[%s] PROCEDURE_%s user=%s procedure=%s",
            timestamp, status, user, procedureName
        ));
    }
}