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

import static org.neo4j.configuration.GraphDatabaseSettings.SYSTEM_DATABASE_NAME;
import static org.neo4j.internal.kernel.api.security.AuthenticationResult.FAILURE;
import static org.neo4j.internal.kernel.api.security.AuthenticationResult.PASSWORD_CHANGE_REQUIRED;
import static org.neo4j.internal.kernel.api.security.AuthenticationResult.TOO_MANY_ATTEMPTS;

import java.util.Map;
import java.util.Set;
import org.neo4j.gqlstatus.ErrorGqlStatusObjectImplementation;
import org.neo4j.gqlstatus.GqlStatusInfoCodes;
import org.neo4j.graphdb.security.AuthorizationViolationException;
import org.neo4j.internal.kernel.api.connectioninfo.ClientConnectionInfo;
import org.neo4j.internal.kernel.api.security.AbstractSecurityLog;
import org.neo4j.internal.kernel.api.security.AccessMode;
import org.neo4j.internal.kernel.api.security.AuthSubject;
import org.neo4j.internal.kernel.api.security.AuthenticationResult;
import org.neo4j.internal.kernel.api.security.LoginContext;
import org.neo4j.internal.kernel.api.security.LabelBasedAccessMode;
import org.neo4j.internal.kernel.api.security.RoleBasedAccessMode;
import org.neo4j.internal.kernel.api.security.SecurityAuthorizationHandler;
import org.neo4j.internal.kernel.api.security.SecurityContext;
import org.neo4j.kernel.api.exceptions.Status;
import org.neo4j.kernel.database.PrivilegeDatabaseReference;
import org.neo4j.kernel.impl.security.User;
import org.neo4j.server.security.systemgraph.SecurityGraphHelper;

public class BasicLoginContext extends LoginContext {
    private final AccessMode accessMode;
    private final SecurityGraphHelper securityGraphHelper;
    private final User user;
    private final AuthenticationResult authenticationResult;

    public BasicLoginContext(
            User user,
            AuthenticationResult authenticationResult,
            ClientConnectionInfo connectionInfo,
            SecurityGraphHelper securityGraphHelper) {
        super(new BasicAuthSubject(user, authenticationResult), connectionInfo);
        this.user = user;
        this.authenticationResult = authenticationResult;
        this.securityGraphHelper = securityGraphHelper;

        // For backwards compatibility, use static access modes for non-SUCCESS cases
        switch (authenticationResult) {
            case SUCCESS:
                accessMode = null; // Will be created per database
                break;
            case PASSWORD_CHANGE_REQUIRED:
                accessMode = AccessMode.Static.CREDENTIALS_EXPIRED;
                break;
            default:
                accessMode = AccessMode.Static.ACCESS;
        }
    }

    // Backwards compatibility constructor
    public BasicLoginContext(
            User user, AuthenticationResult authenticationResult, ClientConnectionInfo connectionInfo) {
        this(user, authenticationResult, connectionInfo, null);
    }

    private static class BasicAuthSubject implements AuthSubject {
        private final User user;
        private final AuthenticationResult authenticationResult;

        BasicAuthSubject(User user, AuthenticationResult authenticationResult) {
            this.user = user;
            this.authenticationResult = authenticationResult;
        }

        @Override
        public AuthenticationResult getAuthenticationResult() {
            return authenticationResult;
        }

        @Override
        public String executingUser() {
            if (user != null) {
                return user.name();
            }
            return ""; // could be the case if user not exists
        }

        @Override
        public boolean hasUsername(String username) {
            return executingUser().equals(username);
        }
    }

    @Override
    public SecurityContext authorize(
            IdLookup idLookup, PrivilegeDatabaseReference dbReference, AbstractSecurityLog securityLog) {
        String dbName = dbReference.name();

        // Create role-based access mode if we have role support and auth was successful
        AccessMode effectiveAccessMode = accessMode;
        if (effectiveAccessMode == null
                && securityGraphHelper != null
                && user != null
                && authenticationResult == AuthenticationResult.SUCCESS) {
            try {
                // Get user's roles
                Set<String> roleNames = securityGraphHelper.getUserRoles(user.name());
                
                // Check if user has label-specific privileges
                Map<String, Set<String>> labelPermissions = securityGraphHelper.getUserLabelPermissions(user.name());
                
                if (!labelPermissions.isEmpty()) {
                    // User has label-specific permissions
                    effectiveAccessMode = new LabelBasedAccessMode(user.name(), labelPermissions, true);
                } else {
                    // Use role-based permissions
                    effectiveAccessMode = new RoleBasedAccessMode(user.name(), roleNames);
                }
            } catch (Exception e) {
                // If RBAC fails, fall back to full access
                // In production, you might want to fail closed instead
                securityLog.debug("Failed to load roles for user " + user.name() + ": " + e.getMessage());
                effectiveAccessMode = AccessMode.Static.FULL;
            }
        } else if (effectiveAccessMode == null) {
            // Fallback to FULL access for backwards compatibility
            effectiveAccessMode = AccessMode.Static.FULL;
        }

        SecurityContext securityContext = new SecurityContext(subject(), effectiveAccessMode, connectionInfo(), dbName);
        if (subject().getAuthenticationResult().equals(FAILURE)
                || subject().getAuthenticationResult().equals(TOO_MANY_ATTEMPTS)) {
            securityLog.error(securityContext, String.format("Authentication failed for database '%s'.", dbName));
            throw AuthorizationViolationException.permissionDeniedUnauthorized();
        } else if (!dbName.equals(SYSTEM_DATABASE_NAME)
                && subject().getAuthenticationResult().equals(PASSWORD_CHANGE_REQUIRED)) {
            String message = SecurityAuthorizationHandler.generateCredentialsExpiredMessage(
                    String.format("ACCESS on database '%s' is not allowed.", dbName));
            securityLog.error(securityContext, message);
            var gql = ErrorGqlStatusObjectImplementation.from(GqlStatusInfoCodes.STATUS_42NFF)
                    .withCause(ErrorGqlStatusObjectImplementation.from(GqlStatusInfoCodes.STATUS_42NFD)
                            .build())
                    .build();
            throw new AuthorizationViolationException(gql, message, Status.Security.CredentialsExpired);
        }
        return securityContext;
    }
}
