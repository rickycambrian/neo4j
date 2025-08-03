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
package org.neo4j.server.security.systemgraph;

import static org.neo4j.configuration.GraphDatabaseSettings.SYSTEM_DATABASE_NAME;
import static org.neo4j.kernel.database.NamedDatabaseId.NAMED_SYSTEM_DATABASE_ID;
import static org.neo4j.server.security.systemgraph.versions.KnownCommunitySecurityComponentVersion.USER_CREDENTIALS;
import static org.neo4j.server.security.systemgraph.versions.KnownCommunitySecurityComponentVersion.USER_EXPIRED;
import static org.neo4j.server.security.systemgraph.versions.KnownCommunitySecurityComponentVersion.USER_ID;
import static org.neo4j.server.security.systemgraph.versions.KnownCommunitySecurityComponentVersion.USER_LABEL;
import static org.neo4j.server.security.systemgraph.versions.KnownCommunitySecurityComponentVersion.USER_NAME;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.neo4j.dbms.database.DatabaseContextProvider;
import org.neo4j.function.Suppliers;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.NotFoundException;
import org.neo4j.graphdb.Transaction;
import org.neo4j.graphdb.security.AuthProviderFailedException;
import org.neo4j.internal.kernel.api.security.AbstractSecurityLog;
import org.neo4j.kernel.api.security.AuthToken;
import org.neo4j.kernel.impl.security.Credential;
import org.neo4j.kernel.impl.security.Role;
import org.neo4j.kernel.impl.security.User;
import org.neo4j.logging.InternalLog;
import org.neo4j.logging.NullLog;
import org.neo4j.server.security.FormatException;
import org.neo4j.server.security.SecureHasher;
import org.neo4j.server.security.SystemGraphCredential;
import org.neo4j.server.security.auth.RoleBasedSecurityLog;
import org.neo4j.server.security.auth.RoleHierarchy;

public class SecurityGraphHelper {
    public static final String NATIVE_AUTH = AuthToken.NATIVE_REALM;

    protected final AbstractSecurityLog securityLog;
    protected final Suppliers.Lazy<GraphDatabaseService> systemSupplier;
    protected final SecureHasher secureHasher;
    protected final RoleSecurityGraphComponent roleComponent;
    protected final RoleBasedSecurityLog rbacLog;

    public SecurityGraphHelper(
            Suppliers.Lazy<GraphDatabaseService> systemSupplier,
            SecureHasher secureHasher,
            AbstractSecurityLog securityLog) {
        this.systemSupplier = systemSupplier;
        this.secureHasher = secureHasher;
        this.securityLog = securityLog;
        this.roleComponent = new RoleSecurityGraphComponent();
        this.rbacLog = new RoleBasedSecurityLog(securityLog, NullLog.getInstance());
    }

    public GraphDatabaseService getSystemDb() {
        return systemSupplier.get();
    }

    public static Suppliers.Lazy<GraphDatabaseService> makeSystemSupplier(
            DatabaseContextProvider<?> databaseContextProvider) {
        return Suppliers.lazySingleton(() -> databaseContextProvider
                .getDatabaseContext(NAMED_SYSTEM_DATABASE_ID)
                .orElseThrow(() ->
                        new AuthProviderFailedException("No database called `" + SYSTEM_DATABASE_NAME + "` was found."))
                .databaseFacade());
    }

    /**
     * Lookup a user information from username, returns null if the user does not exist.
     *
     * @param username username
     * @return user record containing user and auth information
     */
    public User getUserByName(String username) {
        securityLog.debug(String.format("Looking up user '%s'", username));
        try (var tx = systemSupplier.get().beginTx()) {
            Node userNode = tx.findNode(USER_LABEL, USER_NAME, username);
            if (userNode == null) {
                securityLog.debug(String.format("User '%s' not found", username));
                return null;
            }
            return getUser(userNode);
        } catch (NotFoundException n) {
            // Can occur if the user was dropped by another thread after the null check.
            securityLog.debug(String.format("User '%s' not found", username));
            return null;
        }
    }

    /**
     * Lookup a user information from user id, returns null if the user does not exist.
     *
     * @param uuid user id
     * @return user record containing user and auth information
     */
    public User getUserById(String uuid) {
        securityLog.debug(String.format("Looking up user with id '%s'", uuid));
        if (uuid == null) {
            securityLog.debug("Cannot look up user with id = null");
            return null;
        }
        try (var tx = systemSupplier.get().beginTx()) {
            Node userNode = tx.findNode(USER_LABEL, USER_ID, uuid);
            if (userNode == null) {
                securityLog.debug(String.format("User with id '%s' not found", uuid));
                return null;
            }
            return getUser(userNode);
        } catch (NotFoundException n) {
            // Can occur if the user was dropped by another thread after the null check.
            securityLog.debug(String.format("User with id '%s' not found", uuid));
            return null;
        }
    }

    protected User getUser(Node userNode) {
        var userId = (String) userNode.getProperty(USER_ID);
        String username = (String) userNode.getProperty(USER_NAME);
        boolean requirePasswordChange = (boolean) userNode.getProperty(USER_EXPIRED, false);
        Credential credential = null;
        var maybeCredentials = userNode.getProperty(USER_CREDENTIALS, null);
        if (maybeCredentials instanceof String rawCredentials) {
            try {
                credential = SystemGraphCredential.deserialize(rawCredentials, secureHasher);
            } catch (FormatException e) {
                securityLog.debug(String.format("Wrong format of credentials for user %s.", username));
                return null;
            }
        }

        // Load user roles
        Set<String> userRoles = roleComponent.getUserRoles(userNode);
        
        User user = new User(
                username,
                userId,
                new User.SensitiveCredential(credential),
                requirePasswordChange,
                false,
                credential == null ? Collections.emptySet() : Set.of(new User.Auth(NATIVE_AUTH, userId)),
                userRoles);
        securityLog.debug(String.format("Found user: %s", user));
        return user;
    }

    public User getUserByAuth(String provider, String authId) {
        return null;
    }

    public String getAuthId(String provider, String username) {
        return null;
    }

    public boolean hasExternalAuth(String username) {
        return false;
    }
    
    // Role management methods
    
    public Set<Role> getUserRolesWithPrivileges(String username) {
        Set<Role> roles = new HashSet<>();
        try (var tx = systemSupplier.get().beginTx()) {
            Node userNode = tx.findNode(USER_LABEL, USER_NAME, username);
            if (userNode != null) {
                Set<String> roleNames = roleComponent.getUserRoles(userNode);
                for (String roleName : roleNames) {
                    Role role = roleComponent.getRoleByName(tx, roleName);
                    if (role != null) {
                        // Get all privileges including inherited ones
                        Set<Privilege> allPrivileges = RoleHierarchy.getAllPrivilegesIncludingInherited(tx, role);
                        Role roleWithInheritedPrivileges = new Role(role.name(), role.id(), allPrivileges);
                        roles.add(roleWithInheritedPrivileges);
                    }
                }
            }
            tx.commit();
        }
        return roles;
    }
    
    public void assignRoleToUser(String username, String roleName) {
        try (var tx = systemSupplier.get().beginTx()) {
            Node userNode = tx.findNode(USER_LABEL, USER_NAME, username);
            if (userNode != null) {
                roleComponent.assignRoleToUser(tx, userNode, roleName);
                // Log the operation - would need SecurityContext in real implementation
                securityLog.info("Role '" + roleName + "' assigned to user '" + username + "'");
            }
            tx.commit();
        }
    }
    
    public void removeRoleFromUser(String username, String roleName) {
        try (var tx = systemSupplier.get().beginTx()) {
            Node userNode = tx.findNode(USER_LABEL, USER_NAME, username);
            if (userNode != null) {
                roleComponent.removeRoleFromUser(tx, userNode, roleName);
            }
            tx.commit();
        }
    }
    
    public Role createRole(String roleName) {
        try (var tx = systemSupplier.get().beginTx()) {
            Role role = roleComponent.createRole(tx, roleName);
            tx.commit();
            // Log the operation
            securityLog.info("Role '" + roleName + "' created");
            return role;
        }
    }
    
    public void deleteRole(String roleName) {
        try (var tx = systemSupplier.get().beginTx()) {
            roleComponent.deleteRole(tx, roleName);
            tx.commit();
        }
    }
    
    public Set<Role> getAllRoles() {
        try (var tx = systemSupplier.get().beginTx()) {
            Set<Role> roles = roleComponent.getAllRoles(tx);
            tx.commit();
            return roles;
        }
    }
}
