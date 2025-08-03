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

import static org.neo4j.kernel.impl.security.Role.ROLE_ID;
import static org.neo4j.kernel.impl.security.Role.ROLE_LABEL;
import static org.neo4j.kernel.impl.security.Role.ROLE_NAME;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.neo4j.graphdb.Direction;
import org.neo4j.graphdb.Label;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Relationship;
import org.neo4j.graphdb.RelationshipType;
import org.neo4j.graphdb.ResourceIterator;
import org.neo4j.graphdb.Transaction;
import org.neo4j.kernel.impl.security.Privilege;
import org.neo4j.kernel.impl.security.Role;
import org.neo4j.server.security.auth.RBACValidation;

/**
 * Component for managing roles in the system graph.
 */
public class RoleSecurityGraphComponent {

    private static final String HAS_ROLE = "HAS_ROLE";
    private static final String HAS_PRIVILEGE = "HAS_PRIVILEGE";
    private static final String PRIVILEGE_LABEL = "Privilege";

    public Role createRole(Transaction tx, String name) {
        // Validate role name
        RBACValidation.validateRoleName(name);

        // Check if role already exists
        try (ResourceIterator<Node> existing = tx.findNodes(Label.label(ROLE_LABEL), ROLE_NAME, name)) {
            if (existing.hasNext()) {
                throw new IllegalArgumentException("Role '" + name + "' already exists");
            }
        }

        String id = UUID.randomUUID().toString();
        Node roleNode = tx.createNode(Label.label(ROLE_LABEL));
        roleNode.setProperty(ROLE_NAME, name);
        roleNode.setProperty(ROLE_ID, id);

        return new Role(name, id, Set.of());
    }

    public void deleteRole(Transaction tx, String roleName) {
        // Validate role can be deleted
        RBACValidation.validateRoleDeletion(roleName);

        try (ResourceIterator<Node> nodes = tx.findNodes(Label.label(ROLE_LABEL), ROLE_NAME, roleName)) {
            if (nodes.hasNext()) {
                Node roleNode = nodes.next();
                // Remove all relationships
                for (Relationship rel : roleNode.getRelationships()) {
                    rel.delete();
                }
                roleNode.delete();
            } else {
                throw new IllegalArgumentException("Role '" + roleName + "' does not exist");
            }
        }
    }

    public Role getRoleByName(Transaction tx, String name) {
        try (ResourceIterator<Node> nodes = tx.findNodes(Label.label(ROLE_LABEL), ROLE_NAME, name)) {
            if (nodes.hasNext()) {
                Node roleNode = nodes.next();
                return nodeToRole(roleNode);
            }
        }
        return null;
    }

    public Set<Role> getAllRoles(Transaction tx) {
        Set<Role> roles = new HashSet<>();
        try (ResourceIterator<Node> nodes = tx.findNodes(Label.label(ROLE_LABEL))) {
            while (nodes.hasNext()) {
                roles.add(nodeToRole(nodes.next()));
            }
        }
        return roles;
    }

    public void assignRoleToUser(Transaction tx, Node userNode, String roleName) {
        Role role = getRoleByName(tx, roleName);
        if (role != null) {
            try (ResourceIterator<Node> roleNodes = tx.findNodes(Label.label(ROLE_LABEL), ROLE_NAME, roleName)) {
                if (roleNodes.hasNext()) {
                    Node roleNode = roleNodes.next();
                    // Check if relationship already exists
                    boolean hasRole = false;
                    for (Relationship rel :
                            userNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(HAS_ROLE))) {
                        if (rel.getEndNode().equals(roleNode)) {
                            hasRole = true;
                            break;
                        }
                    }
                    if (!hasRole) {
                        userNode.createRelationshipTo(roleNode, RelationshipType.withName(HAS_ROLE));
                    }
                }
            }
        }
    }

    public void removeRoleFromUser(Transaction tx, Node userNode, String roleName) {
        for (Relationship rel : userNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(HAS_ROLE))) {
            Node roleNode = rel.getEndNode();
            if (roleName.equals(roleNode.getProperty(ROLE_NAME))) {
                rel.delete();
                break;
            }
        }
    }

    public Set<String> getUserRoles(Node userNode) {
        Set<String> roleNames = new HashSet<>();
        for (Relationship rel : userNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(HAS_ROLE))) {
            Node roleNode = rel.getEndNode();
            roleNames.add((String) roleNode.getProperty(ROLE_NAME));
        }
        return roleNames;
    }

    public void grantPrivilege(Transaction tx, String roleName, Privilege privilege) {
        // Validate privilege
        RBACValidation.validatePrivilege(privilege);
        RBACValidation.validateRoleModification(roleName);

        Role role = getRoleByName(tx, roleName);
        if (role == null) {
            throw new IllegalArgumentException("Role '" + roleName + "' does not exist");
        }

        try (ResourceIterator<Node> roleNodes = tx.findNodes(Label.label(ROLE_LABEL), ROLE_NAME, roleName)) {
            if (roleNodes.hasNext()) {
                Node roleNode = roleNodes.next();

                // Check if privilege already exists
                for (Relationship rel :
                        roleNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(HAS_PRIVILEGE))) {
                    Node existingPriv = rel.getEndNode();
                    if (matchesPrivilege(existingPriv, privilege)) {
                        throw new IllegalArgumentException("Privilege already exists for role '" + roleName + "'");
                    }
                }

                Node privNode = createPrivilegeNode(tx, privilege);
                roleNode.createRelationshipTo(privNode, RelationshipType.withName(HAS_PRIVILEGE));
            }
        }
    }

    public void revokePrivilege(Transaction tx, String roleName, Privilege privilege) {
        Role role = getRoleByName(tx, roleName);
        if (role != null) {
            try (ResourceIterator<Node> roleNodes = tx.findNodes(Label.label(ROLE_LABEL), ROLE_NAME, roleName)) {
                if (roleNodes.hasNext()) {
                    Node roleNode = roleNodes.next();
                    for (Relationship rel :
                            roleNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(HAS_PRIVILEGE))) {
                        Node privNode = rel.getEndNode();
                        if (matchesPrivilege(privNode, privilege)) {
                            rel.delete();
                            privNode.delete();
                            break;
                        }
                    }
                }
            }
        }
    }

    private Role nodeToRole(Node roleNode) {
        String name = (String) roleNode.getProperty(ROLE_NAME);
        String id = (String) roleNode.getProperty(ROLE_ID);
        Set<Privilege> privileges = loadPrivileges(roleNode);
        return new Role(name, id, privileges);
    }

    private Set<Privilege> loadPrivileges(Node roleNode) {
        Set<Privilege> privileges = new HashSet<>();
        for (Relationship rel :
                roleNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(HAS_PRIVILEGE))) {
            Node privNode = rel.getEndNode();
            Privilege privilege = nodeToPrivilege(privNode);
            if (privilege != null) {
                privileges.add(privilege);
            }
        }
        return privileges;
    }

    private Node createPrivilegeNode(Transaction tx, Privilege privilege) {
        Node privNode = tx.createNode(Label.label(PRIVILEGE_LABEL));
        privNode.setProperty("action", privilege.action().name());
        privNode.setProperty("scope", privilege.scope().name());
        privNode.setProperty("graph", privilege.resource().graph());
        privNode.setProperty("granted", privilege.granted());
        privNode.setProperty("immutable", privilege.immutable());

        // Store labels, types, and properties as arrays
        privNode.setProperty("labels", privilege.resource().labels().toArray(new String[0]));
        privNode.setProperty(
                "relationshipTypes", privilege.resource().relationshipTypes().toArray(new String[0]));
        privNode.setProperty("properties", privilege.resource().properties().toArray(new String[0]));

        if (privilege.resource().pattern() != null) {
            privNode.setProperty("pattern", privilege.resource().pattern());
        }

        return privNode;
    }

    private Privilege nodeToPrivilege(Node privNode) {
        try {
            Privilege.PrivilegeAction action =
                    Privilege.PrivilegeAction.valueOf((String) privNode.getProperty("action"));
            Privilege.PrivilegeScope scope = Privilege.PrivilegeScope.valueOf((String) privNode.getProperty("scope"));
            String graph = (String) privNode.getProperty("graph");
            boolean granted = (boolean) privNode.getProperty("granted");
            boolean immutable = (boolean) privNode.getProperty("immutable");

            Set<String> labels = Set.of((String[]) privNode.getProperty("labels"));
            Set<String> types = Set.of((String[]) privNode.getProperty("relationshipTypes"));
            Set<String> props = Set.of((String[]) privNode.getProperty("properties"));
            String pattern = privNode.hasProperty("pattern") ? (String) privNode.getProperty("pattern") : null;

            Privilege.PrivilegeResource resource =
                    new Privilege.PrivilegeResource(graph, labels, types, props, pattern);

            return new Privilege(action, scope, resource, granted, immutable);
        } catch (Exception e) {
            // Log error and return null
            return null;
        }
    }

    private boolean matchesPrivilege(Node privNode, Privilege privilege) {
        return privNode.getProperty("action").equals(privilege.action().name())
                && privNode.getProperty("scope").equals(privilege.scope().name())
                && privNode.getProperty("graph").equals(privilege.resource().graph())
                && privNode.getProperty("granted").equals(privilege.granted());
    }
}
