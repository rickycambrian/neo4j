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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.neo4j.graphdb.Direction;
import org.neo4j.graphdb.Label;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Relationship;
import org.neo4j.graphdb.RelationshipType;
import org.neo4j.graphdb.ResourceIterator;
import org.neo4j.graphdb.Transaction;
import org.neo4j.kernel.impl.security.Privilege;
import org.neo4j.kernel.impl.security.Role;

/**
 * Manages role hierarchies and privilege inheritance.
 * Supports role inheritance where child roles inherit privileges from parent roles.
 */
public class RoleHierarchy {

    private static final String INHERITS_FROM = "INHERITS_FROM";
    private static final String ROLE_LABEL = "Role";
    private static final String ROLE_NAME = "name";

    /**
     * Creates a role inheritance relationship.
     * The child role will inherit all privileges from the parent role.
     */
    public static void addRoleInheritance(Transaction tx, String childRoleName, String parentRoleName) {
        Node childNode = findRoleNode(tx, childRoleName);
        Node parentNode = findRoleNode(tx, parentRoleName);

        if (childNode == null) {
            throw new IllegalArgumentException("Child role '" + childRoleName + "' does not exist");
        }
        if (parentNode == null) {
            throw new IllegalArgumentException("Parent role '" + parentRoleName + "' does not exist");
        }

        // Check for circular inheritance
        if (wouldCreateCycle(tx, childNode, parentNode)) {
            throw new IllegalArgumentException("Cannot create role inheritance: would create a circular dependency");
        }

        // Check if relationship already exists
        for (Relationship rel :
                childNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(INHERITS_FROM))) {
            if (rel.getEndNode().equals(parentNode)) {
                return; // Already inherits
            }
        }

        // Create inheritance relationship
        childNode.createRelationshipTo(parentNode, RelationshipType.withName(INHERITS_FROM));
    }

    /**
     * Removes a role inheritance relationship.
     */
    public static void removeRoleInheritance(Transaction tx, String childRoleName, String parentRoleName) {
        Node childNode = findRoleNode(tx, childRoleName);
        if (childNode == null) {
            throw new IllegalArgumentException("Child role '" + childRoleName + "' does not exist");
        }

        // Find and delete the inheritance relationship
        for (Relationship rel :
                childNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(INHERITS_FROM))) {
            Node parentNode = rel.getEndNode();
            if (parentRoleName.equals(parentNode.getProperty(ROLE_NAME))) {
                rel.delete();
                return;
            }
        }

        throw new IllegalArgumentException(
                "Role '" + childRoleName + "' does not inherit from '" + parentRoleName + "'");
    }

    /**
     * Gets all privileges for a role including inherited privileges.
     */
    public static Set<Privilege> getAllPrivilegesIncludingInherited(Transaction tx, Role role) {
        Set<Privilege> allPrivileges = new HashSet<>(role.privileges());
        Set<String> visitedRoles = new HashSet<>();

        Node roleNode = findRoleNode(tx, role.name());
        if (roleNode != null) {
            collectInheritedPrivileges(tx, roleNode, allPrivileges, visitedRoles);
        }

        return allPrivileges;
    }

    /**
     * Gets all parent roles (roles that this role inherits from).
     */
    public static Set<String> getParentRoles(Transaction tx, String roleName) {
        Set<String> parentRoles = new HashSet<>();
        Node roleNode = findRoleNode(tx, roleName);

        if (roleNode != null) {
            for (Relationship rel :
                    roleNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(INHERITS_FROM))) {
                Node parentNode = rel.getEndNode();
                parentRoles.add((String) parentNode.getProperty(ROLE_NAME));
            }
        }

        return parentRoles;
    }

    /**
     * Gets all child roles (roles that inherit from this role).
     */
    public static Set<String> getChildRoles(Transaction tx, String roleName) {
        Set<String> childRoles = new HashSet<>();
        Node roleNode = findRoleNode(tx, roleName);

        if (roleNode != null) {
            for (Relationship rel :
                    roleNode.getRelationships(Direction.INCOMING, RelationshipType.withName(INHERITS_FROM))) {
                Node childNode = rel.getStartNode();
                childRoles.add((String) childNode.getProperty(ROLE_NAME));
            }
        }

        return childRoles;
    }

    /**
     * Gets the complete role hierarchy as a map.
     */
    public static Map<String, RoleHierarchyInfo> getRoleHierarchy(Transaction tx) {
        Map<String, RoleHierarchyInfo> hierarchy = new HashMap<>();

        try (ResourceIterator<Node> roleNodes = tx.findNodes(Label.label(ROLE_LABEL))) {
            while (roleNodes.hasNext()) {
                Node roleNode = roleNodes.next();
                String roleName = (String) roleNode.getProperty(ROLE_NAME);

                Set<String> parents = new HashSet<>();
                Set<String> children = new HashSet<>();

                // Get parent roles
                for (Relationship rel :
                        roleNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(INHERITS_FROM))) {
                    parents.add((String) rel.getEndNode().getProperty(ROLE_NAME));
                }

                // Get child roles
                for (Relationship rel :
                        roleNode.getRelationships(Direction.INCOMING, RelationshipType.withName(INHERITS_FROM))) {
                    children.add((String) rel.getStartNode().getProperty(ROLE_NAME));
                }

                hierarchy.put(roleName, new RoleHierarchyInfo(roleName, parents, children));
            }
        }

        return hierarchy;
    }

    // Helper methods

    private static Node findRoleNode(Transaction tx, String roleName) {
        try (ResourceIterator<Node> nodes = tx.findNodes(Label.label(ROLE_LABEL), ROLE_NAME, roleName)) {
            return nodes.hasNext() ? nodes.next() : null;
        }
    }

    private static boolean wouldCreateCycle(Transaction tx, Node childNode, Node parentNode) {
        // Check if parentNode can reach childNode through inheritance chain
        Set<Node> visited = new HashSet<>();
        return canReachNode(parentNode, childNode, visited);
    }

    private static boolean canReachNode(Node from, Node target, Set<Node> visited) {
        if (from.equals(target)) {
            return true;
        }

        if (visited.contains(from)) {
            return false;
        }

        visited.add(from);

        for (Relationship rel : from.getRelationships(Direction.OUTGOING, RelationshipType.withName(INHERITS_FROM))) {
            if (canReachNode(rel.getEndNode(), target, visited)) {
                return true;
            }
        }

        return false;
    }

    private static void collectInheritedPrivileges(
            Transaction tx, Node roleNode, Set<Privilege> privileges, Set<String> visitedRoles) {
        String roleName = (String) roleNode.getProperty(ROLE_NAME);

        if (visitedRoles.contains(roleName)) {
            return; // Avoid infinite loops
        }

        visitedRoles.add(roleName);

        // Traverse parent roles
        for (Relationship rel :
                roleNode.getRelationships(Direction.OUTGOING, RelationshipType.withName(INHERITS_FROM))) {
            Node parentNode = rel.getEndNode();

            // Load parent role's privileges
            // In a real implementation, this would load from RoleSecurityGraphComponent
            // For now, we just traverse the hierarchy
            collectInheritedPrivileges(tx, parentNode, privileges, visitedRoles);
        }
    }

    /**
     * Information about a role's position in the hierarchy.
     */
    public static class RoleHierarchyInfo {
        public final String roleName;
        public final Set<String> parentRoles;
        public final Set<String> childRoles;

        public RoleHierarchyInfo(String roleName, Set<String> parentRoles, Set<String> childRoles) {
            this.roleName = roleName;
            this.parentRoles = parentRoles;
            this.childRoles = childRoles;
        }
    }
}
