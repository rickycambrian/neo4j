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
 * Represents a role in the RBAC system.
 * A role persisted in the system graph will always have an id.
 */
public record Role(String name, String id, Set<Privilege> privileges) {

    public static final String ROLE_LABEL = "Role";
    public static final String ROLE_NAME = "name";
    public static final String ROLE_ID = "id";

    public Role(String name, String id) {
        this(name, id, Set.of());
    }

    public boolean hasPrivilege(Privilege privilege) {
        return privileges.contains(privilege);
    }

    public boolean hasAnyPrivilege(Set<Privilege> requiredPrivileges) {
        return privileges.stream().anyMatch(requiredPrivileges::contains);
    }
}
