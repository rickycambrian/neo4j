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

import org.neo4j.annotations.api.PublicApi;
import org.neo4j.configuration.Config;
import org.neo4j.configuration.GraphDatabaseInternalSettings;
import org.neo4j.configuration.GraphDatabaseSettings;
import org.neo4j.configuration.SettingImpl;
import org.neo4j.configuration.SettingValueParsers;
import org.neo4j.graphdb.config.Setting;

import static org.neo4j.configuration.GraphDatabaseSettings.DEFAULT;
import static org.neo4j.configuration.SettingValueParsers.BOOL;

/**
 * RBAC configuration settings
 */
@PublicApi
public final class RbacSettings {
    
    /**
     * Enable/disable RBAC enforcement
     */
    public static final Setting<Boolean> rbac_enabled = new SettingImpl<>(
            "dbms.security.rbac.enabled",
            BOOL,
            true,
            DEFAULT
    );
    
    /**
     * Enable/disable audit logging
     */
    public static final Setting<Boolean> rbac_audit_enabled = new SettingImpl<>(
            "dbms.security.rbac.audit.enabled",
            BOOL,
            true,
            DEFAULT
    );
    
    /**
     * Default role for new users
     */
    public static final Setting<String> rbac_default_role = new SettingImpl<>(
            "dbms.security.rbac.default_role",
            SettingValueParsers.STRING,
            "reader",
            DEFAULT
    );
    
    /**
     * Enable/disable label-based access control
     */
    public static final Setting<Boolean> rbac_label_based_access_enabled = new SettingImpl<>(
            "dbms.security.rbac.label_based_access.enabled",
            BOOL,
            true,
            DEFAULT
    );
    
    /**
     * Enable/disable property-level access control
     */
    public static final Setting<Boolean> rbac_property_level_access_enabled = new SettingImpl<>(
            "dbms.security.rbac.property_level_access.enabled",
            BOOL,
            false,
            DEFAULT
    );
    
    /**
     * Cache timeout for security decisions (ms)
     */
    public static final Setting<Long> rbac_cache_ttl = new SettingImpl<>(
            "dbms.security.rbac.cache_ttl",
            SettingValueParsers.LONG,
            60000L, // 1 minute
            DEFAULT
    );
    
    /**
     * Enable/disable fail-closed mode (deny access on errors)
     */
    public static final Setting<Boolean> rbac_fail_closed = new SettingImpl<>(
            "dbms.security.rbac.fail_closed",
            BOOL,
            true,
            DEFAULT
    );
    
    /**
     * Maximum number of roles per user
     */
    public static final Setting<Integer> rbac_max_roles_per_user = new SettingImpl<>(
            "dbms.security.rbac.max_roles_per_user",
            SettingValueParsers.INT,
            100,
            DEFAULT
    );
    
    /**
     * Maximum number of privileges per role
     */
    public static final Setting<Integer> rbac_max_privileges_per_role = new SettingImpl<>(
            "dbms.security.rbac.max_privileges_per_role",
            SettingValueParsers.INT,
            1000,
            DEFAULT
    );
    
    private RbacSettings() {
        // Cannot instantiate
    }
}