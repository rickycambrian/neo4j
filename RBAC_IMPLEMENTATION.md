# Neo4j Community Edition RBAC Implementation

This document describes the Role-Based Access Control (RBAC) implementation added to Neo4j Community Edition.

## Overview

The RBAC implementation adds enterprise-level security features to Neo4j Community Edition, including:

- Role management (CREATE/DROP/ALTER ROLE)
- Privilege management (GRANT/DENY/REVOKE)
- User-role assignment
- Fine-grained access control
- Privilege inheritance
- Audit logging

## Architecture

### Core Components

1. **Data Model**
   - `Role.java` - Represents roles with privileges
   - `Privilege.java` - Defines privileges with actions, scopes, and resources
   - Extended `User.java` - Added role associations

2. **Storage Layer**
   - `RoleSecurityGraphComponent.java` - Manages role storage in system graph
   - `SecurityGraphHelper.java` - Extended with role management methods
   - `CommunitySecurityComponentVersion_5_RBAC.java` - Migration and schema management

3. **Access Control**
   - `RoleBasedAccessMode.java` - Dynamic permission evaluation
   - `RoleHierarchy.java` - Privilege inheritance support
   - `RBACValidation.java` - Input validation and security checks

4. **Command Processing**
   - `RoleManagementProcedures.java` - System procedures for role/privilege management
   - `RoleManagementCommands.java` - Command handlers
   - `RBACAdministrationCommandRuntime.scala` - Cypher command runtime

5. **Security Features**
   - `RoleBasedSecurityLog.java` - Audit logging
   - `BasicLoginContext.java` - Modified to use role-based access
   - `BasicSystemGraphRealm.java` - Updated authentication flow

## System Graph Schema

### Nodes
- `:Role` nodes with properties:
  - `name` (String, unique)
  - `id` (String, indexed)

- `:Privilege` nodes with properties:
  - `action` (String)
  - `scope` (String)
  - `graph` (String)
  - `granted` (Boolean)
  - `immutable` (Boolean)
  - `labels` (String[])
  - `relationshipTypes` (String[])
  - `properties` (String[])
  - `pattern` (String, optional)

### Relationships
- `(:User)-[:HAS_ROLE]->(:Role)`
- `(:Role)-[:HAS_PRIVILEGE]->(:Privilege)`
- `(:Role)-[:INHERITS_FROM]->(:Role)`

## Default Roles

The system initializes with these default roles:

1. **admin** - Full system access
2. **architect** - Schema and data management
3. **editor** - Read/write data access
4. **reader** - Read-only access
5. **PUBLIC** - Basic privileges for all users

## Supported Commands

### Role Management
```cypher
CREATE ROLE roleName [IF NOT EXISTS]
DROP ROLE roleName [IF EXISTS]
RENAME ROLE oldName TO newName
GRANT ROLE roleName TO username
REVOKE ROLE roleName FROM username
SHOW ROLES
```

### Privilege Management
```cypher
GRANT privilege ON resource TO role
DENY privilege ON resource TO role
REVOKE privilege ON resource FROM role
SHOW PRIVILEGES
SHOW ROLE roleName PRIVILEGES
SHOW USER username PRIVILEGES
```

### Supported Privileges
- Graph: TRAVERSE, READ, MATCH, WRITE, CREATE, DELETE, SET LABEL, REMOVE LABEL, SET PROPERTY
- Database: ACCESS, START, STOP, CREATE INDEX, DROP INDEX, CREATE CONSTRAINT, DROP CONSTRAINT
- DBMS: USER MANAGEMENT, ROLE MANAGEMENT, DATABASE MANAGEMENT, PRIVILEGE MANAGEMENT
- Execution: EXECUTE PROCEDURE, EXECUTE FUNCTION

## Building and Testing

### Build Requirements
- Java 17+
- Maven 3.8+

### Running Tests
```bash
# Unit tests
mvn test -pl community/security

# Integration tests
mvn verify -pl community/security -Pintegration-test
```

### Enabling RBAC
RBAC is automatically enabled when the system starts. The security graph component detects and migrates to version 6 (RBAC-enabled).

## Configuration

### Environment Variables
- `NEO4J_AUTH` - Set initial admin credentials
- `NEO4J_dbms_security_auth__enabled` - Enable/disable authentication

### Configuration Files
No additional configuration required. RBAC uses the existing security infrastructure.

## Migration

Existing Neo4j installations will be automatically migrated:
1. System graph version updated to 6
2. Default roles created
3. Existing 'neo4j' user assigned 'admin' role
4. Schema constraints and indexes created

## Security Considerations

1. **Reserved Roles** - PUBLIC, SYSTEM, and ANONYMOUS cannot be modified
2. **System Roles** - admin, reader, editor, architect cannot be deleted
3. **Circular Inheritance** - Prevented by validation
4. **Audit Logging** - All security operations are logged
5. **Input Validation** - Strict validation of all inputs

## Performance Impact

- Minimal overhead for permission checks (cached in AccessMode)
- Role hierarchy traversal optimized with cycle detection
- Privileges loaded once per session

## Limitations

1. No support for property-based access control patterns
2. No time-based privileges
3. No conditional privileges
4. Role membership is not hierarchical (must be explicitly assigned)

## Future Enhancements

1. GUI support for role management
2. LDAP/AD integration for role mapping
3. Fine-grained property-level permissions
4. Dynamic privilege evaluation
5. Role templates and profiles

## Troubleshooting

### Common Issues

1. **"Role already exists"** - Use IF NOT EXISTS clause
2. **"Cannot delete system role"** - System roles are protected
3. **"Circular dependency"** - Check role inheritance chain
4. **"Permission denied"** - Check SHOW USER PRIVILEGES

### Debug Logging

Enable debug logging for security operations:
```
dbms.logs.debug.level=DEBUG
```

## API Changes

### New Procedures
- `dbms.security.createRole()`
- `dbms.security.deleteRole()`
- `dbms.security.listRoles()`
- `dbms.security.grantRolesToUser()`
- `dbms.security.revokeRolesFromUser()`
- `dbms.security.grantPrivilege()`
- `dbms.security.denyPrivilege()`
- `dbms.security.revokePrivilege()`
- `dbms.security.showPrivileges()`

### Modified Components
- `User` - Added roles field
- `BasicLoginContext` - Uses RoleBasedAccessMode
- `SecurityGraphHelper` - Extended with role operations
- `CommunitySecurityModule` - Registers RBAC components

## License

This implementation is released under the same GPLv3 license as Neo4j Community Edition.