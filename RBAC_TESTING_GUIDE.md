# Testing Neo4j RBAC Implementation Guide

This guide will help you build Neo4j with the RBAC implementation and verify all functionality works correctly.

## Prerequisites

1. **Java 17** - Ensure you have JDK 17 installed
   ```bash
   java -version  # Should show version 17
   ```

2. **Maven 3.8.2+**
   ```bash
   mvn -version
   ```

3. **Set Maven Memory**
   ```bash
   export MAVEN_OPTS="-Xmx2048m"
   ```

## Building Neo4j with RBAC

1. **Build the project** (from the repository root):
   ```bash
   # Quick build without tests
   mvn clean install -DskipTests -T1C
   
   # Or full build with tests (takes longer)
   mvn clean install -T1C
   ```

2. **Navigate to the built distribution**:
   ```bash
   cd packaging/standalone/target
   ls -la neo4j-community-*.tar.gz
   ```

3. **Extract the distribution**:
   ```bash
   tar -xzf neo4j-community-*.tar.gz
   cd neo4j-community-*/
   ```

## Starting Neo4j

1. **Start the server**:
   ```bash
   bin/neo4j-admin server start
   ```

2. **Check the logs**:
   ```bash
   tail -f logs/neo4j.log
   ```

3. **Access Neo4j Browser**:
   - Open http://localhost:7474
   - Default credentials: neo4j/neo4j
   - You'll be prompted to change the password on first login

## Testing RBAC Functionality

### 1. Initial Setup - Connect as Admin

```bash
# Using cypher-shell (from the bin directory)
bin/cypher-shell -u neo4j -p <your-password>

# Or use Neo4j Browser at http://localhost:7474
```

### 2. Verify Default Roles Were Created

```cypher
// Show all roles (should see admin, reader, editor, architect, PUBLIC)
CALL dbms.security.listRoles();

// Check your current user's roles
SHOW USER PRIVILEGES;
```

### 3. Create Test Users and Roles

```cypher
// Create a new custom role
CREATE ROLE analyst;

// Create test users
CREATE USER alice SET PASSWORD 'alice123' CHANGE NOT REQUIRED;
CREATE USER bob SET PASSWORD 'bob123' CHANGE NOT REQUIRED;
CREATE USER charlie SET PASSWORD 'charlie123' CHANGE NOT REQUIRED;

// Assign roles to users
GRANT ROLE reader TO alice;
GRANT ROLE editor TO bob;
GRANT ROLE admin TO charlie;
```

### 4. Test Privilege Management

```cypher
// Grant specific privileges to the analyst role
CALL dbms.security.grantPrivilege('READ', 'neo4j', 'analyst');
CALL dbms.security.grantPrivilege('EXECUTE_FUNCTION', '*', 'analyst');

// Deny a specific privilege
CALL dbms.security.denyPrivilege('WRITE', 'system', 'analyst');

// Assign the analyst role to alice
GRANT ROLE analyst TO alice;

// Show privileges for a role
SHOW ROLE analyst PRIVILEGES;
```

### 5. Test Access Control

**Test as different users to verify permissions:**

```bash
# Exit current session
:exit

# Login as alice (reader + analyst)
bin/cypher-shell -u alice -p alice123
```

```cypher
// Alice should be able to read
MATCH (n) RETURN n LIMIT 5;

// Alice should NOT be able to write
CREATE (n:TestNode {name: 'test'});  // Should fail

// Check alice's privileges
SHOW USER PRIVILEGES;
```

```bash
# Login as bob (editor)
:exit
bin/cypher-shell -u bob -p bob123
```

```cypher
// Bob should be able to read and write
CREATE (n:TestNode {name: 'bob-test'});
MATCH (n:TestNode) RETURN n;

// Bob should NOT be able to create indexes
CREATE INDEX test_index FOR (n:TestNode) ON (n.name);  // Should fail
```

### 6. Test Role Inheritance

```cypher
// Login as admin (charlie)
:exit
bin/cypher-shell -u charlie -p charlie123

// Create a role hierarchy
CREATE ROLE senior_analyst;
GRANT ROLE analyst TO senior_analyst;  // Inheritance

// Add additional privileges to senior role
CALL dbms.security.grantPrivilege('CREATE_INDEX', 'neo4j', 'senior_analyst');

// Test inheritance
CREATE USER diana SET PASSWORD 'diana123' CHANGE NOT REQUIRED;
GRANT ROLE senior_analyst TO diana;

// Diana should have both analyst and senior_analyst privileges
:exit
bin/cypher-shell -u diana -p diana123
SHOW USER PRIVILEGES;
```

### 7. Test Validation and Error Cases

```cypher
// Login as admin
:exit
bin/cypher-shell -u charlie -p charlie123

// Try to create duplicate role (should fail)
CREATE ROLE analyst;

// Try to delete system role (should fail)
DROP ROLE admin;

// Try to create role with invalid name (should fail)
CREATE ROLE "role with spaces";

// Try to grant non-existent role (should fail)
GRANT ROLE nonexistent TO alice;
```

### 8. Test Audit Logging

Check the security log for audit entries:

```bash
# From the Neo4j directory
grep -i "role\|privilege" logs/security.log
```

You should see entries for:
- Role creation/deletion
- Privilege grants/denies/revokes
- User-role assignments

### 9. Test Cypher Commands (if integrated)

```cypher
// These commands should work if Cypher integration is complete
GRANT MATCH {*} ON GRAPH neo4j NODE * TO analyst;
DENY WRITE ON GRAPH system TO analyst;
REVOKE GRANT READ ON GRAPH * FROM analyst;

SHOW PRIVILEGES;
SHOW PRIVILEGES AS COMMANDS;
SHOW ROLE analyst PRIVILEGES;
```

## Verification Checklist

- [ ] Neo4j starts without errors
- [ ] Default roles are created (admin, reader, editor, architect, PUBLIC)
- [ ] Can create new roles
- [ ] Can create users and assign roles
- [ ] Can grant/deny/revoke privileges via procedures
- [ ] Access control works (readers can't write, etc.)
- [ ] Role inheritance functions correctly
- [ ] Validation prevents invalid operations
- [ ] Audit logs capture security operations
- [ ] System roles cannot be deleted
- [ ] Reserved role names are protected

## Troubleshooting

### If RBAC procedures are not found:

1. Check that procedures are registered:
   ```cypher
   SHOW PROCEDURES YIELD name WHERE name STARTS WITH 'dbms.security';
   ```

2. Check logs for registration errors:
   ```bash
   grep -i "procedure\|rbac" logs/debug.log
   ```

### If roles are not persisting:

1. Check system database:
   ```cypher
   :use system
   MATCH (n:Role) RETURN n;
   ```

2. Verify security component version:
   ```cypher
   CALL dbms.components() YIELD name, versions WHERE name = 'security-users';
   ```

### Enable Debug Logging:

Add to `conf/neo4j.conf`:
```
dbms.logs.debug.level=DEBUG
```

## Stopping Neo4j

```bash
bin/neo4j-admin server stop
```

## Additional Testing

For automated testing, you can create a script that runs all these commands and verifies the expected results. The integration tests in `/community/security/src/test/` provide examples of programmatic testing.

## Notes

- The first time you run Neo4j, it will initialize the security system and create default roles
- All security operations are logged for audit purposes
- The system database stores all security information
- RBAC is automatically enabled; there's no configuration switch needed