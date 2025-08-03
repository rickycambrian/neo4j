# Neo4j Label-Based Access Control Examples

This document shows how to restrict users to specific node labels (tables) in Neo4j Community Edition with our RBAC implementation.

## Basic Concepts

In Neo4j, labels are like table names in relational databases. With our implementation, you can:
- Grant users access to specific labels only
- Control what operations they can perform (READ, WRITE, DELETE, etc.)
- Combine multiple permissions for fine-grained control

## Example Scenarios

### 1. Customer Service Representative
Only needs to read customer data:

```cypher
// Create role
CALL dbms.security.createRole('customer_support');

// Grant read access to Customer label only
CALL dbms.security.grantPrivilege('customer_support', 'READ', ['Customer']);

// Create user and assign role
CALL dbms.security.createUser('support_agent', 'password', false);
CALL dbms.security.grantRoleToUser('support_agent', 'customer_support');
```

### 2. Sales Team Member
Can read products and manage orders:

```cypher
// Create role
CALL dbms.security.createRole('sales_team');

// Grant read access to Product label
CALL dbms.security.grantPrivilege('sales_team', 'READ', ['Product']);

// Grant full access to Order label
CALL dbms.security.grantPrivilege('sales_team', 'READ', ['Order']);
CALL dbms.security.grantPrivilege('sales_team', 'WRITE', ['Order']);
CALL dbms.security.grantPrivilege('sales_team', 'CREATE', ['Order']);
CALL dbms.security.grantPrivilege('sales_team', 'DELETE', ['Order']);
```

### 3. HR Department
Access to Employee data only:

```cypher
// Create role
CALL dbms.security.createRole('hr_department');

// Grant full access to Employee label
CALL dbms.security.grantPrivilege('hr_department', 'ALL', ['Employee']);

// Deny access to sensitive fields (future enhancement)
CALL dbms.security.denyPrivilege('hr_department', 'READ', ['Employee.salary']);
```

### 4. Data Analyst
Read-only access to specific business data:

```cypher
// Create role
CALL dbms.security.createRole('data_analyst');

// Grant read access to multiple labels
CALL dbms.security.grantPrivilege('data_analyst', 'READ', ['Customer', 'Order', 'Product']);

// But no access to internal/system labels
// They won't be able to see User, Role, or other system nodes
```

## Available Privilege Actions

- `READ` - Can read nodes with the specified labels
- `WRITE` - Can update properties on nodes with the specified labels  
- `CREATE` - Can create new nodes with the specified labels
- `DELETE` - Can delete nodes with the specified labels
- `SET_LABEL` - Can add the specified labels to nodes
- `REMOVE_LABEL` - Can remove the specified labels from nodes
- `SET_PROPERTY` - Can set properties on nodes with the specified labels
- `ALL` - All permissions on the specified labels

## Managing Permissions

### List all privileges for a role:
```cypher
CALL dbms.security.listPrivileges('role_name') 
YIELD action, labels, granted 
RETURN action, labels, granted;
```

### Revoke a privilege:
```cypher
CALL dbms.security.revokePrivilege('role_name', 'READ', ['Customer']);
```

### Check user's effective permissions:
```cypher
CALL dbms.security.listRolesForUser('username') YIELD role RETURN role;
```

## Implementation Notes

1. **Default Deny**: Users with label-based permissions are denied access to any labels not explicitly granted
2. **Inheritance**: If a user has multiple roles, they get the union of all permissions
3. **System Access**: Label-based users cannot modify system data (users, roles, etc.)
4. **Performance**: Label checks are performed at query time, so complex permission sets may impact performance

## Best Practices

1. **Principle of Least Privilege**: Only grant the minimum permissions needed
2. **Role Naming**: Use descriptive role names that indicate their purpose
3. **Documentation**: Document what each role is for and why it has specific permissions
4. **Regular Audits**: Periodically review and clean up unused roles and permissions
5. **Test Thoroughly**: Always test permission changes in a non-production environment first