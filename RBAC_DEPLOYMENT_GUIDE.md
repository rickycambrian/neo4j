# Neo4j RBAC Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the Role-Based Access Control (RBAC) implementation in Neo4j Community Edition.

## Prerequisites

- Neo4j Community Edition 5.x
- Java 17 or later
- Maven 3.8 or later (for building from source)
- Administrative access to Neo4j installation

## Deployment Options

### Option 1: Full Build Deployment (Recommended)

1. **Build the RBAC-enabled Neo4j**
   ```bash
   # Clone and build
   git clone https://github.com/your-org/neo4j-rbac.git
   cd neo4j-rbac
   mvn clean install -DskipTests
   ```

2. **Deploy the build**
   ```bash
   # The packaged Neo4j will be in:
   packaging/standalone/target/neo4j-community-5.26.0-rbac.tar.gz
   
   # Extract to installation directory
   tar -xzf neo4j-community-5.26.0-rbac.tar.gz -C /opt/
   ```

### Option 2: Patch Deployment

1. **Build patch JARs**
   ```bash
   ./deploy-rbac-patch.sh
   ```

2. **Deploy patches**
   ```bash
   # Stop Neo4j
   neo4j stop
   
   # Copy patch JARs
   cp rbac-patch/*.jar $NEO4J_HOME/lib/
   
   # Rename with z- prefix to ensure loading order
   cd $NEO4J_HOME/lib/
   mv neo4j-kernel-api-rbac-patch.jar z-neo4j-kernel-api-rbac-patch.jar
   mv neo4j-security-rbac-patch.jar z-neo4j-security-rbac-patch.jar
   mv neo4j-procedure-rbac-patch.jar z-neo4j-procedure-rbac-patch.jar
   ```

## Configuration

### 1. Update neo4j.conf

Add the following settings to `$NEO4J_HOME/conf/neo4j.conf`:

```properties
# Enable RBAC
dbms.security.rbac.enabled=true
dbms.security.rbac.audit.enabled=true
dbms.security.rbac.default_role=reader
dbms.security.rbac.label_based_access.enabled=true
dbms.security.rbac.fail_closed=true

# Performance tuning
dbms.security.rbac.cache_ttl=60000
dbms.security.rbac.max_roles_per_user=100
dbms.security.rbac.max_privileges_per_role=1000

# Audit log location
dbms.directories.logs=logs
```

### 2. Initialize RBAC

Start Neo4j and run the initialization:

```bash
# Start Neo4j
neo4j start

# Initialize RBAC (as neo4j user)
cypher-shell -u neo4j -p password << 'EOF'
// Create default roles
CALL dbms.security.createRole('admin');
CALL dbms.security.createRole('architect');
CALL dbms.security.createRole('editor');
CALL dbms.security.createRole('reader');
CALL dbms.security.createRole('PUBLIC');

// Ensure neo4j user has admin role
CALL dbms.security.grantRoleToUser('neo4j', 'admin');
EOF
```

## Migration from Existing Installation

### 1. Backup Current Installation

```bash
# Create backup
neo4j-admin dump --database=neo4j --to=backup-$(date +%Y%m%d).dump

# Backup configuration
cp -R $NEO4J_HOME/conf conf-backup-$(date +%Y%m%d)
```

### 2. Run Migration Script

```bash
./migrate-to-rbac.sh $NEO4J_HOME
```

### 3. Verify Migration

```bash
# Check roles
cypher-shell -u neo4j -p password "CALL dbms.security.listRoles()"

# Check audit log
tail -f $NEO4J_HOME/logs/neo4j.security.audit.log
```

## Security Best Practices

### 1. Role Design

- **Principle of Least Privilege**: Grant minimum necessary permissions
- **Role Hierarchy**: Use inheritance for common permissions
- **Separation of Duties**: Different roles for different responsibilities

### 2. Label-Based Access

```cypher
// Example: Customer service role
CALL dbms.security.createRole('customer_service');
CALL dbms.security.grantPrivilege('customer_service', 'READ', ['Customer']);
CALL dbms.security.grantPrivilege('customer_service', 'WRITE', ['Customer']);
```

### 3. Audit Configuration

Monitor security events:
```bash
# Watch audit log
tail -f $NEO4J_HOME/logs/neo4j.security.audit.log | grep -E "(AUTH|ROLE|PRIVILEGE|ACCESS_DENIED)"
```

## Troubleshooting

### Common Issues

1. **Procedures not found**
   - Verify patch JARs are in lib directory
   - Check Neo4j logs for loading errors
   - Ensure procedures are registered

2. **Access denied errors**
   - Check user roles: `CALL dbms.security.listRolesForUser('username')`
   - Verify privileges: `CALL dbms.security.listPrivileges('rolename')`
   - Review audit log for details

3. **Performance issues**
   - Increase cache TTL: `dbms.security.rbac.cache_ttl=300000`
   - Monitor label access patterns
   - Consider indexing strategies

### Debug Mode

Enable debug logging:
```properties
# In neo4j.conf
dbms.logs.debug.rotation.size=20m
dbms.logs.debug.rotation.keep_number=5
dbms.logs.debug.level=true
```

## Performance Tuning

### 1. Caching

```properties
# Increase cache for stable environments
dbms.security.rbac.cache_ttl=300000  # 5 minutes
```

### 2. Indexing

```cypher
// Create indexes for security queries
CREATE INDEX role_name_idx FOR (r:Role) ON (r.name);
CREATE INDEX privilege_composite_idx FOR (p:Privilege) ON (p.role, p.action);
```

### 3. Query Optimization

- Use parameterized queries
- Batch privilege checks
- Minimize label checks in hot paths

## Monitoring

### 1. Security Metrics

```cypher
// Count roles and privileges
MATCH (r:Role)
OPTIONAL MATCH (r)-[:HAS_PRIVILEGE]->(p:Privilege)
RETURN r.name as role, count(p) as privilegeCount
ORDER BY privilegeCount DESC;
```

### 2. Audit Analysis

```bash
# Failed access attempts
grep "ACCESS_DENIED" $NEO4J_HOME/logs/neo4j.security.audit.log | tail -100

# Role changes
grep "ROLE" $NEO4J_HOME/logs/neo4j.security.audit.log | tail -50
```

## Backup and Recovery

### Backup RBAC Data

```cypher
// Export RBAC configuration
CALL apoc.export.cypher.query(
  "MATCH (n) WHERE n:User OR n:Role OR n:Privilege RETURN n",
  "rbac-backup.cypher",
  {}
);
```

### Restore RBAC Data

```bash
# Import RBAC configuration
cypher-shell -u neo4j -p password < rbac-backup.cypher
```

## Security Checklist

- [ ] RBAC enabled in configuration
- [ ] Audit logging enabled
- [ ] Default roles created
- [ ] Admin user configured
- [ ] Password policy enforced
- [ ] Fail-closed mode enabled
- [ ] Regular audit log review scheduled
- [ ] Backup procedures in place
- [ ] Monitoring configured
- [ ] Documentation updated

## Support

For issues or questions:
- Check logs: `$NEO4J_HOME/logs/`
- Review audit trail: `neo4j.security.audit.log`
- Enable debug mode for detailed information