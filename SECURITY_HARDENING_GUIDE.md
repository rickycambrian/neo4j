# Neo4j RBAC Security Hardening Guide

## Overview

This guide provides security hardening recommendations for Neo4j deployments with RBAC enabled.

## 1. Network Security

### Firewall Configuration
```bash
# Allow only necessary ports
ufw allow 7474/tcp  # HTTPS (disable HTTP)
ufw allow 7687/tcp  # Bolt
ufw deny 7473/tcp   # HTTP (block)
```

### TLS Configuration
```properties
# In neo4j.conf
dbms.connector.bolt.tls_level=REQUIRED
dbms.connector.https.enabled=true
dbms.connector.http.enabled=false

# Certificate configuration
dbms.ssl.policy.bolt.enabled=true
dbms.ssl.policy.bolt.base_directory=certificates/bolt
dbms.ssl.policy.bolt.private_key=private.key
dbms.ssl.policy.bolt.public_certificate=public.crt
```

## 2. Authentication Hardening

### Password Policy
```properties
# Enforce strong passwords
dbms.security.auth_minimum_password_length=12
dbms.security.auth_password_validators=org.neo4j.server.security.auth.StrongPasswordValidator
```

### Account Lockout
```properties
# Lock accounts after failed attempts
dbms.security.auth_lock_time=30m
dbms.security.auth_max_failed_attempts=5
```

## 3. RBAC Best Practices

### Role Design Principles

1. **Least Privilege**
   ```cypher
   // Don't grant ALL privileges
   // Instead, grant specific actions
   CALL dbms.security.grantPrivilege('analyst', 'READ', ['Customer', 'Order']);
   CALL dbms.security.grantPrivilege('analyst', 'TRAVERSE', ['Customer', 'Order']);
   ```

2. **Role Separation**
   ```cypher
   // Separate read and write roles
   CALL dbms.security.createRole('data_reader');
   CALL dbms.security.createRole('data_writer');
   CALL dbms.security.createRole('data_admin');
   ```

3. **Label Isolation**
   ```cypher
   // Isolate sensitive data
   CALL dbms.security.createRole('pii_reader');
   CALL dbms.security.grantPrivilege('pii_reader', 'READ', ['PersonalInfo']);
   // Don't mix with other roles
   ```

### Privilege Management

1. **Regular Audits**
   ```cypher
   // Review all role assignments
   MATCH (u:User)-[:HAS_ROLE]->(r:Role)
   RETURN u.name as user, collect(r.name) as roles
   ORDER BY user;
   
   // Check privilege usage
   MATCH (r:Role)-[:HAS_PRIVILEGE]->(p:Privilege)
   RETURN r.name as role, count(p) as privilegeCount
   ORDER BY privilegeCount DESC;
   ```

2. **Remove Unused Privileges**
   ```cypher
   // Identify and remove unused roles
   MATCH (r:Role)
   WHERE NOT (:User)-[:HAS_ROLE]->(r)
   AND r.name NOT IN ['admin', 'architect', 'editor', 'reader', 'PUBLIC']
   RETURN r.name as unusedRole;
   ```

## 4. Audit Configuration

### Comprehensive Logging
```properties
# Enable all security events
dbms.security.rbac.audit.enabled=true
dbms.logs.security.level=INFO
dbms.logs.security.rotation.size=100M
dbms.logs.security.rotation.keep_number=10
```

### Log Monitoring
```bash
# Monitor authentication failures
tail -f logs/security.log | grep "AUTH FAILURE"

# Track privilege changes
tail -f logs/security.log | grep -E "(GRANT|REVOKE|PRIVILEGE)"

# Detect suspicious access patterns
grep "ACCESS_DENIED" logs/security.log | \
  awk '{print $4}' | sort | uniq -c | sort -rn
```

## 5. System Hardening

### File Permissions
```bash
# Restrict Neo4j directories
chmod 750 $NEO4J_HOME
chmod 750 $NEO4J_HOME/conf
chmod 640 $NEO4J_HOME/conf/*
chmod 750 $NEO4J_HOME/data
chmod 750 $NEO4J_HOME/logs
```

### Process Isolation
```bash
# Run Neo4j as dedicated user
useradd -r -s /bin/false neo4j
chown -R neo4j:neo4j $NEO4J_HOME
```

### Resource Limits
```properties
# Prevent resource exhaustion
dbms.memory.heap.initial_size=2g
dbms.memory.heap.max_size=4g
dbms.memory.pagecache.size=2g
dbms.connector.bolt.thread_pool_max_size=400
```

## 6. Secure Configuration

### Disable Unnecessary Features
```properties
# Disable shell access
dbms.shell.enabled=false

# Disable remote JMX
dbms.jvm.additional=-Dcom.sun.management.jmxremote=false

# Restrict file access
dbms.security.allow_csv_import_from_file_urls=false
dbms.directories.import=import
```

### Query Restrictions
```properties
# Limit query execution time
dbms.transaction.timeout=30s
cypher.query_max_allocations=1000000000
```

## 7. Backup Security

### Encrypted Backups
```bash
# Backup with encryption
neo4j-admin dump \
  --database=neo4j \
  --to=backup-$(date +%Y%m%d).dump \
  --verbose

# Encrypt the backup
openssl enc -aes-256-cbc -salt \
  -in backup-$(date +%Y%m%d).dump \
  -out backup-$(date +%Y%m%d).dump.enc
```

### Secure Storage
- Store backups in separate location
- Implement retention policies
- Test restore procedures regularly

## 8. Monitoring and Alerting

### Security Metrics
```cypher
// Failed login attempts
MATCH (event:SecurityEvent {type: 'AUTH_FAILURE'})
WHERE event.timestamp > datetime() - duration('PT1H')
RETURN count(event) as failedLogins;

// Privilege escalations
MATCH (event:SecurityEvent {type: 'ROLE_GRANTED'})
WHERE event.role = 'admin'
AND event.timestamp > datetime() - duration('P7D')
RETURN event;
```

### Alerting Rules
1. Multiple failed login attempts
2. Privilege escalations
3. Access to sensitive labels
4. Unusual query patterns
5. Configuration changes

## 9. Incident Response

### Preparation
1. Document all roles and privileges
2. Maintain user access matrix
3. Prepare rollback procedures
4. Test incident scenarios

### Response Steps
1. **Detect**: Monitor audit logs
2. **Contain**: Disable compromised accounts
3. **Investigate**: Review audit trail
4. **Remediate**: Revoke excessive privileges
5. **Recover**: Restore from secure backup
6. **Review**: Update security policies

## 10. Compliance

### Regular Reviews
- Monthly privilege audits
- Quarterly role reviews
- Annual security assessments

### Documentation
- Maintain RBAC policy document
- Track all privilege changes
- Document security incidents
- Keep audit logs for compliance period

## Security Checklist

### Initial Setup
- [ ] TLS enabled for all connections
- [ ] Strong password policy configured
- [ ] RBAC enabled and configured
- [ ] Audit logging enabled
- [ ] File permissions hardened
- [ ] Running as non-root user

### Ongoing Maintenance
- [ ] Regular security updates applied
- [ ] Audit logs reviewed daily
- [ ] Unused accounts disabled
- [ ] Privileges reviewed monthly
- [ ] Backups tested quarterly
- [ ] Security training completed

### Emergency Contacts
- Security Team: security@company.com
- DBA Team: dba@company.com
- Incident Response: +1-XXX-XXX-XXXX