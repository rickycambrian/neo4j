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
package org.neo4j.cypher.internal

import org.neo4j.cypher.internal.ast._
import org.neo4j.cypher.internal.procs.QueryHandler
import org.neo4j.cypher.internal.runtime._
import org.neo4j.cypher.result.RuntimeResult
import org.neo4j.exceptions.InvalidArgumentException
import org.neo4j.exceptions.SecurityAdministrationException
import org.neo4j.internal.kernel.api.security.SecurityAuthorizationHandler
import org.neo4j.kernel.api.procedure.GlobalProcedures
import org.neo4j.memory.MemoryTracker
import org.neo4j.values.virtual.VirtualValues

import scala.jdk.CollectionConverters._

/**
 * Runtime for executing RBAC administration commands.
 * Handles GRANT, DENY, REVOKE, CREATE ROLE, DROP ROLE, etc.
 */
class RBACAdministrationCommandRuntime(
    normalExecutionEngine: ExecutionEngine,
    securityHandler: SecurityAuthorizationHandler
) extends AdministrationChain(normalExecutionEngine, securityHandler) {

  override def canExecute(logicalPlan: LogicalPlan): Boolean = {
    logicalPlan match {
      case _: GrantPrivilege => true
      case _: DenyPrivilege => true
      case _: RevokePrivilege => true
      case _: CreateRole => true
      case _: DropRole => true
      case _: GrantRolesToUsers => true
      case _: RevokeRolesFromUsers => true
      case _: ShowRoles => true
      case _: ShowPrivileges => true
      case _: ShowRolePrivileges => true
      case _: ShowUserPrivileges => true
      case _ => false
    }
  }

  override def execute(
      logicalPlan: LogicalPlan,
      context: RuntimeContext,
      runtime: RuntimeResult.SubscribingQuerySubscriber,
      prePopulateResults: Boolean,
      ignore: InputDataStream,
      subscriber: QuerySubscriber,
      memoryTracker: MemoryTracker
  ): RuntimeResult = {
    
    // Check security authorization
    checkSecurityAuthorization(
      securityHandler,
      context.securityContext,
      "RBAC administration"
    )
    
    val queryHandler = new QueryHandler.LazyQueryHandler(() => {
      try {
        normalExecutionEngine.queryService()
      } catch {
        case _: UnsupportedOperationException =>
          normalExecutionEngine.queryService()
      }
    })
    
    logicalPlan match {
      case grantPriv: GrantPrivilege =>
        executeGrantPrivilege(grantPriv, queryHandler, context, subscriber)
        
      case denyPriv: DenyPrivilege =>
        executeDenyPrivilege(denyPriv, queryHandler, context, subscriber)
        
      case revokePriv: RevokePrivilege =>
        executeRevokePrivilege(revokePriv, queryHandler, context, subscriber)
        
      case createRole: CreateRole =>
        executeCreateRole(createRole, queryHandler, context, subscriber)
        
      case dropRole: DropRole =>
        executeDropRole(dropRole, queryHandler, context, subscriber)
        
      case grantRoles: GrantRolesToUsers =>
        executeGrantRolesToUsers(grantRoles, queryHandler, context, subscriber)
        
      case revokeRoles: RevokeRolesFromUsers =>
        executeRevokeRolesFromUsers(revokeRoles, queryHandler, context, subscriber)
        
      case showRoles: ShowRoles =>
        executeShowRoles(showRoles, queryHandler, context, subscriber)
        
      case showPrivs: ShowPrivileges =>
        executeShowPrivileges(showPrivs, queryHandler, context, subscriber)
        
      case _ =>
        throw new IllegalStateException(s"Unsupported RBAC command: $logicalPlan")
    }
    
    RuntimeResult.empty(subscriber)
  }
  
  private def executeGrantPrivilege(
      command: GrantPrivilege,
      queryHandler: QueryHandler,
      context: RuntimeContext,
      subscriber: QuerySubscriber
  ): Unit = {
    val roles = command.roles.map(_.name)
    val privilegeType = mapPrivilegeType(command.privilege)
    val resource = mapResource(command.privilege)
    
    roles.foreach { role =>
      queryHandler.call(
        context.transactionalContext,
        "CALL dbms.security.grantPrivilege($privilege, $resource, $role)",
        subscriber,
        java.util.Map.of(
          "privilege", privilegeType,
          "resource", resource,
          "role", role
        )
      )
    }
  }
  
  private def executeDenyPrivilege(
      command: DenyPrivilege,
      queryHandler: QueryHandler,
      context: RuntimeContext,
      subscriber: QuerySubscriber
  ): Unit = {
    val roles = command.roles.map(_.name)
    val privilegeType = mapPrivilegeType(command.privilege)
    val resource = mapResource(command.privilege)
    
    roles.foreach { role =>
      queryHandler.call(
        context.transactionalContext,
        "CALL dbms.security.denyPrivilege($privilege, $resource, $role)",
        subscriber,
        java.util.Map.of(
          "privilege", privilegeType,
          "resource", resource,
          "role", role
        )
      )
    }
  }
  
  private def executeRevokePrivilege(
      command: RevokePrivilege,
      queryHandler: QueryHandler,
      context: RuntimeContext,
      subscriber: QuerySubscriber
  ): Unit = {
    val roles = command.roles.map(_.name)
    val privilegeType = mapPrivilegeType(command.privilege)
    val resource = mapResource(command.privilege)
    
    roles.foreach { role =>
      queryHandler.call(
        context.transactionalContext,
        "CALL dbms.security.revokePrivilege($privilege, $resource, $role)",
        subscriber,
        java.util.Map.of(
          "privilege", privilegeType,
          "resource", resource,
          "role", role
        )
      )
    }
  }
  
  private def executeCreateRole(
      command: CreateRole,
      queryHandler: QueryHandler,
      context: RuntimeContext,
      subscriber: QuerySubscriber
  ): Unit = {
    val roleName = command.roleName
    
    if (command.ifExistsDo == IfExistsThrowError) {
      // Check if role exists first
      val existsResult = queryHandler.call(
        context.transactionalContext,
        "CALL dbms.security.listRoles() YIELD role WHERE role = $roleName RETURN count(*) AS count",
        subscriber,
        java.util.Map.of("roleName", roleName)
      )
      
      if (existsResult.hasNext && existsResult.next().get("count").asInstanceOf[Long] > 0) {
        throw new InvalidArgumentException(s"Role '$roleName' already exists")
      }
    }
    
    queryHandler.call(
      context.transactionalContext,
      "CALL dbms.security.createRole($roleName)",
      subscriber,
      java.util.Map.of("roleName", roleName)
    )
  }
  
  private def executeDropRole(
      command: DropRole,
      queryHandler: QueryHandler,
      context: RuntimeContext,
      subscriber: QuerySubscriber
  ): Unit = {
    val roleName = command.roleName
    
    if (command.ifExistsDo == IfExistsThrowError) {
      // Check if role exists first
      val existsResult = queryHandler.call(
        context.transactionalContext,
        "CALL dbms.security.listRoles() YIELD role WHERE role = $roleName RETURN count(*) AS count",
        subscriber,
        java.util.Map.of("roleName", roleName)
      )
      
      if (!existsResult.hasNext || existsResult.next().get("count").asInstanceOf[Long] == 0) {
        throw new InvalidArgumentException(s"Role '$roleName' does not exist")
      }
    }
    
    queryHandler.call(
      context.transactionalContext,
      "CALL dbms.security.deleteRole($roleName)",
      subscriber,
      java.util.Map.of("roleName", roleName)
    )
  }
  
  private def executeGrantRolesToUsers(
      command: GrantRolesToUsers,
      queryHandler: QueryHandler,
      context: RuntimeContext,
      subscriber: QuerySubscriber
  ): Unit = {
    val roles = command.roles.map(_.name)
    val users = command.users.map(_.name)
    
    users.foreach { user =>
      queryHandler.call(
        context.transactionalContext,
        "CALL dbms.security.grantRolesToUser($username, $roles)",
        subscriber,
        java.util.Map.of(
          "username", user,
          "roles", roles.asJava
        )
      )
    }
  }
  
  private def executeRevokeRolesFromUsers(
      command: RevokeRolesFromUsers,
      queryHandler: QueryHandler,
      context: RuntimeContext,
      subscriber: QuerySubscriber
  ): Unit = {
    val roles = command.roles.map(_.name)
    val users = command.users.map(_.name)
    
    users.foreach { user =>
      queryHandler.call(
        context.transactionalContext,
        "CALL dbms.security.revokeRolesFromUser($username, $roles)",
        subscriber,
        java.util.Map.of(
          "username", user,
          "roles", roles.asJava
        )
      )
    }
  }
  
  private def executeShowRoles(
      command: ShowRoles,
      queryHandler: QueryHandler,
      context: RuntimeContext,
      subscriber: QuerySubscriber
  ): Unit = {
    val result = queryHandler.call(
      context.transactionalContext,
      "CALL dbms.security.listRoles()",
      subscriber,
      java.util.Map.of()
    )
    
    // Pass results to subscriber
    while (result.hasNext) {
      val record = result.next()
      subscriber.onRecord(Array(record.get("role")))
    }
  }
  
  private def executeShowPrivileges(
      command: ShowPrivileges,
      queryHandler: QueryHandler,
      context: RuntimeContext,
      subscriber: QuerySubscriber
  ): Unit = {
    val result = queryHandler.call(
      context.transactionalContext,
      "CALL dbms.security.showPrivileges()",
      subscriber,
      java.util.Map.of()
    )
    
    // Pass results to subscriber
    while (result.hasNext) {
      val record = result.next()
      subscriber.onRecord(Array(
        record.get("access"),
        record.get("action"),
        record.get("resource"),
        record.get("role")
      ))
    }
  }
  
  private def mapPrivilegeType(privilege: PrivilegeType): String = {
    privilege match {
      case TraversePrivilege => "TRAVERSE"
      case ReadPrivilege => "READ"
      case MatchPrivilege => "MATCH"
      case WritePrivilege => "WRITE"
      case CreatePrivilege => "CREATE"
      case DeletePrivilege => "DELETE"
      case SetLabelPrivilege => "SET_LABEL"
      case RemoveLabelPrivilege => "REMOVE_LABEL"
      case SetPropertyPrivilege => "SET_PROPERTY"
      case AccessPrivilege => "ACCESS"
      case StartPrivilege => "START"
      case StopPrivilege => "STOP"
      case CreateIndexPrivilege => "CREATE_INDEX"
      case DropIndexPrivilege => "DROP_INDEX"
      case CreateConstraintPrivilege => "CREATE_CONSTRAINT"
      case DropConstraintPrivilege => "DROP_CONSTRAINT"
      case ShowIndexPrivilege => "SHOW_INDEX"
      case ShowConstraintPrivilege => "SHOW_CONSTRAINT"
      case CreateTokenPrivilege => "CREATE_TOKEN"
      case UserManagementPrivilege => "USER_MANAGEMENT"
      case RoleManagementPrivilege => "ROLE_MANAGEMENT"
      case DatabaseManagementPrivilege => "DATABASE_MANAGEMENT"
      case PrivilegeManagementPrivilege => "PRIVILEGE_MANAGEMENT"
      case ImpersonatePrivilege => "IMPERSONATE"
      case ShowTransactionPrivilege => "SHOW_TRANSACTION"
      case TerminateTransactionPrivilege => "TERMINATE_TRANSACTION"
      case _ => throw new IllegalArgumentException(s"Unsupported privilege type: $privilege")
    }
  }
  
  private def mapResource(privilege: PrivilegeType): String = {
    privilege match {
      case _: GraphPrivilege => "GRAPH"
      case _: DatabasePrivilege => "DATABASE"
      case _: DbmsPrivilege => "DBMS"
      case _ => "*"
    }
  }
}