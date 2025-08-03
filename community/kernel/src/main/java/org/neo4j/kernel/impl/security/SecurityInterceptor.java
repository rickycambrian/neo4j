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

import org.neo4j.configuration.Config;
import org.neo4j.graphdb.security.AuthorizationViolationException;
import org.neo4j.internal.kernel.api.NodeCursor;
import org.neo4j.internal.kernel.api.RelationshipScanCursor;
import org.neo4j.internal.kernel.api.security.SecurityAuthorizationHandler;
import org.neo4j.internal.kernel.api.security.SecurityContext;
import org.neo4j.kernel.api.KernelTransaction;
import org.neo4j.kernel.impl.api.KernelTransactionImplementation;
import org.neo4j.kernel.impl.api.security.OverriddenAccessMode;
import org.neo4j.kernel.impl.coreapi.InternalTransaction;
import org.neo4j.logging.Log;
import org.neo4j.logging.LogProvider;
import org.neo4j.token.TokenHolders;

/**
 * Intercepts kernel operations to enforce security
 */
public class SecurityInterceptor {
    private final LabelSecurityValidator labelValidator;
    private final SecurityAuditLogger auditLogger;
    private final Log log;
    private final boolean enforceRbac;
    
    public SecurityInterceptor(
            TokenHolders tokenHolders,
            LogProvider logProvider,
            Config config) {
        this.labelValidator = new LabelSecurityValidator(tokenHolders);
        this.auditLogger = new SecurityAuditLogger(logProvider);
        this.log = logProvider.getLog(SecurityInterceptor.class);
        this.enforceRbac = config.get(RbacSettings.rbac_enabled);
    }
    
    /**
     * Check node read access
     */
    public void checkNodeReadAccess(KernelTransaction transaction, NodeCursor node) {
        if (!enforceRbac) {
            return;
        }
        
        SecurityContext context = transaction.securityContext();
        if (!labelValidator.canReadNode(context, node)) {
            String message = String.format(
                "User '%s' does not have permission to read node %d",
                context.subject().executingUser(),
                node.nodeReference()
            );
            
            auditLogger.logAccessDenied(context, "READ_NODE", node.nodeReference(), message);
            throw new AuthorizationViolationException(message);
        }
    }
    
    /**
     * Check node write access
     */
    public void checkNodeWriteAccess(KernelTransaction transaction, NodeCursor node) {
        if (!enforceRbac) {
            return;
        }
        
        SecurityContext context = transaction.securityContext();
        if (!labelValidator.canWriteNode(context, node)) {
            String message = String.format(
                "User '%s' does not have permission to write to node %d",
                context.subject().executingUser(),
                node.nodeReference()
            );
            
            auditLogger.logAccessDenied(context, "WRITE_NODE", node.nodeReference(), message);
            throw new AuthorizationViolationException(message);
        }
    }
    
    /**
     * Check node creation access
     */
    public void checkNodeCreateAccess(KernelTransaction transaction, int[] labelIds) {
        if (!enforceRbac) {
            return;
        }
        
        SecurityContext context = transaction.securityContext();
        if (!labelValidator.canCreateNodeWithLabels(context, labelIds)) {
            String message = String.format(
                "User '%s' does not have permission to create nodes with specified labels",
                context.subject().executingUser()
            );
            
            auditLogger.logAccessDenied(context, "CREATE_NODE", -1, message);
            throw new AuthorizationViolationException(message);
        }
    }
    
    /**
     * Check node deletion access
     */
    public void checkNodeDeleteAccess(KernelTransaction transaction, NodeCursor node) {
        if (!enforceRbac) {
            return;
        }
        
        SecurityContext context = transaction.securityContext();
        AccessMode mode = context.mode();
        
        // Must have write access to the node
        if (!labelValidator.canWriteNode(context, node)) {
            String message = String.format(
                "User '%s' does not have permission to delete node %d",
                context.subject().executingUser(),
                node.nodeReference()
            );
            
            auditLogger.logAccessDenied(context, "DELETE_NODE", node.nodeReference(), message);
            throw new AuthorizationViolationException(message);
        }
        
        // Check if delete is specifically allowed
        if (!mode.allowsDeleteNode(() -> null)) { // TODO: provide proper TokenSet
            String message = String.format(
                "User '%s' does not have DELETE permission on nodes",
                context.subject().executingUser()
            );
            
            auditLogger.logAccessDenied(context, "DELETE_NODE", node.nodeReference(), message);
            throw new AuthorizationViolationException(message);
        }
    }
    
    /**
     * Filter nodes based on security context
     */
    public boolean shouldIncludeNode(SecurityContext context, NodeCursor node) {
        if (!enforceRbac) {
            return true;
        }
        
        try {
            return labelValidator.canReadNode(context, node);
        } catch (Exception e) {
            log.warn("Error checking node access", e);
            // Fail closed - deny access on error
            return false;
        }
    }
    
    /**
     * Filter labels based on security context
     */
    public long[] filterLabels(SecurityContext context, long[] labels) {
        if (!enforceRbac) {
            return labels;
        }
        
        return labelValidator.filterAllowedLabels(context, labels);
    }
    
    /**
     * Clear security caches
     */
    public void clearCaches() {
        labelValidator.clearCache();
    }
    
    /**
     * Wrap a transaction with security enforcement
     */
    public static KernelTransaction wrapWithSecurity(
            KernelTransaction transaction,
            SecurityInterceptor interceptor) {
        if (transaction instanceof KernelTransactionImplementation) {
            return new SecurityEnforcingTransaction(
                (KernelTransactionImplementation) transaction,
                interceptor
            );
        }
        return transaction;
    }
    
    /**
     * Access mode that enforces label-based security
     */
    public static class SecurityEnforcingAccessMode extends OverriddenAccessMode {
        private final SecurityInterceptor interceptor;
        private final SecurityContext context;
        
        public SecurityEnforcingAccessMode(
                AccessMode original,
                SecurityInterceptor interceptor,
                SecurityContext context) {
            super(original, "");
            this.interceptor = interceptor;
            this.context = context;
        }
        
        @Override
        public boolean allowsTraverseNode(int... labels) {
            if (!super.allowsTraverseNode(labels)) {
                return false;
            }
            
            // Additional label-based check
            long[] longLabels = new long[labels.length];
            for (int i = 0; i < labels.length; i++) {
                longLabels[i] = labels[i];
            }
            
            return interceptor.labelValidator.canAccessNode(context, longLabels);
        }
    }
}