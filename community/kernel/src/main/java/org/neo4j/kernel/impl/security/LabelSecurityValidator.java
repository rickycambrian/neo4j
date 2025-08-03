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

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.neo4j.internal.kernel.api.NodeCursor;
import org.neo4j.internal.kernel.api.security.AccessMode;
import org.neo4j.internal.kernel.api.security.SecurityAuthorizationHandler;
import org.neo4j.internal.kernel.api.security.SecurityContext;
import org.neo4j.kernel.api.KernelTransaction;
import org.neo4j.token.TokenHolders;
import org.neo4j.token.api.TokenNotFoundException;

/**
 * Validates label-based security at the kernel level
 */
public class LabelSecurityValidator {
    private final TokenHolders tokenHolders;
    private final Map<Integer, String> labelIdToNameCache = new ConcurrentHashMap<>();
    
    public LabelSecurityValidator(TokenHolders tokenHolders) {
        this.tokenHolders = tokenHolders;
    }
    
    /**
     * Check if the current security context allows access to a node with given labels
     */
    public boolean canAccessNode(SecurityContext context, long[] labelIds) {
        AccessMode accessMode = context.mode();
        
        // Fast path for full access
        if (accessMode.name().contains("FULL")) {
            return true;
        }
        
        // Check if this is label-based access mode
        if (accessMode.name().startsWith("label-based:")) {
            return checkLabelAccess(accessMode, labelIds);
        }
        
        // Default allow for other access modes
        return true;
    }
    
    /**
     * Check if the security context allows reading a node
     */
    public boolean canReadNode(SecurityContext context, NodeCursor node) {
        if (!node.hasLabel()) {
            // Nodes without labels are accessible by default
            return true;
        }
        
        // Get node labels
        long[] labelIds = node.labels().all();
        return canAccessNode(context, labelIds);
    }
    
    /**
     * Check if the security context allows writing to a node
     */
    public boolean canWriteNode(SecurityContext context, NodeCursor node) {
        AccessMode accessMode = context.mode();
        
        // Must have write permissions
        if (!accessMode.allowsWrites()) {
            return false;
        }
        
        return canReadNode(context, node);
    }
    
    /**
     * Check if the security context allows creating a node with given labels
     */
    public boolean canCreateNodeWithLabels(SecurityContext context, int[] labelIds) {
        AccessMode accessMode = context.mode();
        
        // Must have write permissions
        if (!accessMode.allowsWrites()) {
            return false;
        }
        
        // Check create permission
        return accessMode.allowsCreateNode(labelIds);
    }
    
    /**
     * Filter out labels that the user doesn't have access to
     */
    public long[] filterAllowedLabels(SecurityContext context, long[] requestedLabels) {
        AccessMode accessMode = context.mode();
        
        // Fast path for full access
        if (accessMode.name().contains("FULL")) {
            return requestedLabels;
        }
        
        // For label-based access, filter labels
        if (accessMode.name().startsWith("label-based:")) {
            return filterLabelsForLabelBasedAccess(accessMode, requestedLabels);
        }
        
        return requestedLabels;
    }
    
    private boolean checkLabelAccess(AccessMode accessMode, long[] labelIds) {
        // Extract allowed labels from access mode name
        // Format: "label-based:username:label1,label2,label3"
        String modeName = accessMode.name();
        String[] parts = modeName.split(":");
        if (parts.length < 3) {
            return false;
        }
        
        Set<String> allowedLabels = Set.of(parts[2].split(","));
        
        // Check if any of the node's labels are allowed
        for (long labelId : labelIds) {
            String labelName = getLabelName((int) labelId);
            if (labelName != null && allowedLabels.contains(labelName)) {
                return true;
            }
        }
        
        return false;
    }
    
    private long[] filterLabelsForLabelBasedAccess(AccessMode accessMode, long[] requestedLabels) {
        String modeName = accessMode.name();
        String[] parts = modeName.split(":");
        if (parts.length < 3) {
            return new long[0];
        }
        
        Set<String> allowedLabels = Set.of(parts[2].split(","));
        
        // Count allowed labels
        int count = 0;
        for (long labelId : requestedLabels) {
            String labelName = getLabelName((int) labelId);
            if (labelName != null && allowedLabels.contains(labelName)) {
                count++;
            }
        }
        
        // Create filtered array
        long[] filtered = new long[count];
        int index = 0;
        for (long labelId : requestedLabels) {
            String labelName = getLabelName((int) labelId);
            if (labelName != null && allowedLabels.contains(labelName)) {
                filtered[index++] = labelId;
            }
        }
        
        return filtered;
    }
    
    private String getLabelName(int labelId) {
        return labelIdToNameCache.computeIfAbsent(labelId, id -> {
            try {
                return tokenHolders.labelTokens().getTokenById(id).name();
            } catch (TokenNotFoundException e) {
                return null;
            }
        });
    }
    
    /**
     * Clear the label cache (call when labels are created/deleted)
     */
    public void clearCache() {
        labelIdToNameCache.clear();
    }
}