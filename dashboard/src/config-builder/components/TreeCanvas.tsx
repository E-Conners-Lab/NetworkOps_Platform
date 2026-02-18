/**
 * Tree Canvas Component
 *
 * Displays the hierarchical tree structure and handles drag-and-drop.
 */

import React from 'react';
import { useDroppable } from '@dnd-kit/core';
import { ConfigTreeNode } from '../types';

interface TreeCanvasProps {
  nodes: ConfigTreeNode[];
  selectedNodeId: string | null;
  expandedNodes: Set<string>;
  onSelectNode: (node: ConfigTreeNode | null) => void;
  onToggleExpand: (nodeId: string) => void;
  onDeleteNode: (nodeId: string) => void;
}

const TreeCanvas: React.FC<TreeCanvasProps> = ({
  nodes,
  selectedNodeId,
  expandedNodes,
  onSelectNode,
  onToggleExpand,
  onDeleteNode,
}) => {
  // Root drop zone
  const { setNodeRef: setRootRef, isOver: isOverRoot } = useDroppable({
    id: 'root',
  });

  return (
    <div className="tree-canvas" ref={setRootRef}>
      {nodes.length === 0 ? (
        <div className={`tree-empty ${isOverRoot ? 'drop-target' : ''}`}>
          <p>Drag nodes from the palette to build your config tree.</p>
          <p className="hint">Drop sections here to create root nodes.</p>
        </div>
      ) : (
        <div className="tree-nodes">
          {nodes.map(node => (
            <TreeNodeItem
              key={node.id}
              node={node}
              depth={0}
              selectedNodeId={selectedNodeId}
              expandedNodes={expandedNodes}
              onSelectNode={onSelectNode}
              onToggleExpand={onToggleExpand}
              onDeleteNode={onDeleteNode}
            />
          ))}
        </div>
      )}
    </div>
  );
};

interface TreeNodeItemProps {
  node: ConfigTreeNode;
  depth: number;
  selectedNodeId: string | null;
  expandedNodes: Set<string>;
  onSelectNode: (node: ConfigTreeNode | null) => void;
  onToggleExpand: (nodeId: string) => void;
  onDeleteNode: (nodeId: string) => void;
}

const TreeNodeItem: React.FC<TreeNodeItemProps> = ({
  node,
  depth,
  selectedNodeId,
  expandedNodes,
  onSelectNode,
  onToggleExpand,
  onDeleteNode,
}) => {
  const hasChildren = node.children && node.children.length > 0;
  const isExpanded = expandedNodes.has(node.id);
  const isSelected = selectedNodeId === node.id;

  // Make this node a drop target
  const { setNodeRef, isOver } = useDroppable({
    id: node.id,
  });

  const getNodeIcon = () => {
    if (node.node_type === 'section') return '📁';
    if (node.node_type === 'command') return '⚙️';
    return '📝';
  };

  return (
    <div className="tree-node-container" style={{ marginLeft: `${depth * 20}px` }}>
      <div
        ref={setNodeRef}
        className={`tree-node ${isSelected ? 'selected' : ''} ${isOver ? 'drop-target' : ''} ${node.node_type}`}
        onClick={() => onSelectNode(node)}
      >
        {/* Expand/collapse toggle */}
        {hasChildren && (
          <button
            className="expand-toggle"
            onClick={(e) => {
              e.stopPropagation();
              onToggleExpand(node.id);
            }}
          >
            {isExpanded ? '▼' : '▶'}
          </button>
        )}
        {!hasChildren && <span className="expand-placeholder" />}

        {/* Node icon and label */}
        <span className="node-icon">{getNodeIcon()}</span>
        <span className="node-label">{node.label}</span>

        {/* Node badges */}
        {node.is_required && <span className="badge required">Required</span>}
        {node.is_repeatable && <span className="badge repeatable">Repeatable</span>}

        {/* Delete button */}
        <button
          className="delete-node-button"
          onClick={(e) => {
            e.stopPropagation();
            onDeleteNode(node.id);
          }}
          title="Delete node"
        >
          ×
        </button>
      </div>

      {/* Command template preview */}
      {node.command_template && (
        <div className="node-template-preview">
          <code>{node.command_template}</code>
        </div>
      )}

      {/* Children */}
      {hasChildren && isExpanded && (
        <div className="tree-node-children">
          {node.children.map(child => (
            <TreeNodeItem
              key={child.id}
              node={child}
              depth={depth + 1}
              selectedNodeId={selectedNodeId}
              expandedNodes={expandedNodes}
              onSelectNode={onSelectNode}
              onToggleExpand={onToggleExpand}
              onDeleteNode={onDeleteNode}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export default TreeCanvas;
