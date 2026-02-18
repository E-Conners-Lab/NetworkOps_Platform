/**
 * Config Builder Panel
 *
 * Visual drag-and-drop interface for building Cisco IOS configuration templates.
 * Three-panel layout: Palette | Canvas | Editor
 */

import React, { useState, useCallback, useEffect } from 'react';
import { DndContext, DragEndEvent, DragStartEvent, closestCenter } from '@dnd-kit/core';
import { useAuth } from '../context/AuthContext';
import { API } from '../config';
import { ConfigTree, ConfigTreeNode, NodeTemplate, GenerationResult } from './types';
import TreeCanvas from './components/TreeCanvas';
import NodeEditor from './components/NodeEditor';
import NodePalette from './components/NodePalette';
import ConfigPreview from './components/ConfigPreview';
import './ConfigBuilderPanel.css';

interface ConfigBuilderPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

const ConfigBuilderPanel: React.FC<ConfigBuilderPanelProps> = ({ isOpen, onClose }) => {
  const { getAuthHeaders } = useAuth();

  // Tree state
  const [trees, setTrees] = useState<ConfigTree[]>([]);
  const [selectedTree, setSelectedTree] = useState<ConfigTree | null>(null);
  const [selectedNode, setSelectedNode] = useState<ConfigTreeNode | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());

  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'trees' | 'builder' | 'preview'>('trees');
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [isDirty, setIsDirty] = useState(false);

  // Drag state
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [activeId, setActiveId] = useState<string | null>(null);

  // Templates
  const [sectionTemplates, setSectionTemplates] = useState<NodeTemplate[]>([]);
  const [commandTemplates, setCommandTemplates] = useState<NodeTemplate[]>([]);

  // Generation
  const [variableValues, setVariableValues] = useState<Record<string, string>>({});
  const [generationResult, setGenerationResult] = useState<GenerationResult | null>(null);

  // Create new tree dialog
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newTreeName, setNewTreeName] = useState('');
  const [newTreeDescription, setNewTreeDescription] = useState('');

  // Fetch trees list
  const fetchTrees = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API.base}/api/config-trees`, {
        headers: getAuthHeaders(),
      });
      if (!response.ok) throw new Error('Failed to fetch trees');
      const data = await response.json();
      setTrees(data.trees || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load trees');
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  // Fetch templates
  const fetchTemplates = useCallback(async () => {
    try {
      const [sectionsRes, commandsRes] = await Promise.all([
        fetch(`${API.base}/api/config-trees/templates/sections`, { headers: getAuthHeaders() }),
        fetch(`${API.base}/api/config-trees/templates/commands`, { headers: getAuthHeaders() }),
      ]);

      if (sectionsRes.ok) {
        const data = await sectionsRes.json();
        setSectionTemplates(data.sections || []);
      }
      if (commandsRes.ok) {
        const data = await commandsRes.json();
        setCommandTemplates(data.commands || []);
      }
    } catch (err) {
      console.error('Failed to fetch templates:', err);
    }
  }, [getAuthHeaders]);

  // Load tree with nodes
  const loadTree = useCallback(async (treeId: string) => {
    try {
      setLoading(true);
      const response = await fetch(`${API.base}/api/config-trees/${treeId}`, {
        headers: getAuthHeaders(),
      });
      if (!response.ok) throw new Error('Failed to load tree');
      const data = await response.json();
      setSelectedTree(data.tree);
      setSelectedNode(null);
      setExpandedNodes(new Set());
      setActiveTab('builder');
      setIsDirty(false);
      setVariableValues({});
      setGenerationResult(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load tree');
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  // Create new tree
  const createTree = useCallback(async () => {
    if (!newTreeName.trim()) return;

    try {
      setLoading(true);
      const response = await fetch(`${API.base}/api/config-trees`, {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newTreeName.trim(),
          description: newTreeDescription.trim() || undefined,
        }),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to create tree');
      }
      const data = await response.json();
      setShowCreateDialog(false);
      setNewTreeName('');
      setNewTreeDescription('');
      await fetchTrees();
      loadTree(data.tree.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create tree');
    } finally {
      setLoading(false);
    }
  }, [newTreeName, newTreeDescription, getAuthHeaders, fetchTrees, loadTree]);

  // Delete tree
  const deleteTree = useCallback(async (treeId: string) => {
    if (!window.confirm('Are you sure you want to delete this tree?')) return;

    try {
      setLoading(true);
      const response = await fetch(`${API.base}/api/config-trees/${treeId}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      if (!response.ok) throw new Error('Failed to delete tree');
      if (selectedTree?.id === treeId) {
        setSelectedTree(null);
        setActiveTab('trees');
      }
      await fetchTrees();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete tree');
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders, selectedTree, fetchTrees]);

  // Add node to tree
  const addNode = useCallback(async (
    nodeType: 'section' | 'command',
    label: string,
    parentId: string | null,
    template?: NodeTemplate
  ) => {
    if (!selectedTree) return;

    try {
      const response = await fetch(`${API.base}/api/config-trees/${selectedTree.id}/nodes`, {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          node_type: nodeType,
          label,
          parent_id: parentId,
          command_template: template?.command_template,
          help_text: template?.help_text,
        }),
      });
      if (!response.ok) throw new Error('Failed to add node');

      // Reload tree to get updated structure
      await loadTree(selectedTree.id);
      setIsDirty(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add node');
    }
  }, [selectedTree, getAuthHeaders, loadTree]);

  // Update node
  const updateNode = useCallback(async (nodeId: string, updates: Partial<ConfigTreeNode>) => {
    if (!selectedTree) return;

    try {
      const response = await fetch(`${API.base}/api/config-trees/${selectedTree.id}/nodes/${nodeId}`, {
        method: 'PUT',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      });
      if (!response.ok) throw new Error('Failed to update node');

      await loadTree(selectedTree.id);
      setIsDirty(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update node');
    }
  }, [selectedTree, getAuthHeaders, loadTree]);

  // Delete node
  const deleteNode = useCallback(async (nodeId: string) => {
    if (!selectedTree) return;
    if (!window.confirm('Delete this node and all its children?')) return;

    try {
      const response = await fetch(`${API.base}/api/config-trees/${selectedTree.id}/nodes/${nodeId}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      if (!response.ok) throw new Error('Failed to delete node');

      if (selectedNode?.id === nodeId) {
        setSelectedNode(null);
      }
      await loadTree(selectedTree.id);
      setIsDirty(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete node');
    }
  }, [selectedTree, selectedNode, getAuthHeaders, loadTree]);

  // Generate config
  const generateConfig = useCallback(async () => {
    if (!selectedTree) return;

    try {
      setLoading(true);
      const response = await fetch(`${API.base}/api/config-trees/${selectedTree.id}/generate`, {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ values: variableValues }),
      });
      if (!response.ok) throw new Error('Failed to generate config');
      const data = await response.json();
      setGenerationResult({
        config: data.config,
        errors: data.errors || [],
        warnings: data.warnings || [],
      });
      setActiveTab('preview');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate config');
    } finally {
      setLoading(false);
    }
  }, [selectedTree, variableValues, getAuthHeaders]);

  // Toggle node expansion
  const toggleExpand = useCallback((nodeId: string) => {
    setExpandedNodes(prev => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return next;
    });
  }, []);

  // Drag handlers
  const handleDragStart = (event: DragStartEvent) => {
    setActiveId(event.active.id as string);
  };

  const handleDragEnd = async (event: DragEndEvent) => {
    setActiveId(null);
    const { active, over } = event;

    if (!over || !selectedTree) return;

    // Check if dragging from palette (template)
    const activeData = active.data.current;
    if (activeData?.type === 'template') {
      const template = activeData.template as NodeTemplate;
      const targetId = over.id === 'root' ? null : over.id as string;
      await addNode(template.node_type, template.label, targetId, template);
    }
  };

  // Effects
  useEffect(() => {
    if (isOpen) {
      fetchTrees();
      fetchTemplates();
    }
  }, [isOpen, fetchTrees, fetchTemplates]);

  if (!isOpen) return null;

  return (
    <div className="config-builder-overlay">
      <div className="config-builder-panel">
        {/* Header */}
        <div className="config-builder-header">
          <h2>Config Builder</h2>
          <div className="config-builder-tabs">
            <button
              className={activeTab === 'trees' ? 'active' : ''}
              onClick={() => setActiveTab('trees')}
            >
              Trees
            </button>
            <button
              className={activeTab === 'builder' ? 'active' : ''}
              onClick={() => setActiveTab('builder')}
              disabled={!selectedTree}
            >
              Builder
            </button>
            <button
              className={activeTab === 'preview' ? 'active' : ''}
              onClick={() => setActiveTab('preview')}
              disabled={!selectedTree}
            >
              Preview
            </button>
          </div>
          <button className="close-button" onClick={onClose}>&times;</button>
        </div>

        {/* Error banner */}
        {error && (
          <div className="config-builder-error">
            {error}
            <button onClick={() => setError(null)}>&times;</button>
          </div>
        )}

        {/* Content */}
        <div className="config-builder-content">
          {loading && <div className="config-builder-loading">Loading...</div>}

          {/* Trees List Tab */}
          {activeTab === 'trees' && (
            <div className="trees-list">
              <div className="trees-list-header">
                <h3>Config Trees</h3>
                <button className="create-button" onClick={() => setShowCreateDialog(true)}>
                  + New Tree
                </button>
              </div>
              {trees.length === 0 ? (
                <p className="empty-message">No config trees yet. Create one to get started.</p>
              ) : (
                <ul className="trees-list-items">
                  {trees.map(tree => (
                    <li key={tree.id} className={selectedTree?.id === tree.id ? 'selected' : ''}>
                      <div className="tree-info" onClick={() => loadTree(tree.id)}>
                        <span className="tree-name">{tree.name}</span>
                        <span className="tree-meta">
                          {tree.platform} | {tree.version} | by {tree.created_by}
                        </span>
                      </div>
                      <button className="delete-button" onClick={() => deleteTree(tree.id)}>
                        Delete
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {/* Builder Tab */}
          {activeTab === 'builder' && selectedTree && (
            <DndContext
              collisionDetection={closestCenter}
              onDragStart={handleDragStart}
              onDragEnd={handleDragEnd}
            >
              <div className="builder-layout">
                {/* Left: Node Palette */}
                <div className="builder-palette">
                  <NodePalette
                    sectionTemplates={sectionTemplates}
                    commandTemplates={commandTemplates}
                  />
                </div>

                {/* Center: Tree Canvas */}
                <div className="builder-canvas">
                  <div className="canvas-header">
                    <h3>{selectedTree.name}</h3>
                    <button className="generate-button" onClick={generateConfig}>
                      Generate Config
                    </button>
                  </div>
                  <TreeCanvas
                    nodes={selectedTree.root_nodes}
                    selectedNodeId={selectedNode?.id || null}
                    expandedNodes={expandedNodes}
                    onSelectNode={setSelectedNode}
                    onToggleExpand={toggleExpand}
                    onDeleteNode={deleteNode}
                  />
                </div>

                {/* Right: Node Editor */}
                <div className="builder-editor">
                  <NodeEditor
                    node={selectedNode}
                    onUpdate={updateNode}
                    onDelete={deleteNode}
                    variableValues={variableValues}
                    onVariableChange={(name, value) => {
                      setVariableValues(prev => ({ ...prev, [name]: value }));
                    }}
                  />
                </div>
              </div>
            </DndContext>
          )}

          {/* Preview Tab */}
          {activeTab === 'preview' && selectedTree && (
            <ConfigPreview
              result={generationResult}
              treeName={selectedTree.name}
              onRegenerate={generateConfig}
            />
          )}
        </div>

        {/* Create Tree Dialog */}
        {showCreateDialog && (
          <div className="dialog-overlay">
            <div className="dialog">
              <h3>Create New Tree</h3>
              <div className="form-group">
                <label>Name</label>
                <input
                  type="text"
                  value={newTreeName}
                  onChange={e => setNewTreeName(e.target.value)}
                  placeholder="e.g., Interface Security Template"
                />
              </div>
              <div className="form-group">
                <label>Description (optional)</label>
                <textarea
                  value={newTreeDescription}
                  onChange={e => setNewTreeDescription(e.target.value)}
                  placeholder="What this template is for..."
                />
              </div>
              <div className="dialog-buttons">
                <button onClick={() => setShowCreateDialog(false)}>Cancel</button>
                <button className="primary" onClick={createTree} disabled={!newTreeName.trim()}>
                  Create
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ConfigBuilderPanel;
