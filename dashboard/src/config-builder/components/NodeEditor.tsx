/**
 * Node Editor Component
 *
 * Edit properties of the selected node and fill in variable values.
 */

import React, { useState, useEffect } from 'react';
import { ConfigTreeNode } from '../types';

interface NodeEditorProps {
  node: ConfigTreeNode | null;
  onUpdate: (nodeId: string, updates: Partial<ConfigTreeNode>) => void;
  onDelete: (nodeId: string) => void;
  variableValues: Record<string, string>;
  onVariableChange: (name: string, value: string) => void;
}

const NodeEditor: React.FC<NodeEditorProps> = ({
  node,
  onUpdate,
  onDelete,
  variableValues,
  onVariableChange,
}) => {
  const [editLabel, setEditLabel] = useState('');
  const [editTemplate, setEditTemplate] = useState('');
  const [editHelpText, setEditHelpText] = useState('');
  const [editRequired, setEditRequired] = useState(false);
  const [editRepeatable, setEditRepeatable] = useState(false);

  // Sync local state with selected node
  useEffect(() => {
    if (node) {
      setEditLabel(node.label);
      setEditTemplate(node.command_template || '');
      setEditHelpText(node.help_text || '');
      setEditRequired(node.is_required);
      setEditRepeatable(node.is_repeatable);
    }
  }, [node]);

  // Extract variables from command template
  const extractVariables = (template: string): string[] => {
    const matches = template.match(/\{(\w+)\}/g);
    return matches ? matches.map(m => m.slice(1, -1)) : [];
  };

  if (!node) {
    return (
      <div className="node-editor empty">
        <p>Select a node to edit its properties</p>
      </div>
    );
  }

  const templateVars = extractVariables(editTemplate);

  const handleSave = () => {
    onUpdate(node.id, {
      label: editLabel,
      command_template: editTemplate || undefined,
      help_text: editHelpText || undefined,
      is_required: editRequired,
      is_repeatable: editRepeatable,
    });
  };

  return (
    <div className="node-editor">
      <h4>Node Properties</h4>

      {/* Basic info */}
      <div className="editor-section">
        <div className="form-group">
          <label>Label</label>
          <input
            type="text"
            value={editLabel}
            onChange={e => setEditLabel(e.target.value)}
          />
        </div>

        <div className="form-group">
          <label>Type</label>
          <span className="type-badge">{node.node_type}</span>
        </div>

        <div className="form-group">
          <label>Command Template</label>
          <input
            type="text"
            value={editTemplate}
            onChange={e => setEditTemplate(e.target.value)}
            placeholder="e.g., interface {interface_name}"
          />
          <span className="hint">Use {'{'}var_name{'}'} for variables</span>
        </div>

        <div className="form-group">
          <label>Help Text</label>
          <textarea
            value={editHelpText}
            onChange={e => setEditHelpText(e.target.value)}
            placeholder="Describe what this node configures..."
            rows={2}
          />
        </div>

        <div className="form-group checkbox-group">
          <label>
            <input
              type="checkbox"
              checked={editRequired}
              onChange={e => setEditRequired(e.target.checked)}
            />
            Required
          </label>
          <label>
            <input
              type="checkbox"
              checked={editRepeatable}
              onChange={e => setEditRepeatable(e.target.checked)}
            />
            Repeatable
          </label>
        </div>

        <button className="save-button" onClick={handleSave}>
          Save Changes
        </button>
      </div>

      {/* Variables section */}
      {templateVars.length > 0 && (
        <div className="editor-section">
          <h4>Variable Values</h4>
          <p className="hint">Fill in values for config generation</p>

          {templateVars.map(varName => {
            const nodeVar = node.variables?.find(v => v.var_name === varName);
            return (
              <div key={varName} className="form-group">
                <label>
                  {varName}
                  {nodeVar?.is_required && <span className="required-marker">*</span>}
                </label>
                {nodeVar?.var_type === 'choice' && nodeVar.choices ? (
                  <select
                    value={variableValues[varName] || ''}
                    onChange={e => onVariableChange(varName, e.target.value)}
                  >
                    <option value="">Select...</option>
                    {nodeVar.choices.map(choice => (
                      <option key={choice} value={choice}>{choice}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={nodeVar?.var_type === 'integer' ? 'number' : 'text'}
                    value={variableValues[varName] || ''}
                    onChange={e => onVariableChange(varName, e.target.value)}
                    placeholder={nodeVar?.default_value || `Enter ${varName}`}
                    min={nodeVar?.min_value}
                    max={nodeVar?.max_value}
                  />
                )}
                {nodeVar?.help_text && (
                  <span className="var-hint">{nodeVar.help_text}</span>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Node variables (defined in DB) */}
      {node.variables && node.variables.length > 0 && (
        <div className="editor-section">
          <h4>Defined Variables</h4>
          <ul className="variables-list">
            {node.variables.map(v => (
              <li key={v.id}>
                <strong>{v.var_name}</strong>
                <span className="var-type">{v.var_type}</span>
                {v.is_required && <span className="badge">Required</span>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Delete button */}
      <div className="editor-section danger">
        <button className="delete-button" onClick={() => onDelete(node.id)}>
          Delete Node
        </button>
      </div>
    </div>
  );
};

export default NodeEditor;
