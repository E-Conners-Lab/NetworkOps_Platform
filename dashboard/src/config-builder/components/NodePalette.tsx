/**
 * Node Palette Component
 *
 * Displays draggable node templates for sections and commands.
 */

import React, { useState } from 'react';
import { useDraggable } from '@dnd-kit/core';
import { NodeTemplate } from '../types';

interface NodePaletteProps {
  sectionTemplates: NodeTemplate[];
  commandTemplates: NodeTemplate[];
}

const NodePalette: React.FC<NodePaletteProps> = ({
  sectionTemplates,
  commandTemplates,
}) => {
  const [expandedSections, setExpandedSections] = useState(true);
  const [expandedCommands, setExpandedCommands] = useState(true);

  return (
    <div className="node-palette">
      <h4>Node Templates</h4>
      <p className="hint">Drag nodes to the canvas</p>

      {/* Sections */}
      <div className="palette-category">
        <div
          className="category-header"
          onClick={() => setExpandedSections(!expandedSections)}
        >
          <span>{expandedSections ? '▼' : '▶'}</span>
          <span>Sections ({sectionTemplates.length})</span>
        </div>
        {expandedSections && (
          <div className="palette-items">
            {sectionTemplates.map(template => (
              <DraggableTemplate key={template.id} template={template} />
            ))}
          </div>
        )}
      </div>

      {/* Commands */}
      <div className="palette-category">
        <div
          className="category-header"
          onClick={() => setExpandedCommands(!expandedCommands)}
        >
          <span>{expandedCommands ? '▼' : '▶'}</span>
          <span>Commands ({commandTemplates.length})</span>
        </div>
        {expandedCommands && (
          <div className="palette-items">
            {commandTemplates.map(template => (
              <DraggableTemplate key={template.id} template={template} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

interface DraggableTemplateProps {
  template: NodeTemplate;
}

const DraggableTemplate: React.FC<DraggableTemplateProps> = ({ template }) => {
  const { attributes, listeners, setNodeRef, isDragging } = useDraggable({
    id: `template-${template.id}`,
    data: {
      type: 'template',
      template,
    },
  });

  const getIcon = () => {
    if (template.node_type === 'section') return '📁';
    return '⚙️';
  };

  return (
    <div
      ref={setNodeRef}
      {...attributes}
      {...listeners}
      className={`palette-item ${template.node_type} ${isDragging ? 'dragging' : ''}`}
      title={template.help_text || template.command_template}
    >
      <span className="item-icon">{getIcon()}</span>
      <span className="item-label">{template.label}</span>
      {template.variables && template.variables.length > 0 && (
        <span className="item-vars">({template.variables.length} vars)</span>
      )}
    </div>
  );
};

export default NodePalette;
