/**
 * TypeScript interfaces for Config Builder
 */

export interface ConfigNodeVariable {
  id: string;
  node_id: string;
  var_name: string;
  var_type: 'string' | 'ip_address' | 'subnet_mask' | 'integer' | 'choice';
  choices?: string[];
  validation_regex?: string;
  min_value?: number;
  max_value?: number;
  is_required: boolean;
  default_value?: string;
  help_text?: string;
}

export interface ConfigTreeNode {
  id: string;
  tree_id: string;
  parent_id: string | null;
  node_type: 'section' | 'command' | 'variable';
  label: string;
  command_template?: string;
  sort_order: number;
  is_required: boolean;
  is_repeatable: boolean;
  validation_regex?: string;
  default_value?: string;
  help_text?: string;
  created_at?: string;
  children: ConfigTreeNode[];
  variables: ConfigNodeVariable[];
}

export interface ConfigTree {
  id: string;
  name: string;
  description?: string;
  platform: string;
  version: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  root_nodes: ConfigTreeNode[];
}

export interface NodeTemplate {
  id: string;
  label: string;
  node_type: 'section' | 'command';
  command_template?: string;
  help_text?: string;
  parent_section?: string;
  variables?: {
    var_name: string;
    var_type: string;
    is_required?: boolean;
    min_value?: number;
    max_value?: number;
    choices?: string[];
    default_value?: string;
  }[];
}

export interface GenerationResult {
  config: string;
  errors: string[];
  warnings: string[];
}
