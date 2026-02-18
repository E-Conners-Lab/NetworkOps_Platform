/**
 * Config Preview Component
 *
 * Displays generated IOS configuration with errors and warnings.
 */

import React, { useState } from 'react';
import { GenerationResult } from '../types';

interface ConfigPreviewProps {
  result: GenerationResult | null;
  treeName: string;
  onRegenerate: () => void;
}

const ConfigPreview: React.FC<ConfigPreviewProps> = ({
  result,
  treeName,
  onRegenerate,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (result?.config) {
      await navigator.clipboard.writeText(result.config);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (!result) {
    return (
      <div className="config-preview empty">
        <p>No config generated yet.</p>
        <button onClick={onRegenerate}>Generate Config</button>
      </div>
    );
  }

  return (
    <div className="config-preview">
      <div className="preview-header">
        <h3>Generated Config: {treeName}</h3>
        <div className="preview-actions">
          <button onClick={onRegenerate}>Regenerate</button>
          <button onClick={handleCopy}>
            {copied ? 'Copied!' : 'Copy to Clipboard'}
          </button>
        </div>
      </div>

      {/* Errors */}
      {result.errors.length > 0 && (
        <div className="preview-errors">
          <h4>Errors ({result.errors.length})</h4>
          <ul>
            {result.errors.map((err, i) => (
              <li key={i} className="error">{err}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Warnings */}
      {result.warnings.length > 0 && (
        <div className="preview-warnings">
          <h4>Warnings ({result.warnings.length})</h4>
          <ul>
            {result.warnings.map((warn, i) => (
              <li key={i} className="warning">{warn}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Config output */}
      <div className="preview-config">
        <h4>Configuration</h4>
        <pre className="config-output">
          <code>{result.config || '(No output)'}</code>
        </pre>
      </div>

      {/* Line count */}
      <div className="preview-stats">
        <span>{result.config.split('\n').length} lines</span>
        <span>{result.config.length} characters</span>
      </div>
    </div>
  );
};

export default ConfigPreview;
