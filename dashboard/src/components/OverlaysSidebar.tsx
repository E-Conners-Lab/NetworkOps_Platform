import React, { useState } from 'react';
import './OverlaysSidebar.css';

interface OverlaysSidebarProps {
  isOpen: boolean;
  onClose: () => void;
  // Graph Overlays
  showBgpOverlay: boolean;
  toggleBgpOverlay: () => void;
  bgpLoading: boolean;
  // OSPF
  showOspfOverlay: boolean;
  toggleOspfOverlay: () => void;
  showOspfAreaOverlay: boolean;
  toggleOspfAreaOverlay: () => void;
  ospfLoading: boolean;
  // Ping
  pingResults: any[] | null;
  pingLoading: boolean;
  selectedNode: any | null;
  runPingSweep: () => void;
  clearPingResults: () => void;
  // Fabric Status
  showDmvpnOverlay: boolean;
  toggleDmvpnOverlay: () => void;
  dmvpnLoading: boolean;
  showSwitchOverlay: boolean;
  toggleSwitchOverlay: () => void;
  switchLoading: boolean;
  // Panels
  showEventsPanel: boolean;
  toggleEventsPanel: () => void;
  eventsLoading: boolean;
  showTelemetryPanel: boolean;
  toggleTelemetryPanel: () => void;
  showChatPanel: boolean;
  toggleChatPanel: () => void;
  // Tools
  onOpenMTUCalculator: () => void;
  onOpenSubnetCalculator: () => void;
  onOpenImpactAnalysis: () => void;
  onOpenImpactTrending: () => void;
  onOpenIntentDrift: () => void;
}

/**
 * Sidebar with categorized overlay controls.
 * Replaces the old sidebar overlay buttons with an organized panel.
 */
const OverlaysSidebar: React.FC<OverlaysSidebarProps> = ({
  isOpen,
  onClose,
  showBgpOverlay,
  toggleBgpOverlay,
  bgpLoading,
  showOspfOverlay,
  toggleOspfOverlay,
  showOspfAreaOverlay,
  toggleOspfAreaOverlay,
  ospfLoading,
  pingResults,
  pingLoading,
  selectedNode,
  runPingSweep,
  clearPingResults,
  showDmvpnOverlay,
  toggleDmvpnOverlay,
  dmvpnLoading,
  showSwitchOverlay,
  toggleSwitchOverlay,
  switchLoading,
  showEventsPanel,
  toggleEventsPanel,
  eventsLoading,
  showTelemetryPanel,
  toggleTelemetryPanel,
  showChatPanel,
  toggleChatPanel,
  onOpenMTUCalculator,
  onOpenSubnetCalculator,
  onOpenImpactAnalysis,
  onOpenImpactTrending,
  onOpenIntentDrift,
}) => {
  // Track which categories are expanded
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(['graph', 'fabric', 'panels']) // All expanded by default
  );

  // Track minimized state
  const [isMinimized, setIsMinimized] = useState(false);

  const toggleCategory = (category: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
  };

  if (!isOpen) return null;

  // Minimized view - slim icon bar
  if (isMinimized) {
    return (
      <div className="overlays-sidebar minimized">
        <button
          className="sidebar-expand"
          onClick={() => setIsMinimized(false)}
          title="Expand sidebar"
        >
          ▶
        </button>
        <div className="minimized-icons">
          <button
            className={`mini-icon ${showBgpOverlay ? 'active' : ''}`}
            onClick={toggleBgpOverlay}
            title="BGP Sessions"
          >
            🔗
          </button>
          <button
            className={`mini-icon ${showOspfOverlay ? 'active' : ''}`}
            onClick={toggleOspfOverlay}
            title="OSPF"
          >
            🔀
          </button>
          <button
            className={`mini-icon ${showDmvpnOverlay ? 'active' : ''}`}
            onClick={toggleDmvpnOverlay}
            title="DMVPN"
          >
            🌐
          </button>
          <button
            className={`mini-icon ${showSwitchOverlay ? 'active' : ''}`}
            onClick={toggleSwitchOverlay}
            title="Switches"
          >
            🔌
          </button>
          <button
            className={`mini-icon ${showEventsPanel ? 'active' : ''}`}
            onClick={toggleEventsPanel}
            title="Events Log"
          >
            📋
          </button>
          <button
            className={`mini-icon ${showTelemetryPanel ? 'active' : ''}`}
            onClick={toggleTelemetryPanel}
            title="MDT Telemetry"
          >
            📈
          </button>
          <button
            className={`mini-icon ${showChatPanel ? 'active' : ''}`}
            onClick={toggleChatPanel}
            title="AI Chat"
          >
            💬
          </button>
          <button
            className="mini-icon"
            onClick={onOpenMTUCalculator}
            title="MTU Calculator"
          >
            📐
          </button>
          <button
            className="mini-icon"
            onClick={onOpenSubnetCalculator}
            title="Subnet Calculator"
          >
            🔢
          </button>
          <button
            className="mini-icon"
            onClick={onOpenImpactAnalysis}
            title="Impact Analysis"
          >
            ⚡
          </button>
          <button
            className="mini-icon"
            onClick={onOpenImpactTrending}
            title="Impact Trending"
          >
            📈
          </button>
          <button
            className="mini-icon"
            onClick={onOpenIntentDrift}
            title="Intent Drift Engine"
          >
            🎯
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="overlays-sidebar">
      <div className="overlays-sidebar-header">
        <h3>Overlays</h3>
        <div className="header-buttons">
          <button
            className="sidebar-minimize"
            onClick={() => setIsMinimized(true)}
            title="Minimize sidebar"
          >
            ◀
          </button>
          <button className="sidebar-close" onClick={onClose}>
            &times;
          </button>
        </div>
      </div>

      <div className="overlays-sidebar-content">
        {/* Graph Overlays Category */}
        <div className="overlay-category">
          <button
            className="overlay-category-header"
            onClick={() => toggleCategory('graph')}
          >
            <span className="category-toggle">
              {expandedCategories.has('graph') ? '▼' : '▶'}
            </span>
            <span className="category-name">Graph Overlays</span>
          </button>

          {expandedCategories.has('graph') && (
            <div className="overlay-category-items">
              <button
                className={`overlay-item ${showBgpOverlay ? 'active' : ''} ${bgpLoading ? 'loading' : ''}`}
                onClick={toggleBgpOverlay}
                disabled={bgpLoading}
              >
                <span className="overlay-icon">🔗</span>
                <span className="overlay-name">BGP Sessions</span>
                {showBgpOverlay && <span className="overlay-status active">ON</span>}
              </button>

              <button
                className={`overlay-item ${pingResults ? 'active' : ''} ${pingLoading ? 'loading' : ''}`}
                onClick={pingResults ? clearPingResults : runPingSweep}
                disabled={pingLoading || (!selectedNode && !pingResults)}
                title={!selectedNode && !pingResults ? 'Select a device first' : ''}
              >
                <span className="overlay-icon">📡</span>
                <span className="overlay-name">{pingResults ? 'Clear Ping' : 'Ping Sweep'}</span>
                {pingResults && <span className="overlay-status active">ON</span>}
              </button>

              {/* OSPF sub-group */}
              <div className="overlay-subgroup">
                <span className="subgroup-label">OSPF</span>
                <button
                  className={`overlay-item ospf ${showOspfOverlay ? 'active' : ''} ${ospfLoading ? 'loading' : ''}`}
                  onClick={toggleOspfOverlay}
                  disabled={ospfLoading}
                >
                  <span className="overlay-icon">🔀</span>
                  <span className="overlay-name">Adjacencies</span>
                  {showOspfOverlay && <span className="overlay-status active">ON</span>}
                </button>
                <button
                  className={`overlay-item ospf ${showOspfAreaOverlay ? 'active' : ''} ${ospfLoading ? 'loading' : ''}`}
                  onClick={toggleOspfAreaOverlay}
                  disabled={ospfLoading}
                >
                  <span className="overlay-icon">🗺️</span>
                  <span className="overlay-name">Areas</span>
                  {showOspfAreaOverlay && <span className="overlay-status active">ON</span>}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Fabric Status Category */}
        <div className="overlay-category">
          <button
            className="overlay-category-header"
            onClick={() => toggleCategory('fabric')}
          >
            <span className="category-toggle">
              {expandedCategories.has('fabric') ? '▼' : '▶'}
            </span>
            <span className="category-name">Fabric Status</span>
          </button>

          {expandedCategories.has('fabric') && (
            <div className="overlay-category-items">
              <button
                className={`overlay-item dmvpn ${showDmvpnOverlay ? 'active' : ''} ${dmvpnLoading ? 'loading' : ''}`}
                onClick={toggleDmvpnOverlay}
                disabled={dmvpnLoading}
              >
                <span className="overlay-icon">🌐</span>
                <span className="overlay-name">DMVPN</span>
                {showDmvpnOverlay && <span className="overlay-status active">ON</span>}
              </button>

              <button
                className={`overlay-item switches ${showSwitchOverlay ? 'active' : ''} ${switchLoading ? 'loading' : ''}`}
                onClick={toggleSwitchOverlay}
                disabled={switchLoading}
              >
                <span className="overlay-icon">🔌</span>
                <span className="overlay-name">Switches</span>
                {showSwitchOverlay && <span className="overlay-status active">ON</span>}
              </button>
            </div>
          )}
        </div>

        {/* Panels Category */}
        <div className="overlay-category">
          <button
            className="overlay-category-header"
            onClick={() => toggleCategory('panels')}
          >
            <span className="category-toggle">
              {expandedCategories.has('panels') ? '▼' : '▶'}
            </span>
            <span className="category-name">Data Panels</span>
          </button>

          {expandedCategories.has('panels') && (
            <div className="overlay-category-items">
              <button
                className={`overlay-item ${showEventsPanel ? 'active' : ''} ${eventsLoading ? 'loading' : ''}`}
                onClick={toggleEventsPanel}
              >
                <span className="overlay-icon">📋</span>
                <span className="overlay-name">Events Log</span>
                {showEventsPanel && <span className="overlay-status active">ON</span>}
              </button>

              <button
                className={`overlay-item telemetry ${showTelemetryPanel ? 'active' : ''}`}
                onClick={toggleTelemetryPanel}
              >
                <span className="overlay-icon">📈</span>
                <span className="overlay-name">MDT Telemetry</span>
                {showTelemetryPanel && <span className="overlay-status active">ON</span>}
              </button>

              <button
                className={`overlay-item chat ${showChatPanel ? 'active' : ''}`}
                onClick={toggleChatPanel}
              >
                <span className="overlay-icon">💬</span>
                <span className="overlay-name">AI Chat</span>
                {showChatPanel && <span className="overlay-status active">ON</span>}
              </button>
            </div>
          )}
        </div>

        {/* Tools Category */}
        <div className="overlay-category">
          <button
            className="overlay-category-header"
            onClick={() => toggleCategory('tools')}
          >
            <span className="category-toggle">
              {expandedCategories.has('tools') ? '▼' : '▶'}
            </span>
            <span className="category-name">Tools</span>
          </button>

          {expandedCategories.has('tools') && (
            <div className="overlay-category-items">
              <button
                className="overlay-item tool"
                onClick={onOpenMTUCalculator}
              >
                <span className="overlay-icon">📐</span>
                <span className="overlay-name">MTU Calculator</span>
              </button>
              <button
                className="overlay-item tool"
                onClick={onOpenSubnetCalculator}
              >
                <span className="overlay-icon">🔢</span>
                <span className="overlay-name">Subnet Calculator</span>
              </button>
              <button
                className="overlay-item tool impact"
                onClick={onOpenImpactAnalysis}
              >
                <span className="overlay-icon">⚡</span>
                <span className="overlay-name">Impact Analysis</span>
              </button>
              <button
                className="overlay-item tool trending"
                onClick={onOpenImpactTrending}
              >
                <span className="overlay-icon">📈</span>
                <span className="overlay-name">Impact Trending</span>
              </button>
              <button
                className="overlay-item tool intent"
                onClick={onOpenIntentDrift}
              >
                <span className="overlay-icon">🎯</span>
                <span className="overlay-name">Intent Drift Engine</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default OverlaysSidebar;
