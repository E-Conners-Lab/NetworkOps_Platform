import React, { useState } from 'react';

interface HierarchyLevel {
  type: 'all' | 'region' | 'site' | 'rack' | 'device';
  id: string | null;
  name: string;
}

interface HierarchyRack {
  id: string;
  name: string;
  device_count: number;
}

interface HierarchySite {
  id: string;
  name: string;
  racks: HierarchyRack[];
}

interface HierarchyRegion {
  id: string;
  name: string;
  sites: HierarchySite[];
}

interface HierarchyTree {
  regions: HierarchyRegion[];
}

interface HierarchySidebarProps {
  isOpen: boolean;
  onClose: () => void;
  hierarchyTree: HierarchyTree | null;
  currentLevel: HierarchyLevel;
  onNavigate: (level: HierarchyLevel) => void;
}

/**
 * Sidebar with collapsible tree view for hierarchical navigation.
 * Shows: Regions > Sites > Racks with device counts.
 */
const HierarchySidebar: React.FC<HierarchySidebarProps> = ({
  isOpen,
  onClose,
  hierarchyTree,
  currentLevel,
  onNavigate,
}) => {
  // Track which regions and sites are expanded
  const [expandedRegions, setExpandedRegions] = useState<Set<string>>(new Set());
  const [expandedSites, setExpandedSites] = useState<Set<string>>(new Set());

  const toggleRegion = (regionId: string) => {
    setExpandedRegions(prev => {
      const next = new Set(prev);
      if (next.has(regionId)) {
        next.delete(regionId);
      } else {
        next.add(regionId);
      }
      return next;
    });
  };

  const toggleSite = (siteId: string) => {
    setExpandedSites(prev => {
      const next = new Set(prev);
      if (next.has(siteId)) {
        next.delete(siteId);
      } else {
        next.add(siteId);
      }
      return next;
    });
  };

  const isSelected = (type: HierarchyLevel['type'], id: string | null): boolean => {
    return currentLevel.type === type && currentLevel.id === id;
  };

  // Count total devices in a region
  const countRegionDevices = (region: HierarchyRegion): number => {
    return region.sites.reduce((total, site) =>
      total + site.racks.reduce((siteTotal, rack) => siteTotal + rack.device_count, 0), 0
    );
  };

  // Count total devices in a site
  const countSiteDevices = (site: HierarchySite): number => {
    return site.racks.reduce((total, rack) => total + rack.device_count, 0);
  };

  if (!isOpen) return null;

  return (
    <div className="hierarchy-sidebar">
      <div className="hierarchy-sidebar-header">
        <h3>Site Hierarchy</h3>
        <button className="sidebar-close" onClick={onClose}>
          &times;
        </button>
      </div>

      <div className="hierarchy-sidebar-content">
        {/* All Regions button */}
        <button
          className={`hierarchy-item level-all ${isSelected('all', null) ? 'selected' : ''}`}
          onClick={() => onNavigate({ type: 'all', id: null, name: 'All Regions' })}
        >
          <span className="hierarchy-icon">&#x1F30D;</span>
          <span className="hierarchy-name">All Regions</span>
        </button>

        {/* Regions */}
        {hierarchyTree?.regions.map(region => (
          <div key={region.id} className="hierarchy-region">
            <div className="hierarchy-region-header">
              <button
                className="hierarchy-toggle"
                onClick={() => toggleRegion(region.id)}
              >
                {expandedRegions.has(region.id) ? '▼' : '▶'}
              </button>
              <button
                className={`hierarchy-item level-region ${isSelected('region', region.id) ? 'selected' : ''}`}
                onClick={() => onNavigate({ type: 'region', id: region.id, name: region.name })}
              >
                <span className="hierarchy-name">{region.name}</span>
                <span className="hierarchy-count">{countRegionDevices(region)}</span>
              </button>
            </div>

            {/* Sites within region */}
            {expandedRegions.has(region.id) && (
              <div className="hierarchy-children">
                {region.sites.map(site => (
                  <div key={site.id} className="hierarchy-site">
                    <div className="hierarchy-site-header">
                      <button
                        className="hierarchy-toggle"
                        onClick={() => toggleSite(site.id)}
                      >
                        {expandedSites.has(site.id) ? '▼' : '▶'}
                      </button>
                      <button
                        className={`hierarchy-item level-site ${isSelected('site', site.id) ? 'selected' : ''}`}
                        onClick={() => onNavigate({ type: 'site', id: site.id, name: site.name })}
                      >
                        <span className="hierarchy-name">{site.name}</span>
                        <span className="hierarchy-count">{countSiteDevices(site)}</span>
                      </button>
                    </div>

                    {/* Racks within site */}
                    {expandedSites.has(site.id) && (
                      <div className="hierarchy-children">
                        {site.racks.map(rack => (
                          <button
                            key={rack.id}
                            className={`hierarchy-item level-rack ${isSelected('rack', rack.id) ? 'selected' : ''}`}
                            onClick={() => onNavigate({ type: 'rack', id: rack.id, name: rack.name })}
                          >
                            <span className="hierarchy-icon">&#x1F4E6;</span>
                            <span className="hierarchy-name">{rack.name}</span>
                            <span className="hierarchy-count">{rack.device_count}</span>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default HierarchySidebar;
