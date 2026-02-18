import React from 'react';

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

interface HierarchyBreadcrumbProps {
  currentLevel: HierarchyLevel;
  hierarchyTree: HierarchyTree | null;
  onNavigate: (level: HierarchyLevel) => void;
}

/**
 * Breadcrumb navigation for hierarchical topology view.
 * Shows the current path: All Regions > US West > EVE-NG Lab > Core Rack
 */
const HierarchyBreadcrumb: React.FC<HierarchyBreadcrumbProps> = ({
  currentLevel,
  hierarchyTree,
  onNavigate,
}) => {
  // Build breadcrumb path based on current level
  const buildBreadcrumbs = (): HierarchyLevel[] => {
    const crumbs: HierarchyLevel[] = [
      { type: 'all', id: null, name: 'All Regions' }
    ];

    if (currentLevel.type === 'all' || !hierarchyTree) {
      return crumbs;
    }

    // Find region, site, rack based on current level
    if (currentLevel.type === 'region') {
      const region = hierarchyTree.regions.find(r => r.id === currentLevel.id);
      if (region) {
        crumbs.push({ type: 'region', id: region.id, name: region.name });
      }
    } else if (currentLevel.type === 'site') {
      // Find which region this site belongs to
      for (const region of hierarchyTree.regions) {
        const site = region.sites.find(s => s.id === currentLevel.id);
        if (site) {
          crumbs.push({ type: 'region', id: region.id, name: region.name });
          crumbs.push({ type: 'site', id: site.id, name: site.name });
          break;
        }
      }
    } else if (currentLevel.type === 'rack') {
      // Find the full path to this rack
      for (const region of hierarchyTree.regions) {
        for (const site of region.sites) {
          const rack = site.racks.find(r => r.id === currentLevel.id);
          if (rack) {
            crumbs.push({ type: 'region', id: region.id, name: region.name });
            crumbs.push({ type: 'site', id: site.id, name: site.name });
            crumbs.push({ type: 'rack', id: rack.id, name: rack.name });
            break;
          }
        }
      }
    }

    return crumbs;
  };

  const breadcrumbs = buildBreadcrumbs();

  return (
    <div className="hierarchy-breadcrumb">
      {breadcrumbs.map((crumb, index) => {
        const isLast = index === breadcrumbs.length - 1;
        const isClickable = !isLast;

        return (
          <React.Fragment key={`${crumb.type}-${crumb.id}`}>
            {index > 0 && <span className="breadcrumb-separator">&gt;</span>}
            <button
              className={`breadcrumb-item ${isLast ? 'current' : ''}`}
              onClick={() => isClickable && onNavigate(crumb)}
              disabled={isLast}
            >
              {crumb.name}
            </button>
          </React.Fragment>
        );
      })}
    </div>
  );
};

export default HierarchyBreadcrumb;
