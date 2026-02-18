import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { io, Socket } from 'socket.io-client';
import './App.css';
import { API, WS_URL } from './config';
import { authPost, authGet, authFetch, getToken } from './utils/api';
import { useAuth } from './context/AuthContext';
import UserManagement from './components/UserManagement';
import AddDeviceModal from './components/AddDeviceModal';
import ChangeManagement from './components/ChangeManagement';
import MTUCalculator from './components/MTUCalculator';
import SubnetCalculator from './components/SubnetCalculator';
import ImpactAnalysis from './components/ImpactAnalysis';
import ImpactTrending from './components/ImpactTrending';
import IntentDriftEngine from './components/IntentDriftEngine';
import HierarchyBreadcrumb from './components/HierarchyBreadcrumb';
import HierarchySidebar from './components/HierarchySidebar';
import OverlaysSidebar from './components/OverlaysSidebar';

interface Node {
  id: string;
  ip: string;
  platform?: string;
  status: string;
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
  [key: string]: any;
}

interface Link {
  source: string | Node;
  target: string | Node;
  source_intf: string;
  target_intf: string;
  [key: string]: any;
}

interface TopologyData {
  nodes: Node[];
  links: Link[];
  bgp_links?: Link[];  // Separate - only shown when BGP overlay active
}

interface BgpNeighbor {
  neighbor: string;
  remote_as: string;
  state: string;
  prefixes: number;
  peer_type: string;
  neighbor_name?: string;
}

interface PingResult {
  target: string;
  target_ip: string;
  success_rate: string;
  avg_latency: number;
  status: string;
}

interface DmvpnPeer {
  name: string;
  nbma_addr: string;
  tunnel_addr: string;
  state: string;
  uptime: string;
  type: string;
}

interface EigrpNeighbor {
  interface: string;
  neighbor_ip: string;
  uptime: string;
  state: string;
}

interface SwitchInfo {
  name: string;
  ip: string;
  loopback: string;
  upstream_router: string;
  uplink_interface: string;
  uplink_ip?: string;
  status: string;
  eigrp_neighbor: EigrpNeighbor | null;
  uplink_status: string;
  error?: string;
}

interface SwitchData {
  switches: SwitchInfo[];
  total: number;
  healthy: number;
}

interface EventLogEntry {
  timestamp: string;
  action: string;
  device: string;
  details: string;
  status: string;
  role: string;
}

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  sources?: Array<{ file: string; path: string; page: number | null; score: number }>;
  timestamp: Date;
}

interface LinuxHealth {
  status: string;
  uptime: string | null;
  memory: { total: number; used: number; free: number; percent: number };
  disk: { total: string; used: string; available: string; percent: number };
  network: { gateway_reachable: boolean };
  error?: string;
}

interface ContainerlabHealth {
  status: string;
  container_status: string;
  uptime: string | null;
  memory: { used: string; limit: string; percent: string };
  platform: string;
  error?: string;
}

interface DmvpnData {
  hub: string;
  tunnel: string;
  tunnel_ip: string;
  peer_count: number;
  peers_up: number;
  peers: DmvpnPeer[];
}

interface DeviceInterface {
  name: string;
  ip: string | null;
  admin_status: string;
  line_protocol: string;
  acl_in?: string;
}

interface TelemetryData {
  interfaces: Record<string, Record<string, any>>;
  cpu: Record<string, { five_seconds: number; timestamp: string }>;
  memory: Record<string, { used: number; free: number; total: number; percent_used: number; timestamp: string }>;
  last_update: Record<string, string>;
}

// Hierarchy types for enterprise-scale topology view
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

const NODE_SIZE = 12;

// Default layout positions based on actual network topology
// Centered around (0,0) for the force graph coordinate system
// Compact layout to minimize panning needed
const DEFAULT_LAYOUT: Record<string, { x: number; y: number }> = {
  // Core routers - diamond pattern (compact)
  'R1': { x: 0, y: -80 },       // Top (hub)
  'R2': { x: -100, y: 0 },      // Left
  'R3': { x: 100, y: 0 },       // Right
  'R4': { x: 0, y: 80 },        // Bottom

  // Switches - near their upstream routers
  'Switch-R1': { x: 0, y: -160 },
  'Switch-R2': { x: -180, y: 0 },
  'Switch-R4': { x: 0, y: 160 },

  // Linux hosts
  'Alpine-1': { x: 180, y: 0 },      // Near R3
  'Docker-1': { x: -80, y: -160 },   // Near Switch-R1

  // Containerlab devices - grouped together, closer to main topology
  'edge1': { x: 260, y: -40 },   // BGP peer to R3
  'spine1': { x: 320, y: -40 },
  'R9': { x: 380, y: -40 },      // Connected to spine1
  'R10': { x: 440, y: -40 },     // eBGP peer to R9
  'server1': { x: 320, y: -100 },
  'server2': { x: 320, y: 20 },
};

const LAYOUT_STORAGE_KEY = 'networkDashboardLayout';

// Load saved layout from localStorage
const loadSavedLayout = (): Map<string, { x: number; y: number; fx: number; fy: number }> => {
  try {
    const saved = localStorage.getItem(LAYOUT_STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      return new Map(Object.entries(parsed));
    }
  } catch (e) {
    console.warn('Failed to load saved layout:', e);
  }
  return new Map();
};

// Save layout to localStorage
const saveLayout = (positions: Map<string, { x: number; y: number; fx: number; fy: number }>) => {
  try {
    const obj: Record<string, any> = {};
    positions.forEach((value, key) => {
      obj[key] = value;
    });
    localStorage.setItem(LAYOUT_STORAGE_KEY, JSON.stringify(obj));
  } catch (e) {
    console.warn('Failed to save layout:', e);
  }
};

// Get initial position for a node (saved > default > undefined)
const getInitialPosition = (
  nodeId: string,
  savedPositions: Map<string, { x: number; y: number; fx: number; fy: number }>
): { x?: number; y?: number; fx?: number; fy?: number } | undefined => {
  // First check saved positions
  const saved = savedPositions.get(nodeId);
  if (saved) {
    return saved;
  }
  // Fall back to default layout
  const defaultPos = DEFAULT_LAYOUT[nodeId];
  if (defaultPos) {
    return { x: defaultPos.x, y: defaultPos.y, fx: defaultPos.x, fy: defaultPos.y };
  }
  return undefined;
};

type UserRole = 'admin' | 'operator';

// Vendor-specific command lists
const CISCO_COMMANDS = [
  'show version',
  'show ip interface brief',
  'show ip ospf neighbor',
  'show ip route',
  'show cdp neighbors',
  'show running-config',
  'show interfaces status',
  'show vlan brief',
  'show ip bgp summary',
  'show dmvpn',
];

const FRR_COMMANDS = [
  'show version',
  'show ip route',
  'show ip ospf neighbor',
  'show ip bgp summary',
  'show ip bgp',
  'show running-config',
  'show interface brief',
  'show ip ospf',
  'show ip ospf database',
];

const NOKIA_COMMANDS = [
  'show version',
  'show interface brief',
  'show network-instance default route-table',
  'show network-instance default protocols bgp neighbor',
  'show network-instance default protocols ospf neighbor',
  'info system',
  'show platform chassis',
  'info running',
];

const LINUX_COMMANDS = [
  'ip addr',
  'ip route',
  'cat /etc/os-release',
  'uptime',
  'free -h',
  'df -h',
  'ping -c 3 192.0.2.1',
];

// Claude model options for RAG chatbot
const CLAUDE_MODELS = [
  { id: 'claude-3-5-haiku-20241022', name: 'Haiku', desc: 'Fast & cheap' },
  { id: 'claude-sonnet-4-20250514', name: 'Sonnet', desc: 'Balanced' },
  { id: 'claude-opus-4-20250514', name: 'Opus', desc: 'Most capable' },
];

// Map device names to their vendor type
const getDeviceVendor = (deviceName: string): 'cisco' | 'frr' | 'nokia' | 'linux' => {
  if (['edge1', 'R9', 'R10'].includes(deviceName)) return 'frr';
  if (deviceName === 'spine1') return 'nokia';
  if (['server1', 'server2', 'Alpine-1', 'Docker-1'].includes(deviceName)) return 'linux';
  return 'cisco'; // R1-R4, Switch-R1, Switch-R2, Switch-R4
};

const getCommandsForDevice = (deviceName: string): string[] => {
  const vendor = getDeviceVendor(deviceName);
  switch (vendor) {
    case 'frr': return FRR_COMMANDS;
    case 'nokia': return NOKIA_COMMANDS;
    case 'linux': return LINUX_COMMANDS;
    default: return CISCO_COMMANDS;
  }
};

function App() {
  // Auth context for permission-based access control
  const { user, hasPermission } = useAuth();

  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: window.innerWidth - 320, height: window.innerHeight - 265 });
  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const nodePositions = useRef<Map<string, { x: number; y: number; fx: number; fy: number }>>(loadSavedLayout());

  // Command panel state
  const [userRole, setUserRole] = useState<UserRole>(() => {
    const saved = localStorage.getItem('networkDashboardRole');
    // Only allow valid roles, default to operator
    if (saved === 'admin' || saved === 'operator') return saved;
    return 'operator';
  });
  const [commandDevice, setCommandDevice] = useState<string>('');
  const [commandText, setCommandText] = useState<string>('');
  const [commandOutput, setCommandOutput] = useState<string>('');
  const [commandError, setCommandError] = useState<boolean>(false);
  const [isExecuting, setIsExecuting] = useState(false);
  const [bottomPanelOpen, setBottomPanelOpen] = useState(false);
  const [deviceList, setDeviceList] = useState<string[]>([]);

  // Overlay state
  const [showBgpOverlay, setShowBgpOverlay] = useState(false);
  const [bgpData, setBgpData] = useState<Record<string, BgpNeighbor[]>>({});
  const [bgpLoading, setBgpLoading] = useState(false);
  const [pingResults, setPingResults] = useState<PingResult[] | null>(null);
  const [pingLoading, setPingLoading] = useState(false);
  const [pingSource, setPingSource] = useState<string | null>(null);
  const [, setPingDetailsExpanded] = useState(false);
  // OSPF overlay state
  const [showOspfOverlay, setShowOspfOverlay] = useState(false);
  const [showOspfAreaOverlay, setShowOspfAreaOverlay] = useState(false);
  const [ospfLoading, setOspfLoading] = useState(false);
  const [ospfData, setOspfData] = useState<{
    devices: Record<string, { neighbors: any[], interfaces: any[] }>;
    areas: Record<number, string[]>;
    link_costs: Record<string, number>;
    router_id_map: Record<string, string>;
  } | null>(null);

  // DMVPN state
  const [showDmvpnOverlay, setShowDmvpnOverlay] = useState(false);
  const [showDmvpnPanel, setShowDmvpnPanel] = useState(false);
  const [dmvpnData, setDmvpnData] = useState<DmvpnData | null>(null);
  const [dmvpnLoading, setDmvpnLoading] = useState(false);

  // Switch fabric state
  const [showSwitchOverlay, setShowSwitchOverlay] = useState(false);
  const [showSwitchPanel, setShowSwitchPanel] = useState(false);
  const [switchData, setSwitchData] = useState<SwitchData | null>(null);
  const [switchLoading, setSwitchLoading] = useState(false);

  // Interface and remediation state
  const [deviceInterfaces, setDeviceInterfaces] = useState<DeviceInterface[]>([]);
  const [interfacesLoading, setInterfacesLoading] = useState(false);
  const [remediating, setRemediating] = useState<string | null>(null);

  // Linux health state
  const [linuxHealth, setLinuxHealth] = useState<LinuxHealth | null>(null);
  const [linuxHealthLoading, setLinuxHealthLoading] = useState(false);

  // Containerlab health state
  const [containerlabHealth, setContainerlabHealth] = useState<ContainerlabHealth | null>(null);
  const [containerlabHealthLoading, setContainerlabHealthLoading] = useState(false);

  // Real-time telemetry state
  const [showTelemetryPanel, setShowTelemetryPanel] = useState(false);
  const [telemetryData, setTelemetryData] = useState<TelemetryData | null>(null);
  const [telemetryConnected, setTelemetryConnected] = useState(false);
  const socketRef = useRef<Socket | null>(null);

  // Event log state
  const [showEventsPanel, setShowEventsPanel] = useState(false);
  const [events, setEvents] = useState<EventLogEntry[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsFilter, setEventsFilter] = useState<string>('all');
  const [expandedEvent, setExpandedEvent] = useState<number | null>(null);

  // RAG Chat state
  const [showChatPanel, setShowChatPanel] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const [chatModel, setChatModel] = useState('claude-sonnet-4-20250514');
  const chatMessagesRef = useRef<HTMLDivElement>(null);

  // User Management state
  const [showUserManagement, setShowUserManagement] = useState(false);

  // Add Device Modal state
  const [showAddDeviceModal, setShowAddDeviceModal] = useState(false);

  // MTU Calculator Modal state
  const [showMTUCalculator, setShowMTUCalculator] = useState(false);
  const [showSubnetCalculator, setShowSubnetCalculator] = useState(false);
  const [showImpactAnalysis, setShowImpactAnalysis] = useState(false);
  const [showImpactTrending, setShowImpactTrending] = useState(false);
  const [showIntentDrift, setShowIntentDrift] = useState(false);

  // Change Management Modal state
  const [showChangeManagement, setShowChangeManagement] = useState(false);

  // Hierarchy state (for enterprise-scale topology)
  const [hierarchyEnabled, setHierarchyEnabled] = useState(false);
  const [hierarchyTree, setHierarchyTree] = useState<HierarchyTree | null>(null);
  const [currentLevel, setCurrentLevel] = useState<HierarchyLevel>({
    type: 'all',
    id: null,
    name: 'All Regions'
  });
  const [, setHierarchyLoading] = useState(false);
  const [showHierarchySidebar, setShowHierarchySidebar] = useState(false);
  const [showOverlaysSidebar, setShowOverlaysSidebar] = useState(false);

  // UI animation state
  const [refreshing, setRefreshing] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [, setAnimationTick] = useState(0);  // Used to trigger re-renders for selection glow animation

  // Computed graph data - merges bgp_links only when overlay is active
  const graphData = useMemo(() => {
    if (!topology) return { nodes: [], links: [] };
    if (!showBgpOverlay || !topology.bgp_links || topology.bgp_links.length === 0) {
      return { nodes: topology.nodes, links: topology.links };
    }
    // Merge BGP links when overlay is active
    return {
      nodes: topology.nodes,
      links: [...topology.links, ...topology.bgp_links]
    };
  }, [topology, showBgpOverlay]);

  // Animation timer for selection glow pulse effect
  useEffect(() => {
    if (selectedNode) {
      const interval = setInterval(() => {
        setAnimationTick(t => t + 1);
      }, 50);  // 20fps for smooth animation
      return () => clearInterval(interval);
    }
  }, [selectedNode]);

  useEffect(() => {
    let resizeTimeout: NodeJS.Timeout | null = null;
    let animationFrameId: number | null = null;

    const updateDimensions = () => {
      const container = containerRef.current;
      if (container) {
        // Try multiple methods to get accurate dimensions
        const rect = container.getBoundingClientRect();
        let newWidth = Math.floor(rect.width);
        let newHeight = Math.floor(rect.height);

        // Fallback to offsetWidth/Height
        if (newWidth === 0 || newHeight === 0) {
          newWidth = container.offsetWidth;
          newHeight = container.offsetHeight;
        }

        // Fallback to clientWidth/Height
        if (newWidth === 0 || newHeight === 0) {
          newWidth = container.clientWidth;
          newHeight = container.clientHeight;
        }

        // Final fallback: calculate from parent minus sidebar
        if (newWidth === 0 || newHeight === 0) {
          const parent = container.parentElement;
          if (parent) {
            const parentRect = parent.getBoundingClientRect();
            newWidth = Math.floor(parentRect.width) - 320; // sidebar width
            newHeight = Math.floor(parentRect.height);
          }
        }

        // Only update if dimensions are valid and different
        if (newWidth > 100 && newHeight > 100) {
          setDimensions(prev => {
            if (prev.width !== newWidth || prev.height !== newHeight) {
              return { width: newWidth, height: newHeight };
            }
            return prev;
          });
        }
      }
    };

    // Debounced resize handler
    const handleResize = () => {
      if (resizeTimeout) {
        clearTimeout(resizeTimeout);
      }
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
      }

      // Use requestAnimationFrame for smooth updates
      animationFrameId = requestAnimationFrame(() => {
        updateDimensions();
      });

      // Delayed update to catch final size
      resizeTimeout = setTimeout(() => {
        updateDimensions();
      }, 300);
    };

    // Initial dimension checks with multiple delays to catch layout completion
    const timers = [
      setTimeout(() => updateDimensions(), 0),
      setTimeout(() => updateDimensions(), 50),
      setTimeout(() => updateDimensions(), 100),
      setTimeout(() => updateDimensions(), 250),
      setTimeout(() => updateDimensions(), 500),
      setTimeout(() => updateDimensions(), 1000),
    ];

    // ResizeObserver for container size changes
    const resizeObserver = new ResizeObserver((entries) => {
      // Only trigger if size actually changed
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        if (width > 0 && height > 0) {
          handleResize();
        }
      }
    });

    if (containerRef.current) {
      resizeObserver.observe(containerRef.current);
    }

    // Window resize listener
    window.addEventListener('resize', handleResize);

    return () => {
      timers.forEach(t => clearTimeout(t));
      if (resizeTimeout) clearTimeout(resizeTimeout);
      if (animationFrameId) cancelAnimationFrame(animationFrameId);
      resizeObserver.disconnect();
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  const fetchTopology = useCallback(async () => {
    try {
      const response = await authGet(API.topology);
      if (!response.ok) throw new Error('Failed to fetch topology');
      const data = await response.json();

      setTopology(prevTopology => {
        if (prevTopology && prevTopology.nodes.length > 0) {
          // Update existing topology - preserve positions
          const existingNodesMap = new Map<string, Node>(
            prevTopology.nodes.map(n => [n.id, n])
          );

          // Check if structure changed
          const existingIds = new Set(prevTopology.nodes.map(n => n.id));
          const structureChanged = data.nodes.length !== prevTopology.nodes.length ||
            data.nodes.some((n: Node) => !existingIds.has(n.id));

          if (!structureChanged) {
            // Same structure - update properties in place, keep positions
            prevTopology.nodes.forEach(node => {
              const newData = data.nodes.find((n: Node) => n.id === node.id);
              if (newData) {
                node.status = newData.status;
                node.ip = newData.ip;
                node.platform = newData.platform;
              }
            });
            // Return same object reference to minimize re-render impact
            return { ...prevTopology, bgp_links: data.bgp_links };
          }

          // Structure changed - merge with preserved positions
          const updatedNodes = data.nodes.map((newNode: Node) => {
            const existingNode = existingNodesMap.get(newNode.id);
            if (existingNode && existingNode.x !== undefined) {
              return {
                ...newNode,
                x: existingNode.x,
                y: existingNode.y,
                fx: existingNode.fx,
                fy: existingNode.fy
              };
            }
            // Use saved positions or defaults
            const pos = getInitialPosition(newNode.id, nodePositions.current);
            if (pos) {
              return { ...newNode, ...pos };
            }
            return newNode;
          });
          return { nodes: updatedNodes, links: data.links, bgp_links: data.bgp_links };
        }

        // First load - apply saved positions or defaults
        data.nodes = data.nodes.map((node: Node) => {
          const pos = getInitialPosition(node.id, nodePositions.current);
          return pos ? { ...node, ...pos } : node;
        });
        return data;
      });
      setError(null);
    } catch (err) {
      setError('Unable to connect to API. Using sample data.');
      const sampleData: TopologyData = {
        nodes: [
          { id: 'R1', ip: '192.0.2.11', status: 'healthy', platform: 'C8000V' },
          { id: 'R2', ip: '192.0.2.12', status: 'healthy', platform: 'C8000V' },
          { id: 'R3', ip: '192.0.2.13', status: 'healthy', platform: 'C8000V' },
          { id: 'R4', ip: '192.0.2.14', status: 'healthy', platform: 'C8000V' },
          { id: 'Switch-R1', ip: '192.0.2.21', status: 'healthy', platform: 'Cat9kv' },
          { id: 'Switch-R2', ip: '192.0.2.22', status: 'healthy', platform: 'Cat9kv' },
          { id: 'Switch-R4', ip: '192.0.2.24', status: 'healthy', platform: 'Cat9kv' },
        ],
        links: [
          { source: 'R1', target: 'R2', source_intf: 'Gi1', target_intf: 'Gi1' },
          { source: 'R1', target: 'R3', source_intf: 'Gi2', target_intf: 'Gi2' },
          { source: 'R2', target: 'R4', source_intf: 'Gi2', target_intf: 'Gi2' },
          { source: 'R3', target: 'R4', source_intf: 'Gi5', target_intf: 'Gi5' },
          { source: 'R1', target: 'Switch-R1', source_intf: 'Gi3', target_intf: 'Gi1/0/1' },
          { source: 'R2', target: 'Switch-R2', source_intf: 'Gi3', target_intf: 'Gi1/0/1' },
          { source: 'R4', target: 'Switch-R4', source_intf: 'Gi3', target_intf: 'Gi1/0/1' },
        ],
      };

      setTopology(prevTopology => {
        if (prevTopology) {
          const existingNodesMap = new Map(prevTopology.nodes.map(n => [n.id, n]));

          const updatedNodes = sampleData.nodes.map((newNode) => {
            const existingNode = existingNodesMap.get(newNode.id);
            if (existingNode) {
              return {
                ...existingNode,
                ...newNode,
                x: existingNode.x,
                y: existingNode.y,
                fx: existingNode.fx,
                fy: existingNode.fy,
              };
            }
            const pos = getInitialPosition(newNode.id, nodePositions.current);
            if (pos) {
              return { ...newNode, ...pos };
            }
            return newNode;
          });

          return { nodes: updatedNodes, links: sampleData.links };
        }

        // First load - apply saved or default positions
        sampleData.nodes = sampleData.nodes.map((node) => {
          const pos = getInitialPosition(node.id, nodePositions.current);
          if (pos) {
            return { ...node, ...pos };
          }
          return node;
        });
        return sampleData;
      });
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial topology fetch only (on mount)
  useEffect(() => {
    fetchTopology();
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-refresh when page becomes visible (after sleep/tab switch)
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        console.log('Page visible - refreshing topology');
        fetchTopology();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [fetchTopology]);

  // Polling that respects current hierarchy level
  useEffect(() => {
    const refreshTopology = async () => {
      if (currentLevel.type === 'all') {
        await fetchTopology();
      } else {
        // Fetch filtered topology for current hierarchy level
        try {
          const response = await authGet(API.topologyLevel(currentLevel.type, currentLevel.id!));
          if (!response.ok) return;
          const data = await response.json();
          data.nodes = data.nodes.map((node: Node) => {
            const pos = getInitialPosition(node.id, nodePositions.current);
            return pos ? { ...node, ...pos } : node;
          });
          setTopology({ nodes: data.nodes, links: data.links });
        } catch (err) {
          console.warn('Failed to refresh filtered topology');
        }
      }
    };

    // Only set up polling, don't fetch immediately (navigateToLevel handles that)
    const interval = setInterval(refreshTopology, 30000);
    return () => clearInterval(interval);
  }, [currentLevel, fetchTopology]);

  // Check if hierarchy view is enabled and fetch hierarchy tree
  useEffect(() => {
    const fetchHierarchy = async () => {
      try {
        setHierarchyLoading(true);
        const response = await authGet(API.hierarchy);
        if (response.status === 403) {
          // Hierarchy is disabled on server
          setHierarchyEnabled(false);
          setHierarchyTree(null);
          return;
        }
        if (!response.ok) {
          throw new Error('Failed to fetch hierarchy');
        }
        const data = await response.json();
        setHierarchyEnabled(true);
        setHierarchyTree(data);
      } catch (err) {
        console.warn('Hierarchy view not available:', err);
        setHierarchyEnabled(false);
        setHierarchyTree(null);
      } finally {
        setHierarchyLoading(false);
      }
    };

    fetchHierarchy();
  }, []);

  // Navigate to a hierarchy level and fetch filtered topology
  const navigateToLevel = useCallback(async (level: HierarchyLevel) => {
    setCurrentLevel(level);

    if (level.type === 'all') {
      // Show all devices - use regular topology endpoint
      await fetchTopology();
      // Center and fit after loading all devices
      setTimeout(() => {
        graphRef.current?.centerAt(0, 0, 0);
        graphRef.current?.zoom(1, 0);
      }, 100);
      setTimeout(() => {
        graphRef.current?.zoomToFit(400, 50);
      }, 400);
      return;
    }

    // Fetch filtered topology for the specific level
    try {
      setLoading(true);
      const response = await authGet(API.topologyLevel(level.type, level.id!));
      if (!response.ok) throw new Error('Failed to fetch level topology');
      const data = await response.json();

      // Apply positions to filtered nodes
      data.nodes = data.nodes.map((node: Node) => {
        const pos = getInitialPosition(node.id, nodePositions.current);
        return pos ? { ...node, ...pos } : node;
      });

      setTopology({ nodes: data.nodes, links: data.links });
      setError(null);

      // Center and fit the filtered topology after render
      setTimeout(() => {
        graphRef.current?.centerAt(0, 0, 0);
        graphRef.current?.zoom(1, 0);
      }, 100);
      setTimeout(() => {
        graphRef.current?.zoomToFit(400, 50);
      }, 400);
    } catch (err) {
      setError('Failed to load level topology');
    } finally {
      setLoading(false);
    }
  }, [fetchTopology]);

  // Handle manual refresh with loading animation
  const handleRefresh = async () => {
    setRefreshKey(k => k + 1);  // Force animation restart by changing key
    setRefreshing(true);
    const startTime = Date.now();

    try {
      // Force fresh fetch with cache-busting
      const response = await authFetch(`${API.topology}?_t=${Date.now()}`, {
        headers: { 'Cache-Control': 'no-cache' }
      });
      if (!response.ok) throw new Error('Failed to refresh topology');
      const data = await response.json();

      // Force full topology update
      const nodesWithPositions = data.nodes.map((node: Node) => {
        const pos = getInitialPosition(node.id, nodePositions.current);
        return pos ? { ...node, ...pos } : node;
      });
      setTopology({ nodes: nodesWithPositions, links: data.links });
    } catch (error) {
      console.error('Refresh failed:', error);
    }

    // Ensure animation runs for at least 600ms
    const elapsed = Date.now() - startTime;
    if (elapsed < 600) {
      await new Promise(resolve => setTimeout(resolve, 600 - elapsed));
    }
    setRefreshing(false);
  };

  // Track if we've done initial fit for this page load
  const hasInitialFit = useRef(false);

  // Auto-fit view when topology first loads
  useEffect(() => {
    if (topology && topology.nodes.length > 0 && graphRef.current && !hasInitialFit.current) {
      // Multiple steps to ensure proper centering after positions are applied
      const timers = [
        setTimeout(() => {
          // First: center on origin and reset zoom
          graphRef.current?.centerAt(0, 0, 0);
          graphRef.current?.zoom(1, 0);
        }, 200),
        setTimeout(() => {
          // Second: fit all nodes in view
          graphRef.current?.zoomToFit(400, 100);
          hasInitialFit.current = true;
        }, 600),
      ];
      return () => timers.forEach(t => clearTimeout(t));
    }
  }, [topology]);

  // Re-fit when dimensions change (window resize)
  useEffect(() => {
    if (topology && graphRef.current && hasInitialFit.current) {
      // Reset view transform first, then fit
      const timers = [
        setTimeout(() => {
          graphRef.current?.centerAt(0, 0, 0);
          graphRef.current?.zoom(1, 0);
        }, 50),
        setTimeout(() => {
          graphRef.current?.zoomToFit(400, 100);
        }, 150),
      ];
      return () => timers.forEach(t => clearTimeout(t));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dimensions.width, dimensions.height]);


  // Trigger resize when bottom panel toggles so graph can use freed/reduced space
  useEffect(() => {
    // Small delay to let CSS transition complete
    const timer = setTimeout(() => {
      window.dispatchEvent(new Event('resize'));
    }, 100);
    return () => clearTimeout(timer);
  }, [bottomPanelOpen]);

  // Save role to localStorage when it changes
  useEffect(() => {
    localStorage.setItem('networkDashboardRole', userRole);
  }, [userRole]);

  // Fetch device list on mount
  useEffect(() => {
    authGet(API.devices)
      .then(res => res.json())
      .then(data => setDeviceList(data))
      .catch(() => setDeviceList([]));
  }, []);

  // Update command device when a node is selected
  useEffect(() => {
    if (selectedNode) {
      setCommandDevice(selectedNode.id);
    }
  }, [selectedNode]);

  // Fetch interfaces when a node is selected
  const fetchDeviceInterfaces = useCallback(async (deviceName: string) => {
    setInterfacesLoading(true);
    setDeviceInterfaces([]);

    try {
      const response = await authPost(API.command, {
        device: deviceName,
        command: 'show ip interface brief',
      });

      const data = await response.json();
      if (data.status === 'success') {
        const lines = data.output.split('\n').filter((l: string) => l.trim());
        const intfList: DeviceInterface[] = [];

        for (const line of lines.slice(1)) {
          const lineLower = line.toLowerCase();
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 6) {
            const name = parts[0];
            const ip = parts[1];
            // Check if line contains "administratively down" anywhere
            const isAdminDown = lineLower.includes('administratively down');
            // Protocol is always the last column
            const protocol = parts[parts.length - 1];
            intfList.push({
              name,
              ip: ip === 'unassigned' ? null : ip,
              admin_status: isAdminDown ? 'admin_down' : 'up',
              line_protocol: protocol.toLowerCase()
            });
          }
        }
        // Fetch ACL overlay and merge into interface list
        try {
          const aclResp = await authGet(`${API.interfaceAcls}?device=${deviceName}`);
          if (aclResp.ok) {
            const aclData = await aclResp.json();
            for (const intf of intfList) {
              if (aclData[intf.name]) {
                intf.acl_in = aclData[intf.name].acl_in || undefined;
              }
            }
          }
        } catch {
          // ACL fetch is best-effort; don't block interface display
        }

        setDeviceInterfaces(intfList);
      }
    } catch (err) {
      console.error('Failed to fetch interfaces:', err);
    } finally {
      setInterfacesLoading(false);
    }
  }, []);

  // Fetch Linux health details
  const fetchLinuxHealth = useCallback(async (deviceName: string) => {
    setLinuxHealthLoading(true);
    setLinuxHealth(null);

    try {
      const response = await authGet(API.linuxHealth(deviceName));
      const data = await response.json();
      if (data.status !== 'error') {
        setLinuxHealth(data);
      }
    } catch (err) {
      console.error('Failed to fetch Linux health:', err);
    } finally {
      setLinuxHealthLoading(false);
    }
  }, []);

  // Fetch Containerlab health details
  const fetchContainerlabHealth = useCallback(async (deviceName: string) => {
    setContainerlabHealthLoading(true);
    setContainerlabHealth(null);
    setDeviceInterfaces([]);

    try {
      const response = await authGet(API.containerlabHealth(deviceName));
      const data = await response.json();
      if (data.status !== 'error') {
        setContainerlabHealth(data);
        // Set interfaces if available in response
        if (data.interfaces && Array.isArray(data.interfaces)) {
          setDeviceInterfaces(data.interfaces);
        }
      }
    } catch (err) {
      console.error('Failed to fetch containerlab health:', err);
    } finally {
      setContainerlabHealthLoading(false);
    }
  }, []);

  // Remediate interface
  const remediateInterface = async (deviceName: string, interfaceName: string, action: string, aclName?: string) => {
    if (userRole !== 'admin') {
      alert('Only admin can perform remediation');
      return;
    }

    if (action === 'remove_acl' && !window.confirm(`Remove ACL "${aclName}" from ${interfaceName}?`)) return;

    setRemediating(interfaceName);

    try {
      const body: Record<string, string> = {
        device: deviceName,
        interface: interfaceName,
        action: action,
      };
      if (aclName) body.acl_name = aclName;
      const response = await authPost(API.remediate, body);

      const data = await response.json();
      if (data.success) {
        // Refresh interfaces after remediation
        await fetchDeviceInterfaces(deviceName);
      } else {
        alert(`Remediation failed: ${data.error}`);
      }
    } catch (err) {
      alert('Failed to connect to API');
    } finally {
      setRemediating(null);
    }
  };

  // Fetch interfaces when node is selected (or health data for Linux/containerlab hosts)
  useEffect(() => {
    if (selectedNode && !isLinuxHost(selectedNode) && !isContainerlabDevice(selectedNode)) {
      fetchDeviceInterfaces(selectedNode.id);
      setLinuxHealth(null);
      setContainerlabHealth(null);
    } else if (selectedNode && isLinuxHost(selectedNode)) {
      fetchLinuxHealth(selectedNode.id);
      setDeviceInterfaces([]);
      setContainerlabHealth(null);
    } else if (selectedNode && isContainerlabDevice(selectedNode)) {
      fetchContainerlabHealth(selectedNode.id);
      // Don't clear deviceInterfaces here - fetchContainerlabHealth will set them
      setLinuxHealth(null);
    } else {
      setDeviceInterfaces([]);
      setLinuxHealth(null);
      setContainerlabHealth(null);
    }
  }, [selectedNode, fetchDeviceInterfaces, fetchLinuxHealth, fetchContainerlabHealth]);

  const executeCommand = async () => {
    if (!commandDevice || !commandText) return;

    setIsExecuting(true);
    setCommandOutput('');
    setCommandError(false);

    try {
      const response = await authPost(API.command, {
        device: commandDevice,
        command: commandText,
      });

      const data = await response.json();

      if (response.ok && data.status === 'success') {
        setCommandOutput(data.output);
        setCommandError(false);
      } else {
        setCommandOutput(data.error || 'Unknown error occurred');
        setCommandError(true);
      }
    } catch (err) {
      setCommandOutput('Failed to connect to API server');
      setCommandError(true);
    } finally {
      setIsExecuting(false);
    }
  };

  // BGP-capable routers — not all devices run BGP
  const BGP_DEVICES = ['R1', 'R2', 'R3', 'R4', 'edge1', 'R9', 'R10'];

  // Fetch BGP data for all routers and edge1
  const fetchBgpData = async () => {
    setBgpLoading(true);
    const devices = BGP_DEVICES;
    const newBgpData: Record<string, BgpNeighbor[]> = {};

    try {
      for (const device of devices) {
        const response = await authGet(`${API.bgpSummary}?device=${device}`);
        if (response.ok) {
          const data = await response.json();
          if (data.status === 'success') {
            newBgpData[device] = data.neighbors;
          }
        }
      }
      setBgpData(newBgpData);
    } catch (err) {
      console.error('Failed to fetch BGP data:', err);
    } finally {
      setBgpLoading(false);
    }
  };

  // Toggle BGP overlay
  const toggleBgpOverlay = () => {
    if (!showBgpOverlay && Object.keys(bgpData).length === 0) {
      fetchBgpData();
    }
    setShowBgpOverlay(!showBgpOverlay);
  };

  // Run ping sweep from selected device
  const runPingSweep = async () => {
    if (!selectedNode) return;

    setPingLoading(true);
    setPingSource(selectedNode.id);
    setPingResults(null);

    try {
      const response = await authPost(API.pingSweep, {
        device: selectedNode.id,
      });

      const data = await response.json();
      if (data.status === 'success') {
        setPingResults(data.results);
      }
    } catch (err) {
      console.error('Failed to run ping sweep:', err);
    } finally {
      setPingLoading(false);
    }
  };

  // Clear ping results
  const clearPingResults = () => {
    setPingResults(null);
    setPingSource(null);
    setPingDetailsExpanded(false);
  };

  // Fetch OSPF status data
  const fetchOspfData = async () => {
    setOspfLoading(true);
    try {
      const response = await authGet(API.ospfStatus);
      const data = await response.json();
      if (data.status === 'success') {
        setOspfData(data);
      }
    } catch (err) {
      console.error('Failed to fetch OSPF data:', err);
    } finally {
      setOspfLoading(false);
    }
  };

  // Toggle OSPF overlays
  const toggleOspfOverlay = () => {
    if (!showOspfOverlay && !ospfData) {
      fetchOspfData();
    }
    setShowOspfOverlay(!showOspfOverlay);
  };

  const toggleOspfAreaOverlay = () => {
    if (!showOspfAreaOverlay && !ospfData) {
      fetchOspfData();
    }
    setShowOspfAreaOverlay(!showOspfAreaOverlay);
  };


  // Auto-refresh events when panel is open
  useEffect(() => {
    if (showEventsPanel) {
      const interval = setInterval(fetchEvents, 5000);
      return () => clearInterval(interval);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showEventsPanel, eventsFilter]);

  // Fetch DMVPN status
  const fetchDmvpnData = async () => {
    setDmvpnLoading(true);
    try {
      const response = await authGet(API.dmvpnStatus);
      const data = await response.json();
      if (data.status === 'success') {
        setDmvpnData(data);
      }
    } catch (err) {
      console.error('Failed to fetch DMVPN data:', err);
    } finally {
      setDmvpnLoading(false);
    }
  };

  // Toggle DMVPN overlay and panel
  const toggleDmvpnOverlay = () => {
    if (!showDmvpnOverlay && !dmvpnData) {
      fetchDmvpnData();
    }
    setShowDmvpnOverlay(!showDmvpnOverlay);
    setShowDmvpnPanel(!showDmvpnPanel);
  };

  // Fetch Switch fabric status
  const fetchSwitchData = async () => {
    setSwitchLoading(true);
    try {
      const response = await authGet(API.switchStatus);
      const data = await response.json();
      if (data.status === 'success') {
        setSwitchData(data);
      }
    } catch (err) {
      console.error('Failed to fetch switch data:', err);
    } finally {
      setSwitchLoading(false);
    }
  };

  // Toggle Switch overlay and panel
  const toggleSwitchOverlay = () => {
    if (!showSwitchOverlay && !switchData) {
      fetchSwitchData();
    }
    setShowSwitchOverlay(!showSwitchOverlay);
    setShowSwitchPanel(!showSwitchPanel);
  };

  // Fetch Event log data
  const fetchEvents = async () => {
    setEventsLoading(true);
    try {
      const url = eventsFilter === 'all'
        ? `${API.events}?limit=50`
        : `${API.events}?limit=50&device=${eventsFilter}`;
      const response = await authGet(url);
      const data = await response.json();
      if (data.events) {
        setEvents(data.events);
      }
    } catch (err) {
      console.error('Failed to fetch events:', err);
    } finally {
      setEventsLoading(false);
    }
  };

  // Toggle Events panel
  const toggleEventsPanel = () => {
    if (!showEventsPanel) {
      fetchEvents();
    }
    setShowEventsPanel(!showEventsPanel);
  };

  // Chat panel functions
  const toggleChatPanel = () => {
    setShowChatPanel(!showChatPanel);
  };

  const sendChatMessage = async () => {
    if (!chatInput.trim() || chatLoading) return;

    const userMessage: ChatMessage = {
      role: 'user',
      content: chatInput.trim(),
      timestamp: new Date()
    };

    setChatMessages(prev => [...prev, userMessage]);
    setChatInput('');
    setChatLoading(true);

    try {
      // Build conversation history for multi-turn context
      const history = chatMessages.map(msg => ({
        role: msg.role,
        content: msg.content
      }));

      const response = await authPost(API.chat, {
        message: userMessage.content,
        model: chatModel,
        history: history
      });

      const data = await response.json();

      const assistantMessage: ChatMessage = {
        role: 'assistant',
        content: data.response || data.error || 'No response',
        sources: data.sources || [],
        timestamp: new Date()
      };

      setChatMessages(prev => [...prev, assistantMessage]);
    } catch (err) {
      const errorMessage: ChatMessage = {
        role: 'assistant',
        content: 'Error: Unable to connect to chat API',
        timestamp: new Date()
      };
      setChatMessages(prev => [...prev, errorMessage]);
    } finally {
      setChatLoading(false);
    }
  };

  // Auto-scroll chat to bottom when new messages arrive
  useEffect(() => {
    if (chatMessagesRef.current) {
      chatMessagesRef.current.scrollTop = chatMessagesRef.current.scrollHeight;
    }
  }, [chatMessages]);

  // Format timestamp for display
  const formatEventTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { hour12: false });
  };

  // WebSocket connection for real-time updates (always on for device status)
  useEffect(() => {
    if (!socketRef.current) {
      const socket = io(WS_URL, {
        transports: ['websocket', 'polling'],
        auth: {
          token: getToken(),
        },
      });

      socket.on('connect', () => {
        console.log('WebSocket connected');
        setTelemetryConnected(true);
      });

      socket.on('disconnect', () => {
        console.log('WebSocket disconnected');
        setTelemetryConnected(false);
      });

      // Handle real-time device status updates (from MDT state changes)
      socket.on('device_status', (message: any) => {
        console.log('Device status update:', message);
        const { device, status } = message;
        if (device && status) {
          setTopology(prev => {
            if (!prev) return prev;
            const updatedNodes = prev.nodes.map(node =>
              node.id === device ? { ...node, status } : node
            );
            return { ...prev, nodes: updatedNodes };
          });
        }
      });

      socket.on('telemetry_update', (message: any) => {
        console.log('Telemetry update:', message);
        if (message.type === 'initial' && message.device === 'all') {
          setTelemetryData(message.data);
        } else if (message.type === 'cpu') {
          setTelemetryData(prev => {
            const base = prev || { interfaces: {}, cpu: {}, memory: {}, last_update: {} };
            return {
              ...base,
              cpu: { ...base.cpu, [message.device]: { five_seconds: message.data.cpu_percent, timestamp: message.timestamp } },
              last_update: { ...base.last_update, [message.device]: message.timestamp }
            };
          });
        } else if (message.type === 'memory') {
          setTelemetryData(prev => {
            const base = prev || { interfaces: {}, cpu: {}, memory: {}, last_update: {} };
            return {
              ...base,
              memory: { ...base.memory, [message.device]: message.data },
              last_update: { ...base.last_update, [message.device]: message.timestamp }
            };
          });
        }
      });

      socketRef.current = socket;
    }

    return () => {
      // Only disconnect on unmount, not when telemetry panel closes
    };
  }, []);

  // Fetch telemetry data via REST and subscribe via WebSocket when panel opens
  useEffect(() => {
    if (!showTelemetryPanel) return;

    // Always fetch via REST for reliable initial load
    const fetchTelemetryRest = async () => {
      try {
        const response = await authGet(API.telemetryData);
        const data = await response.json();
        if (data.status === 'success' && data.telemetry) {
          setTelemetryData(data.telemetry);
        }
      } catch (err) {
        console.error('Failed to fetch telemetry via REST:', err);
      }
    };
    fetchTelemetryRest();

    // Also subscribe via WebSocket for live updates
    if (socketRef.current?.connected) {
      socketRef.current.emit('subscribe_telemetry', { devices: [] });
    }

    // Periodic REST refresh as safety net
    const interval = setInterval(fetchTelemetryRest, 10000);
    return () => clearInterval(interval);
  }, [showTelemetryPanel]);

  // Toggle telemetry panel
  const toggleTelemetryPanel = () => {
    setShowTelemetryPanel(!showTelemetryPanel);
  };

  // Reset layout to defaults
  const resetLayout = () => {
    // Clear saved positions
    localStorage.removeItem(LAYOUT_STORAGE_KEY);
    nodePositions.current.clear();

    // Apply default positions to current topology
    if (topology) {
      const resetNodes = topology.nodes.map(node => {
        const defaultPos = DEFAULT_LAYOUT[node.id];
        if (defaultPos) {
          return {
            ...node,
            x: defaultPos.x,
            y: defaultPos.y,
            fx: defaultPos.x,
            fy: defaultPos.y
          };
        }
        // For nodes without defaults, let force simulation place them
        return { ...node, x: undefined, y: undefined, fx: undefined, fy: undefined };
      });

      // Create new link objects to force ForceGraph2D to re-resolve references
      // (it mutates links to store node object refs, so we need fresh objects)
      const resetLinks = topology.links.map(link => ({
        ...link,
        source: typeof link.source === 'object' ? link.source.id : link.source,
        target: typeof link.target === 'object' ? link.target.id : link.target,
      }));

      setTopology({ nodes: resetNodes, links: resetLinks });

      // Center and fit after reset
      setTimeout(() => {
        graphRef.current?.centerAt(0, 0, 0);
        graphRef.current?.zoom(1, 0);
      }, 100);
      setTimeout(() => {
        graphRef.current?.zoomToFit(400, 100);
      }, 300);
    }
  };

  // Format bytes to human readable
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  // Get ping result for a specific target
  const getPingResultForNode = (nodeId: string): PingResult | undefined => {
    if (!pingResults) return undefined;
    return pingResults.find(r => r.target === nodeId);
  };

  const getNodeColor = (node: Node) => {
    switch (node.status) {
      case 'healthy': return '#22c55e';
      case 'degraded': return '#eab308';
      case 'critical': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const isSwitch = (node: Node) => node.id.toLowerCase().includes('switch');
  const isLinuxHost = (node: Node) => node.platform === 'Linux';
  const isContainerlabDevice = (node: Node) => {
    const platform = node.platform?.toLowerCase() || '';
    return platform.includes('nokia') || platform.includes('srlinux') ||
           platform.includes('frrouting') || platform.includes('frr') ||
           platform.includes('alpine (clab)');
  };

  // Draw DMVPN tunnel arc between two nodes
  const drawDmvpnTunnel = (
    ctx: CanvasRenderingContext2D,
    fromNode: any,
    toNode: any,
    peer: DmvpnPeer,
    globalScale: number
  ) => {
    if (!fromNode || !toNode || fromNode.x === undefined || toNode.x === undefined) return;

    const color = peer.state === 'UP' ? '#a855f7' : '#ef4444';

    const midX = (fromNode.x + toNode.x) / 2;
    const midY = (fromNode.y + toNode.y) / 2;
    const dx = toNode.x - fromNode.x;
    const dy = toNode.y - fromNode.y;
    const dist = Math.sqrt(dx * dx + dy * dy);

    const curvature = 0.3;
    const offsetX = -dy / dist * dist * curvature;
    const offsetY = dx / dist * dist * curvature;
    const ctrlX = midX + offsetX;
    const ctrlY = midY + offsetY;

    ctx.beginPath();
    ctx.moveTo(fromNode.x, fromNode.y);
    ctx.quadraticCurveTo(ctrlX, ctrlY, toNode.x, toNode.y);
    ctx.strokeStyle = color;
    ctx.lineWidth = 2 / globalScale;
    ctx.setLineDash([6 / globalScale, 4 / globalScale]);
    ctx.stroke();
    ctx.setLineDash([]);

    const labelX = midX + offsetX * 0.5;
    const labelY = midY + offsetY * 0.5;
    ctx.font = `bold ${8 / globalScale}px Arial`;
    ctx.fillStyle = 'rgba(15, 23, 42, 0.9)';
    const labelText = `DMVPN`;
    const textWidth = ctx.measureText(labelText).width;
    ctx.fillRect(labelX - textWidth / 2 - 3, labelY - 6 / globalScale, textWidth + 6, 12 / globalScale);
    ctx.fillStyle = color;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(labelText, labelX, labelY);
  };

  // Draw eBGP peering line between two nodes
  const drawEbgpPeering = (
    ctx: CanvasRenderingContext2D,
    fromNode: any,
    toNode: any,
    state: string,
    globalScale: number
  ) => {
    if (!fromNode || !toNode || fromNode.x === undefined || toNode.x === undefined) return;

    const color = state === 'Established' ? '#f97316' :  // Orange for eBGP
                  state === 'Active' ? '#eab308' : '#ef4444';

    const midX = (fromNode.x + toNode.x) / 2;
    const midY = (fromNode.y + toNode.y) / 2;
    const dx = toNode.x - fromNode.x;
    const dy = toNode.y - fromNode.y;
    const dist = Math.sqrt(dx * dx + dy * dy);

    // Curve in opposite direction from DMVPN
    const curvature = -0.2;
    const offsetX = -dy / dist * dist * curvature;
    const offsetY = dx / dist * dist * curvature;
    const ctrlX = midX + offsetX;
    const ctrlY = midY + offsetY;

    ctx.beginPath();
    ctx.moveTo(fromNode.x, fromNode.y);
    ctx.quadraticCurveTo(ctrlX, ctrlY, toNode.x, toNode.y);
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5 / globalScale;
    ctx.setLineDash([8 / globalScale, 4 / globalScale]);
    ctx.stroke();
    ctx.setLineDash([]);

    const labelX = midX + offsetX * 0.5;
    const labelY = midY + offsetY * 0.5;
    ctx.font = `bold ${8 / globalScale}px Arial`;
    ctx.fillStyle = 'rgba(15, 23, 42, 0.9)';
    const labelText = `eBGP`;
    const textWidth = ctx.measureText(labelText).width;
    ctx.fillRect(labelX - textWidth / 2 - 3, labelY - 6 / globalScale, textWidth + 6, 12 / globalScale);
    ctx.fillStyle = color;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(labelText, labelX, labelY);
  };

  const drawNode = (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const label = node.id;
    const fontSize = Math.max(12 / globalScale, 4);
    const color = getNodeColor(node);
    const isSelected = selectedNode && selectedNode.id === node.id;

    const pingResult = getPingResultForNode(node.id);
    const isPingSource = pingSource === node.id;

    // Draw selection glow (pulsing ring matching status color)
    if (isSelected) {
      const time = Date.now() / 1000;
      const pulseScale = 1 + 0.2 * Math.sin(time * 4);  // Pulsing effect
      const glowAlpha = 0.5 + 0.3 * Math.sin(time * 4);

      ctx.save();
      ctx.shadowColor = color;
      ctx.shadowBlur = 20 * pulseScale / globalScale;

      // Draw outer glow ring
      ctx.beginPath();
      if (isSwitch(node)) {
        const width = NODE_SIZE * 2 + 12;
        const height = NODE_SIZE + 12;
        ctx.rect(node.x - width / 2, node.y - height / 2, width, height);
      } else if (isLinuxHost(node)) {
        const size = NODE_SIZE + 10;
        ctx.moveTo(node.x, node.y - size);
        ctx.lineTo(node.x + size, node.y);
        ctx.lineTo(node.x, node.y + size);
        ctx.lineTo(node.x - size, node.y);
        ctx.closePath();
      } else {
        ctx.arc(node.x, node.y, NODE_SIZE + 10, 0, 2 * Math.PI);
      }
      ctx.strokeStyle = color;
      ctx.lineWidth = 3 / globalScale;
      ctx.globalAlpha = glowAlpha;
      ctx.stroke();
      ctx.restore();
    }

    if (showDmvpnOverlay && dmvpnData && node.id === dmvpnData.hub) {
      dmvpnData.peers.forEach(peer => {
        const spokeNode = topology?.nodes.find(n => n.id === peer.name);
        if (spokeNode) {
          drawDmvpnTunnel(ctx, node, spokeNode, peer, globalScale);
        }
      });
    }

    // Draw eBGP peerings dynamically using neighbor_name from API
    if (showBgpOverlay && node.id === 'R3') {
      const r3Bgp = bgpData['R3'];
      if (r3Bgp) {
        const ebgpSession = r3Bgp.find(n => n.peer_type === 'eBGP');
        if (ebgpSession) {
          const peerNode = ebgpSession.neighbor_name
            ? topology?.nodes.find(n => n.id === ebgpSession.neighbor_name)
            : null;
          if (peerNode) {
            drawEbgpPeering(ctx, node, peerNode, ebgpSession.state, globalScale);
          }
        }
      }
    }

    if (isSwitch(node)) {
      const width = NODE_SIZE * 2;
      const height = NODE_SIZE;
      ctx.fillStyle = color;
      ctx.fillRect(node.x - width / 2, node.y - height / 2, width, height);
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 2 / globalScale;
      ctx.strokeRect(node.x - width / 2, node.y - height / 2, width, height);

      // Ping result highlight ring for switches
      if (pingResult && !isPingSource) {
        const pingColor = pingResult.success_rate === '100%' ? '#22c55e' :
                         pingResult.success_rate === '0%' ? '#ef4444' : '#eab308';
        const outerWidth = width + 12;
        const outerHeight = height + 12;
        ctx.strokeStyle = pingColor;
        ctx.lineWidth = 3 / globalScale;
        ctx.strokeRect(node.x - outerWidth / 2, node.y - outerHeight / 2, outerWidth, outerHeight);
      }
    } else if (isLinuxHost(node)) {
      const size = NODE_SIZE;
      ctx.beginPath();
      ctx.moveTo(node.x, node.y - size);
      ctx.lineTo(node.x + size, node.y);
      ctx.lineTo(node.x, node.y + size);
      ctx.lineTo(node.x - size, node.y);
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 2 / globalScale;
      ctx.stroke();

      if (pingResult && !isPingSource) {
        const pingColor = pingResult.success_rate === '100%' ? '#22c55e' :
                         pingResult.success_rate === '0%' ? '#ef4444' : '#eab308';
        const outerSize = size + 6;
        ctx.beginPath();
        ctx.moveTo(node.x, node.y - outerSize);
        ctx.lineTo(node.x + outerSize, node.y);
        ctx.lineTo(node.x, node.y + outerSize);
        ctx.lineTo(node.x - outerSize, node.y);
        ctx.closePath();
        ctx.strokeStyle = pingColor;
        ctx.lineWidth = 3 / globalScale;
        ctx.stroke();
      }
    } else {
      ctx.beginPath();
      ctx.arc(node.x, node.y, NODE_SIZE, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 2 / globalScale;
      ctx.stroke();

      if (pingResult && !isPingSource) {
        const pingColor = pingResult.success_rate === '100%' ? '#22c55e' :
                         pingResult.success_rate === '0%' ? '#ef4444' : '#eab308';
        ctx.beginPath();
        ctx.arc(node.x, node.y, NODE_SIZE + 6, 0, 2 * Math.PI);
        ctx.strokeStyle = pingColor;
        ctx.lineWidth = 3 / globalScale;
        ctx.stroke();
      }

      if (isPingSource) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, NODE_SIZE + 8, 0, 2 * Math.PI);
        ctx.strokeStyle = '#3b82f6';
        ctx.lineWidth = 3 / globalScale;
        ctx.setLineDash([5 / globalScale, 5 / globalScale]);
        ctx.stroke();
        ctx.setLineDash([]);
      }
    }

    // OSPF Area overlay - show area badge next to node
    if (showOspfAreaOverlay && ospfData) {
      const areaColors: Record<number, string> = {
        0: '#3b82f6',  // Area 0 - Blue (backbone)
        1: '#22c55e',  // Area 1 - Green
        2: '#f59e0b',  // Area 2 - Orange
        3: '#a855f7',  // Area 3 - Purple
        4: '#ef4444',  // Area 4 - Red
      };

      // Find which areas this node belongs to
      const nodeAreas: number[] = [];
      for (const [areaStr, devices] of Object.entries(ospfData.areas)) {
        const area = parseInt(areaStr);
        if ((devices as string[]).includes(node.id)) {
          nodeAreas.push(area);
        }
      }

      if (nodeAreas.length > 0) {
        // Sort areas so Area 0 (backbone) is innermost
        const sortedAreas = [...nodeAreas].sort((a, b) => a - b);

        // Draw multiple concentric rings - one for each area
        sortedAreas.forEach((area, idx) => {
          const areaColor = areaColors[area] || '#64748b';
          const ringRadius = NODE_SIZE + 8 + (idx * 6);  // Concentric rings

          ctx.beginPath();
          ctx.arc(node.x, node.y, ringRadius, 0, 2 * Math.PI);
          ctx.strokeStyle = areaColor;
          ctx.lineWidth = 3 / globalScale;
          ctx.stroke();
        });

        // Draw area labels above the node
        const labelY = node.y - NODE_SIZE - 12 - (sortedAreas.length * 6);
        ctx.font = `bold ${9 / globalScale}px Arial`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        // Background for label
        const areaText = sortedAreas.map(a => `A${a}`).join(' ');
        const textWidth = ctx.measureText(areaText).width;
        ctx.fillStyle = 'rgba(15, 23, 42, 0.85)';
        ctx.fillRect(node.x - textWidth / 2 - 4, labelY - 6 / globalScale, textWidth + 8, 12 / globalScale);

        // Draw each area label with its color
        let xOffset = node.x - textWidth / 2;
        sortedAreas.forEach((area, idx) => {
          const areaColor = areaColors[area] || '#64748b';
          const aText = `A${area}`;
          ctx.fillStyle = areaColor;
          ctx.textAlign = 'left';
          ctx.fillText(aText, xOffset, labelY);
          xOffset += ctx.measureText(aText + ' ').width;
        });
      }
    }

    ctx.font = `bold ${fontSize}px Arial`;
    ctx.fillStyle = '#fff';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText(label, node.x, node.y + NODE_SIZE + 4);

    if (pingResult && pingResult.avg_latency > 0) {
      ctx.font = `${fontSize * 0.8}px Arial`;
      ctx.fillStyle = '#a3e635';
      ctx.fillText(`${pingResult.avg_latency}ms`, node.x, node.y + NODE_SIZE + 4 + fontSize + 2);
    }
  };

  const paintPointerArea = (node: any, color: string, ctx: CanvasRenderingContext2D) => {
    ctx.fillStyle = color;
    if (isSwitch(node)) {
      const width = NODE_SIZE * 2;
      const height = NODE_SIZE;
      ctx.fillRect(node.x - width / 2, node.y - height / 2, width, height);
    } else if (isLinuxHost(node)) {
      const size = NODE_SIZE;
      ctx.beginPath();
      ctx.moveTo(node.x, node.y - size);
      ctx.lineTo(node.x + size, node.y);
      ctx.lineTo(node.x, node.y + size);
      ctx.lineTo(node.x - size, node.y);
      ctx.closePath();
      ctx.fill();
    } else {
      ctx.beginPath();
      ctx.arc(node.x, node.y, NODE_SIZE, 0, 2 * Math.PI);
      ctx.fill();
    }
  };

  if (loading) {
    return (
      <div className="app loading">
        <div className="spinner"></div>
        <p>Loading topology...</p>
      </div>
    );
  }

  return (
    <div className={`app ${showHierarchySidebar ? 'hierarchy-sidebar-open' : ''} ${showOverlaysSidebar ? 'overlays-sidebar-open' : ''}`}>
      {/* Hierarchy Sidebar */}
      {hierarchyEnabled && (
        <HierarchySidebar
          isOpen={showHierarchySidebar}
          onClose={() => setShowHierarchySidebar(false)}
          hierarchyTree={hierarchyTree}
          currentLevel={currentLevel}
          onNavigate={navigateToLevel}
        />
      )}

      {/* Overlays Sidebar */}
      <OverlaysSidebar
        isOpen={showOverlaysSidebar}
        onClose={() => setShowOverlaysSidebar(false)}
        showBgpOverlay={showBgpOverlay}
        toggleBgpOverlay={toggleBgpOverlay}
        bgpLoading={bgpLoading}
        showOspfOverlay={showOspfOverlay}
        toggleOspfOverlay={toggleOspfOverlay}
        showOspfAreaOverlay={showOspfAreaOverlay}
        toggleOspfAreaOverlay={toggleOspfAreaOverlay}
        ospfLoading={ospfLoading}
        pingResults={pingResults}
        pingLoading={pingLoading}
        selectedNode={selectedNode}
        runPingSweep={runPingSweep}
        clearPingResults={clearPingResults}
        showDmvpnOverlay={showDmvpnOverlay}
        toggleDmvpnOverlay={toggleDmvpnOverlay}
        dmvpnLoading={dmvpnLoading}
        showSwitchOverlay={showSwitchOverlay}
        toggleSwitchOverlay={toggleSwitchOverlay}
        switchLoading={switchLoading}
        showEventsPanel={showEventsPanel}
        toggleEventsPanel={toggleEventsPanel}
        eventsLoading={eventsLoading}
        showTelemetryPanel={showTelemetryPanel}
        toggleTelemetryPanel={toggleTelemetryPanel}
        showChatPanel={showChatPanel}
        toggleChatPanel={toggleChatPanel}
        onOpenMTUCalculator={() => setShowMTUCalculator(true)}
        onOpenSubnetCalculator={() => setShowSubnetCalculator(true)}
        onOpenImpactAnalysis={() => setShowImpactAnalysis(true)}
        onOpenImpactTrending={() => setShowImpactTrending(true)}
        onOpenIntentDrift={() => setShowIntentDrift(true)}
      />

      <header>
        <h1>Network Topology Dashboard</h1>
        <div className="header-controls">
          {/* Refresh button - moved to front */}
          <button
            onClick={handleRefresh}
            className={`refresh-btn ${refreshing ? 'spinning' : ''}`}
            disabled={refreshing}
          >
            <span key={refreshKey} className="refresh-icon">↻</span> Refresh
          </button>
          {/* Show user info and groups */}
          {user && (
            <div className="user-info" title={`Groups: ${(user.groups || []).join(', ') || 'None'}`}>
              <span className="user-icon">👤</span>
              <span className="username">{user.username}</span>
              {(user.groups || []).length > 0 && (
                <span className="user-group">({user.groups[0]})</span>
              )}
            </div>
          )}
          {/* Role selector only for admins (for testing/impersonation) */}
          {hasPermission('manage_users') && (
            <div className="role-selector">
              <label>View as:</label>
              <select
                value={userRole}
                onChange={(e) => setUserRole(e.target.value as UserRole)}
                className={`role-${userRole}`}
              >
                <option value="admin">Admin</option>
                <option value="operator">Operator</option>
              </select>
            </div>
          )}
          {/* User management button for admins */}
          {hasPermission('manage_users') && (
            <button
              onClick={() => setShowUserManagement(true)}
              className="refresh-btn users-btn"
              title="Manage Users"
            >
              Users
            </button>
          )}
          {/* Add Device button for admins */}
          {hasPermission('manage_users') && (
            <button
              onClick={() => setShowAddDeviceModal(true)}
              className="refresh-btn add-device-btn"
              title="Add Device to NetBox"
            >
              + Device
            </button>
          )}
          {/* Change Management button for admins */}
          {hasPermission('run_config_commands') && (
            <button
              onClick={() => setShowChangeManagement(true)}
              className="refresh-btn changes-btn"
              title="Change Management"
            >
              Changes
            </button>
          )}
          {/* Hierarchy toggle button (only when enabled) */}
          {hierarchyEnabled && (
            <button
              onClick={() => {
                if (!showHierarchySidebar) {
                  setShowOverlaysSidebar(false); // Close overlays if opening sites
                }
                setShowHierarchySidebar(!showHierarchySidebar);
              }}
              className="refresh-btn hierarchy-toggle-btn"
              title={showHierarchySidebar ? "Hide Hierarchy" : "Show Hierarchy"}
            >
              {showHierarchySidebar ? '◀' : '▶'} Sites
            </button>
          )}
          {/* Overlays toggle button */}
          <button
            onClick={() => {
              if (!showOverlaysSidebar) {
                setShowHierarchySidebar(false); // Close sites if opening overlays
              }
              setShowOverlaysSidebar(!showOverlaysSidebar);
            }}
            className="refresh-btn overlays-toggle-btn"
            title={showOverlaysSidebar ? "Hide Overlays" : "Show Overlays"}
          >
            {showOverlaysSidebar ? '◀' : '▶'} Overlays
          </button>
          {/* Terminal button */}
          {hasPermission('run_show_commands') && (
            <button
              onClick={() => setBottomPanelOpen(true)}
              className="refresh-btn terminal-btn"
              title="Open Command Terminal"
            >
              Terminal
            </button>
          )}
          <button
            onClick={() => {
              graphRef.current?.centerAt(0, 0, 0);
              graphRef.current?.zoom(1, 0);
              setTimeout(() => graphRef.current?.zoomToFit(400, 100), 100);
            }}
            className="refresh-btn"
            title="Reset view to fit all nodes"
          >
            Fit View
          </button>
          <button
            onClick={resetLayout}
            className="refresh-btn"
            title="Reset to default topology layout"
            style={{ background: '#6366f1' }}
          >
            Reset Layout
          </button>
        </div>
      </header>

      {error && <div className="error-banner">{error}</div>}

      {/* Hierarchy Breadcrumb Navigation */}
      {hierarchyEnabled && (
        <HierarchyBreadcrumb
          currentLevel={currentLevel}
          hierarchyTree={hierarchyTree}
          onNavigate={navigateToLevel}
        />
      )}

      <div className="main-content">
        <div className="top-section">
          <div className="graph-container" ref={containerRef}>
            {topology && dimensions.width > 0 && dimensions.height > 0 && (
              <ForceGraph2D
                key={`graph-${currentLevel.type}-${currentLevel.id || 'all'}`}
                ref={graphRef}
                width={dimensions.width}
                height={dimensions.height}
                graphData={graphData}
                nodeId="id"
                nodeColor={getNodeColor}
                linkColor={(link: any) => {
                  // BGP links colored when overlay is active
                  if (link.link_type === 'bgp') {
                    return link.session_type === 'ebgp' ? '#f59e0b' : '#22c55e';  // orange for eBGP, green for iBGP
                  }
                  return '#64748b';
                }}
                linkWidth={(link: any) => {
                  if (link.link_type === 'bgp') return 3;
                  return 2;
                }}
                linkDirectionalParticles={2}
                linkDirectionalParticleSpeed={0.005}
                linkCanvasObjectMode={() => (showBgpOverlay || showOspfOverlay) ? 'after' : undefined}
                linkCanvasObject={(showBgpOverlay || showOspfOverlay) ? (link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
                  const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
                  const targetId = typeof link.target === 'object' ? link.target.id : link.target;
                  const sourceNode = typeof link.source === 'object' ? link.source : null;
                  const targetNode = typeof link.target === 'object' ? link.target : null;

                  if (!sourceNode || !targetNode) return;

                  const dx = targetNode.x - sourceNode.x;
                  const dy = targetNode.y - sourceNode.y;
                  const len = Math.sqrt(dx * dx + dy * dy);
                  const nx = -dy / len * 4;
                  const ny = dx / len * 4;
                  const midX = (sourceNode.x + targetNode.x) / 2;
                  const midY = (sourceNode.y + targetNode.y) / 2;

                  if (showBgpOverlay) {
                    const sourceBgp = bgpData[sourceId];
                    const targetBgp = bgpData[targetId];

                    if (sourceBgp && targetBgp) {
                      const loopbackMap: Record<string, string> = {};
                      topology?.nodes?.forEach((n: Node) => { if (n.loopback) loopbackMap[n.id] = n.loopback; });
                      const sourceLoopback = loopbackMap[sourceId] || null;
                      const targetLoopback = loopbackMap[targetId] || null;

                      if (sourceLoopback && targetLoopback) {
                        const bgpSession = sourceBgp.find(n => n.neighbor === targetLoopback);
                        if (bgpSession) {
                          const bgpColor = bgpSession.state === 'Established' ? '#22c55e' :
                                           bgpSession.state === 'Active' ? '#eab308' : '#ef4444';

                          ctx.beginPath();
                          ctx.moveTo(sourceNode.x + nx, sourceNode.y + ny);
                          ctx.lineTo(targetNode.x + nx, targetNode.y + ny);
                          ctx.strokeStyle = bgpColor;
                          ctx.lineWidth = 2 / globalScale;
                          ctx.setLineDash([4 / globalScale, 4 / globalScale]);
                          ctx.stroke();
                          ctx.setLineDash([]);

                          const bgpLabelX = midX + nx * 3;
                          const bgpLabelY = midY + ny * 3;
                          ctx.font = `${8 / globalScale}px Arial`;
                          ctx.fillStyle = bgpColor;
                          ctx.textAlign = 'center';
                          ctx.fillText('BGP', bgpLabelX, bgpLabelY);
                        }
                      }
                    }

                    // Draw label for topology-based BGP links (eBGP to edge1, etc.)
                    if (link.link_type === 'bgp') {
                      const bgpColor = link.session_type === 'ebgp' ? '#f59e0b' : '#22c55e';
                      const labelText = link.session_type === 'ebgp' ? 'eBGP' : 'iBGP';

                      const bgpLabelX = midX + nx * 3;
                      const bgpLabelY = midY + ny * 3;
                      ctx.font = `bold ${8 / globalScale}px Arial`;
                      ctx.fillStyle = bgpColor;
                      ctx.textAlign = 'center';
                      ctx.fillText(labelText, bgpLabelX, bgpLabelY);
                    }
                  }

                  // OSPF Adjacency overlay - show green line for OSPF neighbors
                  if (showOspfOverlay && ospfData) {
                    const sourceOspf = ospfData.devices[sourceId];
                    const targetOspf = ospfData.devices[targetId];

                    if (sourceOspf && targetOspf) {
                      // Use router_id_map from API to resolve neighbor_id → device name
                      const ridMap = ospfData.router_id_map || {};
                      const isOspfNeighbor = sourceOspf.neighbors?.some(
                        (n: any) => n.state === 'FULL' && ridMap[n.neighbor_id] === targetId
                      );

                      if (isOspfNeighbor) {
                        ctx.beginPath();
                        ctx.moveTo(sourceNode.x - nx, sourceNode.y - ny);
                        ctx.lineTo(targetNode.x - nx, targetNode.y - ny);
                        ctx.strokeStyle = '#22c55e';
                        ctx.lineWidth = 3 / globalScale;
                        ctx.stroke();

                        const ospfLabelX = midX - nx * 3;
                        const ospfLabelY = midY - ny * 3;
                        ctx.font = `bold ${8 / globalScale}px Arial`;
                        ctx.fillStyle = '#22c55e';
                        ctx.textAlign = 'center';
                        ctx.fillText('OSPF', ospfLabelX, ospfLabelY);
                      }
                    }
                  }

                } : undefined}
                onNodeClick={(node: any) => setSelectedNode(node)}
                onNodeDragEnd={(node: any) => {
                  node.fx = node.x;
                  node.fy = node.y;
                  nodePositions.current.set(node.id, {
                    x: node.x, y: node.y, fx: node.x, fy: node.y
                  });
                  // Persist to localStorage
                  saveLayout(nodePositions.current);
                }}
                enableNodeDrag={true}
                nodeCanvasObject={drawNode}
                nodePointerAreaPaint={paintPointerArea}
                cooldownTicks={20}
                cooldownTime={100}
                warmupTicks={0}
                d3AlphaDecay={0.5}
                d3VelocityDecay={0.95}
                d3AlphaMin={0.1}
                minZoom={0.1}
                maxZoom={10}
                enablePanInteraction={true}
                enableZoomInteraction={true}
                onEngineStop={() => {
                  // Freeze all nodes in place after simulation stops
                  topology?.nodes.forEach(node => {
                    if (node.x !== undefined && node.y !== undefined) {
                      node.fx = node.x;
                      node.fy = node.y;
                      nodePositions.current.set(node.id, {
                        x: node.x, y: node.y, fx: node.x, fy: node.y
                      });
                    }
                  });
                }}
                onNodeDrag={(node: any) => {
                  // Unfreeze node while dragging
                  node.fx = node.x;
                  node.fy = node.y;
                }}
              />
            )}
          </div>

          <aside className="sidebar">
            {/* Hide legend and stats when a device is selected to give more room to device panel */}
            {!selectedNode && (
              <>
                <div className="legend">
                  <h3>Legend</h3>
                  <div className="legend-item">
                    <span className="shape circle healthy"></span> Router (Healthy)
                  </div>
                  <div className="legend-item">
                    <span className="shape circle degraded"></span> Router (Degraded)
                  </div>
                  <div className="legend-item">
                    <span className="shape rect healthy"></span> Switch (Healthy)
                  </div>
                  <div className="legend-item">
                    <span className="shape rect degraded"></span> Switch (Degraded)
                  </div>
                  <div className="legend-item">
                    <span className="shape diamond healthy"></span> Linux Host
                  </div>
                  <div className="legend-item">
                    <span className="shape circle critical"></span> Critical
                  </div>
                </div>

                <div className="stats">
                  <h3>Network Stats</h3>
                  {topology && (
                    <>
                      <p>Total Devices: {topology.nodes.length}</p>
                      <p>Routers: {topology.nodes.filter(n => !isSwitch(n) && !isLinuxHost(n)).length}</p>
                      <p>Switches: {topology.nodes.filter(n => isSwitch(n)).length}</p>
                      <p>Linux Hosts: {topology.nodes.filter(n => isLinuxHost(n)).length}</p>
                      <p>Links: {topology.links.length}</p>
                    </>
                  )}
                </div>
              </>
            )}

            {selectedNode ? (
              <div className="node-details">
                <h3>Selected Device</h3>
                <p><strong>Name:</strong> {selectedNode.id}</p>
                <p><strong>Type:</strong> {isLinuxHost(selectedNode) ? 'Linux Host' : isSwitch(selectedNode) ? 'Switch' : 'Router'}</p>
                <p><strong>IP:</strong> {selectedNode.ip}</p>
                <p><strong>Platform:</strong> {selectedNode.platform || 'Unknown'}</p>
                <p><strong>Status:</strong> <span className={`status-${selectedNode.status}`}>{selectedNode.status}</span></p>

                {!isLinuxHost(selectedNode) && (
                  <div className="interface-list">
                    <h4>
                      Interfaces
                      {(isContainerlabDevice(selectedNode) ? containerlabHealthLoading : interfacesLoading) && <span className="loading-sm">...</span>}
                      {!(isContainerlabDevice(selectedNode) ? containerlabHealthLoading : interfacesLoading) && selectedNode && (
                        <button
                          className="intf-refresh-btn"
                          onClick={() => isContainerlabDevice(selectedNode) ? fetchContainerlabHealth(selectedNode.id) : fetchDeviceInterfaces(selectedNode.id)}
                          title="Refresh interfaces"
                        >
                          ↻
                        </button>
                      )}
                    </h4>
                    {deviceInterfaces.length > 0 ? (
                      <div className="interfaces">
                        {deviceInterfaces.map(intf => (
                          <div key={intf.name} className={`interface-row ${intf.admin_status === 'admin_down' ? 'down' : intf.line_protocol === 'up' ? 'up' : 'down'}`}>
                            <div className="intf-info">
                              <span className="intf-name">
                                {intf.name}
                                {intf.ip && <span className="intf-ip">{intf.ip}</span>}
                              </span>
                              <span className="intf-status">
                                <span className={`status-dot ${intf.admin_status === 'admin_down' ? 'admin-down' : intf.line_protocol === 'up' ? 'up' : 'down'}`}></span>
                                {intf.admin_status === 'admin_down' ? 'Admin Down' :
                                 intf.line_protocol === 'up' ? 'Up' : 'Down'}
                              </span>
                            </div>
                            {hasPermission('remediate_interfaces') && intf.admin_status === 'admin_down' && (
                              <button
                                className="remediate-btn"
                                onClick={() => remediateInterface(selectedNode.id, intf.name, 'no_shutdown')}
                                disabled={remediating === intf.name}
                              >
                                {remediating === intf.name ? '...' : 'Enable'}
                              </button>
                            )}
                            {hasPermission('remediate_interfaces') && intf.admin_status !== 'admin_down' && (
                              <button
                                className="remediate-btn bounce"
                                onClick={() => remediateInterface(selectedNode.id, intf.name, 'bounce')}
                                disabled={remediating === intf.name}
                              >
                                {remediating === intf.name ? '...' : 'Bounce'}
                              </button>
                            )}
                            {hasPermission('remediate_interfaces') && intf.acl_in && (
                              <button
                                className="remediate-btn danger"
                                onClick={() => remediateInterface(selectedNode.id, intf.name, 'remove_acl', intf.acl_in)}
                                disabled={remediating === intf.name}
                              >
                                {remediating === intf.name ? '...' : 'Remove ACL'}
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : !(isContainerlabDevice(selectedNode) ? containerlabHealthLoading : interfacesLoading) && (
                      <p className="hint">No interfaces found</p>
                    )}
                  </div>
                )}

                {isLinuxHost(selectedNode) && (
                  <div className="linux-health">
                    <h4>System Health {linuxHealthLoading && <span className="loading-sm">...</span>}</h4>
                    {linuxHealth ? (
                      <div className="health-metrics">
                        <p><strong>Uptime:</strong> {linuxHealth.uptime || 'N/A'}</p>
                        <p><strong>Memory:</strong> {linuxHealth.memory.percent}% used ({linuxHealth.memory.used}MB / {linuxHealth.memory.total}MB)</p>
                        <p><strong>Disk:</strong> {linuxHealth.disk.percent}% used ({linuxHealth.disk.used} / {linuxHealth.disk.total})</p>
                        <p><strong>Gateway:</strong>{' '}
                          <span className={linuxHealth.network.gateway_reachable ? 'status-healthy' : 'status-critical'}>
                            {linuxHealth.network.gateway_reachable ? 'Reachable' : 'Unreachable'}
                          </span>
                        </p>
                      </div>
                    ) : !linuxHealthLoading && (
                      <p className="hint">Unable to fetch health data</p>
                    )}
                  </div>
                )}

                {isContainerlabDevice(selectedNode) && (
                  <div className="containerlab-health">
                    <h4>Container Health {containerlabHealthLoading && <span className="loading-sm">...</span>}</h4>
                    {containerlabHealth ? (
                      <div className="health-metrics">
                        <p><strong>Container:</strong>{' '}
                          <span className={containerlabHealth.container_status === 'running' ? 'status-healthy' : 'status-critical'}>
                            {containerlabHealth.container_status}
                          </span>
                        </p>
                        <p><strong>Uptime:</strong> {containerlabHealth.uptime || 'N/A'}</p>
                        <p><strong>Memory:</strong> {containerlabHealth.memory.percent} ({containerlabHealth.memory.used} / {containerlabHealth.memory.limit})</p>
                      </div>
                    ) : !containerlabHealthLoading && (
                      <p className="hint">Unable to fetch health data</p>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="node-details">
                <h3>Selected Device</h3>
                <p className="hint">Click a device to see details</p>
              </div>
            )}
          </aside>
        </div>

        {/* Command Terminal Modal */}
        {bottomPanelOpen && (
          <div className="terminal-modal-overlay" onClick={() => setBottomPanelOpen(false)}>
            <div className="terminal-modal" onClick={e => e.stopPropagation()}>
              <div className="terminal-modal-header">
                <h3>Command Terminal</h3>
                <button className="close-btn" onClick={() => setBottomPanelOpen(false)}>×</button>
              </div>
              <div className="command-input-bar">
                <select
                  value={commandDevice}
                  onChange={(e) => { setCommandDevice(e.target.value); setCommandText(''); }}
                >
                  <option value="">Select Device</option>
                  {deviceList.map(d => (
                    <option key={d} value={d}>{d}</option>
                  ))}
                </select>

                {hasPermission('run_config_commands') ? (
                  <input
                    type="text"
                    placeholder="Enter command..."
                    value={commandText}
                    onChange={(e) => setCommandText(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && executeCommand()}
                    autoFocus
                  />
                ) : (
                  <select
                    value={commandText}
                    onChange={(e) => setCommandText(e.target.value)}
                  >
                    <option value="">Select Command</option>
                    {commandDevice && getCommandsForDevice(commandDevice).map(cmd => (
                      <option key={cmd} value={cmd}>{cmd}</option>
                    ))}
                  </select>
                )}

                <button
                  className="execute-btn"
                  onClick={executeCommand}
                  disabled={isExecuting || !commandDevice || !commandText}
                >
                  {isExecuting ? 'Running...' : 'Execute'}
                </button>
              </div>

              <div className={`command-output ${commandError ? 'error' : ''}`}>
                {commandOutput || (
                  <span className="placeholder">
                    Select a device and command, then click Execute.
                  </span>
                )}
              </div>
            </div>
          </div>
        )}

        {/* DMVPN Panel */}
        {showDmvpnPanel && dmvpnData && (
          <div className="dmvpn-panel">
            <div className="dmvpn-panel-header">
              <h3>DMVPN Fabric Status</h3>
              <div className="dmvpn-summary">
                <span>Hub: {dmvpnData.hub} ({dmvpnData.tunnel})</span>
                <span className={`status-badge ${dmvpnData.peers_up === dmvpnData.peer_count ? 'running' : 'degraded'}`}>
                  {dmvpnData.peers_up}/{dmvpnData.peer_count} UP
                </span>
              </div>
              <button className="close-btn" onClick={() => { setShowDmvpnPanel(false); setShowDmvpnOverlay(false); }}>×</button>
            </div>
            <div className="dmvpn-content">
              <table className="dmvpn-table">
                <thead>
                  <tr>
                    <th>Peer</th>
                    <th>Tunnel IP</th>
                    <th>NBMA Address</th>
                    <th>State</th>
                    <th>Uptime</th>
                  </tr>
                </thead>
                <tbody>
                  {dmvpnData.peers.map(peer => (
                    <tr key={peer.name}>
                      <td className="peer-name">{peer.name}</td>
                      <td className="tunnel-ip">{peer.tunnel_addr}</td>
                      <td className="nbma-addr">{peer.nbma_addr}</td>
                      <td className={peer.state === 'UP' ? 'state-up' : 'state-down'}>
                        {peer.state}
                      </td>
                      <td className="uptime">{peer.uptime}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Switch Fabric Panel */}
        {showSwitchPanel && switchData && (
          <div className="switch-panel">
            <div className="switch-panel-header">
              <h3>Switch Fabric Status</h3>
              <div className="switch-summary">
                <span className={`status-badge ${switchData.healthy === switchData.total ? 'running' : 'degraded'}`}>
                  {switchData.healthy}/{switchData.total} Healthy
                </span>
                <span>EIGRP AS 100</span>
              </div>
              <button className="close-btn" onClick={() => { setShowSwitchPanel(false); setShowSwitchOverlay(false); }}>×</button>
            </div>
            <div className="switch-content">
              <table className="switch-table">
                <thead>
                  <tr>
                    <th>Switch</th>
                    <th>Loopback</th>
                    <th>Uplink</th>
                    <th>Upstream Router</th>
                    <th>EIGRP Neighbor</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {switchData.switches.map(sw => (
                    <tr key={sw.name}>
                      <td className="switch-name">{sw.name}</td>
                      <td className="loopback-ip">{sw.loopback}</td>
                      <td className="uplink-info">
                        <span className={sw.uplink_status === 'up' ? 'state-up' : 'state-down'}>
                          {sw.uplink_ip || 'N/A'}
                        </span>
                      </td>
                      <td className="upstream-router">{sw.upstream_router}</td>
                      <td className="eigrp-neighbor">
                        {sw.eigrp_neighbor ? (
                          <span className="state-up">
                            {sw.eigrp_neighbor.neighbor_ip} ({sw.eigrp_neighbor.uptime})
                          </span>
                        ) : (
                          <span className="state-down">No neighbor</span>
                        )}
                      </td>
                      <td className={`status-${sw.status}`}>{sw.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Real-time Telemetry Panel */}
        {showTelemetryPanel && (
          <div className="telemetry-panel">
            <div className="telemetry-panel-header">
              <h3>Real-time Telemetry (MDT)</h3>
              <div className="telemetry-status">
                <span className={`status-badge ${telemetryConnected ? 'running' : 'stopped'}`}>
                  {telemetryConnected ? 'Connected' : 'Disconnected'}
                </span>
                <span className="update-interval">5s interval</span>
              </div>
              <button className="close-btn" onClick={() => setShowTelemetryPanel(false)}>×</button>
            </div>
            <div className="telemetry-content">
              {telemetryData ? (
                <>
                  <div className="telemetry-grid">
                    {/* Show devices that have telemetry data (C8000V routers with MDT configured) */}
                    {Object.keys(telemetryData.last_update).length > 0 ?
                      Object.keys(telemetryData.last_update).sort().map(device => {
                      const cpu = telemetryData.cpu[device];
                      const mem = telemetryData.memory[device];
                      const intfs = telemetryData.interfaces[device] || {};
                      const intfCount = Object.keys(intfs).length;
                      const totalIn = Object.values(intfs).reduce((sum: number, i: any) => sum + (i?.in_octets || 0), 0);
                      const totalOut = Object.values(intfs).reduce((sum: number, i: any) => sum + (i?.out_octets || 0), 0);

                      return (
                        <div key={device} className="telemetry-card">
                          <div className="card-header">
                            <h4>{device}</h4>
                            <span className={`card-status ${telemetryData.last_update[device] ? 'active' : 'inactive'}`}>
                              {telemetryData.last_update[device] ? '●' : '○'}
                            </span>
                          </div>
                          <div className="telemetry-metrics">
                            <div className="metric">
                              <span className="metric-label">CPU (5s avg)</span>
                              <span className="metric-value">
                                {cpu?.five_seconds !== undefined ? `${cpu.five_seconds}%` : '--'}
                              </span>
                              {cpu?.five_seconds !== undefined && (
                                <div className="metric-bar">
                                  <div
                                    className={`metric-bar-fill cpu ${cpu.five_seconds > 80 ? 'critical' : cpu.five_seconds > 50 ? 'warning' : ''}`}
                                    style={{ width: `${Math.min(cpu.five_seconds, 100)}%` }}
                                  />
                                </div>
                              )}
                            </div>
                            <div className="metric">
                              <span className="metric-label">Memory</span>
                              <div className="metric-row">
                                <span className="metric-value">
                                  {mem?.percent_used !== undefined ? `${mem.percent_used}%` : '--'}
                                </span>
                                {mem?.used !== undefined && mem?.total !== undefined && (
                                  <span className="metric-detail">
                                    {(mem.used / 1024 / 1024 / 1024).toFixed(1)}GB / {(mem.total / 1024 / 1024 / 1024).toFixed(1)}GB
                                  </span>
                                )}
                              </div>
                              {mem?.percent_used !== undefined && (
                                <div className="metric-bar">
                                  <div
                                    className={`metric-bar-fill memory ${mem.percent_used > 90 ? 'critical' : mem.percent_used > 70 ? 'warning' : ''}`}
                                    style={{ width: `${Math.min(mem.percent_used, 100)}%` }}
                                  />
                                </div>
                              )}
                            </div>
                            <div className="metric">
                              <span className="metric-label">Interfaces</span>
                              <span className="metric-value">{intfCount > 0 ? intfCount : '--'}</span>
                            </div>
                            <div className="metric traffic">
                              <span className="metric-label">Traffic</span>
                              <div className="traffic-stats">
                                <span className="traffic-in">↓ {formatBytes(totalIn)}</span>
                                <span className="traffic-out">↑ {formatBytes(totalOut)}</span>
                              </div>
                            </div>
                            <div className="metric">
                              <span className="metric-label">Updated</span>
                              <span className="metric-value timestamp">
                                {telemetryData.last_update[device]
                                  ? new Date(telemetryData.last_update[device]).toLocaleTimeString()
                                  : '--'}
                              </span>
                            </div>
                          </div>
                        </div>
                      );
                    }) : (
                      <div className="telemetry-empty">
                        <p>No devices streaming yet</p>
                        <p className="hint">MDT configured on: R1-R4 (C8000V), Switch-R1/R2/R4 (Cat9kv)</p>
                      </div>
                    )}
                  </div>
                  <div className="telemetry-summary">
                    <div className="summary-item">
                      <span className="summary-label">Streaming Devices</span>
                      <span className="summary-value">{Object.keys(telemetryData.last_update).length} devices</span>
                    </div>
                    <div className="summary-item">
                      <span className="summary-label">Subscriptions</span>
                      <span className="summary-value">Interface Stats, CPU, Memory</span>
                    </div>
                  </div>
                </>
              ) : (
                <div className="telemetry-empty">
                  <p>Waiting for telemetry data...</p>
                  <p className="hint">Pipeline: Devices → Telegraf (:57000) → API (:5001) → Dashboard</p>
                  <p className="hint">MDT configured on: R1-R4 (C8000V), Switch-R1/R2/R4 (Cat9kv)</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Event Log Panel */}
        {showEventsPanel && (
          <div className="events-panel">
            <div className="events-panel-header">
              <h3>Event Log</h3>
              <div className="events-controls">
                <select
                  value={eventsFilter}
                  onChange={(e) => setEventsFilter(e.target.value)}
                  className="events-filter"
                >
                  <option value="all">All Devices</option>
                  {deviceList.map(d => (
                    <option key={d} value={d}>{d}</option>
                  ))}
                </select>
                <span className="event-count">{events.length} events</span>
                {eventsLoading && <span className="loading-indicator">...</span>}
              </div>
              <button className="close-btn" onClick={() => setShowEventsPanel(false)}>×</button>
            </div>
            <div className="events-content">
              <table className="events-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Device</th>
                    <th>Action</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event, idx) => (
                    <React.Fragment key={idx}>
                      <tr
                        className={`event-row ${expandedEvent === idx ? 'expanded' : ''}`}
                        onClick={() => setExpandedEvent(expandedEvent === idx ? null : idx)}
                      >
                        <td>{formatEventTime(event.timestamp)}</td>
                        <td>{event.device}</td>
                        <td className={`action-${event.action}`}>{event.action}</td>
                        <td className={`status-${event.status}`}>{event.status}</td>
                      </tr>
                      {expandedEvent === idx && (
                        <tr className="event-details-row">
                          <td colSpan={4}>
                            <div className="event-details">
                              <span><strong>Role:</strong> {event.role}</span>
                              <span><strong>Details:</strong> {event.details}</span>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
              {events.length === 0 && !eventsLoading && (
                <div className="events-empty">No events recorded</div>
              )}
            </div>
          </div>
        )}

        {/* RAG Chat Panel */}
        {showChatPanel && (
          <div className="chat-panel">
            <div className="chat-panel-header">
              <h3>Documentation Assistant</h3>
              <button className="close-btn" onClick={() => setShowChatPanel(false)}>×</button>
            </div>
            <div className="chat-messages" ref={chatMessagesRef}>
              {chatMessages.length === 0 && (
                <div className="chat-welcome">
                  <p>Ask questions about network documentation.</p>
                  <p className="hint">Example: "How do I configure OSPF?"</p>
                </div>
              )}
              {chatMessages.map((msg, idx) => (
                <div key={idx} className={`chat-message ${msg.role}`}>
                  <div className="message-content">{msg.content}</div>
                  {msg.sources && msg.sources.length > 0 && (
                    <div className="message-sources">
                      <span className="sources-label">Sources:</span>
                      {msg.sources.map((src, srcIdx) => (
                        <span key={srcIdx} className="source-tag" title={src.path}>
                          {src.file}{src.page && ` (p.${src.page})`}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {chatLoading && (
                <div className="chat-message assistant loading">
                  <div className="typing-indicator">
                    <span></span><span></span><span></span>
                  </div>
                </div>
              )}
            </div>
            <div className="chat-input-wrapper">
              <div className="chat-model-row">
                <span className="chat-model-label">Model:</span>
                <select
                  className="chat-model-select"
                  value={chatModel}
                  onChange={(e) => setChatModel(e.target.value)}
                  disabled={chatLoading}
                >
                  {CLAUDE_MODELS.map(m => (
                    <option key={m.id} value={m.id}>{m.name} - {m.desc}</option>
                  ))}
                </select>
              </div>
              <div className="chat-input-container">
                <input
                  type="text"
                  className="chat-input"
                  placeholder="Ask a question..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && sendChatMessage()}
                  disabled={chatLoading}
                />
                <button
                  className="chat-send-btn"
                  onClick={sendChatMessage}
                  disabled={chatLoading || !chatInput.trim()}
                >
                  Send
                </button>
              </div>
            </div>
          </div>
        )}

        {/* User Management Panel */}
        <UserManagement
          isOpen={showUserManagement}
          onClose={() => setShowUserManagement(false)}
        />

        {/* Add Device Modal */}
        <AddDeviceModal
          isOpen={showAddDeviceModal}
          onClose={() => setShowAddDeviceModal(false)}
          onDeviceAdded={() => {
            // Refresh topology after device is added
            fetchTopology();
          }}
        />

        {/* MTU Calculator Modal */}
        <MTUCalculator
          isOpen={showMTUCalculator}
          onClose={() => setShowMTUCalculator(false)}
        />
        <SubnetCalculator
          isOpen={showSubnetCalculator}
          onClose={() => setShowSubnetCalculator(false)}
        />
        <ImpactAnalysis
          isOpen={showImpactAnalysis}
          onClose={() => setShowImpactAnalysis(false)}
        />
        <ImpactTrending
          isOpen={showImpactTrending}
          onClose={() => setShowImpactTrending(false)}
        />
        <IntentDriftEngine
          isOpen={showIntentDrift}
          onClose={() => setShowIntentDrift(false)}
        />

        {/* Change Management Panel */}
        <ChangeManagement
          isOpen={showChangeManagement}
          onClose={() => setShowChangeManagement(false)}
        />

      </div>
    </div>
  );
}

export default App;