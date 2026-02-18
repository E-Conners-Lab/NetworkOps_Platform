"""
Network Dependency Graph for Impact Analysis.

Builds a NetworkX DiGraph from LLDP, BGP, and OSPF discovery data to enable
forward/backward impact analysis and blast radius calculation.

Node types: device, interface
Edge types: physical_link, ospf_adjacency, bgp_peering, route_via

Usage:
    from core.dependency_graph import NetworkDependencyGraph

    graph = NetworkDependencyGraph()
    await graph.build()

    # What breaks if R3 goes down?
    impact = graph.forward_impact("R3")

    # What must be up for R3 to work?
    deps = graph.backward_dependencies("R3")

    # Blast radius of a specific interface going down
    blast = graph.blast_radius("R3", "GigabitEthernet4")
"""

import json
import logging
from core.timestamps import isonow
from typing import Optional

import networkx as nx
from networkx.readwrite import json_graph

from core.unified_db import UnifiedDB

logger = logging.getLogger(__name__)


class NetworkDependencyGraph:
    """
    NetworkX-based dependency graph for network infrastructure.
    """

    def __init__(self, db: UnifiedDB = None):
        self.db = db or UnifiedDB.get_instance()
        self.graph: nx.DiGraph = nx.DiGraph()

    async def build(self) -> nx.DiGraph:
        """
        Build the dependency graph from live discovery data.

        Uses LLDP for physical links, BGP for peering, and OSPF for adjacencies.
        """
        self.graph = nx.DiGraph()

        # Collect topology data
        try:
            from core.topology_helpers import discover_topology
            topology = discover_topology(telemetry_data=None)
        except Exception as e:
            logger.error(f"Failed to discover topology for graph: {e}")
            topology = {"nodes": [], "links": [], "bgp_links": []}

        nodes = topology.get("nodes", [])
        links = topology.get("links", [])
        bgp_links = topology.get("bgp_links", [])

        # Add device nodes
        for node in nodes:
            name = node.get("id") or node.get("name", "")
            if not name:
                continue
            self.graph.add_node(
                name,
                node_type="device",
                platform=node.get("platform", "unknown"),
                status=node.get("status", "unknown"),
                group=node.get("group", ""),
            )

        # Add physical links (bidirectional)
        for link in links:
            src = link.get("source", "")
            tgt = link.get("target", "")
            if not src or not tgt:
                continue

            src_intf = link.get("source_intf", "")
            tgt_intf = link.get("target_intf", "")

            # Add interface nodes
            if src_intf:
                intf_id = f"{src}:{src_intf}"
                self.graph.add_node(intf_id, node_type="interface", device=src)
                self.graph.add_edge(src, intf_id, edge_type="has_interface")
                self.graph.add_edge(intf_id, src, edge_type="belongs_to")

            if tgt_intf:
                intf_id = f"{tgt}:{tgt_intf}"
                self.graph.add_node(intf_id, node_type="interface", device=tgt)
                self.graph.add_edge(tgt, intf_id, edge_type="has_interface")
                self.graph.add_edge(intf_id, tgt, edge_type="belongs_to")

            # Physical link between devices
            self.graph.add_edge(
                src, tgt,
                edge_type="physical_link",
                source_intf=src_intf,
                target_intf=tgt_intf,
            )
            self.graph.add_edge(
                tgt, src,
                edge_type="physical_link",
                source_intf=tgt_intf,
                target_intf=src_intf,
            )

        # Add BGP peering edges
        for bgp_link in bgp_links:
            src = bgp_link.get("source", "")
            tgt = bgp_link.get("target", "")
            if not src or not tgt:
                continue

            self.graph.add_edge(
                src, tgt,
                edge_type="bgp_peering",
                session_type=bgp_link.get("session_type", ""),
                state=bgp_link.get("state", ""),
            )

        # Add OSPF adjacency edges from snapshot data if available
        self._add_ospf_edges()

        logger.info(
            f"Dependency graph built: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

        # Persist
        self.save()

        return self.graph

    def _add_ospf_edges(self):
        """Add OSPF adjacency edges from the most recent snapshots."""
        try:
            with self.db.connect() as conn:
                conn.row_factory = __import__("sqlite3").Row
                # Get the most recent snapshot per device
                rows = conn.execute("""
                    SELECT device, ospf_neighbors
                    FROM snapshots
                    WHERE ospf_neighbors IS NOT NULL
                    AND timestamp = (
                        SELECT MAX(s2.timestamp) FROM snapshots s2
                        WHERE s2.device = snapshots.device
                    )
                """).fetchall()

            # Build loopback-to-device map for resolving neighbor IDs
            from config.devices import LOOPBACK_MAP
            loopback_to_device = {v: k for k, v in LOOPBACK_MAP.items()}

            for row in rows:
                device = row["device"]
                neighbors = json.loads(row["ospf_neighbors"] or "[]")
                for n in neighbors:
                    nid = n.get("neighbor_id", "")
                    peer_device = loopback_to_device.get(nid)
                    if peer_device and peer_device in self.graph:
                        self.graph.add_edge(
                            device, peer_device,
                            edge_type="ospf_adjacency",
                            state=n.get("state", ""),
                            interface=n.get("interface", ""),
                        )

        except Exception as e:
            logger.warning(f"Failed to add OSPF edges: {e}")

    def forward_impact(self, device: str) -> dict:
        """
        Determine what breaks if a device goes down.

        Traces all downstream dependencies using BFS.
        """
        if device not in self.graph:
            return {
                "device": device,
                "affected_devices": [],
                "affected_services": [],
                "total_affected": 0,
                "error": f"Device '{device}' not in graph",
            }

        # Find all nodes reachable from this device (downstream)
        affected = set()
        for successor in nx.descendants(self.graph, device):
            node_data = self.graph.nodes.get(successor, {})
            if node_data.get("node_type") == "device":
                affected.add(successor)

        # Remove the device itself
        affected.discard(device)

        # Classify by edge types
        bgp_affected = set()
        ospf_affected = set()
        physical_affected = set()

        for neighbor in self.graph.successors(device):
            edge_data = self.graph.edges[device, neighbor]
            edge_type = edge_data.get("edge_type", "")
            target = neighbor
            node_data = self.graph.nodes.get(neighbor, {})
            if node_data.get("node_type") == "interface":
                target = node_data.get("device", neighbor)

            if edge_type == "bgp_peering":
                bgp_affected.add(target)
            elif edge_type == "ospf_adjacency":
                ospf_affected.add(target)
            elif edge_type == "physical_link":
                physical_affected.add(target)

        result = {
            "device": device,
            "affected_devices": sorted(affected),
            "direct_neighbors": sorted(
                set(self.graph.successors(device))
                & set(n for n in self.graph if self.graph.nodes[n].get("node_type") == "device")
            ),
            "bgp_affected": sorted(bgp_affected),
            "ospf_affected": sorted(ospf_affected),
            "physical_affected": sorted(physical_affected),
            "total_affected": len(affected),
        }
        result["findings"] = self._generate_findings("forward", device, result)
        return result

    def backward_dependencies(self, device: str) -> dict:
        """
        Determine what must be up for a device to work.

        Traces all upstream dependencies.
        """
        if device not in self.graph:
            return {
                "device": device,
                "dependencies": [],
                "total_dependencies": 0,
                "error": f"Device '{device}' not in graph",
            }

        # Find all ancestors (what must be up for this device)
        ancestors = set()
        for predecessor in nx.ancestors(self.graph, device):
            node_data = self.graph.nodes.get(predecessor, {})
            if node_data.get("node_type") == "device":
                ancestors.add(predecessor)

        ancestors.discard(device)

        result = {
            "device": device,
            "dependencies": sorted(ancestors),
            "direct_dependencies": sorted(
                set(self.graph.predecessors(device))
                & set(n for n in self.graph if self.graph.nodes[n].get("node_type") == "device")
            ),
            "total_dependencies": len(ancestors),
        }
        result["findings"] = self._generate_findings("backward", device, result)
        return result

    # Cisco interface abbreviation map (LLDP uses short names)
    _INTF_ABBREVS = {
        "GigabitEthernet": "Gi",
        "TenGigabitEthernet": "Te",
        "FastEthernet": "Fa",
        "Loopback": "Lo",
        "Tunnel": "Tu",
        "Vlan": "Vl",
        "Port-channel": "Po",
    }

    def _resolve_interface_node(self, device: str, interface: str) -> str | None:
        """Resolve an interface name to its graph node ID.

        Handles mismatches between full names (GigabitEthernet4) and
        LLDP-abbreviated names (Gi4) stored in the graph.
        """
        exact = f"{device}:{interface}"
        if exact in self.graph:
            return exact

        # Try abbreviating: GigabitEthernet4 -> Gi4
        for full, short in self._INTF_ABBREVS.items():
            if interface.startswith(full):
                abbrev = short + interface[len(full):]
                candidate = f"{device}:{abbrev}"
                if candidate in self.graph:
                    return candidate

        # Try expanding: Gi4 -> GigabitEthernet4
        for full, short in self._INTF_ABBREVS.items():
            if interface.startswith(short) and not interface.startswith(full):
                expanded = full + interface[len(short):]
                candidate = f"{device}:{expanded}"
                if candidate in self.graph:
                    return candidate

        return None

    def blast_radius(self, device: str, interface: str) -> dict:
        """
        Calculate blast radius of a specific interface going down.

        More precise than device-level forward_impact because it only
        considers paths through the specific interface.
        """
        intf_node = self._resolve_interface_node(device, interface)

        if intf_node is None:
            # Fall back to device-level analysis
            result = self.forward_impact(device)
            result["interface"] = interface
            result["note"] = "Interface not in graph, showing device-level impact"
            return result

        # Find what's connected through this interface
        affected = set()
        for successor in nx.descendants(self.graph, intf_node):
            node_data = self.graph.nodes.get(successor, {})
            if node_data.get("node_type") == "device":
                affected.add(successor)

        affected.discard(device)

        # Check direct connections through this interface
        direct = set()
        for successor in self.graph.successors(intf_node):
            node_data = self.graph.nodes.get(successor, {})
            if node_data.get("node_type") == "device":
                direct.add(successor)
        direct.discard(device)

        # Device-level edges (physical_link, bgp_peering, ospf_adjacency)
        # store the interface in source_intf metadata. Match against both
        # the abbreviated graph name and the full user-provided name.
        intf_short = intf_node.split(":", 1)[1] if ":" in intf_node else interface
        match_names = {intf_short, interface}
        for _, tgt, data in self.graph.edges(device, data=True):
            etype = data.get("edge_type", "")
            if etype in ("physical_link", "bgp_peering", "ospf_adjacency"):
                src_intf = data.get("source_intf", "") or data.get("interface", "")
                if src_intf in match_names:
                    tgt_data = self.graph.nodes.get(tgt, {})
                    if tgt_data.get("node_type") == "device":
                        direct.add(tgt)

        result = {
            "device": device,
            "interface": interface,
            "affected_devices": sorted(affected),
            "directly_connected": sorted(direct),
            "total_affected": len(affected),
        }
        result["findings"] = self._generate_findings("blast-radius", device, result)
        return result

    def _generate_findings(self, analysis_type: str, device: str, result: dict) -> dict:
        """Generate human-readable findings from impact analysis results.

        Returns dict with risk_level, summary, findings list, and warnings.
        """
        findings = []
        warnings = []

        if analysis_type == "forward":
            total = result.get("total_affected", 0)
            direct = result.get("direct_neighbors", [])
            bgp = result.get("bgp_affected", [])
            ospf = result.get("ospf_affected", [])
            physical = result.get("physical_affected", [])

            # Risk level
            if total == 0:
                risk = "low"
                summary = f"{device} has no downstream dependencies. Taking it offline has minimal impact."
            elif total <= 3:
                risk = "medium"
                summary = f"If {device} goes down, {total} device(s) are affected."
            else:
                risk = "high"
                summary = f"If {device} goes down, {total} devices are affected across the network."

            # Direct neighbor findings
            if direct:
                findings.append(f"{len(direct)} directly connected device(s): {', '.join(direct[:5])}{'...' if len(direct) > 5 else ''}.")

            if ospf:
                findings.append(f"OSPF adjacencies affected: {', '.join(ospf)}. Routes through these neighbors will reconverge.")
            if bgp:
                findings.append(f"BGP peerings affected: {', '.join(bgp)}. External route exchange will be disrupted.")
            if physical:
                findings.append(f"Physical links affected: {', '.join(physical)}. These devices lose direct connectivity.")

            # Single-point-of-failure detection
            for neighbor in direct:
                if neighbor not in self.graph:
                    continue
                # Count how many device-level predecessors this neighbor has (excluding interfaces)
                upstream_devices = set()
                for pred in self.graph.predecessors(neighbor):
                    pred_data = self.graph.nodes.get(pred, {})
                    if pred_data.get("node_type") == "device" and pred != neighbor:
                        upstream_devices.add(pred)
                    elif pred_data.get("node_type") == "interface":
                        parent = pred_data.get("device", "")
                        if parent and parent != neighbor:
                            upstream_devices.add(parent)
                if len(upstream_devices) <= 1:
                    warnings.append(f"{neighbor} has no redundant upstream path — {device} is its single point of failure.")

        elif analysis_type == "backward":
            total = result.get("total_dependencies", 0)
            direct = result.get("direct_dependencies", [])

            if total == 0:
                risk = "low"
                summary = f"{device} has no upstream dependencies. It operates independently."
            elif total <= 3:
                risk = "medium"
                summary = f"{device} depends on {total} upstream device(s) to function."
            else:
                risk = "high"
                summary = f"{device} has a deep dependency chain of {total} devices."

            if direct:
                findings.append(f"Direct upstream dependencies: {', '.join(direct)}. If any of these go down, {device} is immediately impacted.")

            # Check if device has single upstream
            if len(direct) == 1:
                warnings.append(f"{device} has only one upstream path through {direct[0]} — no redundancy.")
            elif len(direct) >= 2:
                findings.append(f"{device} has {len(direct)} direct upstream paths, providing some redundancy.")

        elif analysis_type == "blast-radius":
            total = result.get("total_affected", 0)
            interface = result.get("interface", "unknown")
            direct_connected = result.get("directly_connected", result.get("direct_neighbors", []))

            if total == 0:
                risk = "low"
                summary = f"Shutting down {device} {interface} has no downstream impact."
            elif total <= 3:
                risk = "medium"
                summary = f"Shutting down {device} {interface} affects {total} device(s)."
            else:
                risk = "high"
                summary = f"Shutting down {device} {interface} has a wide blast radius of {total} devices."

            if direct_connected:
                findings.append(f"Directly connected through this interface: {', '.join(direct_connected)}.")

            if result.get("note"):
                findings.append(result["note"])

            # Check for single-point-of-failure on directly connected devices
            for neighbor in direct_connected:
                if neighbor not in self.graph:
                    continue
                upstream_devices = set()
                for pred in self.graph.predecessors(neighbor):
                    pred_data = self.graph.nodes.get(pred, {})
                    if pred_data.get("node_type") == "device" and pred != neighbor:
                        upstream_devices.add(pred)
                    elif pred_data.get("node_type") == "interface":
                        parent = pred_data.get("device", "")
                        if parent and parent != neighbor:
                            upstream_devices.add(parent)
                if len(upstream_devices) <= 1:
                    warnings.append(f"{neighbor} loses all connectivity — this interface is its only uplink through {device}.")

        else:
            risk = "unknown"
            summary = "Analysis complete."

        return {
            "risk_level": risk,
            "summary": summary,
            "findings": findings,
            "warnings": warnings,
        }

    def save(self):
        """Persist graph to the dependency_graph table."""
        try:
            graph_data = json_graph.node_link_data(self.graph)
            with self.db.connect() as conn:
                conn.execute("""
                    INSERT INTO dependency_graph
                    (captured_at, graph_json, node_count, edge_count)
                    VALUES (?, ?, ?, ?)
                """, (
                    isonow(),
                    json.dumps(graph_data),
                    self.graph.number_of_nodes(),
                    self.graph.number_of_edges(),
                ))
                conn.commit()
            logger.info("Dependency graph saved to database")
        except Exception as e:
            logger.error(f"Failed to save dependency graph: {e}")

    def load_latest(self) -> bool:
        """Load the most recent graph from the database."""
        try:
            with self.db.connect() as conn:
                conn.row_factory = __import__("sqlite3").Row
                row = conn.execute("""
                    SELECT graph_json FROM dependency_graph
                    ORDER BY captured_at DESC LIMIT 1
                """).fetchone()

            if not row:
                return False

            graph_data = json.loads(row["graph_json"])
            self.graph = json_graph.node_link_graph(graph_data, directed=True)
            logger.info(
                f"Loaded dependency graph: {self.graph.number_of_nodes()} nodes, "
                f"{self.graph.number_of_edges()} edges"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to load dependency graph: {e}")
            return False

    def to_dict(self) -> dict:
        """Export graph summary as dict."""
        device_nodes = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == "device"
        ]
        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "device_count": len(device_nodes),
            "devices": sorted(device_nodes),
            "edge_types": list(set(
                d.get("edge_type", "unknown")
                for _, _, d in self.graph.edges(data=True)
            )),
        }
