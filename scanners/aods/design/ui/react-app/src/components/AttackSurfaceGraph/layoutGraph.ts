import dagre from 'dagre';
import type { Node, Edge } from '@xyflow/react';

const nodeWidth = 210;
const nodeHeight = 80;
const groupPadding = 40;

/** Adaptive spacing - wider gaps for larger graphs */
function adaptiveSpacing(nodeCount: number): { nodesep: number; ranksep: number } {
  if (nodeCount > 40) return { nodesep: 50, ranksep: 100 };
  if (nodeCount > 20) return { nodesep: 60, ranksep: 120 };
  return { nodesep: 70, ranksep: 140 };
}

/**
 * Separate nodes into connected (have ≥1 edge) and orphan (no edges) sets.
 */
function partitionByConnectivity(
  nodes: Node[],
  edges: Edge[],
): { connected: Node[]; orphans: Node[] } {
  const connectedIds = new Set<string>();
  for (const e of edges) {
    connectedIds.add(e.source);
    connectedIds.add(e.target);
  }
  const connected: Node[] = [];
  const orphans: Node[] = [];
  for (const n of nodes) {
    if (connectedIds.has(n.id)) {
      connected.push(n);
    } else {
      orphans.push(n);
    }
  }
  return { connected, orphans };
}

/**
 * Arrange orphan nodes in a compact grid below the dagre-laid-out area.
 * Sorts orphans: findings-first (by severity), then alphabetically.
 */
function layoutOrphansGrid(
  orphans: Node[],
  startY: number,
  direction: 'LR' | 'TB',
): void {
  if (orphans.length === 0) return;

  const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  orphans.sort((a, b) => {
    const aData = a.data as Record<string, unknown>;
    const bData = b.data as Record<string, unknown>;
    const aCount = (aData.findingCount as number) || 0;
    const bCount = (bData.findingCount as number) || 0;
    // Findings first
    if (aCount > 0 && bCount === 0) return -1;
    if (aCount === 0 && bCount > 0) return 1;
    // By severity
    const aSev = sevOrder[(aData.severity as string) || 'info'] ?? 5;
    const bSev = sevOrder[(bData.severity as string) || 'info'] ?? 5;
    if (aSev !== bSev) return aSev - bSev;
    // Alphabetical
    const aLabel = (aData.label as string) || '';
    const bLabel = (bData.label as string) || '';
    return aLabel.localeCompare(bLabel);
  });

  const gap = 20;
  const cols = direction === 'TB' ? Math.ceil(Math.sqrt(orphans.length * 1.5)) : Math.ceil(Math.sqrt(orphans.length));
  const offsetY = startY + 60; // gap between connected graph and orphan grid

  for (let i = 0; i < orphans.length; i++) {
    const col = i % cols;
    const row = Math.floor(i / cols);
    orphans[i].position = {
      x: col * (nodeWidth + gap),
      y: offsetY + row * (nodeHeight + gap),
    };
  }
}

/**
 * Use dagre to auto-layout connected nodes, then arrange orphans in a grid below.
 */
export function layoutGraph(
  nodes: Node[],
  edges: Edge[],
  direction: 'LR' | 'TB' = 'LR',
): { nodes: Node[]; edges: Edge[] } {
  const { connected, orphans } = partitionByConnectivity(nodes, edges);

  // Layout connected nodes with dagre
  let maxY = 0;
  if (connected.length > 0) {
    const spacing = adaptiveSpacing(connected.length);
    const g = new dagre.graphlib.Graph();
    g.setDefaultEdgeLabel(() => ({}));
    g.setGraph({
      rankdir: direction,
      nodesep: spacing.nodesep,
      ranksep: spacing.ranksep,
      marginx: 30,
      marginy: 30,
    });

    for (const node of connected) {
      g.setNode(node.id, { width: nodeWidth, height: nodeHeight });
    }
    for (const edge of edges) {
      g.setEdge(edge.source, edge.target);
    }

    dagre.layout(g);

    for (const node of connected) {
      const pos = g.node(node.id);
      if (pos) {
        node.position = {
          x: pos.x - nodeWidth / 2,
          y: pos.y - nodeHeight / 2,
        };
        const bottom = node.position.y + nodeHeight;
        if (bottom > maxY) maxY = bottom;
      }
    }
  }

  // Layout orphans in a compact grid below
  layoutOrphansGrid(orphans, maxY, direction);

  return { nodes: [...connected, ...orphans], edges };
}

/**
 * Layout with dagre compound graph - nodes are grouped by package prefix.
 */
export function layoutGraphGrouped(
  nodes: Node[],
  edges: Edge[],
  direction: 'LR' | 'TB' = 'LR',
): { nodes: Node[]; edges: Edge[]; groupNodes: Node[] } {
  const componentTypes = new Set(['activity', 'service', 'receiver', 'provider']);

  const packageMap = new Map<string, string[]>();
  for (const node of nodes) {
    const fullName: string = (node.data as Record<string, unknown>)?.fullName as string || '';
    const nodeType: string = (node.data as Record<string, unknown>)?.nodeType as string || '';
    if (!componentTypes.has(nodeType) || !fullName.includes('.')) continue;
    const parts = fullName.split('.');
    const pkg = parts.slice(0, -1).join('.');
    if (!packageMap.has(pkg)) packageMap.set(pkg, []);
    packageMap.get(pkg)!.push(node.id);
  }

  const groups = new Map<string, string[]>();
  for (const [pkg, ids] of packageMap) {
    if (ids.length >= 2) groups.set(pkg, ids);
  }

  const spacing = adaptiveSpacing(nodes.length);
  const g = new dagre.graphlib.Graph({ compound: true });
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: direction,
    nodesep: spacing.nodesep,
    ranksep: spacing.ranksep,
    marginx: 30,
    marginy: 30,
  });

  const groupNodes: Node[] = [];
  for (const [pkg, ids] of groups) {
    const groupId = `group:${pkg}`;
    const shortPkg = pkg.split('.').slice(-2).join('.');
    g.setNode(groupId, {
      width: (ids.length * (nodeWidth + 40)) + groupPadding * 2,
      height: nodeHeight + groupPadding * 2,
    });
    groupNodes.push({
      id: groupId,
      type: 'group',
      position: { x: 0, y: 0 },
      data: { label: shortPkg, nodeType: 'group' },
      style: { width: (ids.length * (nodeWidth + 40)) + groupPadding * 2, height: nodeHeight + groupPadding * 2 },
    });
  }

  for (const node of nodes) {
    g.setNode(node.id, { width: nodeWidth, height: nodeHeight });
    for (const [pkg, ids] of groups) {
      if (ids.includes(node.id)) {
        g.setParent(node.id, `group:${pkg}`);
        break;
      }
    }
  }
  for (const edge of edges) {
    g.setEdge(edge.source, edge.target);
  }

  dagre.layout(g);

  for (const node of [...nodes, ...groupNodes]) {
    const pos = g.node(node.id);
    if (pos) {
      node.position = {
        x: pos.x - (pos.width || nodeWidth) / 2,
        y: pos.y - (pos.height || nodeHeight) / 2,
      };
      if (node.type === 'group' && pos.width && pos.height) {
        node.style = { ...node.style, width: pos.width, height: pos.height };
      }
    }
  }

  for (const [pkg, ids] of groups) {
    const groupId = `group:${pkg}`;
    const groupPos = g.node(groupId);
    if (!groupPos) continue;
    for (const node of nodes) {
      if (ids.includes(node.id)) {
        node.parentId = groupId;
        node.position = {
          x: node.position.x - (groupPos.x - (groupPos.width || 0) / 2),
          y: node.position.y - (groupPos.y - (groupPos.height || 0) / 2),
        };
      }
    }
  }

  return { nodes, edges, groupNodes };
}
