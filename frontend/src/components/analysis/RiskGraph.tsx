import { useEffect, useRef } from 'react'
import * as d3 from 'd3'
import type { RiskGraph as RiskGraphData, GraphNode, GraphEdge } from '@/types/risk'

const NODE_COLORS: Record<string, string> = {
  analysis:   '#6366f1',
  finding:    '#ef4444',
  library:    '#3b82f6',
  cve:        '#991b1b',
  host:       '#0d9488',
  component:  '#2563eb',
  permission: '#7c3aed',
}

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
  info:     '#6b7280',
}

function nodeColor(n: GraphNode): string {
  if (n.type === 'finding' && n.severity) return SEV_COLORS[n.severity] ?? NODE_COLORS.finding
  if (n.type === 'cve' && n.severity) return SEV_COLORS[n.severity] ?? NODE_COLORS.cve
  return NODE_COLORS[n.type] ?? '#6b7280'
}

interface SimNode extends d3.SimulationNodeDatum {
  id: string
  type: string
  label: string
  severity: string | null
}

interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  relation: string
}

interface Props {
  data: RiskGraphData
  onNodeClick?: (node: GraphNode) => void
}

export function RiskGraph({ data, onNodeClick }: Props) {
  const svgRef = useRef<SVGSVGElement>(null)

  useEffect(() => {
    if (!svgRef.current || data.nodes.length === 0) return

    const el = svgRef.current
    const width = el.clientWidth || 800
    const height = el.clientHeight || 600

    d3.select(el).selectAll('*').remove()

    const svg = d3.select(el)
    const g = svg.append('g')

    // Zoom/pan
    svg.call(
      d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.2, 4])
        .on('zoom', (event) => g.attr('transform', event.transform))
    )

    const nodes: SimNode[] = data.nodes.map((n) => ({ ...n }))
    const nodeById = new Map(nodes.map((n) => [n.id, n]))

    const links: SimLink[] = data.edges
      .filter((e) => nodeById.has(e.source) && nodeById.has(e.target))
      .map((e) => ({ source: e.source, target: e.target, relation: e.relation }))

    const simulation = d3
      .forceSimulation(nodes)
      .force('link', d3.forceLink<SimNode, SimLink>(links).id((d) => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(24))

    // Edges
    const link = g
      .append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#3f3f46')
      .attr('stroke-width', 1)
      .attr('stroke-opacity', 0.6)

    // Nodes
    const node = g
      .append('g')
      .selectAll<SVGCircleElement, SimNode>('circle')
      .data(nodes)
      .join('circle')
      .attr('r', (d) => (d.type === 'analysis' ? 18 : 10))
      .attr('fill', (d) => nodeColor(d as GraphNode))
      .attr('stroke', '#18181b')
      .attr('stroke-width', 1.5)
      .attr('cursor', 'pointer')
      .call(
        d3.drag<SVGCircleElement, SimNode>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart()
            d.fx = d.x; d.fy = d.y
          })
          .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0)
            d.fx = null; d.fy = null
          })
      )
      .on('click', (_, d) => onNodeClick?.(d as GraphNode))

    // Labels
    const label = g
      .append('g')
      .selectAll('text')
      .data(nodes)
      .join('text')
      .text((d) => d.label.length > 20 ? d.label.substring(0, 18) + '…' : d.label)
      .attr('font-size', '9px')
      .attr('fill', '#a1a1aa')
      .attr('text-anchor', 'middle')
      .attr('dy', (d) => (d.type === 'analysis' ? 30 : 20))
      .attr('pointer-events', 'none')

    // Tooltip
    node.append('title').text((d) => `${d.type}: ${d.label}`)

    simulation.on('tick', () => {
      link
        .attr('x1', (d) => (d.source as SimNode).x ?? 0)
        .attr('y1', (d) => (d.source as SimNode).y ?? 0)
        .attr('x2', (d) => (d.target as SimNode).x ?? 0)
        .attr('y2', (d) => (d.target as SimNode).y ?? 0)

      node.attr('cx', (d) => d.x ?? 0).attr('cy', (d) => d.y ?? 0)
      label.attr('x', (d) => d.x ?? 0).attr('y', (d) => d.y ?? 0)
    })

    return () => { simulation.stop() }
  }, [data, onNodeClick])

  return <svg ref={svgRef} className="w-full h-full" />
}
