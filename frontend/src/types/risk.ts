export interface RiskScore {
  score: number
  grade: string
  breakdown: {
    findings: Record<string, number>
    cves: Record<string, number>
    raw_score: number
  }
  finding_count_by_severity: Record<string, number>
}

export interface GraphNode {
  id: string
  type: 'analysis' | 'finding' | 'library' | 'cve' | 'host' | 'component' | 'permission'
  label: string
  severity: string | null
}

export interface GraphEdge {
  source: string
  target: string
  relation: string
}

export interface RiskGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
}
