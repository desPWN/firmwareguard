import { useCallback, useEffect, useMemo, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
  Search,
  ExternalLink,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Loader2,
  FileCode,
  Binary,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { BoardSectionHeader, FlapCounter, PipMeter } from '@/components/ui/split-flap'
import { formatFileSize } from '@/utils/format'
import { getBinaryHardening } from '@/api/analysis'
import { listFirmware } from '@/api/firmware'
import type { FirmwareHardeningResponse, FirmwareDetail } from '@/types'

// Badge color logic adhering to test contract
function getBadgeColor(val: boolean | string): 'green' | 'red' | 'yellow' | 'blue' | 'gray' {
  if (val === true || val === 'full') return 'green'
  if (val === false || val === 'none') return 'red'
  if (val === 'DSO') return 'blue'
  return 'yellow'
}

const BADGE_CLASSES: Record<string, string> = {
  green: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/35',
  red: 'bg-red-500/10 text-red-400 border-red-500/35',
  yellow: 'bg-amber-500/10 text-amber-400 border-amber-500/35',
  blue: 'bg-blue-500/10 text-blue-400 border-blue-500/35',
  gray: 'bg-muted text-muted-foreground border-border',
}

type SortField = 'score' | 'path' | 'size' | 'architecture'
type SortOrder = 'asc' | 'desc'
type TypeFilter = 'all' | 'executable' | 'shared_library'
type RiskFilter = 'all' | 'missing_nx' | 'missing_canary' | 'no_pie' | 'no_relro' | 'low_score'

export default function HardeningPage() {
  const { projectId } = useParams<{ projectId: string }>()

  const [data, setData] = useState<FirmwareHardeningResponse | null>(null)
  const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
  const [selectedFirmwareId, setSelectedFirmwareId] = useState<string | undefined>()
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all')
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all')
  const [sortField, setSortField] = useState<SortField>('score')
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc')

  // Fetch unpacked firmware list
  useEffect(() => {
    if (!projectId) return
    listFirmware(projectId)
      .then((fws) => {
        const unpacked = fws.filter((fw) => fw.extracted_path)
        setFirmwareList(unpacked)
        if (unpacked.length > 0 && !selectedFirmwareId) {
          setSelectedFirmwareId(unpacked[0].id)
        }
      })
      .catch(() => {})
  }, [projectId, selectedFirmwareId])

  // Fetch hardening data
  const fetchData = useCallback(
    async (bypassCache = false) => {
      if (!projectId) return
      if (bypassCache) setRefreshing(true)
      else setLoading(true)
      setError(null)

      try {
        const res = await getBinaryHardening(projectId, selectedFirmwareId, bypassCache)
        setData(res)
      } catch (err: unknown) {
        const msg = (err as { response?: { data?: { detail?: string } }; message?: string })
          ?.response?.data?.detail || (err as Error)?.message || 'Failed to load binary hardening matrix'
        setError(msg)
      } finally {
        setLoading(false)
        setRefreshing(false)
      }
    },
    [projectId, selectedFirmwareId],
  )

  useEffect(() => {
    fetchData(false)
  }, [fetchData])

  // Sorting helper
  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortOrder('asc')
    }
  }

  // Filtered and sorted binaries
  const filteredBinaries = useMemo(() => {
    if (!data?.binaries) return []

    return data.binaries
      .filter((b) => {
        // Search query
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase().trim()
          const matchPath = b.path.toLowerCase().includes(q)
          const matchFile = b.filename.toLowerCase().includes(q)
          if (!matchPath && !matchFile) return false
        }

        // Type filter
        if (typeFilter !== 'all' && b.binary_type !== typeFilter) {
          return false
        }

        // Risk filter
        if (riskFilter === 'missing_nx' && b.nx) return false
        if (riskFilter === 'missing_canary' && b.canary) return false
        if (riskFilter === 'no_pie' && (b.pie || b.pie_status !== 'No PIE')) return false
        if (riskFilter === 'no_relro' && b.relro !== 'none') return false
        if (riskFilter === 'low_score' && b.score >= 2.5) return false

        return true
      })
      .sort((a, b) => {
        let cmp = 0
        if (sortField === 'score') cmp = a.score - b.score
        else if (sortField === 'path') cmp = a.path.localeCompare(b.path)
        else if (sortField === 'size') cmp = a.size - b.size
        else if (sortField === 'architecture') cmp = a.architecture.localeCompare(b.architecture)

        return sortOrder === 'asc' ? cmp : -cmp
      })
  }, [data?.binaries, searchQuery, typeFilter, riskFilter, sortField, sortOrder])

  const summary = data?.summary

  return (
    <div className="space-y-5 animate-flap-settle">
      {/* Page Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="font-display text-2xl font-bold uppercase tracking-[0.05em] text-foreground flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-primary" />
              Binary Hardening Matrix
            </h1>
            {data && (
              <Badge variant="outline" className="text-[10px] uppercase text-muted-foreground">
                {data.cached ? 'CACHED' : 'LIVE SCAN'}
              </Badge>
            )}
          </div>
          <p className="text-sm text-muted-foreground mt-0.5">
            Audit ELF executables and shared libraries for exploit mitigation protections (checksec).
          </p>
        </div>

        <div className="flex items-center gap-2">
          {firmwareList.length > 1 && (
            <select
              aria-label="Select firmware image"
              value={selectedFirmwareId}
              onChange={(e) => setSelectedFirmwareId(e.target.value)}
              className="h-8 rounded-md border border-border bg-background px-2.5 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {firmwareList.map((fw) => (
                <option key={fw.id} value={fw.id}>
                  {fw.original_filename || fw.id.slice(0, 8)}
                </option>
              ))}
            </select>
          )}

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => fetchData(true)}
            disabled={loading || refreshing}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Rescan
          </Button>
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="board-surface flex flex-col items-center justify-center rounded-md py-16 gap-3 text-muted-foreground">
          <Loader2 className="h-7 w-7 animate-spin text-primary" />
          <p className="font-mono text-xs">Auditing ELF binaries in extracted root filesystem...</p>
        </div>
      )}

      {/* Error state */}
      {!loading && error && (
        <Card className="border-destructive/40 bg-destructive/10">
          <CardHeader>
            <CardTitle className="text-[#FF7B7F] flex items-center gap-2 text-base">
              <ShieldAlert className="h-5 w-5" />
              Failed to load hardening matrix
            </CardTitle>
            <CardDescription>{error}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button type="button" variant="outline" size="sm" onClick={() => fetchData(false)}>
              Retry
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Main Content */}
      {!loading && !error && data && summary && (
        <>
          {/* Split-Flap Telemetry Ribbon */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <FlapCounter
              label="Total Binaries"
              value={String(summary.total_binaries).padStart(2, '0')}
              subtext={`${summary.executable_count} exec · ${summary.library_count} libs`}
              tone="neutral"
            />
            <FlapCounter
              label="NX Protection"
              value={`${summary.nx_percentage}%`}
              subtext={`${summary.nx_count} / ${summary.total_binaries} protected`}
              tone={summary.nx_percentage >= 70 ? 'green' : summary.nx_percentage >= 40 ? 'amber' : 'red'}
              lamp={summary.nx_percentage >= 70 ? 'green' : summary.nx_percentage >= 40 ? 'amber' : 'red'}
            />
            <FlapCounter
              label="Stack Canaries"
              value={`${summary.canary_percentage}%`}
              subtext={`${summary.canary_count} / ${summary.total_binaries} protected`}
              tone={summary.canary_percentage >= 50 ? 'green' : summary.canary_percentage > 0 ? 'amber' : 'red'}
              lamp={summary.canary_percentage >= 50 ? 'green' : summary.canary_percentage > 0 ? 'amber' : 'red'}
            />
            <FlapCounter
              label="PIE / ASLR"
              value={`${summary.pie_percentage}%`}
              subtext={`${summary.pie_count} / ${summary.total_binaries} randomized`}
              tone={summary.pie_percentage >= 50 ? 'green' : summary.pie_percentage > 0 ? 'amber' : 'red'}
              lamp={summary.pie_percentage >= 50 ? 'green' : summary.pie_percentage > 0 ? 'amber' : 'red'}
            />
            <FlapCounter
              label="Full RELRO"
              value={`${summary.full_relro_percentage}%`}
              subtext={`${summary.partial_relro_count} part · ${summary.no_relro_count} none`}
              tone={summary.full_relro_percentage >= 50 ? 'green' : summary.partial_relro_count > 0 ? 'amber' : 'red'}
              lamp={summary.full_relro_percentage >= 50 ? 'green' : summary.partial_relro_count > 0 ? 'amber' : 'red'}
            />
            <FlapCounter
              label="Hardening Score"
              value={`${summary.average_score.toFixed(1)}/5`}
              subtext={summary.average_score >= 3.5 ? 'Moderate posture' : 'High risk posture'}
              tone={summary.average_score >= 3.5 ? 'green' : summary.average_score >= 2.0 ? 'amber' : 'red'}
              lamp={summary.average_score >= 3.5 ? 'green' : summary.average_score >= 2.0 ? 'amber' : 'red'}
            />
          </div>

          {/* Filter & Search Toolbar */}
          <div className="flex flex-col gap-3 rounded-md border border-border bg-card p-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-1 flex-wrap items-center gap-2">
              <div className="relative flex-1 min-w-[200px] max-w-sm">
                <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  type="text"
                  placeholder="Filter by path or binary name..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8 h-8 text-xs"
                />
              </div>

              <div className="flex rounded-md border border-border bg-background p-0.5">
                {[
                  { id: 'all' as TypeFilter, label: `All (${summary.total_binaries})` },
                  { id: 'executable' as TypeFilter, label: `Execs (${summary.executable_count})` },
                  { id: 'shared_library' as TypeFilter, label: `Libs (${summary.library_count})` },
                ].map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setTypeFilter(opt.id)}
                    className={`px-2.5 py-1 text-xs rounded-[4px] font-mono transition-colors ${
                      typeFilter === opt.id
                        ? 'bg-secondary text-foreground font-semibold'
                        : 'text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="font-display text-xs uppercase tracking-[0.06em] text-muted-foreground">Risk:</span>
              <select
                aria-label="Filter by mitigation risk"
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value as RiskFilter)}
                className="h-8 rounded-md border border-border bg-background px-2.5 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <option value="all">ALL BINARIES</option>
                <option value="missing_nx">MISSING NX ({summary.total_binaries - summary.nx_count})</option>
                <option value="missing_canary">MISSING CANARY ({summary.total_binaries - summary.canary_count})</option>
                <option value="no_pie">NO PIE ({summary.total_binaries - summary.pie_count})</option>
                <option value="no_relro">NO RELRO ({summary.no_relro_count})</option>
                <option value="low_score">SCORE &lt; 2.5</option>
              </select>

              {(searchQuery || typeFilter !== 'all' || riskFilter !== 'all') && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setSearchQuery('')
                    setTypeFilter('all')
                    setRiskFilter('all')
                  }}
                  className="h-8 text-xs"
                >
                  Reset
                </Button>
              )}
            </div>
          </div>

          {/* Hardening Matrix Table */}
          <div className="board-surface overflow-hidden rounded-md">
            <BoardSectionHeader
              title="ELF Mitigation Board"
              right={
                <span className="font-mono text-xs text-muted-foreground tabular-nums">
                  {filteredBinaries.length} / {summary.total_binaries} · SORT {sortField.toUpperCase()} ({sortOrder.toUpperCase()})
                </span>
              }
            />

            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left border-collapse">
                <thead>
                  <tr className="border-b border-border bg-muted/40 font-display text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                    <th
                      className="py-2.5 px-3 cursor-pointer hover:text-foreground select-none"
                      onClick={() => handleSort('path')}
                    >
                      <div className="flex items-center gap-1">
                        Path
                        {sortField === 'path' ? (
                          sortOrder === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
                        ) : (
                          <ArrowUpDown className="h-3 w-3 opacity-40" />
                        )}
                      </div>
                    </th>
                    <th className="py-2.5 px-2">Type</th>
                    <th
                      className="py-2.5 px-2 cursor-pointer hover:text-foreground select-none"
                      onClick={() => handleSort('architecture')}
                    >
                      <div className="flex items-center gap-1">
                        Arch
                        {sortField === 'architecture' && (
                          sortOrder === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
                        )}
                      </div>
                    </th>
                    <th
                      className="py-2.5 px-2 cursor-pointer hover:text-foreground select-none"
                      onClick={() => handleSort('size')}
                    >
                      <div className="flex items-center gap-1">
                        Size
                        {sortField === 'size' && (
                          sortOrder === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
                        )}
                      </div>
                    </th>
                    <th className="py-2.5 px-2 text-center">NX</th>
                    <th className="py-2.5 px-2 text-center">Canary</th>
                    <th className="py-2.5 px-2 text-center">PIE</th>
                    <th className="py-2.5 px-2 text-center">RELRO</th>
                    <th className="py-2.5 px-2 text-center">Fortify</th>
                    <th className="py-2.5 px-2 text-center">Stripped</th>
                    <th
                      className="py-2.5 px-3 text-center cursor-pointer hover:text-foreground select-none"
                      onClick={() => handleSort('score')}
                    >
                      <div className="flex items-center justify-center gap-1">
                        Score
                        {sortField === 'score' ? (
                          sortOrder === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
                        ) : (
                          <ArrowUpDown className="h-3 w-3 opacity-40" />
                        )}
                      </div>
                    </th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {filteredBinaries.length === 0 ? (
                    <tr>
                      <td colSpan={12} className="py-8 text-center text-muted-foreground">
                        No binaries match the selected filters.
                      </td>
                    </tr>
                  ) : (
                    filteredBinaries.map((b) => {
                      const nxColor = getBadgeColor(b.nx)
                      const canaryColor = getBadgeColor(b.canary)
                      const pieColor = b.pie ? (b.pie_status === 'DSO' ? 'blue' : 'green') : 'red'
                      const relroColor = getBadgeColor(b.relro)
                      const fortifyColor = b.fortify ? 'green' : 'gray'
                      const strippedColor = b.stripped ? 'yellow' : 'gray'
                      const scoreColor = b.score >= 3.5 ? 'green' : b.score >= 2.0 ? 'yellow' : 'red'

                      return (
                        <tr key={b.path} className="hover:bg-muted/30 transition-colors">
                          {/* Path */}
                          <td className="py-2 px-3 font-mono max-w-[280px] truncate" title={b.path}>
                            <div className="flex items-center gap-1.5">
                              {b.binary_type === 'executable' ? (
                                <Binary className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                              ) : (
                                <FileCode className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                              )}
                              <span className="truncate">{b.path}</span>
                            </div>
                          </td>

                          {/* Type */}
                          <td className="py-2 px-2 whitespace-nowrap">
                            <Badge variant="outline" className="text-[10px] font-normal py-0">
                              {b.binary_type === 'executable' ? 'Executable' : 'Library'}
                            </Badge>
                          </td>

                          {/* Arch */}
                          <td className="py-2 px-2 whitespace-nowrap text-muted-foreground">
                            {b.architecture} ({b.bits}b)
                          </td>

                          {/* Size */}
                          <td className="py-2 px-2 whitespace-nowrap font-mono text-muted-foreground">
                            {formatFileSize(b.size)}
                          </td>

                          {/* NX */}
                          <td className="py-2 px-2 text-center whitespace-nowrap">
                            <Badge variant="outline" className={`text-[10px] py-0 ${BADGE_CLASSES[nxColor]}`}>
                              {b.nx ? 'Enabled' : 'Disabled'}
                            </Badge>
                          </td>

                          {/* Canary */}
                          <td className="py-2 px-2 text-center whitespace-nowrap">
                            <Badge variant="outline" className={`text-[10px] py-0 ${BADGE_CLASSES[canaryColor]}`}>
                              {b.canary ? 'Enabled' : 'Missing'}
                            </Badge>
                          </td>

                          {/* PIE */}
                          <td className="py-2 px-2 text-center whitespace-nowrap">
                            <Badge variant="outline" className={`text-[10px] py-0 ${BADGE_CLASSES[pieColor]}`}>
                              {b.pie_status}
                            </Badge>
                          </td>

                          {/* RELRO */}
                          <td className="py-2 px-2 text-center whitespace-nowrap">
                            <Badge variant="outline" className={`text-[10px] py-0 ${BADGE_CLASSES[relroColor]}`}>
                              {b.relro === 'full' ? 'Full' : b.relro === 'partial' ? 'Partial' : 'None'}
                            </Badge>
                          </td>

                          {/* Fortify */}
                          <td className="py-2 px-2 text-center whitespace-nowrap">
                            <Badge variant="outline" className={`text-[10px] py-0 ${BADGE_CLASSES[fortifyColor]}`}>
                              {b.fortify ? 'Yes' : 'No'}
                            </Badge>
                          </td>

                          {/* Stripped */}
                          <td className="py-2 px-2 text-center whitespace-nowrap">
                            <Badge variant="outline" className={`text-[10px] py-0 ${BADGE_CLASSES[strippedColor]}`}>
                              {b.stripped ? 'Stripped' : 'Symbols'}
                            </Badge>
                          </td>

                          {/* Score */}
                          <td className="py-2 px-3 text-center whitespace-nowrap">
                            <div className="inline-flex items-center gap-2">
                              <PipMeter value={b.score} max={5} segments={5} />
                              <Badge variant="outline" className={`font-mono font-semibold text-[11px] py-0 ${BADGE_CLASSES[scoreColor]}`}>
                                {b.score.toFixed(1)}
                              </Badge>
                            </div>
                          </td>

                          {/* Actions */}
                          <td className="py-2 px-3 text-right whitespace-nowrap">
                            <Button variant="ghost" size="sm" className="h-6 px-2 text-xs hover:text-primary" asChild>
                              <Link
                                to={`/projects/${projectId}/explore?path=${encodeURIComponent(b.path)}`}
                                title="Inspect in File Explorer"
                              >
                                <ExternalLink className="h-3 w-3 mr-1" />
                                Inspect
                              </Link>
                            </Button>
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
