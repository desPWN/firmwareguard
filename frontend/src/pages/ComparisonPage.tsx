import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  GitCompareArrows,
  Loader2,
  Plus,
  Minus,
  FileEdit,
  Lock,
  Binary,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { FlapCounter } from '@/components/ui/split-flap'
import { listFirmware } from '@/api/firmware'
import { diffFirmware, diffBinary } from '@/api/comparison'
import { formatFileSize } from '@/utils/format'
import type { FirmwareDetail, FirmwareDiff, BinaryDiff, FileDiffEntry } from '@/types'

type Tab = 'files' | 'binaries' | 'binary-detail'

export default function ComparisonPage() {
  const { projectId } = useParams<{ projectId: string }>()

  const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
  const [fwAId, setFwAId] = useState('')
  const [fwBId, setFwBId] = useState('')
  const [loading, setLoading] = useState(false)
  const [fsDiff, setFsDiff] = useState<FirmwareDiff | null>(null)
  const [binDiff, setBinDiff] = useState<BinaryDiff | null>(null)
  const [binLoading, setBinLoading] = useState(false)
  const [tab, setTab] = useState<Tab>('files')
  const [error, setError] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<string>('all')

  useEffect(() => {
    if (projectId) {
      listFirmware(projectId).then((list) => {
        const unpacked = list.filter((fw) => fw.extracted_path)
        setFirmwareList(unpacked)
        if (unpacked.length >= 2) {
          setFwAId(unpacked[0].id)
          setFwBId(unpacked[1].id)
        }
      })
    }
  }, [projectId])

  const handleCompare = async () => {
    if (!projectId || !fwAId || !fwBId) return
    setLoading(true)
    setError(null)
    setFsDiff(null)
    setBinDiff(null)
    setTab('files')
    try {
      const result = await diffFirmware(projectId, fwAId, fwBId)
      setFsDiff(result)
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Comparison failed')
    } finally {
      setLoading(false)
    }
  }

  const handleBinaryDiff = async (path: string) => {
    if (!projectId || !fwAId || !fwBId) return
    setBinLoading(true)
    setBinDiff(null)
    setTab('binary-detail')
    try {
      const result = await diffBinary(projectId, fwAId, fwBId, path)
      setBinDiff(result)
    } catch {
      // ignore
    } finally {
      setBinLoading(false)
    }
  }

  const fwALabel = firmwareList.find((fw) => fw.id === fwAId)
  const fwBLabel = firmwareList.find((fw) => fw.id === fwBId)

  const allEntries: FileDiffEntry[] = fsDiff
    ? [...fsDiff.added, ...fsDiff.removed, ...fsDiff.modified, ...fsDiff.permissions_changed]
    : []
  const filteredEntries = statusFilter === 'all'
    ? allEntries
    : allEntries.filter((e) => e.status === statusFilter)

  // Identify modified ELF binaries (likely binaries: in /bin, /sbin, /usr/bin, /usr/lib, etc.)
  const modifiedBinaries = fsDiff?.modified.filter((e) => {
    const p = e.path.toLowerCase()
    return p.includes('/bin/') || p.includes('/sbin/') || p.includes('/lib/') ||
           p.endsWith('.so') || p.includes('.so.')
  }) ?? []

  return (
    <div className="space-y-5 animate-flap-settle">
      <div>
        <h1 className="font-display text-2xl font-bold uppercase tracking-[0.05em] text-foreground flex items-center gap-2">
          <GitCompareArrows className="h-5 w-5 text-primary" />
          Firmware Version Comparison
        </h1>
        <p className="mt-0.5 text-sm text-muted-foreground">
          Diff unpacked filesystem trees, permissions, and modified ELF binaries across two firmware releases.
        </p>
      </div>

      {/* Firmware selectors */}
      <div className="board-surface rounded-md p-4">
        <div className="flex items-end gap-4 flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <label className="font-display text-xs uppercase tracking-[0.07em] text-muted-foreground mb-1.5 block">
              Firmware A (Baseline)
            </label>
            <select
              className="h-9 w-full rounded-md border border-border bg-background px-3 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              value={fwAId}
              onChange={(e) => setFwAId(e.target.value)}
            >
              <option value="">Select baseline firmware...</option>
              {firmwareList.map((fw) => (
                <option key={fw.id} value={fw.id}>
                  {fw.original_filename}{fw.version_label ? ` (${fw.version_label})` : ''} - {fw.architecture || 'unknown'}
                </option>
              ))}
            </select>
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="font-display text-xs uppercase tracking-[0.07em] text-muted-foreground mb-1.5 block">
              Firmware B (Target)
            </label>
            <select
              className="h-9 w-full rounded-md border border-border bg-background px-3 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              value={fwBId}
              onChange={(e) => setFwBId(e.target.value)}
            >
              <option value="">Select target firmware...</option>
              {firmwareList.map((fw) => (
                <option key={fw.id} value={fw.id}>
                  {fw.original_filename}{fw.version_label ? ` (${fw.version_label})` : ''} - {fw.architecture || 'unknown'}
                </option>
              ))}
            </select>
          </div>
          <Button
            type="button"
            onClick={handleCompare}
            disabled={!fwAId || !fwBId || fwAId === fwBId || loading}
          >
            {loading && <Loader2 className="h-4 w-4 animate-spin" />}
            Run Diff
          </Button>
        </div>
        {fwAId === fwBId && fwAId && (
          <p className="text-xs text-[#FF7B7F] mt-2">Select two different firmware versions</p>
        )}
        {error && <p className="text-sm text-[#FF7B7F] mt-2">{error}</p>}
      </div>

      {/* Results */}
      {fsDiff && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <FlapCounter
              label="Added Files"
              value={String(fsDiff.added.length).padStart(2, '0')}
              subtext={
                <span className="inline-flex items-center gap-1">
                  <Plus className="h-3 w-3" /> New in Firmware B
                </span>
              }
              tone={fsDiff.added.length > 0 ? 'green' : 'muted'}
              lamp={fsDiff.added.length > 0 ? 'green' : 'idle'}
            />
            <FlapCounter
              label="Removed Files"
              value={String(fsDiff.removed.length).padStart(2, '0')}
              subtext={
                <span className="inline-flex items-center gap-1">
                  <Minus className="h-3 w-3" /> Deleted from A
                </span>
              }
              tone={fsDiff.removed.length > 0 ? 'red' : 'muted'}
              lamp={fsDiff.removed.length > 0 ? 'red' : 'idle'}
            />
            <FlapCounter
              label="Modified Files"
              value={String(fsDiff.modified.length).padStart(2, '0')}
              subtext={
                <span className="inline-flex items-center gap-1">
                  <FileEdit className="h-3 w-3" /> {modifiedBinaries.length} ELF binaries
                </span>
              }
              tone={fsDiff.modified.length > 0 ? 'amber' : 'muted'}
              lamp={fsDiff.modified.length > 0 ? 'amber' : 'idle'}
            />
            <FlapCounter
              label="Permissions"
              value={String(fsDiff.permissions_changed.length).padStart(2, '0')}
              subtext={
                <span className="inline-flex items-center gap-1">
                  <Lock className="h-3 w-3" /> Mode / setuid shifts
                </span>
              }
              tone={fsDiff.permissions_changed.length > 0 ? 'amber' : 'muted'}
              lamp={fsDiff.permissions_changed.length > 0 ? 'amber' : 'idle'}
            />
          </div>

          {/* Tabs */}
          <div className="flex gap-1 border-b">
            <button
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                tab === 'files' ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
              }`}
              onClick={() => setTab('files')}
            >
              Files ({allEntries.length})
            </button>
            <button
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                tab === 'binaries' ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
              }`}
              onClick={() => setTab('binaries')}
            >
              Binaries ({modifiedBinaries.length})
            </button>
            {binDiff && (
              <button
                className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                  tab === 'binary-detail' ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}
                onClick={() => setTab('binary-detail')}
              >
                <Binary className="inline h-3.5 w-3.5 mr-1" />
                {binDiff.binary_path.split('/').pop()}
              </button>
            )}
          </div>

          {/* Files tab */}
          {tab === 'files' && (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">File Differences</CardTitle>
                  <select
                    className="rounded border bg-background px-2 py-1 text-xs"
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                  >
                    <option value="all">All ({allEntries.length})</option>
                    <option value="added">Added ({fsDiff.added.length})</option>
                    <option value="removed">Removed ({fsDiff.removed.length})</option>
                    <option value="modified">Modified ({fsDiff.modified.length})</option>
                    <option value="permissions_changed">Perms ({fsDiff.permissions_changed.length})</option>
                  </select>
                </div>
              </CardHeader>
              <CardContent>
                {fsDiff.truncated && (
                  <p className="text-xs text-muted-foreground mb-2">Results truncated to 500 entries per category</p>
                )}
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b text-left text-muted-foreground">
                        <th className="pb-2 pr-3 font-medium">Path</th>
                        <th className="pb-2 pr-3 font-medium w-24">Status</th>
                        <th className="pb-2 pr-3 font-medium w-20 text-right">Size A</th>
                        <th className="pb-2 pr-3 font-medium w-20 text-right">Size B</th>
                        <th className="pb-2 font-medium w-16 text-right">Delta</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredEntries.slice(0, 200).map((entry, i) => {
                        const delta = entry.size_a != null && entry.size_b != null && entry.size_a > 0
                          ? ((entry.size_b - entry.size_a) / entry.size_a * 100)
                          : null
                        return (
                          <tr key={i} className="border-b border-border/30 hover:bg-muted/50">
                            <td className="py-1.5 pr-3 font-mono truncate max-w-[400px]">{entry.path}</td>
                            <td className="py-1.5 pr-3">
                              <StatusBadge status={entry.status} />
                            </td>
                            <td className="py-1.5 pr-3 text-right">
                              {entry.size_a != null ? formatFileSize(entry.size_a) : '-'}
                            </td>
                            <td className="py-1.5 pr-3 text-right">
                              {entry.size_b != null ? formatFileSize(entry.size_b) : '-'}
                            </td>
                            <td className="py-1.5 text-right">
                              {delta != null ? (
                                <span className={delta > 0 ? 'text-green-600' : delta < 0 ? 'text-red-600' : ''}>
                                  {delta > 0 ? '+' : ''}{delta.toFixed(1)}%
                                </span>
                              ) : '-'}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                  {filteredEntries.length > 200 && (
                    <p className="text-xs text-muted-foreground mt-2">
                      Showing first 200 of {filteredEntries.length} entries
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Binaries tab */}
          {tab === 'binaries' && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Modified Binaries</CardTitle>
              </CardHeader>
              <CardContent>
                {modifiedBinaries.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No modified binaries detected</p>
                ) : (
                  <div className="space-y-1">
                    {modifiedBinaries.map((entry, i) => {
                      const delta = entry.size_a != null && entry.size_b != null && entry.size_a > 0
                        ? ((entry.size_b - entry.size_a) / entry.size_a * 100)
                        : null
                      return (
                        <div
                          key={i}
                          className="flex items-center justify-between rounded px-3 py-2 hover:bg-muted/50 cursor-pointer"
                          onClick={() => handleBinaryDiff(entry.path)}
                        >
                          <span className="font-mono text-xs">{entry.path}</span>
                          <div className="flex items-center gap-3 text-xs">
                            <span className="text-muted-foreground">
                              {entry.size_a != null ? formatFileSize(entry.size_a) : '?'} &rarr;{' '}
                              {entry.size_b != null ? formatFileSize(entry.size_b) : '?'}
                            </span>
                            {delta != null && (
                              <span className={delta > 0 ? 'text-green-600' : delta < 0 ? 'text-red-600' : ''}>
                                {delta > 0 ? '+' : ''}{delta.toFixed(1)}%
                              </span>
                            )}
                            <Button size="sm" variant="outline" className="h-6 text-xs">
                              Diff
                            </Button>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Binary detail tab */}
          {tab === 'binary-detail' && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Binary className="h-4 w-4" />
                  Binary Diff: {binDiff?.binary_path || 'Loading...'}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {binLoading && (
                  <div className="flex items-center gap-2 py-4 text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Analyzing binary differences...
                  </div>
                )}
                {binDiff && !binLoading && (
                  <div className="space-y-4">
                    <div className="flex gap-4 text-xs">
                      <span>A: {fwALabel?.version_label || fwALabel?.original_filename} ({formatFileSize(Number(binDiff.info_a?.file_size) || 0)})</span>
                      <span>B: {fwBLabel?.version_label || fwBLabel?.original_filename} ({formatFileSize(Number(binDiff.info_b?.file_size) || 0)})</span>
                    </div>

                    <div className="flex gap-3 text-sm">
                      <Badge variant="outline" className="text-green-600">
                        +{binDiff.functions_added.length} added
                      </Badge>
                      <Badge variant="outline" className="text-red-600">
                        -{binDiff.functions_removed.length} removed
                      </Badge>
                      <Badge variant="outline" className="text-yellow-600">
                        ~{binDiff.functions_modified.length} modified
                      </Badge>
                    </div>

                    {binDiff.functions_added.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-green-600 mb-1">Functions Added</h4>
                        <div className="space-y-0.5">
                          {binDiff.functions_added.map((f, i) => (
                            <div key={i} className="flex justify-between text-xs font-mono px-2 py-0.5 hover:bg-muted/50 rounded">
                              <span>{f.name}</span>
                              <span className="text-muted-foreground">{f.size_b} bytes</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {binDiff.functions_removed.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-red-600 mb-1">Functions Removed</h4>
                        <div className="space-y-0.5">
                          {binDiff.functions_removed.map((f, i) => (
                            <div key={i} className="flex justify-between text-xs font-mono px-2 py-0.5 hover:bg-muted/50 rounded">
                              <span>{f.name}</span>
                              <span className="text-muted-foreground">{f.size_a} bytes</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {binDiff.functions_modified.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-yellow-600 mb-1">Functions Modified</h4>
                        <div className="space-y-0.5">
                          {binDiff.functions_modified.map((f, i) => (
                            <div key={i} className="flex justify-between text-xs font-mono px-2 py-0.5 hover:bg-muted/50 rounded">
                              <span>{f.name}</span>
                              <span className="text-muted-foreground">
                                {f.size_a} &rarr; {f.size_b} bytes
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {binDiff.functions_added.length === 0 &&
                     binDiff.functions_removed.length === 0 &&
                     binDiff.functions_modified.length === 0 && (
                      <p className="text-sm text-muted-foreground">
                        No function-level differences detected. The binary may be stripped
                        (no symbol table), or changes are limited to data sections.
                      </p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Empty state */}
      {!fsDiff && !loading && (
        <div className="text-center py-12 text-muted-foreground">
          <GitCompareArrows className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">Select two firmware versions and click Compare to see differences</p>
          {firmwareList.length < 2 && (
            <p className="text-xs mt-2">
              Upload at least two firmware versions from the project overview to use this feature
            </p>
          )}
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { color: string; label: string }> = {
    added: { color: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400', label: 'Added' },
    removed: { color: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400', label: 'Removed' },
    modified: { color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400', label: 'Modified' },
    permissions_changed: { color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400', label: 'Perms' },
  }
  const c = config[status] || { color: 'bg-muted text-muted-foreground', label: status }
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium ${c.color}`}>
      {c.label}
    </span>
  )
}
