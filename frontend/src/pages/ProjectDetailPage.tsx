import { useEffect, useRef, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  Trash2,
  FolderSearch,
  ShieldCheck,
  KeyRound,
  Cpu,
  HardDrive,
  Hash,
  FileText,
  Loader2,
  AlertCircle,
  Plus,
  Tag,
  Download,
  Pencil,
  Check,
  X,
  ArrowRight,
  Copy,
  ShieldAlert,
  GitCompareArrows,
  LockKeyhole,
} from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { listFirmware, deleteFirmware, updateFirmware } from '@/api/firmware'
import { getBinaryHardening } from '@/api/analysis'
import { getSecretsHarvest } from '@/api/secrets'
import { getVulnerabilitySummary } from '@/api/sbom'
import { listFindings } from '@/api/findings'
import type {
  FirmwareDetail,
  FirmwareHardeningResponse,
  SecretsHarvestResponse,
  SbomSummary,
  Finding,
} from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  BoardSectionHeader,
  FlapCounter,
  PipMeter,
  SignalLamp,
} from '@/components/ui/split-flap'
import { formatFileSize, formatDate } from '@/utils/format'
import FirmwareUpload from '@/components/projects/FirmwareUpload'
import FirmwareDecryptDialog from '@/components/projects/FirmwareDecryptDialog'
import FirmwareMetadataCard from '@/components/projects/FirmwareMetadataCard'
import DocumentsCard from '@/components/projects/DocumentsCard'
import McpConnectionCard from '@/components/projects/McpConnectionCard'
import { exportProject } from '@/api/exportImport'

interface PriorityItem {
  id: string
  severity: 'critical' | 'high' | 'medium'
  module: string
  title: string
  detail: string
  location: string
  to: string
}

const SEV_STYLE: Record<'critical' | 'high' | 'medium', string> = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/35',
  high: 'bg-amber-500/10 text-amber-400 border-amber-500/35',
  medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/35',
}

export default function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()
  const {
    currentProject: project,
    loading,
    unpacking,
    fetchProject,
    removeProject,
    unpackFirmware,
    clearCurrentProject,
  } = useProjectStore()

  const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
  const [secretsData, setSecretsData] = useState<SecretsHarvestResponse | null>(null)
  const [hardeningData, setHardeningData] = useState<FirmwareHardeningResponse | null>(null)
  const [sbomSummary, setSbomSummary] = useState<SbomSummary | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [telemetryLoading, setTelemetryLoading] = useState(false)

  const [showUpload, setShowUpload] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const [editingVersionLabel, setEditingVersionLabel] = useState<string | null>(null)
  const [versionLabelDraft, setVersionLabelDraft] = useState('')
  const [copiedSha, setCopiedSha] = useState<string | null>(null)
  const [decryptTarget, setDecryptTarget] = useState<{ id: string; filename: string } | null>(null)
  const versionInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (projectId) fetchProject(projectId)
    return () => clearCurrentProject()
  }, [projectId, fetchProject, clearCurrentProject])

  useEffect(() => {
    if (projectId && project) {
      listFirmware(projectId).then(setFirmwareList).catch(() => { })
    }
  }, [project, projectId])

  useEffect(() => {
    if (!projectId || project?.status !== 'unpacking') return
    const interval = setInterval(() => {
      fetchProject(projectId)
      listFirmware(projectId).then(setFirmwareList).catch(() => { })
    }, 2000)
    return () => clearInterval(interval)
  }, [projectId, project?.status, fetchProject])

  const hasUnpacked = firmwareList.some((fw) => fw.extracted_path)

  // Fetch overview posture telemetry once in parallel when firmware is unpacked
  useEffect(() => {
    if (!projectId || !hasUnpacked) return
    let cancelled = false
    setTelemetryLoading(true)
    Promise.all([
      getSecretsHarvest(projectId).catch(() => null),
      getBinaryHardening(projectId).catch(() => null),
      getVulnerabilitySummary(projectId).catch(() => null),
      listFindings(projectId).catch(() => []),
    ])
      .then(([sec, hard, sbom, fnds]) => {
        if (cancelled) return
        setSecretsData(sec)
        setHardeningData(hard)
        setSbomSummary(sbom)
        setFindings(fnds)
      })
      .finally(() => {
        if (!cancelled) setTelemetryLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [projectId, hasUnpacked])

  if (loading || !project) {
    return (
      <div className="flex items-center justify-center gap-2.5 py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin text-primary" />
        <span className="font-mono text-xs">Loading firmware target board...</span>
      </div>
    )
  }

  const firmware = project.firmware ?? []
  const status = project.status
  const unpackedCount = firmwareList.filter((fw) => fw.extracted_path).length
  const primaryFw = firmware[0]

  const handleDelete = async () => {
    if (window.confirm('Delete this project and all its data? This cannot be undone.')) {
      await removeProject(project.id)
      navigate('/projects')
    }
  }

  const handleUnpack = async (firmwareId: string) => {
    if (projectId) {
      try {
        await unpackFirmware(projectId, firmwareId)
        listFirmware(projectId).then(setFirmwareList).catch(() => { })
      } catch {
        // error shown via store
      }
    }
  }

  const handleDeleteFirmware = async (firmwareId: string) => {
    if (!projectId) return
    if (!window.confirm('Delete this firmware version? This cannot be undone.')) return
    try {
      await deleteFirmware(projectId, firmwareId)
      fetchProject(projectId)
      listFirmware(projectId).then(setFirmwareList).catch(() => { })
    } catch {
      // ignore
    }
  }

  const handleExport = async () => {
    if (!projectId) return
    setExporting(true)
    setExportError(null)
    try {
      const blob = await exportProject(projectId)
      const safeName = project.name.replace(/\s+/g, '_').replace(/\//g, '_')
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${safeName}.firmwareguard`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'Export failed')
    } finally {
      setExporting(false)
    }
  }

  const startEditingVersionLabel = (fwId: string, current: string | null) => {
    setEditingVersionLabel(fwId)
    setVersionLabelDraft(current ?? '')
    setTimeout(() => versionInputRef.current?.focus(), 0)
  }

  const saveVersionLabel = async (fwId: string) => {
    if (!projectId) return
    const label = versionLabelDraft.trim() || null
    try {
      await updateFirmware(projectId, fwId, { version_label: label })
      fetchProject(projectId)
      listFirmware(projectId).then(setFirmwareList).catch(() => { })
    } catch {
      // ignore
    }
    setEditingVersionLabel(null)
  }

  const handleUploadComplete = () => {
    setShowUpload(false)
    if (projectId) {
      fetchProject(projectId)
      listFirmware(projectId).then(setFirmwareList).catch(() => { })
    }
  }

  const copySha = (sha: string) => {
    navigator.clipboard.writeText(sha)
    setCopiedSha(sha)
    setTimeout(() => setCopiedSha(null), 1800)
  }

  // Derive executive telemetry numbers
  const secSum = secretsData?.summary
  const exposedSecretsCount = secSum
    ? secSum.unencrypted_private_keys +
    secSum.cracked_accounts +
    secSum.empty_password_accounts +
    secSum.router_default_credentials +
    secSum.high_entropy_secrets
    : 0
  const hardSum = hardeningData?.summary
  const openFindingsCount = findings.filter((f) => f.status === 'open').length
  const criticalFindingsCount = findings.filter((f) => f.severity === 'critical').length
  const critCves = sbomSummary?.vulns_by_severity?.['critical'] ?? 0
  const highCves = sbomSummary?.vulns_by_severity?.['high'] ?? 0

  // Build concise priority triage rows (top 6 real risks across secrets & findings)
  const priorityItems: PriorityItem[] = []
  if (secretsData) {
    for (const k of secretsData.private_keys) {
      if (!k.encrypted) {
        priorityItems.push({
          id: `pk-${k.path}-${k.line_number ?? 0}`,
          severity: 'critical',
          module: 'SECRETS',
          title: `Unencrypted ${k.key_type} Private Key`,
          detail: k.format,
          location: k.line_number ? `${k.path}:${k.line_number}` : k.path,
          to: `/projects/${project.id}/secrets`,
        })
      }
    }
    for (const a of secretsData.accounts) {
      if (a.cracked_password) {
        priorityItems.push({
          id: `acc-c-${a.username}`,
          severity: 'critical',
          module: 'SECRETS',
          title: `Cracked Account: ${a.username}`,
          detail: `password "${a.cracked_password}" (${a.hash_type})`,
          location: `${a.source_file}:${a.line_number}`,
          to: `/projects/${project.id}/secrets`,
        })
      } else if (a.status === 'empty' && a.severity === 'critical') {
        priorityItems.push({
          id: `acc-e-${a.username}`,
          severity: 'critical',
          module: 'SECRETS',
          title: `Empty Password: ${a.username}`,
          detail: `login shell ${a.shell || '/bin/sh'}`,
          location: `${a.source_file}:${a.line_number}`,
          to: `/projects/${project.id}/secrets`,
        })
      }
    }
    for (const r of secretsData.router_credentials) {
      priorityItems.push({
        id: `rc-${r.service}-${r.matched_rule}-${r.line_number ?? 0}`,
        severity: r.severity === 'critical' ? 'critical' : 'high',
        module: 'DEFAULTS',
        title: `Default ${r.service.toUpperCase()} Credential`,
        detail: r.username ? `${r.username} · ${r.matched_rule}` : r.matched_rule,
        location: r.line_number ? `${r.source_file}:${r.line_number}` : r.source_file,
        to: `/projects/${project.id}/secrets`,
      })
    }
    for (const g of secretsData.generic_secrets) {
      priorityItems.push({
        id: `gen-${g.path}-${g.line_number}`,
        severity: g.severity === 'critical' ? 'critical' : g.severity === 'high' ? 'high' : 'medium',
        module: 'TOKENS',
        title: `Hardcoded ${g.category.replace(/_/g, ' ')}`,
        detail: `${g.entropy.toFixed(2)} bits entropy`,
        location: `${g.path}:${g.line_number}`,
        to: `/projects/${project.id}/secrets`,
      })
    }
  }
  const topPriority = priorityItems.slice(0, 6)

  return (
    <div className="space-y-5 animate-flap-settle">
      {/* Compact Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <h1 className="font-display text-2xl font-bold uppercase tracking-[0.05em] text-foreground">
            {project.name}
          </h1>
          <p className="mt-1 font-mono text-xs text-muted-foreground truncate">
            {primaryFw ? (
              <>
                {primaryFw.original_filename}
                {primaryFw.architecture ? ` · ${primaryFw.architecture}` : ''}
                {primaryFw.endianness ? ` (${primaryFw.endianness})` : ''}
                {primaryFw.file_size != null ? ` · ${formatFileSize(primaryFw.file_size)}` : ''}
                {' · '}
              </>
            ) : null}
            {status !== 'ready' ? `${status} · ` : ''}
            created {formatDate(project.created_at)}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {hasUnpacked && (
            <Button size="sm" asChild>
              <Link to={`/projects/${project.id}/explore`}>
                <FolderSearch className="h-3.5 w-3.5" />
                Explore Files
              </Link>
            </Button>
          )}
          {unpackedCount >= 2 && (
            <Button variant="outline" size="sm" asChild>
              <Link to={`/projects/${project.id}/compare`}>
                <GitCompareArrows className="h-3.5 w-3.5" />
                Compare
              </Link>
            </Button>
          )}
          <Button type="button" variant="outline" size="sm" onClick={() => setShowUpload((v) => !v)}>
            <Plus className="h-3.5 w-3.5" />
            Upload
          </Button>
          <Button type="button" variant="outline" size="sm" onClick={handleExport} disabled={exporting}>
            {exporting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
            Export
          </Button>
          <Button
            type="button"
            variant="destructive"
            size="icon-sm"
            onClick={handleDelete}
            title="Delete project"
            aria-label="Delete project"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {exportError && (
        <div
          role="alert"
          className="rounded-[4px] border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-[#FF7B7F]"
        >
          Export failed: {exportError}
        </div>
      )}

      {/* Upload Dropzone when triggered or empty project */}
      {(showUpload || (status === 'created' && firmware.length === 0)) && (
        <div className="board-surface overflow-hidden rounded-md">
          <BoardSectionHeader
            title="Upload Firmware Image"
            right={
              firmware.length > 0 ? (
                <Button type="button" variant="ghost" size="icon-xs" onClick={() => setShowUpload(false)}>
                  <X className="h-3.5 w-3.5" />
                </Button>
              ) : undefined
            }
          />
          <div className="p-4">
            <FirmwareUpload
              projectId={project.id}
              onComplete={handleUploadComplete}
              showVersionLabel
            />
          </div>
        </div>
      )}

      {/* Executive 4-Cell Split-Flap Posture Strip */}
      {hasUnpacked && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <FlapCounter
            label="Exposed Secrets"
            value={secSum ? String(exposedSecretsCount).padStart(2, '0') : telemetryLoading ? '—' : '00'}
            subtext={
              secSum
                ? `${secSum.cracked_accounts} cracked · ${secSum.empty_password_accounts} empty · ${secSum.router_default_credentials} defaults`
                : 'Scanning rootfs...'
            }
            tone={
              secSum && (secSum.unencrypted_private_keys > 0 || secSum.cracked_accounts > 0 || secSum.empty_password_accounts > 0)
                ? 'red'
                : exposedSecretsCount > 0
                  ? 'amber'
                  : 'muted'
            }
            lamp={
              secSum && (secSum.unencrypted_private_keys > 0 || secSum.cracked_accounts > 0 || secSum.empty_password_accounts > 0)
                ? 'red'
                : exposedSecretsCount > 0
                  ? 'amber'
                  : secSum
                    ? 'green'
                    : 'idle'
            }
            onClick={() => navigate(`/projects/${project.id}/secrets`)}
          />

          <FlapCounter
            label="SBOM & CVEs"
            value={
              sbomSummary
                ? String(sbomSummary.open_count).padStart(2, '0')
                : telemetryLoading
                  ? '—'
                  : '00'
            }
            subtext={
              sbomSummary && sbomSummary.total_components > 0
                ? `${critCves} crit · ${highCves} high · ${sbomSummary.total_components} pkgs`
                : 'Run SBOM scan'
            }
            tone={critCves > 0 ? 'red' : highCves > 0 || (sbomSummary?.open_count ?? 0) > 0 ? 'amber' : 'muted'}
            lamp={critCves > 0 ? 'red' : highCves > 0 ? 'amber' : sbomSummary?.total_components ? 'green' : 'idle'}
            onClick={() => navigate(`/projects/${project.id}/sbom`)}
          />

          <FlapCounter
            label="Hardening Score"
            value={hardSum ? `${hardSum.average_score.toFixed(1)}/5` : telemetryLoading ? '—' : 'N/A'}
            subtext={
              hardSum
                ? `${hardSum.total_binaries} ELFs · ${hardSum.nx_percentage}% NX · ${hardSum.pie_percentage}% PIE`
                : 'Auditing binaries...'
            }
            tone={
              !hardSum
                ? 'muted'
                : hardSum.average_score >= 3.5
                  ? 'green'
                  : hardSum.average_score >= 2.0
                    ? 'amber'
                    : 'red'
            }
            lamp={
              !hardSum
                ? 'idle'
                : hardSum.average_score >= 3.5
                  ? 'green'
                  : hardSum.average_score >= 2.0
                    ? 'amber'
                    : 'red'
            }
            onClick={() => navigate(`/projects/${project.id}/hardening`)}
          />

          <FlapCounter
            label="Tracked Findings"
            value={String(findings.length).padStart(2, '0')}
            subtext={
              findings.length > 0
                ? `${criticalFindingsCount} critical · ${openFindingsCount} open`
                : 'Export from Secrets or SBOM'
            }
            tone={criticalFindingsCount > 0 ? 'red' : openFindingsCount > 0 ? 'amber' : 'muted'}
            lamp={criticalFindingsCount > 0 ? 'red' : openFindingsCount > 0 ? 'amber' : 'idle'}
            onClick={() => navigate(`/projects/${project.id}/findings`)}
          />
        </div>
      )}

      {/* Main 2-Column Split-Flap Command Grid */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12 items-start">
        {/* LEFT COLUMN (7/12): Priority Risk Board + Firmware Images + Image Structure */}
        <div className="space-y-5 lg:col-span-7 min-w-0">
          {/* Priority Risks Triage Board */}
          {hasUnpacked && (
            <div className="board-surface overflow-hidden rounded-md">
              <BoardSectionHeader
                title={
                  <>
                    <ShieldAlert className="h-4 w-4 text-primary" />
                    Priority Exposure Board
                  </>
                }
                right={
                  <Button variant="outline" size="sm" asChild className="h-7 text-xs">
                    <Link to={`/projects/${project.id}/secrets`}>
                      Full Secrets Board <ArrowRight className="h-3.5 w-3.5" />
                    </Link>
                  </Button>
                }
              />

              {telemetryLoading && !secretsData ? (
                <div className="flex items-center gap-2 px-4 py-6 font-mono text-xs text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin text-primary" />
                  Harvesting credentials, keys, and defaults...
                </div>
              ) : topPriority.length === 0 ? (
                <div className="flex items-center justify-between px-4 py-5 text-xs text-muted-foreground">
                  <span className="inline-flex items-center gap-2">
                    <SignalLamp tone="green" />
                    No cracked accounts, exposed private keys, or hardcoded defaults detected.
                  </span>
                  <Link
                    to={`/projects/${project.id}/findings`}
                    className="font-mono text-primary hover:underline"
                  >
                    Findings →
                  </Link>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead className="border-b border-border bg-muted/40 font-display text-[11px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                      <tr>
                        <th className="py-2 px-4">Sev</th>
                        <th className="py-2 px-3">Finding</th>
                        <th className="py-2 px-3">Evidence</th>
                        <th className="py-2 px-4 text-right">Source</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/70">
                      {topPriority.map((item) => (
                        <tr
                          key={item.id}
                          onClick={() => navigate(item.to)}
                          className="cursor-pointer transition-colors hover:bg-muted/30"
                        >
                          <td className="py-2.5 px-4 whitespace-nowrap">
                            <Badge variant="outline" className={`text-[10px] ${SEV_STYLE[item.severity]}`}>
                              {item.severity.toUpperCase()}
                            </Badge>
                          </td>
                          <td className="py-2.5 px-3 font-medium text-foreground whitespace-nowrap">
                            {item.title}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[11px] text-muted-foreground max-w-[200px] truncate">
                            {item.detail}
                          </td>
                          <td className="py-2.5 px-4 text-right font-mono text-[11px] text-muted-foreground tabular-nums whitespace-nowrap">
                            {item.location}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {priorityItems.length > topPriority.length && (
                    <div className="border-t border-border bg-muted/25 px-4 py-2 flex items-center justify-between text-xs">
                      <span className="font-mono text-muted-foreground tabular-nums">
                        +{priorityItems.length - topPriority.length} more exposed items
                      </span>
                      <Link
                        to={`/projects/${project.id}/secrets`}
                        className="font-mono text-foreground hover:underline"
                      >
                        Inspect all {priorityItems.length} →
                      </Link>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Firmware Images Board */}
          {firmware.length > 0 && (
            <div className="board-surface overflow-hidden rounded-md">
              <BoardSectionHeader
                title={`Firmware Images (${firmware.length})`}
                right={
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-7 text-xs"
                    onClick={() => setShowUpload((v) => !v)}
                  >
                    <Plus className="h-3.5 w-3.5" />
                    Add Version
                  </Button>
                }
              />
              <div className="divide-y divide-border">
                {firmware.map((fw) => {
                  const fwDetail = firmwareList.find((f) => f.id === fw.id)
                  const isUnpacked = Boolean(fwDetail?.extracted_path)
                  const hasError = Boolean(fwDetail?.unpack_log && !isUnpacked && status === 'error')

                  return (
                    <div key={fw.id} className="p-4 space-y-2.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2 min-w-0">
                          <FileText className="h-4 w-4 text-primary shrink-0" />
                          <span className="font-mono text-xs font-semibold text-foreground break-all">
                            {fw.original_filename}
                          </span>

                          {editingVersionLabel === fw.id ? (
                            <span className="inline-flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                              <Input
                                ref={versionInputRef}
                                value={versionLabelDraft}
                                onChange={(e) => setVersionLabelDraft(e.target.value)}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') saveVersionLabel(fw.id)
                                  if (e.key === 'Escape') setEditingVersionLabel(null)
                                }}
                                placeholder="v1.0.3"
                                className="h-6 w-28 text-xs"
                              />
                              <Button type="button" size="icon-xs" variant="ghost" onClick={() => saveVersionLabel(fw.id)}>
                                <Check className="h-3 w-3" />
                              </Button>
                              <Button type="button" size="icon-xs" variant="ghost" onClick={() => setEditingVersionLabel(null)}>
                                <X className="h-3 w-3" />
                              </Button>
                            </span>
                          ) : fw.version_label ? (
                            <Badge
                              variant="secondary"
                              className="cursor-pointer hover:border-primary/60"
                              onClick={() => startEditingVersionLabel(fw.id, fw.version_label ?? null)}
                            >
                              <Tag className="h-3 w-3" />
                              {fw.version_label}
                              <Pencil className="ml-0.5 h-2.5 w-2.5 opacity-60" />
                            </Badge>
                          ) : (
                            <button
                              type="button"
                              className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
                              onClick={() => startEditingVersionLabel(fw.id, null)}
                            >
                              <Tag className="h-3 w-3" />
                              Tag
                            </button>
                          )}
                        </div>

                        <div className="flex items-center gap-1">
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            onClick={() =>
                              setDecryptTarget({
                                id: fw.id,
                                filename: fw.original_filename ?? 'firmware.bin',
                              })
                            }
                            title="Inspect Shannon entropy or decrypt wrapped/encrypted firmware"
                          >
                            <LockKeyhole className="h-3.5 w-3.5" />
                            Decrypt
                          </Button>
                          {!isUnpacked && !hasError && (
                            <Button type="button" size="sm" onClick={() => handleUnpack(fw.id)} disabled={unpacking}>
                              {unpacking && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                              Unpack
                            </Button>
                          )}
                          <Button
                            type="button"
                            size="icon-xs"
                            variant="ghost"
                            className="text-[#FF7B7F] hover:bg-destructive/15"
                            aria-label="Delete firmware image"
                            onClick={() => handleDeleteFirmware(fw.id)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5 rounded-[4px] border border-border bg-background/60 px-3 py-2 font-mono text-[11px]">
                        <span className="inline-flex items-center gap-1.5">
                          <HardDrive className="h-3 w-3 text-muted-foreground" />
                          <span className="text-muted-foreground">SIZE</span>
                          <span className="tabular-nums text-foreground">
                            {fw.file_size != null ? formatFileSize(fw.file_size) : 'N/A'}
                          </span>
                        </span>
                        <span className="inline-flex items-center gap-1.5">
                          <Cpu className="h-3 w-3 text-muted-foreground" />
                          <span className="text-muted-foreground">ARCH</span>
                          <span className="text-foreground">
                            {fw.architecture ? `${fw.architecture}${fw.endianness ? ` (${fw.endianness})` : ''}` : 'Detecting'}
                          </span>
                        </span>
                        <span className="inline-flex items-center gap-1.5 min-w-0">
                          <Hash className="h-3 w-3 text-muted-foreground shrink-0" />
                          <span className="truncate max-w-[180px] text-muted-foreground" title={fw.sha256}>
                            {fw.sha256.slice(0, 16)}…
                          </span>
                          <button
                            type="button"
                            onClick={() => copySha(fw.sha256)}
                            className="text-muted-foreground hover:text-primary"
                            aria-label="Copy SHA-256"
                          >
                            {copiedSha === fw.sha256 ? (
                              <Check className="h-3 w-3 text-[#4ADE80]" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        </span>
                      </div>

                      {hasError && fwDetail?.unpack_log && (
                        <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 space-y-2">
                          <div className="flex items-center gap-2 text-xs font-semibold text-[#FF7B7F]">
                            <AlertCircle className="h-4 w-4" />
                            Unpacking Failed
                          </div>
                          <pre className="max-h-36 overflow-auto rounded bg-background p-2.5 font-mono text-xs text-muted-foreground">
                            {fwDetail.unpack_log}
                          </pre>
                          <div className="flex flex-wrap items-center gap-2">
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              onClick={() => handleUnpack(fw.id)}
                              disabled={unpacking}
                            >
                              {unpacking && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                              Retry Unpack
                            </Button>
                            <Button
                              type="button"
                              size="sm"
                              onClick={() =>
                                setDecryptTarget({
                                  id: fw.id,
                                  filename: fw.original_filename ?? 'firmware.bin',
                                })
                              }
                            >
                              <LockKeyhole className="h-3.5 w-3.5" />
                              Inspect Entropy / Decrypt
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Firmware Structure Metadata (when present) */}
          {firmwareList
            .filter((fw) => fw.extracted_path)
            .map((fw) => (
              <FirmwareMetadataCard key={fw.id} projectId={project.id} firmwareId={fw.id} />
            ))}
        </div>

        {/* RIGHT COLUMN (5/12): Hardening Pip Health + Secrets Breakdown + Docs + Compact MCP */}
        <div className="space-y-5 lg:col-span-5 min-w-0">
          {/* Binary Hardening Health Panel (Pip Meters) */}
          {hasUnpacked && hardSum && hardSum.total_binaries > 0 && (
            <div className="board-surface overflow-hidden rounded-md">
              <BoardSectionHeader
                title={
                  <>
                    <ShieldCheck className="h-4 w-4 text-primary" />
                    Binary Hardening Health
                  </>
                }
                right={
                  <Button variant="outline" size="sm" asChild className="h-7 text-xs">
                    <Link to={`/projects/${project.id}/hardening`}>
                      Matrix <ArrowRight className="h-3 w-3" />
                    </Link>
                  </Button>
                }
              />
              <div className="p-4 space-y-3">
                {[
                  {
                    label: 'NX Stack',
                    pct: hardSum.nx_percentage,
                    count: `${hardSum.nx_count}/${hardSum.total_binaries}`,
                  },
                  {
                    label: 'Stack Canaries',
                    pct: hardSum.canary_percentage,
                    count: `${hardSum.canary_count}/${hardSum.total_binaries}`,
                  },
                  {
                    label: 'PIE / ASLR',
                    pct: hardSum.pie_percentage,
                    count: `${hardSum.pie_count}/${hardSum.total_binaries}`,
                  },
                  {
                    label: 'Full RELRO',
                    pct: hardSum.full_relro_percentage,
                    count: `${hardSum.full_relro_count}/${hardSum.total_binaries}`,
                  },
                ].map((m) => (
                  <div key={m.label} className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-mono text-[#D1D5DB]">{m.label}</span>
                    <div className="flex items-center gap-2.5">
                      <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
                        {m.count}
                      </span>
                      <PipMeter value={m.pct} segments={10} showLabel />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Compact Secrets Breakdown Summary */}
          {hasUnpacked && secSum && (
            <div className="board-surface overflow-hidden rounded-md">
              <BoardSectionHeader
                title={
                  <>
                    <KeyRound className="h-4 w-4 text-primary" />
                    Credentials Breakdown
                  </>
                }
                right={
                  <Link
                    to={`/projects/${project.id}/secrets`}
                    className="font-mono text-[11px] text-primary hover:underline"
                  >
                    Open →
                  </Link>
                }
              />
              <div className="divide-y divide-border/70 px-4 py-1 font-mono text-xs">
                {[
                  {
                    label: 'Unencrypted Private Keys',
                    val: secSum.unencrypted_private_keys,
                    tone: secSum.unencrypted_private_keys > 0 ? 'text-red-400' : 'text-muted-foreground',
                  },
                  {
                    label: 'Device X.509 Certificates',
                    val: secSum.total_certificates,
                    tone: secSum.expired_certificates > 0 ? 'text-amber-400' : 'text-muted-foreground',
                  },
                  {
                    label: 'Cracked User Accounts',
                    val: secSum.cracked_accounts,
                    tone: secSum.cracked_accounts > 0 ? 'text-red-400' : 'text-muted-foreground',
                  },
                  {
                    label: 'Empty-Password Login Shells',
                    val: secSum.empty_password_accounts,
                    tone: secSum.empty_password_accounts > 0 ? 'text-red-400' : 'text-muted-foreground',
                  },
                  {
                    label: 'Router Default Credentials',
                    val: secSum.router_default_credentials,
                    tone: secSum.router_default_credentials > 0 ? 'text-amber-400' : 'text-muted-foreground',
                  },
                  {
                    label: 'API Tokens & High-Entropy',
                    val: secSum.high_entropy_secrets,
                    tone: secSum.high_entropy_secrets > 0 ? 'text-amber-400' : 'text-muted-foreground',
                  },
                ].map((row) => (
                  <div key={row.label} className="flex items-center justify-between py-2.5">
                    <span className="text-foreground/85">{row.label}</span>
                    <span className={`font-semibold tabular-nums ${row.tone}`}>
                      {String(row.val).padStart(2, '0')}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Project Documents */}
          <DocumentsCard projectId={project.id} />

          {/* Compact MCP Connection Card */}
          {hasUnpacked && <McpConnectionCard projectId={project.id} />}
        </div>
      </div>

      {decryptTarget && (
        <FirmwareDecryptDialog
          open={true}
          onOpenChange={(open) => {
            if (!open) setDecryptTarget(null)
          }}
          projectId={project.id}
          firmwareId={decryptTarget.id}
          filename={decryptTarget.filename}
          onDecrypted={() => {
            fetchProject(project.id)
            listFirmware(project.id).then(setFirmwareList).catch(() => { })
          }}
        />
      )}
    </div>
  )
}
