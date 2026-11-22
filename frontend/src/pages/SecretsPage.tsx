import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  ShieldCheck,
  RefreshCw,
  Search,
  Eye,
  EyeOff,
  Copy,
  Check,
  Download,
  AlertTriangle,
  Lock,
  Unlock,
  FileKey,
  Users,
  Wifi,
  ExternalLink,
  Loader2,
  Code2,
  X,
  FolderOpen,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { BoardSectionHeader, FlapCounter } from '@/components/ui/split-flap'
import { getFirmwareSecrets, exportSecretsToFindings } from '@/api/analysis'
import { listFirmware } from '@/api/firmware'
import type {
  CertificateFinding,
  FirmwareDetail,
  SecretsHarvestResponse,
  SecretSeverity,
} from '@/types'

const SEVERITY_RANK: Record<SecretSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
}

const SEVERITY_BADGES: Record<SecretSeverity, string> = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/35',
  high: 'bg-amber-500/10 text-amber-400 border-amber-500/35',
  medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/35',
  low: 'bg-blue-500/10 text-blue-400 border-blue-500/35',
  info: 'bg-muted text-muted-foreground border-border',
}

const CATEGORY_LABELS: Record<string, string> = {
  aws_access_key: 'AWS Access Key',
  github_token: 'GitHub Token',
  google_api_key: 'Google API Key',
  slack_token: 'Slack Token',
  stripe_live_key: 'Stripe Live Key',
  bearer_token: 'Bearer Token',
  jwt_token: 'JWT Token',
  wpa_passphrase: 'WPA Passphrase',
  api_key: 'API Key',
  api_secret: 'API Secret',
  secret_key: 'Secret Key',
  auth_token: 'Auth Token',
  access_token: 'Access Token',
  private_token: 'Private Token',
  client_secret: 'Client Secret',
  db_password: 'DB Password',
  master_key: 'Master Key',
}

type TabType = 'keys_certs' | 'accounts' | 'router_creds' | 'generic'

function formatCategory(cat: string): string {
  if (CATEGORY_LABELS[cat]) return CATEGORY_LABELS[cat]
  return cat
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (ch) => ch.toUpperCase())
}

function getCertificateSeverity(cert: CertificateFinding): SecretSeverity {
  if (!cert.issues || cert.issues.length === 0) return 'info'
  return cert.issues.reduce<SecretSeverity>((highest, issue) => {
    return SEVERITY_RANK[issue.severity] > SEVERITY_RANK[highest] ? issue.severity : highest
  }, 'info')
}

function pickInitialTab(res: SecretsHarvestResponse): TabType {
  const candidates: Array<{ tab: TabType; count: number; critical: number }> = [
    {
      tab: 'accounts',
      count: res.accounts.length,
      critical: res.accounts.filter((a) => a.severity === 'critical').length,
    },
    {
      tab: 'router_creds',
      count: res.router_credentials.length,
      critical: res.router_credentials.filter((r) => r.severity === 'critical').length,
    },
    {
      tab: 'keys_certs',
      count: res.private_keys.length + res.certificates.length,
      critical:
        res.private_keys.filter((k) => k.severity === 'critical').length +
        res.certificates.filter((c) => getCertificateSeverity(c) === 'critical').length,
    },
    {
      tab: 'generic',
      count: res.generic_secrets.length,
      critical: res.generic_secrets.filter((g) => g.severity === 'critical').length,
    },
  ]

  const withCritical = candidates.find((c) => c.critical > 0)
  if (withCritical) return withCritical.tab
  const withAny = candidates.find((c) => c.count > 0)
  return withAny ? withAny.tab : 'accounts'
}

export default function SecretsPage() {
  const { projectId } = useParams<{ projectId: string }>()

  const [data, setData] = useState<SecretsHarvestResponse | null>(null)
  const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
  const [selectedFirmwareId, setSelectedFirmwareId] = useState<string | undefined>()
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [exportMessage, setExportMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const [activeTab, setActiveTab] = useState<TabType>('accounts')
  const userPickedTabRef = useRef(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [showSensitive, setShowSensitive] = useState(false)
  const [revealedIds, setRevealedIds] = useState<Record<string, boolean>>({})
  const [copiedId, setCopiedId] = useState<string | null>(null)

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
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Failed to list firmware')
      })
  }, [projectId, selectedFirmwareId])

  const fetchData = useCallback(
    async (refresh = false) => {
      if (!projectId) return
      try {
        if (refresh) setRefreshing(true)
        else setLoading(true)
        setError(null)
        const res = await getFirmwareSecrets(projectId, selectedFirmwareId, refresh)
        setData(res)
        if (!userPickedTabRef.current) {
          setActiveTab(pickInitialTab(res))
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load secrets findings')
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

  const handleSelectTab = (tab: TabType) => {
    userPickedTabRef.current = true
    setActiveTab(tab)
  }

  const handleFirmwareChange = (fwId: string) => {
    userPickedTabRef.current = false
    setRevealedIds({})
    setSelectedFirmwareId(fwId)
  }

  const toggleRowReveal = (rowId: string) => {
    setRevealedIds((prev) => ({ ...prev, [rowId]: !prev[rowId] }))
  }

  const isValueVisible = (rowId: string) => showSensitive || Boolean(revealedIds[rowId])

  const clearFilters = () => {
    setSearchQuery('')
    setSeverityFilter('all')
  }

  const hasActiveFilters = searchQuery.trim().length > 0 || severityFilter !== 'all'

  const handleExportFindings = async () => {
    if (!projectId) return
    try {
      setExporting(true)
      setExportMessage(null)
      const res = await exportSecretsToFindings(projectId, selectedFirmwareId, 'medium')
      if (res.created_count === 0 && res.skipped_count > 0) {
        setExportMessage(
          `All ${res.skipped_count} findings are already tracked in project Findings.`,
        )
      } else {
        setExportMessage(
          `Exported ${res.created_count} new findings (${res.skipped_count} duplicates skipped).`,
        )
      }
      setTimeout(() => setExportMessage(null), 10000)
    } catch (err) {
      setExportMessage(err instanceof Error ? err.message : 'Failed to export findings')
    } finally {
      setExporting(false)
    }
  }

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const filteredKeys = useMemo(() => {
    if (!data) return []
    const q = searchQuery.trim().toLowerCase()
    return data.private_keys.filter((k) => {
      if (severityFilter !== 'all' && k.severity !== severityFilter) return false
      if (!q) return true
      return k.path.toLowerCase().includes(q) || k.key_type.toLowerCase().includes(q)
    })
  }, [data, severityFilter, searchQuery])

  const filteredCerts = useMemo(() => {
    if (!data) return []
    const q = searchQuery.trim().toLowerCase()
    return data.certificates.filter((c) => {
      if (severityFilter !== 'all' && getCertificateSeverity(c) !== severityFilter) return false
      if (!q) return true
      return (
        c.path.toLowerCase().includes(q) ||
        c.subject.toLowerCase().includes(q) ||
        c.issuer.toLowerCase().includes(q)
      )
    })
  }, [data, severityFilter, searchQuery])

  const filteredAccounts = useMemo(() => {
    if (!data) return []
    const q = searchQuery.trim().toLowerCase()
    return data.accounts.filter((a) => {
      if (severityFilter !== 'all' && a.severity !== severityFilter) return false
      if (!q) return true
      return (
        a.username.toLowerCase().includes(q) ||
        a.source_file.toLowerCase().includes(q) ||
        (a.shell && a.shell.toLowerCase().includes(q)) ||
        (a.cracked_password && a.cracked_password.toLowerCase().includes(q))
      )
    })
  }, [data, severityFilter, searchQuery])

  const filteredRouterCreds = useMemo(() => {
    if (!data) return []
    const q = searchQuery.trim().toLowerCase()
    return data.router_credentials.filter((r) => {
      if (severityFilter !== 'all' && r.severity !== severityFilter) return false
      if (!q) return true
      return (
        r.service.toLowerCase().includes(q) ||
        r.source_file.toLowerCase().includes(q) ||
        (r.username && r.username.toLowerCase().includes(q)) ||
        r.matched_rule.toLowerCase().includes(q) ||
        (showSensitive && r.password ? r.password.toLowerCase().includes(q) : false)
      )
    })
  }, [data, severityFilter, searchQuery, showSensitive])

  const filteredGenericSecrets = useMemo(() => {
    if (!data) return []
    const q = searchQuery.trim().toLowerCase()
    return data.generic_secrets.filter((g) => {
      if (severityFilter !== 'all' && g.severity !== severityFilter) return false
      if (!q) return true
      return (
        g.path.toLowerCase().includes(q) ||
        g.category.toLowerCase().includes(q) ||
        formatCategory(g.category).toLowerCase().includes(q) ||
        (showSensitive && g.match_text.toLowerCase().includes(q))
      )
    })
  }, [data, severityFilter, searchQuery, showSensitive])

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <Loader2 className="w-7 h-7 animate-spin text-primary" />
        <p className="font-mono text-xs text-muted-foreground">
          Scanning firmware rootfs for keys, accounts, router defaults, and tokens...
        </p>
      </div>
    )
  }

  const vulnerableAccountCount = data
    ? data.summary.empty_password_accounts + data.summary.cracked_accounts
    : 0
  const keyCertTotal = data ? data.private_keys.length + data.certificates.length : 0
  const genericCount = data ? data.generic_secrets.length : 0

  return (
    <div className="space-y-5 animate-flap-settle">
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="font-display text-2xl font-bold uppercase tracking-[0.05em] text-foreground">
              Secrets &amp; Credential Harvester
            </h1>
            {data && (
              <Badge variant="outline" className="text-[10px] uppercase text-muted-foreground">
                {data.cached ? 'CACHED' : 'FRESH SCAN'}
              </Badge>
            )}
          </div>
          <p className="text-sm text-muted-foreground mt-0.5">
            Embedded private keys, device certificates, system accounts, router defaults, and hardcoded API tokens.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {firmwareList.length > 1 && (
            <select
              aria-label="Select firmware image"
              value={selectedFirmwareId}
              onChange={(e) => handleFirmwareChange(e.target.value)}
              className="h-8 text-xs font-mono bg-background border border-border rounded-md px-2.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
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
            onClick={() => setShowSensitive((prev) => !prev)}
            className="h-8 gap-1.5 text-xs"
          >
            {showSensitive ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            {showSensitive ? 'Hide Values' : 'Reveal Values'}
          </Button>

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => fetchData(true)}
            disabled={refreshing}
            className="h-8 gap-1.5 text-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Rescan
          </Button>

          <Button
            type="button"
            size="sm"
            onClick={handleExportFindings}
            disabled={exporting || !data || data.summary.total_findings === 0}
            className="h-8 gap-1.5 text-xs"
          >
            <Download className="w-3.5 h-3.5" />
            {exporting ? 'Exporting...' : 'Export to Findings'}
          </Button>
        </div>
      </div>

      {exportMessage && (
        <div
          role="status"
          className="px-3.5 py-2.5 bg-[#22C55E]/10 border border-[#22C55E]/40 rounded-[4px] text-[#4ADE80] text-xs flex flex-wrap items-center justify-between gap-2"
        >
          <span>{exportMessage}</span>
          <Link
            to={`/projects/${projectId}/findings`}
            className="underline font-mono font-medium flex items-center gap-1 hover:opacity-80"
          >
            VIEW FINDINGS <ExternalLink className="w-3 h-3" />
          </Link>
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="p-3.5 bg-destructive/10 border border-destructive/40 rounded-[4px] text-[#FF7B7F] text-sm flex items-center gap-2"
        >
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Split-Flap Concourse Telemetry Strip */}
      {data && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <FlapCounter
            label="Total Findings"
            value={String(data.summary.total_findings).padStart(2, '0')}
            subtext={`${data.summary.critical_count} crit · ${data.summary.high_count} high`}
            tone={data.summary.critical_count > 0 ? 'red' : data.summary.total_findings > 0 ? 'neutral' : 'muted'}
            lamp={data.summary.critical_count > 0 ? 'red' : data.summary.high_count > 0 ? 'amber' : 'green'}
          />
          <FlapCounter
            label="Keys & Certs"
            value={String(keyCertTotal).padStart(2, '0')}
            subtext={`${data.summary.unencrypted_private_keys} exposed · ${data.summary.expired_certificates} expired`}
            tone={
              data.summary.unencrypted_private_keys > 0
                ? 'red'
                : keyCertTotal > 0
                  ? 'neutral'
                  : 'muted'
            }
            lamp={data.summary.unencrypted_private_keys > 0 ? 'red' : data.summary.expired_certificates > 0 ? 'amber' : 'idle'}
            active={activeTab === 'keys_certs'}
            onClick={() => handleSelectTab('keys_certs')}
          />
          <FlapCounter
            label="Vulnerable Accts"
            value={String(vulnerableAccountCount).padStart(2, '0')}
            subtext={`${data.summary.cracked_accounts} cracked · ${data.summary.empty_password_accounts} empty`}
            tone={vulnerableAccountCount > 0 ? 'red' : 'muted'}
            lamp={vulnerableAccountCount > 0 ? 'red' : 'green'}
            active={activeTab === 'accounts'}
            onClick={() => handleSelectTab('accounts')}
          />
          <FlapCounter
            label="Router Defaults"
            value={String(data.summary.router_default_credentials).padStart(2, '0')}
            subtext="NVRAM, web, FTP, Wi-Fi"
            tone={data.summary.router_default_credentials > 0 ? 'amber' : 'muted'}
            lamp={data.summary.router_default_credentials > 0 ? 'amber' : 'idle'}
            active={activeTab === 'router_creds'}
            onClick={() => handleSelectTab('router_creds')}
          />
          <FlapCounter
            label="Tokens & Secrets"
            value={String(genericCount).padStart(2, '0')}
            subtext="API keys & high-entropy"
            tone={genericCount > 0 ? 'amber' : 'muted'}
            lamp={genericCount > 0 ? 'amber' : 'idle'}
            active={activeTab === 'generic'}
            onClick={() => handleSelectTab('generic')}
            className="col-span-2 sm:col-span-1"
          />
        </div>
      )}

      {/* Navigation Tabs & Filter Bar */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between border-b border-border pb-3">
        <div role="tablist" aria-label="Secrets categories" className="flex flex-wrap items-center gap-1.5">
          {[
            { id: 'accounts' as TabType, label: 'Accounts & Passwords', count: data?.accounts.length ?? 0 },
            { id: 'router_creds' as TabType, label: 'Router Defaults', count: data?.router_credentials.length ?? 0 },
            { id: 'keys_certs' as TabType, label: 'Keys & Certs', count: keyCertTotal },
            { id: 'generic' as TabType, label: 'Tokens & Secrets', count: genericCount },
          ].map((tab) => {
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={isActive}
                onClick={() => handleSelectTab(tab.id)}
                className={`inline-flex h-8 items-center gap-2 rounded-md border px-3 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
                  isActive
                    ? 'border-border bg-secondary text-foreground'
                    : 'border-transparent bg-transparent text-muted-foreground hover:bg-muted/50 hover:text-foreground'
                }`}
              >
                <span>{tab.label}</span>
                <span className="font-mono text-[11px] tabular-nums opacity-80">
                  {String(tab.count).padStart(2, '0')}
                </span>
              </button>
            )
          })}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
            <Input
              aria-label="Filter secrets"
              placeholder="Filter path, user, service..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8 pl-8 pr-7 text-xs w-52 sm:w-60"
            />
            {searchQuery && (
              <button
                type="button"
                aria-label="Clear search query"
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <select
            aria-label="Filter by severity"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="h-8 text-xs font-mono bg-background border border-border rounded-md px-2.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <option value="all">ALL SEVERITIES</option>
            <option value="critical">CRITICAL</option>
            <option value="high">HIGH</option>
            <option value="medium">MEDIUM</option>
            <option value="low">LOW</option>
            <option value="info">INFO</option>
          </select>

          {hasActiveFilters && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={clearFilters}
              className="h-8 px-2 text-xs text-muted-foreground"
            >
              Reset
            </Button>
          )}
        </div>
      </div>

      {/* TAB: Keys & Certificates */}
      {activeTab === 'keys_certs' && (
        <div className="space-y-5">
          <div className="board-surface overflow-hidden rounded-md">
            <BoardSectionHeader
              title={
                <>
                  <FileKey className="w-4 h-4 text-primary" />
                  Embedded Private Keys
                </>
              }
              subtitle="PEM and OpenSSH private key blocks bundled directly in the firmware image."
              right={
                <span className="font-mono text-xs text-muted-foreground tabular-nums">
                  {filteredKeys.length} / {data?.private_keys.length ?? 0}
                </span>
              }
            />
            {filteredKeys.length === 0 ? (
              <div className="p-6 text-center text-xs text-muted-foreground">
                {data && data.private_keys.length > 0 && hasActiveFilters ? (
                  <div className="space-y-2">
                    <p>No private keys match the active filter.</p>
                    <Button type="button" variant="outline" size="sm" onClick={clearFilters} className="h-7 text-xs">
                      Clear filters
                    </Button>
                  </div>
                ) : (
                  <div className="inline-flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-[#4ADE80]" />
                    No embedded private keys detected in this firmware.
                  </div>
                )}
              </div>
            ) : (
              <div className="divide-y divide-border">
                {filteredKeys.map((k, idx) => {
                  const rowId = `key-${idx}`
                  const visible = isValueVisible(rowId)
                  return (
                    <div key={`${k.path}:${k.line_number ?? idx}`} className="p-4 hover:bg-muted/30 transition-colors space-y-2.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2 min-w-0">
                          <Badge variant="outline" className={`text-[10px] ${SEVERITY_BADGES[k.severity]}`}>
                            {k.severity.toUpperCase()}
                          </Badge>
                          <span className="font-mono text-xs font-medium break-all text-foreground">
                            {k.path}
                            {k.line_number ? `:${k.line_number}` : ''}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <Badge variant="outline" className="text-[10px]">
                            {k.key_type} ({k.format})
                          </Badge>
                          {k.encrypted ? (
                            <Badge variant="outline" className="text-[10px] bg-[#22C55E]/10 text-[#4ADE80] border-[#22C55E]/40">
                              <Lock className="w-2.5 h-2.5" /> ENCRYPTED
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="text-[10px] bg-[#E5484D]/15 text-[#FF7B7F] border-[#E5484D]/50">
                              <Unlock className="w-2.5 h-2.5" /> UNENCRYPTED
                            </Badge>
                          )}
                        </div>
                      </div>

                      <div className="rounded-[4px] border border-border bg-background px-3 py-2 text-[11px] font-mono text-muted-foreground flex items-center justify-between gap-2">
                        <span className="break-all whitespace-pre-wrap">
                          {visible ? k.preview : '••••••••••••••••••••••••••••••••••••••••••••••••'}
                        </span>
                        <div className="flex items-center gap-1 shrink-0">
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-xs"
                            aria-label={visible ? 'Hide private key preview' : 'Reveal private key preview'}
                            onClick={() => toggleRowReveal(rowId)}
                          >
                            {visible ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-xs"
                            aria-label="Copy private key preview"
                            onClick={() => copyToClipboard(k.preview, rowId)}
                          >
                            {copiedId === rowId ? <Check className="w-3 h-3 text-[#4ADE80]" /> : <Copy className="w-3 h-3" />}
                          </Button>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          <div className="board-surface overflow-hidden rounded-md">
            <BoardSectionHeader
              title={
                <>
                  <ShieldCheck className="w-4 h-4 text-primary" />
                  Device X.509 Certificates
                </>
              }
              subtitle="Device TLS certificates checked for expiry, weak key sizes, and deprecated signatures. System CA trust bundles are excluded."
              right={
                <span className="font-mono text-xs text-muted-foreground tabular-nums">
                  {filteredCerts.length} / {data?.certificates.length ?? 0}
                </span>
              }
            />
            {filteredCerts.length === 0 ? (
              <div className="p-6 text-center text-xs text-muted-foreground">
                {data && data.certificates.length > 0 && hasActiveFilters ? (
                  <div className="space-y-2">
                    <p>No certificates match the active filter.</p>
                    <Button type="button" variant="outline" size="sm" onClick={clearFilters} className="h-7 text-xs">
                      Clear filters
                    </Button>
                  </div>
                ) : (
                  <div className="inline-flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-[#4ADE80]" />
                    No device certificates found.
                  </div>
                )}
              </div>
            ) : (
              <div className="divide-y divide-border">
                {filteredCerts.map((c, idx) => {
                  const certSev = getCertificateSeverity(c)
                  return (
                    <div key={`${c.path}-${c.serial}-${idx}`} className="p-4 hover:bg-muted/30 transition-colors space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2 min-w-0">
                          <Badge variant="outline" className={`text-[10px] ${SEVERITY_BADGES[certSev]}`}>
                            {certSev.toUpperCase()}
                          </Badge>
                          <span className="font-mono text-xs font-medium break-all">{c.path}</span>
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-[11px] text-muted-foreground font-mono tabular-nums">
                            EXP {c.not_after.slice(0, 10)}
                          </span>
                          {c.is_expired && (
                            <Badge variant="outline" className="text-[10px] bg-[#E5484D]/15 text-[#FF7B7F] border-[#E5484D]/50">
                              EXPIRED
                            </Badge>
                          )}
                          {c.self_signed && (
                            <Badge variant="outline" className="text-[10px] bg-[#F5A623]/15 text-[#F5A623] border-[#F5A623]/50">
                              SELF-SIGNED
                            </Badge>
                          )}
                        </div>
                      </div>

                      <div className="text-xs grid grid-cols-1 sm:grid-cols-2 gap-1 text-muted-foreground">
                        <div className="truncate" title={c.subject}>
                          <span className="font-medium text-foreground">Subject:</span> {c.subject}
                        </div>
                        <div>
                          <span className="font-medium text-foreground">Key:</span>{' '}
                          <span className="font-mono tabular-nums">
                            {c.key_type} {c.key_size}-bit · {c.signature_algorithm}
                          </span>
                        </div>
                      </div>

                      {c.issues.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {c.issues.map((iss, iIdx) => (
                            <span
                              key={iIdx}
                              className={`font-mono text-[10.5px] px-2 py-0.5 rounded-[3px] border ${SEVERITY_BADGES[iss.severity]}`}
                            >
                              {iss.issue}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB: Accounts & Passwords */}
      {activeTab === 'accounts' && (
        <div className="board-surface overflow-hidden rounded-md">
          <BoardSectionHeader
            title={
              <>
                <Users className="w-4 h-4 text-primary" />
                User Accounts &amp; Password Hashes
              </>
            }
            subtitle="Parsed from /etc/passwd and /etc/shadow with offline IoT default dictionary cracking."
            right={
              <span className="font-mono text-xs text-muted-foreground tabular-nums">
                {filteredAccounts.length} / {data?.accounts.length ?? 0}
              </span>
            }
          />
          {filteredAccounts.length === 0 ? (
            <div className="p-6 text-center text-xs text-muted-foreground">
              {data && data.accounts.length > 0 && hasActiveFilters ? (
                <div className="space-y-2">
                  <p>No accounts match the active filter.</p>
                  <Button type="button" variant="outline" size="sm" onClick={clearFilters} className="h-7 text-xs">
                    Clear filters
                  </Button>
                </div>
              ) : (
                'No passwd or shadow accounts extracted.'
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-muted/40 border-b border-border font-display text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                  <tr>
                    <th className="py-2.5 px-4">Severity</th>
                    <th className="py-2.5 px-4">Username</th>
                    <th className="py-2.5 px-4">UID:GID</th>
                    <th className="py-2.5 px-4">Hash</th>
                    <th className="py-2.5 px-4">Password / Status</th>
                    <th className="py-2.5 px-4">Shell</th>
                    <th className="py-2.5 px-4 text-right">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/80">
                  {filteredAccounts.map((a, idx) => {
                    const rowId = `acc-${idx}`
                    const visible = isValueVisible(rowId)
                    return (
                      <tr key={`${a.username}-${a.source_file}-${a.line_number}`} className="hover:bg-muted/30 transition-colors">
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <Badge variant="outline" className={`text-[10px] ${SEVERITY_BADGES[a.severity]}`}>
                            {a.severity.toUpperCase()}
                          </Badge>
                        </td>
                        <td className="py-2.5 px-4 font-mono font-semibold text-foreground whitespace-nowrap">
                          {a.username}
                        </td>
                        <td className="py-2.5 px-4 font-mono text-muted-foreground tabular-nums whitespace-nowrap">
                          {a.uid !== null && a.uid !== undefined ? `${a.uid}:${a.gid}` : '—'}
                        </td>
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <Badge variant="outline" className="text-[10px]">
                            {a.hash_type}
                          </Badge>
                        </td>
                        <td className="py-2.5 px-4">
                          {a.cracked_password ? (
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <Badge variant="destructive" className="text-[10px] px-1.5 py-0">
                                CRACKED
                              </Badge>
                              <span className="font-mono text-[#FF7B7F] font-semibold bg-[#E5484D]/15 border border-[#E5484D]/35 px-2 py-0.5 rounded-[3px] text-xs">
                                {visible ? a.cracked_password : '••••••'}
                              </span>
                              <button
                                type="button"
                                onClick={() => toggleRowReveal(rowId)}
                                className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-accent"
                                aria-label={visible ? 'Hide cracked password' : 'Reveal cracked password'}
                              >
                                {visible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                              </button>
                              <button
                                type="button"
                                onClick={() => copyToClipboard(a.cracked_password!, `pass-${idx}`)}
                                className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-accent"
                                aria-label="Copy plaintext password"
                              >
                                {copiedId === `pass-${idx}` ? (
                                  <Check className="w-3.5 h-3.5 text-[#4ADE80]" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                            </div>
                          ) : a.status === 'empty' ? (
                            <span
                              className={`font-mono font-medium inline-flex items-center gap-1 ${
                                a.severity === 'critical' ? 'text-[#FF7B7F]' : 'text-muted-foreground'
                              }`}
                            >
                              <Unlock className="w-3.5 h-3.5" /> EMPTY PASSWORD
                            </span>
                          ) : a.status === 'locked' ? (
                            <span className="text-muted-foreground font-mono inline-flex items-center gap-1">
                              <Lock className="w-3.5 h-3.5" /> LOCKED
                            </span>
                          ) : (
                            <div className="flex items-center gap-1.5">
                              <span
                                className="text-muted-foreground font-mono text-[11px] break-all max-w-xs inline-block"
                                title={visible ? a.hash_value || undefined : undefined}
                              >
                                {visible ? a.hash_value : '••••••••••••••••'}
                              </span>
                              {a.hash_value && (
                                <>
                                  <button
                                    type="button"
                                    onClick={() => toggleRowReveal(rowId)}
                                    className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-accent shrink-0"
                                    aria-label={visible ? 'Hide hash' : 'Reveal hash'}
                                  >
                                    {visible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => copyToClipboard(a.hash_value!, `hash-${idx}`)}
                                    className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-accent shrink-0"
                                    aria-label="Copy cryptographic hash"
                                  >
                                    {copiedId === `hash-${idx}` ? (
                                      <Check className="w-3.5 h-3.5 text-[#4ADE80]" />
                                    ) : (
                                      <Copy className="w-3.5 h-3.5" />
                                    )}
                                  </button>
                                </>
                              )}
                            </div>
                          )}
                        </td>
                        <td className="py-2.5 px-4 font-mono text-muted-foreground whitespace-nowrap">
                          {a.shell || '—'}
                        </td>
                        <td className="py-2.5 px-4 text-right font-mono text-[11px] text-muted-foreground tabular-nums whitespace-nowrap">
                          {a.source_file}:{a.line_number}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB: Router Defaults */}
      {activeTab === 'router_creds' && (
        <div className="board-surface overflow-hidden rounded-md">
          <BoardSectionHeader
            title={
              <>
                <Wifi className="w-4 h-4 text-primary" />
                Router Defaults &amp; Service Credentials
              </>
            }
            subtitle="Factory defaults extracted from NVRAM/default configs, web servers, FTP/Samba, PPP secrets, and UCI wireless."
            right={
              <span className="font-mono text-xs text-muted-foreground tabular-nums">
                {filteredRouterCreds.length} / {data?.router_credentials.length ?? 0}
              </span>
            }
          />
          {filteredRouterCreds.length === 0 ? (
            <div className="p-6 text-center text-xs text-muted-foreground">
              {data && data.router_credentials.length > 0 && hasActiveFilters ? (
                <div className="space-y-2">
                  <p>No router credentials match the active filter.</p>
                  <Button type="button" variant="outline" size="sm" onClick={clearFilters} className="h-7 text-xs">
                    Clear filters
                  </Button>
                </div>
              ) : (
                <div className="inline-flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-[#4ADE80]" />
                  No hardcoded router default credentials detected.
                </div>
              )}
            </div>
          ) : (
            <div className="divide-y divide-border/80">
              {filteredRouterCreds.map((r, idx) => {
                const rowId = `rc-${idx}`
                const visible = isValueVisible(rowId)
                const copyVal =
                  r.username && r.password
                    ? `${r.username}:${r.password}`
                    : r.password || r.username || ''
                return (
                  <div
                    key={`${r.source_file}:${r.line_number ?? idx}-${r.matched_rule}`}
                    className="p-4 hover:bg-muted/30 transition-colors flex flex-col gap-2.5 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant="outline" className={`text-[10px] ${SEVERITY_BADGES[r.severity]}`}>
                          {r.severity.toUpperCase()}
                        </Badge>
                        <Badge variant="secondary" className="text-[10px] uppercase">
                          {r.service}
                        </Badge>
                        <span className="font-mono text-xs text-foreground break-all">
                          {r.matched_rule}
                        </span>
                      </div>
                      <div className="font-mono text-[11px] text-muted-foreground tabular-nums break-all">
                        {r.source_file}
                        {r.line_number ? `:${r.line_number}` : ''}
                      </div>
                    </div>

                    <div className="rounded-[4px] border border-border bg-background px-3 py-1.5 font-mono text-xs flex items-center justify-between sm:justify-end gap-2.5 shrink-0">
                      <div className="flex flex-wrap items-center gap-2.5">
                        {r.username && (
                          <span className="text-muted-foreground">
                            USER <span className="text-foreground font-semibold">{r.username}</span>
                          </span>
                        )}
                        {r.password && (
                          <span className="text-muted-foreground">
                            PASS{' '}
                            <span className="text-[#FF7B7F] font-semibold">
                              {visible ? r.password : '••••••••'}
                            </span>
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-0.5 shrink-0">
                        {r.password && (
                          <button
                            type="button"
                            onClick={() => toggleRowReveal(rowId)}
                            className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-accent"
                            aria-label={visible ? 'Hide password' : 'Reveal password'}
                          >
                            {visible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                          </button>
                        )}
                        {copyVal && (
                          <button
                            type="button"
                            onClick={() => copyToClipboard(copyVal, rowId)}
                            className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-accent"
                            aria-label="Copy credential"
                          >
                            {copiedId === rowId ? (
                              <Check className="w-3.5 h-3.5 text-[#4ADE80]" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB: Tokens & Hardcoded Secrets */}
      {activeTab === 'generic' && (
        <div className="board-surface overflow-hidden rounded-md">
          <BoardSectionHeader
            title={
              <>
                <Code2 className="w-4 h-4 text-primary" />
                API Tokens &amp; High-Entropy Secrets
              </>
            }
            subtitle="Cloud keys, Bearer/JWT tokens, and hardcoded high-entropy secret assignments discovered in scripts and configs."
            right={
              <span className="font-mono text-xs text-muted-foreground tabular-nums">
                {filteredGenericSecrets.length} / {genericCount}
              </span>
            }
          />
          {filteredGenericSecrets.length === 0 ? (
            <div className="p-6 text-center text-xs text-muted-foreground">
              {data && data.generic_secrets.length > 0 && hasActiveFilters ? (
                <div className="space-y-2">
                  <p>No tokens or secrets match the active filter.</p>
                  <Button type="button" variant="outline" size="sm" onClick={clearFilters} className="h-7 text-xs">
                    Clear filters
                  </Button>
                </div>
              ) : (
                <div className="inline-flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-[#4ADE80]" />
                  No hardcoded API tokens or high-entropy secrets detected.
                </div>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-muted/40 border-b border-border font-display text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                  <tr>
                    <th className="py-2.5 px-4">Severity</th>
                    <th className="py-2.5 px-4">Type</th>
                    <th className="py-2.5 px-4">Matched Secret</th>
                    <th className="py-2.5 px-4">Entropy</th>
                    <th className="py-2.5 px-4 text-right">Location</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/80">
                  {filteredGenericSecrets.map((g, idx) => {
                    const rowId = `gen-${idx}`
                    const visible = isValueVisible(rowId)
                    return (
                      <tr key={`${g.path}:${g.line_number}-${g.category}-${idx}`} className="hover:bg-muted/30 transition-colors">
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <Badge variant="outline" className={`text-[10px] ${SEVERITY_BADGES[g.severity]}`}>
                            {g.severity.toUpperCase()}
                          </Badge>
                        </td>
                        <td className="py-2.5 px-4 font-medium whitespace-nowrap">
                          {formatCategory(g.category)}
                        </td>
                        <td className="py-2.5 px-4">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-[11px] bg-background border border-border px-2 py-0.5 rounded-[3px] break-all max-w-sm">
                              {visible ? g.match_text : '••••••••••••••••••••'}
                            </span>
                            <button
                              type="button"
                              onClick={() => toggleRowReveal(rowId)}
                              className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-accent shrink-0"
                              aria-label={visible ? 'Hide secret value' : 'Reveal secret value'}
                            >
                              {visible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                            </button>
                            <button
                              type="button"
                              onClick={() => copyToClipboard(g.match_text, rowId)}
                              className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-accent shrink-0"
                              aria-label="Copy secret value"
                            >
                              {copiedId === rowId ? (
                                <Check className="w-3.5 h-3.5 text-[#4ADE80]" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </td>
                        <td className="py-2.5 px-4 font-mono text-muted-foreground tabular-nums whitespace-nowrap">
                          {g.entropy.toFixed(2)} bits
                        </td>
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <div className="flex items-center justify-end gap-1.5 font-mono text-[11px] text-muted-foreground tabular-nums">
                            <span>
                              {g.path}:{g.line_number}
                            </span>
                            <Link
                              to={`/projects/${projectId}/explore?path=${encodeURIComponent(g.path)}`}
                              className="text-muted-foreground hover:text-primary p-0.5 rounded hover:bg-accent"
                              title="Open in File Explorer"
                              aria-label={`Inspect ${g.path} in File Explorer`}
                            >
                              <FolderOpen className="w-3.5 h-3.5" />
                            </Link>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
