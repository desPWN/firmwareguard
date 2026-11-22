import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  KeyRound,
  ArrowRight,
  Loader2,
  RefreshCw,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { BoardSectionHeader, FlapCounter, SignalLamp } from '@/components/ui/split-flap'
import { getSecretsHarvest } from '@/api/secrets'
import type { SecretsHarvestResponse } from '@/types'

interface SecretsKpiRibbonProps {
  projectId: string
  firmwareId?: string
  data?: SecretsHarvestResponse | null
  onRefresh?: () => void
}

export default function SecretsKpiRibbon({
  projectId,
  firmwareId,
  data: propData,
  onRefresh,
}: SecretsKpiRibbonProps) {
  const [data, setData] = useState<SecretsHarvestResponse | null>(propData ?? null)
  const [loading, setLoading] = useState(propData === undefined)
  const [refreshing, setRefreshing] = useState(false)

  const loadData = async (refresh = false) => {
    try {
      if (refresh) setRefreshing(true)
      else setLoading(true)
      const res = await getSecretsHarvest(projectId, firmwareId, refresh)
      setData(res)
      if (onRefresh) onRefresh()
    } catch {
      // Silently catch in ribbon widget
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    if (propData !== undefined) {
      setData(propData)
      setLoading(false)
      return
    }
    loadData(false)
  }, [projectId, firmwareId, propData])

  if (loading) {
    return (
      <div className="board-surface flex items-center gap-2.5 rounded-md px-4 py-4 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin text-primary" />
        <span className="font-mono text-xs">Auditing cryptographic material &amp; credentials...</span>
      </div>
    )
  }

  if (!data || !data.summary || data.summary.total_findings === 0) {
    return null
  }

  const { summary, accounts } = data
  const rootAccount = (accounts || []).find((a) => a.username === 'root')
  const rootEmpty = rootAccount
    ? rootAccount.status === 'empty'
    : summary.empty_password_accounts > 0
  const rootCracked = rootAccount
    ? Boolean(rootAccount.cracked_password)
    : summary.cracked_accounts > 0

  return (
    <div className="board-surface overflow-hidden rounded-md">
      <BoardSectionHeader
        title={
          <>
            <KeyRound className="h-4 w-4 text-primary" />
            Secrets &amp; Credential Harvester
            {rootEmpty ? (
              <Badge variant="destructive" className="ml-1">
                <SignalLamp tone="red" className="h-1.5 w-1.5" />
                ROOT: EMPTY PASSWORD
              </Badge>
            ) : rootCracked ? (
              <Badge variant="destructive" className="ml-1">
                <SignalLamp tone="red" className="h-1.5 w-1.5" />
                ROOT: CRACKED ({rootAccount?.cracked_password ?? 'DEFAULT'})
              </Badge>
            ) : (
              <Badge variant="outline" className="ml-1 text-[#4ADE80] border-[#22C55E]/40">
                <SignalLamp tone="green" className="h-1.5 w-1.5" />
                ROOT: SECURED
              </Badge>
            )}
          </>
        }
        right={
          <>
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              onClick={() => loadData(true)}
              disabled={refreshing}
              aria-label="Rescan rootfs for secrets"
              className="h-7 w-7"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            </Button>
            <Button type="button" variant="outline" size="sm" asChild className="h-7 text-xs">
              <Link to={`/projects/${projectId}/secrets`}>
                Inspect Board <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 p-4 sm:grid-cols-5">
        <FlapCounter
          label="Private Keys"
          value={String(summary.total_private_keys).padStart(2, '0')}
          subtext={
            summary.unencrypted_private_keys > 0
              ? `${summary.unencrypted_private_keys} unencrypted`
              : 'None exposed'
          }
          tone={summary.unencrypted_private_keys > 0 ? 'red' : summary.total_private_keys > 0 ? 'neutral' : 'muted'}
          lamp={summary.unencrypted_private_keys > 0 ? 'red' : 'idle'}
        />
        <FlapCounter
          label="Certificates"
          value={String(summary.total_certificates).padStart(2, '0')}
          subtext={
            summary.expired_certificates > 0
              ? `${summary.expired_certificates} expired`
              : 'Device certs'
          }
          tone={summary.expired_certificates > 0 ? 'amber' : summary.total_certificates > 0 ? 'neutral' : 'muted'}
          lamp={summary.expired_certificates > 0 ? 'amber' : 'idle'}
        />
        <FlapCounter
          label="Accounts"
          value={String(summary.total_accounts).padStart(2, '0')}
          subtext={`${summary.cracked_accounts} cracked · ${summary.empty_password_accounts} empty`}
          tone={
            summary.cracked_accounts > 0 || summary.empty_password_accounts > 0
              ? 'red'
              : 'neutral'
          }
          lamp={
            summary.cracked_accounts > 0 || summary.empty_password_accounts > 0
              ? 'red'
              : 'green'
          }
        />
        <FlapCounter
          label="Router Defaults"
          value={String(summary.router_default_credentials).padStart(2, '0')}
          subtext="NVRAM / web / FTP"
          tone={summary.router_default_credentials > 0 ? 'amber' : 'muted'}
          lamp={summary.router_default_credentials > 0 ? 'amber' : 'idle'}
        />
        <FlapCounter
          label="Tokens & Secrets"
          value={String(summary.high_entropy_secrets).padStart(2, '0')}
          subtext="API & high-entropy"
          tone={summary.high_entropy_secrets > 0 ? 'amber' : 'muted'}
          lamp={summary.high_entropy_secrets > 0 ? 'amber' : 'idle'}
          className="col-span-2 sm:col-span-1"
        />
      </div>
    </div>
  )
}
