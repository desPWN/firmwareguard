import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { KeyRound, ArrowRight, Loader2, Unlock } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { getFirmwareSecrets } from '@/api/analysis'
import type { SecretsHarvestResponse } from '@/types'

interface SecretsWidgetProps {
  projectId: string
  firmwareId?: string
}

export default function SecretsWidget({ projectId, firmwareId }: SecretsWidgetProps) {
  const [data, setData] = useState<SecretsHarvestResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    getFirmwareSecrets(projectId, firmwareId)
      .then((res) => {
        if (!cancelled) setData(res)
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err?.response?.data?.detail || err.message || 'Failed to load secrets')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [projectId, firmwareId])

  if (loading) {
    return (
      <Card>
        <CardContent className="flex items-center gap-2 py-6 text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin text-primary" />
          <span className="text-sm">Harvesting embedded secrets & credentials...</span>
        </CardContent>
      </Card>
    )
  }

  if (error || !data || !data.summary || data.summary.total_findings === 0) {
    return null
  }

  const { summary } = data
  const hasCritical = summary.critical_count > 0 || summary.unencrypted_private_keys > 0

  return (
    <Card className={`border ${hasCritical ? 'border-red-500/30 bg-red-500/[0.02]' : 'border-border'}`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-amber-500" />
            Secrets & Credential Harvester
          </CardTitle>
          <div className="flex items-center gap-2">
            {summary.critical_count > 0 && (
              <Badge variant="outline" className="text-xs bg-red-500/10 text-red-600 border-red-500/30">
                {summary.critical_count} Critical
              </Badge>
            )}
            {summary.unencrypted_private_keys > 0 && (
              <Badge variant="outline" className="text-xs bg-red-500/10 text-red-600 border-red-500/30 flex items-center gap-1">
                <Unlock className="w-3 h-3" /> {summary.unencrypted_private_keys} Keys Exposed
              </Badge>
            )}
            <Link to={`/projects/${projectId}/secrets`}>
              <Button variant="ghost" size="sm" className="gap-1 text-xs">
                Inspect All <ArrowRight className="h-3.5 w-3.5" />
              </Button>
            </Link>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-4 gap-3">
          <div className="p-3 rounded bg-muted/40 text-center">
            <div className="text-xs text-muted-foreground">Total Findings</div>
            <div className="text-lg font-bold tabular-nums mt-1">{summary.total_findings}</div>
          </div>
          <div className="p-3 rounded bg-muted/40 text-center">
            <div className="text-xs text-muted-foreground">Private Keys</div>
            <div className={`text-lg font-bold tabular-nums mt-1 ${summary.unencrypted_private_keys > 0 ? 'text-red-500' : ''}`}>
              {summary.total_private_keys}
            </div>
          </div>
          <div className="p-3 rounded bg-muted/40 text-center">
            <div className="text-xs text-muted-foreground">Accounts / Hashes</div>
            <div className={`text-lg font-bold tabular-nums mt-1 ${summary.cracked_accounts > 0 || summary.empty_password_accounts > 0 ? 'text-amber-500' : ''}`}>
              {summary.total_accounts}
            </div>
          </div>
          <div className="p-3 rounded bg-muted/40 text-center">
            <div className="text-xs text-muted-foreground">Router Defaults</div>
            <div className={`text-lg font-bold tabular-nums mt-1 ${summary.router_default_credentials > 0 ? 'text-red-500' : ''}`}>
              {summary.router_default_credentials}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

