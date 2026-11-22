import { useEffect, useState } from 'react'
import { Wifi, Globe, HardDrive, Eye, EyeOff, Copy, Check, Key } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { getSecretsHarvest } from '@/api/secrets'
import type { SecretsHarvestResponse } from '@/types'

interface RouterDefaultsCardProps {
  projectId: string
  firmwareId?: string
  data?: SecretsHarvestResponse | null
}

export default function RouterDefaultsCard({
  projectId,
  firmwareId,
  data: propData,
}: RouterDefaultsCardProps) {
  const [data, setData] = useState<SecretsHarvestResponse | null>(propData ?? null)
  const [revealedIdxs, setRevealedIdxs] = useState<Set<number>>(new Set())
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  useEffect(() => {
    if (propData !== undefined) {
      setData(propData)
      return
    }
    getSecretsHarvest(projectId, firmwareId)
      .then(setData)
      .catch(() => {})
  }, [projectId, firmwareId, propData])

  const toggleReveal = (idx: number) => {
    setRevealedIdxs((prev) => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx)
      else next.add(idx)
      return next
    })
  }

  const copyText = (val: string, key: string) => {
    navigator.clipboard.writeText(val)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const creds = data?.router_credentials ?? []

  if (!data || creds.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Key className="h-4 w-4 text-primary" />
            Router Default Credentials & NVRAM Secrets
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="py-4 text-center text-sm text-muted-foreground">
            No default router credentials detected in this image.
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Key className="h-4 w-4 text-primary" />
              Router Default Credentials & NVRAM Secrets
            </CardTitle>
            <CardDescription className="mt-1 text-xs">
              Hardcoded web management credentials, NVRAM defaults, and WiFi pre-shared keys.
            </CardDescription>
          </div>
          <Badge variant="outline" className="font-mono text-xs">
            {creds.length} Found
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {creds.map((c, idx) => {
            const isRevealed = revealedIdxs.has(idx)
            const passwordDisplay = c.password
              ? isRevealed
                ? c.password
                : '••••••••'
              : 'N/A'

            return (
              <div
                key={idx}
                className="flex flex-col gap-2 rounded-lg border border-border bg-card/50 p-3"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {c.service === 'uci_wifi' ? (
                      <Wifi className="h-4 w-4 text-blue-500" />
                    ) : c.service === 'web' ? (
                      <Globe className="h-4 w-4 text-emerald-500" />
                    ) : (
                      <HardDrive className="h-4 w-4 text-amber-500" />
                    )}
                    <span className="font-mono text-xs font-semibold uppercase">{c.service}</span>
                  </div>
                  <Badge variant="outline" className="font-mono text-[10px]">
                    {c.matched_rule}
                  </Badge>
                </div>

                <div className="truncate font-mono text-xs text-muted-foreground">
                  Source: {c.source_file}
                  {c.line_number ? `:${c.line_number}` : ''}
                </div>

                <div className="mt-1 grid grid-cols-2 gap-2 rounded bg-muted/40 p-2 font-mono text-xs">
                  <div>
                    <span className="block text-[10px] text-muted-foreground">USERNAME</span>
                    <span className="font-semibold text-foreground">{c.username || 'admin'}</span>
                  </div>
                  <div>
                    <span className="block text-[10px] text-muted-foreground">PASSWORD</span>
                    <div className="flex items-center justify-between gap-1">
                      <span className="truncate font-semibold text-foreground">
                        {passwordDisplay}
                      </span>
                      {c.password && (
                        <div className="flex items-center gap-0.5">
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-5 w-5 text-muted-foreground hover:text-foreground"
                            onClick={() => toggleReveal(idx)}
                            title={isRevealed ? 'Hide password' : 'Show password'}
                          >
                            {isRevealed ? (
                              <EyeOff className="h-3 w-3" />
                            ) : (
                              <Eye className="h-3 w-3" />
                            )}
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-5 w-5 text-muted-foreground hover:text-foreground"
                            onClick={() => copyText(c.password!, `cred-${idx}`)}
                            title="Copy password"
                          >
                            {copiedKey === `cred-${idx}` ? (
                              <Check className="h-3 w-3 text-emerald-500" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}
