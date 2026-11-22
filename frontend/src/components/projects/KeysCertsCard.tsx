import { useEffect, useState } from 'react'
import { FileKey, Lock, Unlock, Copy, Check, AlertTriangle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { getSecretsHarvest } from '@/api/secrets'
import type { SecretsHarvestResponse } from '@/types'

interface KeysCertsCardProps {
  projectId: string
  firmwareId?: string
  data?: SecretsHarvestResponse | null
}

export default function KeysCertsCard({
  projectId,
  firmwareId,
  data: propData,
}: KeysCertsCardProps) {
  const [data, setData] = useState<SecretsHarvestResponse | null>(propData ?? null)
  const [activeTab, setActiveTab] = useState<'keys' | 'certs'>('keys')
  const [copiedPath, setCopiedPath] = useState<string | null>(null)

  useEffect(() => {
    if (propData !== undefined) {
      setData(propData)
      return
    }
    getSecretsHarvest(projectId, firmwareId)
      .then(setData)
      .catch(() => {})
  }, [projectId, firmwareId, propData])

  const copyPath = (path: string) => {
    navigator.clipboard.writeText(path)
    setCopiedPath(path)
    setTimeout(() => setCopiedPath(null), 2000)
  }

  const keys = data?.private_keys ?? []
  const certs = data?.certificates ?? []

  if (!data || (keys.length === 0 && certs.length === 0)) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <FileKey className="h-4 w-4 text-primary" />
            Cryptographic Keys & Certificates
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="py-4 text-center text-sm text-muted-foreground">
            No cryptographic certificates or keys detected in this image.
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <FileKey className="h-4 w-4 text-primary" />
              Cryptographic Keys & Certificates
            </CardTitle>
            <CardDescription className="mt-1 text-xs">
              Audited SSL/TLS certificates and private keys located on the root filesystem.
            </CardDescription>
          </div>
          <div className="flex items-center gap-1 rounded-md bg-muted p-1">
            <button
              onClick={() => setActiveTab('keys')}
              className={`rounded-sm px-3 py-1 text-xs font-medium transition-colors ${
                activeTab === 'keys'
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Private Keys ({keys.length})
            </button>
            <button
              onClick={() => setActiveTab('certs')}
              className={`rounded-sm px-3 py-1 text-xs font-medium transition-colors ${
                activeTab === 'certs'
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Certificates ({certs.length})
            </button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {activeTab === 'keys' ? (
          <div className="space-y-3">
            {keys.length === 0 ? (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No private keys detected.
              </p>
            ) : (
              keys.map((k, idx) => (
                <div
                  key={idx}
                  className="flex flex-col gap-2 rounded-lg border border-border bg-card/50 p-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span className="font-semibold">{k.path}</span>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-5 w-5 text-muted-foreground hover:text-foreground"
                        onClick={() => copyPath(k.path)}
                      >
                        {copiedPath === k.path ? (
                          <Check className="h-3 w-3 text-emerald-500" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                      </Button>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono text-xs">
                        {k.key_type}
                      </Badge>
                      {k.encrypted ? (
                        <Badge
                          variant="outline"
                          className="flex items-center gap-1 border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-600"
                        >
                          <Lock className="h-3 w-3" /> Encrypted
                        </Badge>
                      ) : (
                        <Badge variant="destructive" className="flex items-center gap-1 text-xs">
                          <Unlock className="h-3 w-3" /> Unencrypted
                        </Badge>
                      )}
                    </div>
                  </div>
                  {k.preview && (
                    <pre className="overflow-x-auto rounded bg-muted/60 p-2 font-mono text-xs text-muted-foreground">
                      {k.preview}
                    </pre>
                  )}
                </div>
              ))
            )}
          </div>
        ) : (
          <div className="space-y-3">
            {certs.length === 0 ? (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No certificates detected.
              </p>
            ) : (
              certs.map((c, idx) => (
                <div
                  key={idx}
                  className="flex flex-col gap-2 rounded-lg border border-border bg-card/50 p-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="font-mono text-xs font-semibold">{c.path}</div>
                    <div className="flex items-center gap-1.5">
                      {c.is_expired && (
                        <Badge variant="destructive" className="text-xs">
                          Expired
                        </Badge>
                      )}
                      {c.self_signed && (
                        <Badge
                          variant="outline"
                          className="border-amber-500/30 bg-amber-500/10 text-xs text-amber-600"
                        >
                          Self-Signed
                        </Badge>
                      )}
                      <Badge variant="outline" className="font-mono text-xs">
                        {c.key_type} {c.key_size}b
                      </Badge>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 gap-2 text-xs text-muted-foreground sm:grid-cols-2">
                    <div>
                      <span className="font-semibold text-foreground">Subject:</span> {c.subject}
                    </div>
                    <div>
                      <span className="font-semibold text-foreground">Issuer:</span> {c.issuer}
                    </div>
                    <div>
                      <span className="font-semibold text-foreground">Valid:</span>{' '}
                      {c.not_before.split('T')[0]} to {c.not_after.split('T')[0]}
                    </div>
                    <div>
                      <span className="font-semibold text-foreground">Algorithm:</span>{' '}
                      {c.signature_algorithm}
                    </div>
                  </div>
                  {c.issues && c.issues.length > 0 && (
                    <div className="mt-1 space-y-1">
                      {c.issues.map((iss, iIdx) => (
                        <div
                          key={iIdx}
                          className="flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400"
                        >
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                          <span>{iss.issue}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
