import { useEffect, useState } from 'react'
import {
  Users,
  AlertCircle,
  ShieldAlert,
  ShieldCheck,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { getSecretsHarvest } from '@/api/secrets'
import type { SecretsHarvestResponse } from '@/types'

interface AccountsCardProps {
  projectId: string
  firmwareId?: string
  data?: SecretsHarvestResponse | null
}

const PAGE_SIZE = 10

export default function AccountsCard({
  projectId,
  firmwareId,
  data: propData,
}: AccountsCardProps) {
  const [data, setData] = useState<SecretsHarvestResponse | null>(propData ?? null)
  const [page, setPage] = useState(0)
  const [copiedValue, setCopiedValue] = useState<string | null>(null)

  useEffect(() => {
    if (propData !== undefined) {
      setData(propData)
      return
    }
    getSecretsHarvest(projectId, firmwareId)
      .then(setData)
      .catch(() => {})
  }, [projectId, firmwareId, propData])

  const copyText = (val: string) => {
    navigator.clipboard.writeText(val)
    setCopiedValue(val)
    setTimeout(() => setCopiedValue(null), 2000)
  }

  const accounts = data?.accounts ?? []
  const rootAccount = accounts.find((a) => a.username === 'root')
  const rootEmpty = rootAccount
    ? rootAccount.status === 'empty'
    : false
  const rootCracked = rootAccount?.cracked_password ?? null

  const totalPages = Math.ceil(accounts.length / PAGE_SIZE)
  const paginatedAccounts = accounts.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  if (!data || accounts.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Users className="h-4 w-4 text-primary" />
            User Accounts & Password Hashes
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="py-4 text-center text-sm text-muted-foreground">
            No /etc/passwd or /etc/shadow user accounts detected in this image.
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
              <Users className="h-4 w-4 text-primary" />
              User Accounts & Password Hashes
            </CardTitle>
            <CardDescription className="mt-1 text-xs">
              Discovered accounts from /etc/passwd and /etc/shadow with offline dictionary cracking results.
            </CardDescription>
          </div>
          <Badge variant="outline" className="font-mono text-xs">
            {accounts.length} Accounts Found
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Root Alert Banner */}
        {rootEmpty ? (
          <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs font-medium text-red-600 dark:text-red-400">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span>CRITICAL: Root account has no password configured.</span>
          </div>
        ) : rootCracked ? (
          <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs font-medium text-amber-600 dark:text-amber-400">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>CRITICAL: Root password cracked: '{rootCracked}'.</span>
          </div>
        ) : (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs font-medium text-emerald-600 dark:text-emerald-400">
            <ShieldCheck className="h-4 w-4 shrink-0" />
            <span>Root account is secured with a non-default password hash.</span>
          </div>
        )}

        {/* Accounts Table */}
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border bg-muted font-semibold text-muted-foreground">
              <tr>
                <th className="px-3 py-2">Username</th>
                <th className="px-3 py-2">UID:GID</th>
                <th className="px-3 py-2">Shell</th>
                <th className="px-3 py-2">Hash Format</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Cracked Password</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {paginatedAccounts.map((a, idx) => {
                const uidGid = `${a.uid ?? 0}:${a.gid ?? 0}`
                const isUidZero = a.uid === 0 && a.username !== 'root'
                return (
                  <tr key={idx} className="transition-colors hover:bg-muted/50">
                    <td className="flex items-center gap-1.5 px-3 py-2 font-mono font-semibold">
                      {a.username}
                      {isUidZero && (
                        <Badge variant="destructive" className="px-1 py-0 text-[10px]">
                          UID 0
                        </Badge>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-muted-foreground">{uidGid}</td>
                    <td className="px-3 py-2 font-mono text-muted-foreground">
                      {a.shell || 'N/A'}
                    </td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className="font-mono text-[10px]">
                        {a.hash_type}
                      </Badge>
                    </td>
                    <td className="px-3 py-2">
                      {a.status === 'empty' ? (
                        <Badge variant="destructive" className="text-[10px]">
                          empty
                        </Badge>
                      ) : a.status === 'locked' ? (
                        <Badge variant="outline" className="text-[10px] text-muted-foreground">
                          locked
                        </Badge>
                      ) : (
                        <Badge variant="secondary" className="text-[10px]">
                          has_hash
                        </Badge>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono">
                      {a.cracked_password ? (
                        <span className="inline-flex items-center gap-1 rounded bg-red-500/10 px-1.5 py-0.5 font-bold text-red-600 dark:text-red-400">
                          {a.cracked_password}
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-4 w-4"
                            onClick={() => copyText(a.cracked_password!)}
                            title="Copy cracked password"
                          >
                            {copiedValue === a.cracked_password ? (
                              <Check className="h-3 w-3 text-emerald-500" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </Button>
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination controls */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between pt-1 text-xs text-muted-foreground">
            <span>
              Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, accounts.length)} of {accounts.length}
            </span>
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="icon"
                className="h-7 w-7"
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </Button>
              <span className="px-2 font-mono">
                {page + 1} / {totalPages}
              </span>
              <Button
                variant="outline"
                size="icon"
                className="h-7 w-7"
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
