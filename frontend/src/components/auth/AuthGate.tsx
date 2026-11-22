import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { Loader2, Lock } from 'lucide-react'
import apiClient from '@/api/client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

interface AuthStatus {
  auth_enabled: boolean
  authenticated: boolean
}

export default function AuthGate({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus | null>(null)
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    apiClient
      .get<AuthStatus>('/auth/status')
      .then((res) => {
        if (active) setStatus(res.data)
      })
      .catch(() => {
        if (active) setStatus({ auth_enabled: false, authenticated: true })
      })

    const handleUnauthorized = () => {
      setStatus({ auth_enabled: true, authenticated: false })
    }
    window.addEventListener('fg:unauthorized', handleUnauthorized)
    return () => {
      active = false
      window.removeEventListener('fg:unauthorized', handleUnauthorized)
    }
  }, [])

  if (status === null) {
    return (
      <div className="flex h-screen items-center justify-center bg-background text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
      </div>
    )
  }

  if (!status.auth_enabled || status.authenticated) {
    return <>{children}</>
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!password.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      const res = await apiClient.post<AuthStatus>('/auth/login', { password })
      setPassword('')
      setStatus(res.data)
    } catch {
      setError('Invalid password. Check AUTH_PASSWORD in .env.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6 text-foreground">
      <div className="w-full max-w-sm rounded-lg border border-border bg-card p-6">
        <div className="mb-5 flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-md border border-border bg-secondary text-foreground">
            <Lock className="h-4 w-4" />
          </div>
          <div>
            <h1 className="text-base font-semibold tracking-tight text-foreground">
              FirmwareGuard
            </h1>
            <p className="text-xs text-muted-foreground">
              Enter workspace password to continue
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label
              htmlFor="fg-auth-password"
              className="text-xs font-medium text-muted-foreground"
            >
              Password
            </label>
            <Input
              id="fg-auth-password"
              type="password"
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Workspace password"
            />
          </div>

          {error && (
            <p className="text-xs text-destructive" role="alert">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={submitting || !password.trim()}>
            {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Sign In'}
          </Button>
        </form>
      </div>
    </div>
  )
}
