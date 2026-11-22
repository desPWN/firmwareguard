import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ShieldCheck, ArrowRight, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { BoardSectionHeader, FlapCounter, PipMeter } from '@/components/ui/split-flap'
import { getBinaryHardening } from '@/api/analysis'
import type { FirmwareHardeningResponse } from '@/types'

interface HardeningWidgetProps {
  projectId: string
  firmwareId?: string
}

export default function HardeningWidget({ projectId, firmwareId }: HardeningWidgetProps) {
  const [data, setData] = useState<FirmwareHardeningResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    getBinaryHardening(projectId, firmwareId)
      .then((res) => {
        if (!cancelled) setData(res)
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err?.response?.data?.detail || err.message || 'Failed to load hardening assessment')
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
      <div className="board-surface flex items-center gap-2.5 rounded-md px-4 py-4 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin text-primary" />
        <span className="font-mono text-xs">Auditing ELF binary security mitigations...</span>
      </div>
    )
  }

  if (error || !data || !data.summary || data.summary.total_binaries === 0) {
    return null
  }

  const { summary } = data
  const scoreTone =
    summary.average_score >= 3.5 ? 'green' : summary.average_score >= 2.0 ? 'amber' : 'red'

  const mitigations = [
    {
      label: 'NX (Non-Executable Stack)',
      pct: summary.nx_percentage,
      missing: summary.total_binaries - summary.nx_count,
    },
    {
      label: 'Stack Canaries',
      pct: summary.canary_percentage,
      missing: summary.total_binaries - summary.canary_count,
    },
    {
      label: 'PIE / ASLR',
      pct: summary.pie_percentage,
      missing: summary.total_binaries - summary.pie_count,
    },
  ]

  return (
    <div className="board-surface overflow-hidden rounded-md">
      <BoardSectionHeader
        title={
          <>
            <ShieldCheck className="h-4 w-4 text-primary" />
            Binary Hardening Posture
          </>
        }
        right={
          <Button size="sm" variant="outline" asChild className="h-7 text-xs">
            <Link to={`/projects/${projectId}/hardening`}>
              Open Matrix
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 p-4 lg:grid-cols-12">
        {/* Recessed Split-Flap Readouts */}
        <div className="grid grid-cols-2 gap-3 lg:col-span-5">
          <FlapCounter
            label="Audited ELFs"
            value={String(summary.total_binaries).padStart(2, '0')}
            subtext={`${summary.executable_count} exec · ${summary.library_count} libs`}
            tone="neutral"
          />
          <FlapCounter
            label="Avg Hardening"
            value={`${summary.average_score.toFixed(1)}/5`}
            subtext={
              summary.average_score >= 3.5
                ? 'Solid baseline'
                : summary.average_score >= 2.0
                  ? 'Partial mitigations'
                  : 'Weakly hardened'
            }
            tone={scoreTone}
            lamp={scoreTone}
          />
        </div>

        {/* Segmented Pip Meters (System Health style) */}
        <div className="flex flex-col justify-center gap-2.5 rounded-[4px] border border-border bg-background/60 px-4 py-3 lg:col-span-7">
          {mitigations.map((m) => (
            <div
              key={m.label}
              className="flex flex-wrap items-center justify-between gap-2 text-xs"
            >
              <span className="font-mono text-[#D1D5DB]">{m.label}</span>
              <div className="flex items-center gap-3">
                <span className="hidden sm:inline font-mono text-[11px] text-muted-foreground tabular-nums">
                  {m.missing} exposed
                </span>
                <PipMeter value={m.pct} segments={10} showLabel />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
