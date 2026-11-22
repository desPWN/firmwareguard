import * as React from 'react'
import { cn } from '@/lib/utils'

export type SignalTone = 'idle' | 'amber' | 'red' | 'green'

const LAMP_COLORS: Record<SignalTone, string> = {
  idle: 'bg-zinc-600',
  amber: 'bg-amber-400',
  red: 'bg-red-500',
  green: 'bg-emerald-500',
}

export function SignalLamp({
  tone = 'idle',
  className,
  label,
}: {
  tone?: SignalTone
  className?: string
  label?: string
}) {
  return (
    <span
      className={cn(
        'inline-block h-2 w-2 shrink-0 rounded-full',
        LAMP_COLORS[tone],
        className,
      )}
      aria-label={label}
      role={label ? 'img' : undefined}
    />
  )
}

const FLAP_VALUE_TONES: Record<'neutral' | 'amber' | 'red' | 'green' | 'muted', string> = {
  neutral: 'text-foreground',
  amber: 'text-amber-400',
  red: 'text-red-400',
  green: 'text-emerald-400',
  muted: 'text-muted-foreground',
}

interface FlapCounterProps {
  label: string
  value: React.ReactNode
  subtext?: React.ReactNode
  tone?: 'neutral' | 'amber' | 'red' | 'green' | 'muted'
  lamp?: SignalTone
  active?: boolean
  onClick?: () => void
  className?: string
}

export function FlapCounter({
  label,
  value,
  subtext,
  tone = 'neutral',
  lamp,
  active = false,
  onClick,
  className,
}: FlapCounterProps) {
  const Tag = onClick ? 'button' : 'div'
  return (
    <Tag
      type={onClick ? 'button' : undefined}
      onClick={onClick}
      className={cn(
        'flap-cell rounded-md px-3.5 py-3 text-left transition-colors',
        onClick &&
          'cursor-pointer hover:border-foreground/25 hover:bg-secondary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        active && 'border-foreground/30 bg-secondary/50',
        className,
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-display text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
          {label}
        </span>
        {lamp && <SignalLamp tone={lamp} />}
      </div>
      <div
        className={cn(
          'mt-1.5 font-mono text-2xl font-semibold leading-none tabular-nums tracking-tight',
          FLAP_VALUE_TONES[tone],
        )}
      >
        {value}
      </div>
      {subtext && (
        <div className="mt-2 truncate font-mono text-[11px] text-muted-foreground tabular-nums">
          {subtext}
        </div>
      )}
    </Tag>
  )
}

interface PipMeterProps {
  value: number
  max?: number
  segments?: number
  tone?: 'auto' | 'green' | 'amber' | 'red'
  className?: string
  showLabel?: boolean
}

export function PipMeter({
  value,
  max = 100,
  segments = 10,
  tone = 'auto',
  className,
  showLabel = false,
}: PipMeterProps) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0
  const filled = Math.round((pct / 100) * segments)

  const resolvedTone =
    tone !== 'auto'
      ? tone
      : pct >= 70
        ? 'green'
        : pct >= 40
          ? 'amber'
          : 'red'

  const pipColor =
    resolvedTone === 'green'
      ? 'bg-emerald-500'
      : resolvedTone === 'amber'
        ? 'bg-amber-400'
        : 'bg-red-500'

  return (
    <div className={cn('inline-flex items-center gap-2', className)}>
      <div
        className="inline-flex items-center gap-1"
        role="progressbar"
        aria-valuenow={Math.round(pct)}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        {Array.from({ length: segments }).map((_, idx) => (
          <span
            key={idx}
            className={cn(
              'h-2.5 w-1.5 rounded-[1px] transition-colors',
              idx < filled ? pipColor : 'bg-zinc-800',
            )}
          />
        ))}
      </div>
      {showLabel && (
        <span className="font-mono text-xs text-muted-foreground tabular-nums">
          {Math.round(pct)}%
        </span>
      )}
    </div>
  )
}

export function BoardSectionHeader({
  title,
  subtitle,
  right,
  className,
}: {
  title: React.ReactNode
  subtitle?: React.ReactNode
  right?: React.ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'board-header flex flex-wrap items-center justify-between gap-2 px-4 py-2.5',
        className,
      )}
    >
      <div className="min-w-0">
        <div className="font-display text-sm font-semibold uppercase tracking-[0.07em] text-foreground flex items-center gap-2">
          {title}
        </div>
        {subtitle && (
          <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>
        )}
      </div>
      {right && <div className="flex items-center gap-2 shrink-0">{right}</div>}
    </div>
  )
}
