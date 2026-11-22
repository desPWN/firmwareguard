import { useEffect, useState, type FormEvent } from 'react'
import { AlertCircle, CheckCircle2, KeyRound, Loader2, LockKeyhole, ShieldAlert, Unlock } from 'lucide-react'
import { decryptFirmware, getFirmwareEntropy } from '@/api/firmware'
import type { FirmwareDecryptResponse, FirmwareEntropy } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { formatFileSize } from '@/utils/format'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  projectId: string
  firmwareId: string
  filename: string
  onDecrypted: () => void
}

const ALGORITHMS = [
  { value: 'aes-128-cbc', label: 'AES-128-CBC (16-byte key + 16-byte IV)' },
  { value: 'aes-256-cbc', label: 'AES-256-CBC (32-byte key + 16-byte IV)' },
  { value: 'aes-128-ctr', label: 'AES-128-CTR (16-byte key + 16-byte nonce)' },
  { value: 'aes-256-ctr', label: 'AES-256-CTR (32-byte key + 16-byte nonce)' },
  { value: 'aes-128-ecb', label: 'AES-128-ECB (16-byte key, no IV)' },
  { value: 'aes-256-ecb', label: 'AES-256-ECB (32-byte key, no IV)' },
  { value: 'xor', label: 'Repeating XOR (hex or text key)' },
  { value: 'strip-header', label: 'Strip Leading Header Bytes Only' },
]

const VERDICT_META: Record<
  FirmwareEntropy['verdict'],
  { label: string; badgeClass: string }
> = {
  auto_decryptable: {
    label: 'Auto-Decryptable Wrapper',
    badgeClass: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
  },
  likely_encrypted: {
    label: 'Likely Encrypted',
    badgeClass: 'border-red-500/40 bg-red-500/15 text-red-300',
  },
  compressed_or_mixed: {
    label: 'Compressed / Mixed',
    badgeClass: 'border-amber-500/40 bg-amber-500/15 text-amber-300',
  },
  unencrypted: {
    label: 'Unencrypted',
    badgeClass: 'border-border bg-secondary text-foreground',
  },
}

function parseOffsetInput(raw: string): number | null {
  const trimmed = raw.trim()
  if (!trimmed) return 0
  const parsed = trimmed.toLowerCase().startsWith('0x')
    ? Number.parseInt(trimmed.slice(2), 16)
    : Number.parseInt(trimmed, 10)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null
}

export default function FirmwareDecryptDialog({
  open,
  onOpenChange,
  projectId,
  firmwareId,
  filename,
  onDecrypted,
}: Props) {
  const [entropy, setEntropy] = useState<FirmwareEntropy | null>(null)
  const [loadingEntropy, setLoadingEntropy] = useState(false)
  const [entropyError, setEntropyError] = useState<string | null>(null)

  const [algorithm, setAlgorithm] = useState('aes-128-cbc')
  const [keyFormat, setKeyFormat] = useState<'hex' | 'utf8'>('hex')
  const [key, setKey] = useState('')
  const [iv, setIv] = useState('')
  const [offsetInput, setOffsetInput] = useState('0')
  const [unpad, setUnpad] = useState(false)

  const [submitting, setSubmitting] = useState(false)
  const [decryptError, setDecryptError] = useState<string | null>(null)
  const [decryptResult, setDecryptResult] = useState<FirmwareDecryptResponse | null>(null)

  useEffect(() => {
    if (!open) return
    let active = true
    setLoadingEntropy(true)
    setEntropyError(null)
    setDecryptError(null)
    setDecryptResult(null)
    getFirmwareEntropy(projectId, firmwareId)
      .then((data) => {
        if (active) setEntropy(data)
      })
      .catch((err) => {
        if (active) {
          setEntropyError(err?.response?.data?.detail ?? 'Failed to analyze firmware entropy')
        }
      })
      .finally(() => {
        if (active) setLoadingEntropy(false)
      })
    return () => {
      active = false
    }
  }, [open, projectId, firmwareId])

  const needsKey = algorithm !== 'strip-header'
  const needsIv = algorithm.endsWith('-cbc') || algorithm.endsWith('-ctr')
  const supportsUnpad = algorithm.endsWith('-cbc') || algorithm.endsWith('-ecb')

  const handleAutoDecrypt = async () => {
    setSubmitting(true)
    setDecryptError(null)
    setDecryptResult(null)
    try {
      const res = await decryptFirmware(projectId, firmwareId, {
        mode: 'auto',
        auto_unpack: true,
      })
      setDecryptResult(res)
      onDecrypted()
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setDecryptError(detail ?? 'Auto-decryption failed')
    } finally {
      setSubmitting(false)
    }
  }

  const handleCustomDecrypt = async (e: FormEvent) => {
    e.preventDefault()
    const parsedOffset = parseOffsetInput(offsetInput)
    if (parsedOffset === null) {
      setDecryptError('Offset must be a non-negative integer or hex value (e.g. 0, 64, 0x6dc).')
      return
    }
    setSubmitting(true)
    setDecryptError(null)
    setDecryptResult(null)
    try {
      const res = await decryptFirmware(projectId, firmwareId, {
        mode: 'custom',
        algorithm,
        key: needsKey ? key : '',
        key_format: keyFormat,
        iv: needsIv ? iv : '',
        offset: parsedOffset,
        unpad: supportsUnpad ? unpad : false,
        auto_unpack: true,
      })
      setDecryptResult(res)
      onDecrypted()
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setDecryptError(detail ?? 'Decryption failed')
    } finally {
      setSubmitting(false)
    }
  }

  const verdictMeta = entropy ? VERDICT_META[entropy.verdict] : null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[88vh] overflow-y-auto bg-card border-border">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 font-mono text-sm uppercase tracking-wider">
            <LockKeyhole className="h-4 w-4 text-primary" />
            Entropy &amp; Decryption — {filename}
          </DialogTitle>
          <DialogDescription className="text-xs">
            Inspect Shannon entropy for encryption, run known vendor decryptors, or supply a custom key/IV extracted via UART or Ghidra.
          </DialogDescription>
        </DialogHeader>

        {/* Section 1: Entropy Analysis */}
        <div className="space-y-3 rounded-md border border-border bg-background/60 p-3.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              Shannon Entropy Profile
            </span>
            {verdictMeta && (
              <Badge variant="outline" className={`font-mono text-[11px] ${verdictMeta.badgeClass}`}>
                {verdictMeta.label}
              </Badge>
            )}
          </div>

          {loadingEntropy && (
            <div className="flex items-center gap-2 py-6 justify-center text-xs text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Calculating block entropy and scanning headers...
            </div>
          )}

          {entropyError && (
            <div className="flex items-center gap-2 text-xs text-destructive">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {entropyError}
            </div>
          )}

          {entropy && !loadingEntropy && (
            <>
              <div className="grid grid-cols-3 gap-2 font-mono text-xs">
                <div className="rounded border border-border bg-card px-2.5 py-2">
                  <div className="text-[10px] uppercase text-muted-foreground">Overall</div>
                  <div className="mt-0.5 text-sm font-semibold tabular-nums">
                    {entropy.overall_entropy.toFixed(2)} <span className="text-[10px] text-muted-foreground">/ 8.0</span>
                  </div>
                </div>
                <div className="rounded border border-border bg-card px-2.5 py-2">
                  <div className="text-[10px] uppercase text-muted-foreground">High-Entropy Blocks</div>
                  <div className="mt-0.5 text-sm font-semibold tabular-nums">
                    {Math.round(entropy.high_entropy_ratio * 100)}%
                  </div>
                </div>
                <div className="rounded border border-border bg-card px-2.5 py-2">
                  <div className="text-[10px] uppercase text-muted-foreground">Image Size</div>
                  <div className="mt-0.5 text-sm font-semibold tabular-nums">
                    {formatFileSize(entropy.file_size)}
                  </div>
                </div>
              </div>

              {/* 64-bar Shannon Entropy Plot */}
              {entropy.blocks.length > 0 && (
                <div className="space-y-1">
                  <div
                    className="relative flex h-20 items-end gap-[2px] rounded border border-border bg-card px-2 pt-3 pb-1"
                    role="img"
                    aria-label="Block Shannon entropy distribution from 0 to 8 bits per byte"
                  >
                    <div
                      className="pointer-events-none absolute inset-x-0 border-t border-dashed border-red-500/40"
                      style={{ bottom: `${(7.8 / 8.0) * 100}%` }}
                      title="7.8 bits/byte encryption threshold"
                    />
                    {entropy.blocks.map((block, idx) => {
                      const pct = Math.max(4, Math.min(100, (block.entropy / 8.0) * 100))
                      const barColor =
                        block.entropy >= 7.8
                          ? 'bg-red-400/85'
                          : block.entropy >= 7.0
                            ? 'bg-amber-400/80'
                            : 'bg-zinc-400/75'
                      return (
                        <div
                          key={idx}
                          className={`flex-1 rounded-t-[1px] ${barColor}`}
                          style={{ height: `${pct}%` }}
                          title={`Offset 0x${block.offset.toString(16)}: ${block.entropy.toFixed(2)} bits/byte`}
                        />
                      )
                    })}
                  </div>
                  <div className="flex items-center justify-between font-mono text-[10px] text-muted-foreground">
                    <span>0x0</span>
                    <span>Dashed line: 7.8 bits/byte (encrypted / compressed)</span>
                    <span>0x{entropy.file_size.toString(16)}</span>
                  </div>
                </div>
              )}

              <p className="text-xs leading-relaxed text-muted-foreground">{entropy.summary}</p>

              {entropy.known_signatures.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-[10px] uppercase text-muted-foreground">Signatures:</span>
                  {entropy.known_signatures.map((sig) => (
                    <Badge key={sig} variant="secondary" className="font-mono text-[10px]">
                      {sig}
                    </Badge>
                  ))}
                </div>
              )}

              {/* Built-in Vendor Auto-Decrypt Banner */}
              {entropy.verdict === 'auto_decryptable' && (
                <div className="flex flex-wrap items-center justify-between gap-2 rounded border border-emerald-500/35 bg-emerald-500/10 p-3">
                  <div className="space-y-0.5">
                    <div className="font-mono text-xs font-semibold text-emerald-300">
                      {entropy.detected_format_label}
                    </div>
                    <div className="text-[11px] text-muted-foreground">
                      Built-in decryptor ready — decrypts without modifying the original upload.
                    </div>
                  </div>
                  <Button type="button" size="sm" onClick={handleAutoDecrypt} disabled={submitting}>
                    {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Unlock className="h-3.5 w-3.5" />}
                    Auto-Decrypt &amp; Unpack
                  </Button>
                </div>
              )}
            </>
          )}
        </div>

        {/* Section 2: Custom Key / IV (BYOK) Decryptor */}
        <form onSubmit={handleCustomDecrypt} className="space-y-3 rounded-md border border-border bg-background/40 p-3.5">
          <div className="flex items-center gap-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            <KeyRound className="h-3.5 w-3.5 text-primary" />
            Custom Key / IV Decryptor (BYOK)
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="fg-dec-alg" className="text-xs">
                Cipher / Operation
              </Label>
              <select
                id="fg-dec-alg"
                value={algorithm}
                onChange={(e) => setAlgorithm(e.target.value)}
                className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 font-mono text-xs text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              >
                {ALGORITHMS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {needsKey && (
              <div className="space-y-1.5 sm:col-span-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="fg-dec-key" className="text-xs">
                    Key
                  </Label>
                  <div className="flex items-center gap-1 rounded border border-border bg-card p-0.5 font-mono text-[10px]">
                    <button
                      type="button"
                      onClick={() => setKeyFormat('hex')}
                      className={`rounded px-2 py-0.5 ${
                        keyFormat === 'hex' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'
                      }`}
                    >
                      HEX
                    </button>
                    <button
                      type="button"
                      onClick={() => setKeyFormat('utf8')}
                      className={`rounded px-2 py-0.5 ${
                        keyFormat === 'utf8' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'
                      }`}
                    >
                      TEXT
                    </button>
                  </div>
                </div>
                <Input
                  id="fg-dec-key"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                  className="font-mono text-xs"
                  placeholder={
                    keyFormat === 'hex'
                      ? 'e.g. c05fbf1936c99429ce2a0781f08d6ad8'
                      : 'ASCII / UTF-8 key string'
                  }
                  required
                />
              </div>
            )}

            {needsIv && (
              <div className="space-y-1.5">
                <Label htmlFor="fg-dec-iv" className="text-xs">
                  IV / Nonce (32 hex chars)
                </Label>
                <Input
                  id="fg-dec-iv"
                  value={iv}
                  onChange={(e) => setIv(e.target.value)}
                  className="font-mono text-xs"
                  placeholder="00112233445566778899aabbccddeeff"
                  required
                />
              </div>
            )}

            <div className="space-y-1.5">
              <Label htmlFor="fg-dec-offset" className="text-xs">
                Header Offset (decimal or 0x hex)
              </Label>
              <Input
                id="fg-dec-offset"
                value={offsetInput}
                onChange={(e) => setOffsetInput(e.target.value)}
                className="font-mono text-xs"
                placeholder="0 or 0x6dc"
              />
            </div>
          </div>

          {supportsUnpad && (
            <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
              <input
                type="checkbox"
                checked={unpad}
                onChange={(e) => setUnpad(e.target.checked)}
                className="rounded border-border"
              />
              Strip PKCS#7 padding after decryption
            </label>
          )}

          {decryptError && (
            <div className="flex items-start gap-2 rounded border border-destructive/40 bg-destructive/10 p-2.5 text-xs text-red-300" role="alert">
              <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{decryptError}</span>
            </div>
          )}

          {decryptResult && (
            <div className="flex items-start gap-2 rounded border border-emerald-500/40 bg-emerald-500/10 p-2.5 text-xs text-emerald-300">
              <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <div>{decryptResult.message}</div>
                {decryptResult.unpack_started && (
                  <div className="text-[11px] text-muted-foreground">
                    Background unpacking started — close this dialog to monitor extraction progress.
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="flex items-center justify-end gap-2 pt-1">
            <Button type="button" variant="outline" size="sm" onClick={() => onOpenChange(false)}>
              Close
            </Button>
            <Button type="submit" size="sm" disabled={submitting}>
              {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Unlock className="h-3.5 w-3.5" />}
              Decrypt &amp; Unpack
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
