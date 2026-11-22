import { useState } from 'react'
import { Copy, Check, Terminal, ChevronDown, ChevronRight, Usb } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { BoardSectionHeader, SignalLamp } from '@/components/ui/split-flap'

interface McpConnectionCardProps {
  projectId: string
}

export default function McpConnectionCard({ projectId }: McpConnectionCardProps) {
  const [copied, setCopied] = useState<string | null>(null)
  const [showAdvanced, setShowAdvanced] = useState(false)

  const containerName = 'firmwareguard-backend-1'
  const claudeCodeCmd = `claude mcp add firmwareguard -- docker exec -i ${containerName} uv run firmwareguard-mcp --project-id ${projectId}`
  const uartBridgeCmd = 'python3 scripts/firmwareguard-uart-bridge.py --bind 0.0.0.0 --port 9999'

  const claudeDesktopConfig = JSON.stringify(
    {
      mcpServers: {
        firmwareguard: {
          command: 'docker',
          args: ['exec', '-i', containerName, 'uv', 'run', 'firmwareguard-mcp', '--project-id', projectId],
        },
      },
    },
    null,
    2,
  )

  const handleCopy = async (text: string, key: string) => {
    await navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(null), 2000)
  }

  return (
    <div className="board-surface overflow-hidden rounded-md">
      <BoardSectionHeader
        title={
          <>
            <Terminal className="h-4 w-4 text-primary" />
            AI Analysis via MCP
          </>
        }
        right={
          <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-[#4ADE80]">
            <SignalLamp tone="green" className="h-1.5 w-1.5" />
            60+ TOOLS
          </span>
        }
      />

      <div className="p-4 space-y-3">
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] text-muted-foreground">CLAUDE CODE CLI</span>
            <Button
              type="button"
              variant="ghost"
              size="xs"
              onClick={() => handleCopy(claudeCodeCmd, 'claude-code')}
            >
              {copied === 'claude-code' ? (
                <Check className="h-3 w-3 text-[#4ADE80]" />
              ) : (
                <Copy className="h-3 w-3" />
              )}
              {copied === 'claude-code' ? 'Copied' : 'Copy'}
            </Button>
          </div>
          <pre className="rounded-[4px] border border-border bg-background p-2.5 font-mono text-[11px] text-foreground/90 overflow-x-auto whitespace-pre-wrap break-all">
            {claudeCodeCmd}
          </pre>
        </div>

        <button
          type="button"
          onClick={() => setShowAdvanced((v) => !v)}
          className="flex w-full items-center justify-between border-t border-border pt-2.5 font-mono text-[11px] text-muted-foreground hover:text-foreground transition-colors"
        >
          <span className="inline-flex items-center gap-1.5">
            {showAdvanced ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            Desktop JSON &amp; UART Bridge
          </span>
          <Usb className="h-3.5 w-3.5" />
        </button>

        {showAdvanced && (
          <div className="space-y-3 pt-1">
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-mono text-[11px] text-muted-foreground">MCP JSON CONFIG</span>
                <Button
                  type="button"
                  variant="ghost"
                  size="xs"
                  onClick={() => handleCopy(claudeDesktopConfig, 'desktop')}
                >
                  {copied === 'desktop' ? <Check className="h-3 w-3 text-[#4ADE80]" /> : <Copy className="h-3 w-3" />}
                  Copy
                </Button>
              </div>
              <pre className="rounded-[4px] border border-border bg-background p-2.5 font-mono text-[11px] text-muted-foreground overflow-x-auto">
                {claudeDesktopConfig}
              </pre>
            </div>

            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-mono text-[11px] text-muted-foreground">HOST UART BRIDGE</span>
                <Button
                  type="button"
                  variant="ghost"
                  size="xs"
                  onClick={() => handleCopy(uartBridgeCmd, 'uart')}
                >
                  {copied === 'uart' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  Copy
                </Button>
              </div>
              <pre className="rounded-[4px] border border-border bg-background p-2.5 font-mono text-[11px] text-muted-foreground overflow-x-auto whitespace-pre-wrap break-all">
                {uartBridgeCmd}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
