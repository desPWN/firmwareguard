import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { MoreHorizontal, FolderOpen, Trash2, Download } from 'lucide-react'
import type { Project } from '@/types'
import { exportProject } from '@/api/exportImport'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { formatDate } from '@/utils/format'

const STATUS_BADGE: Record<string, string> = {
  ready: 'bg-secondary text-foreground border-border',
  unpacking: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  error: 'bg-red-500/10 text-red-400 border-red-500/30',
  created: 'bg-background text-muted-foreground border-border',
}

interface ProjectCardProps {
  project: Project
  onDelete: (id: string) => void
}

export default function ProjectCard({ project, onDelete }: ProjectCardProps) {
  const navigate = useNavigate()
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  const handleExport = async () => {
    setExporting(true)
    setExportError(null)
    try {
      const blob = await exportProject(project.id)
      const safeName = project.name.replace(/\s+/g, '_').replace(/\//g, '_')
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${safeName}.firmwareguard`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Export failed'
      setExportError(msg)
    } finally {
      setExporting(false)
    }
  }

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => navigate(`/projects/${project.id}`)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          navigate(`/projects/${project.id}`)
        }
      }}
      className="group board-surface flex cursor-pointer flex-col justify-between gap-4 rounded-md p-4 transition-colors hover:border-foreground/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <div className="space-y-1.5">
        <div className="flex items-start justify-between gap-2">
          <h2 className="text-base font-semibold leading-snug text-foreground truncate">
            {project.name}
          </h2>
          <DropdownMenu>
            <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
              <Button type="button" variant="ghost" size="icon-xs" aria-label="Project options">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
              <DropdownMenuItem onClick={() => navigate(`/projects/${project.id}`)}>
                <FolderOpen className="mr-2 h-4 w-4" />
                Open
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleExport} disabled={exporting}>
                <Download className="mr-2 h-4 w-4" />
                {exporting ? 'Exporting...' : 'Export'}
              </DropdownMenuItem>
              <DropdownMenuItem variant="destructive" onClick={() => onDelete(project.id)}>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        <p className="line-clamp-2 text-xs text-muted-foreground leading-relaxed">
          {project.description || 'No description'}
        </p>

        {exportError && (
          <div className="mt-2 rounded-[4px] border border-red-500/35 bg-red-500/10 p-2 text-xs text-red-400">
            Export failed: {exportError}
          </div>
        )}
      </div>

      <div className="flex items-center justify-between pt-1">
        <Badge
          variant="outline"
          className={`text-[11px] font-normal ${STATUS_BADGE[project.status] ?? STATUS_BADGE.created}`}
        >
          {project.status}
        </Badge>
        <span className="text-xs text-muted-foreground tabular-nums">
          {formatDate(project.created_at)}
        </span>
      </div>
    </div>
  )
}
