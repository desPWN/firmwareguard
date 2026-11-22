import { Link, useLocation, useParams } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'

function resolveRouteLabel(pathname: string): string {
  if (pathname === '/projects') return 'Projects Directory'
  if (pathname === '/help') return 'Help & MCP Guide'
  if (pathname.includes('/explore')) return 'File Explorer'
  if (pathname.includes('/findings')) return 'Findings Tracker'
  if (pathname.includes('/hardening')) return 'Binary Hardening'
  if (pathname.includes('/secrets')) return 'Secrets & Credentials'
  if (pathname.includes('/map')) return 'Component Map'
  if (pathname.includes('/sbom')) return 'SBOM & Vulnerabilities'
  if (pathname.includes('/emulation')) return 'QEMU Emulation'
  if (pathname.includes('/fuzzing')) return 'AFL++ Fuzzing'
  if (pathname.includes('/compare')) return 'Firmware Comparison'
  if (pathname.startsWith('/projects/')) return 'Project Overview'
  return 'FirmwareGuard'
}

export default function Header() {
  const { pathname } = useLocation()
  const { projectId } = useParams<{ projectId: string }>()
  const projects = useProjectStore((s) => s.projects)
  const currentProject = useProjectStore((s) => s.currentProject)

  const activeProject =
    (projectId && currentProject?.id === projectId ? currentProject : null) ||
    (projectId ? projects.find((p) => p.id === projectId) : null)

  const sectionTitle = resolveRouteLabel(pathname)

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-border bg-background px-5 md:px-6">
      <div className="flex min-w-0 items-center gap-2">
        <Link
          to="/projects"
          className="font-display text-xs font-semibold uppercase tracking-[0.09em] text-muted-foreground hover:text-foreground transition-colors shrink-0"
        >
          Board
        </Link>

        {activeProject && (
          <>
            <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/50 shrink-0" />
            <Link
              to={`/projects/${activeProject.id}`}
              className="truncate font-mono text-xs font-medium text-muted-foreground hover:text-foreground transition-colors max-w-[180px]"
            >
              {activeProject.name}
            </Link>
          </>
        )}

        <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/50 shrink-0" />
        <span className="truncate font-display text-base font-semibold uppercase tracking-[0.06em] text-foreground">
          {sectionTitle}
        </span>
      </div>
    </header>
  )
}
