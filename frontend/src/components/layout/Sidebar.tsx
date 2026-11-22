import { useEffect, useState } from 'react'
import { NavLink, Link, useParams, useNavigate } from 'react-router-dom'
import {
  PanelLeftClose,
  PanelLeftOpen,
  FolderOpen,
  ChevronRight,
  LayoutDashboard,
  FolderSearch,
  ShieldAlert,
  ShieldCheck,
  KeyRound,
  Network,
  Package,
  PlayCircle,
  Bug,
  GitCompareArrows,
  HelpCircle,
} from 'lucide-react'
import firmwareguardIcon from '@/assets/firmwareguard_logo.png'
import { useProjectStore } from '@/stores/projectStore'
import { SignalLamp, type SignalTone } from '@/components/ui/split-flap'

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

const projectSubPages = [
  { suffix: '', label: 'Overview', icon: LayoutDashboard, experimental: false },
  { suffix: '/explore', label: 'File Explorer', icon: FolderSearch, experimental: false },
  { suffix: '/findings', label: 'Findings', icon: ShieldAlert, experimental: false },
  { suffix: '/hardening', label: 'Binary Hardening', icon: ShieldCheck, experimental: false },
  { suffix: '/secrets', label: 'Secrets & Creds', icon: KeyRound, experimental: false },
  { suffix: '/map', label: 'Component Map', icon: Network, experimental: false },
  { suffix: '/sbom', label: 'SBOM & CVEs', icon: Package, experimental: false },
  { suffix: '/emulation', label: 'Emulation', icon: PlayCircle, experimental: false },
  { suffix: '/fuzzing', label: 'Fuzzing', icon: Bug, experimental: true },
  { suffix: '/compare', label: 'Compare', icon: GitCompareArrows, experimental: false },
]

function projectStatusTone(status: string): SignalTone {
  if (status === 'ready') return 'green'
  if (status === 'unpacking') return 'amber'
  if (status === 'error') return 'red'
  return 'idle'
}

export default function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { projectId: activeProjectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()
  const projects = useProjectStore((s) => s.projects)
  const fetchProjects = useProjectStore((s) => s.fetchProjects)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  useEffect(() => {
    fetchProjects()
  }, [fetchProjects])

  useEffect(() => {
    if (activeProjectId) {
      setExpandedId(activeProjectId)
    }
  }, [activeProjectId])

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id))
  }

  if (collapsed) {
    return (
      <aside className="flex h-full w-14 shrink-0 flex-col items-center border-r border-border bg-sidebar text-sidebar-foreground">
        <div className="flex h-14 w-full items-center justify-center border-b border-border">
          <button
            type="button"
            onClick={onToggle}
            className="rounded-md border border-transparent p-1.5 hover:border-border hover:bg-sidebar-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            title="Expand sidebar"
            aria-label="Expand sidebar"
          >
            <img src={firmwareguardIcon} alt="FirmwareGuard" className="h-6 w-6 invert" />
          </button>
        </div>

        <nav className="flex flex-1 flex-col items-center gap-2 py-3">
          <button
            type="button"
            onClick={onToggle}
            className="flex items-center justify-center rounded-md p-2 text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
            title="Expand navigation"
            aria-label="Expand navigation"
          >
            <PanelLeftOpen className="h-4 w-4" />
          </button>
          <NavLink
            to="/projects"
            title="Projects"
            className={({ isActive }) =>
              `flex items-center justify-center rounded-md border p-2 transition-colors ${
                isActive
                  ? 'border-border bg-sidebar-accent text-foreground'
                  : 'border-transparent text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground'
              }`
            }
          >
            <FolderOpen className="h-4 w-4" />
          </NavLink>
        </nav>

        <div className="border-t border-border py-3 w-full flex justify-center">
          <NavLink
            to="/help"
            title="Help"
            className={({ isActive }) =>
              `flex items-center justify-center rounded-md border p-2 transition-colors ${
                isActive
                  ? 'border-border bg-sidebar-accent text-foreground'
                  : 'border-transparent text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground'
              }`
            }
          >
            <HelpCircle className="h-4 w-4" />
          </NavLink>
        </div>
      </aside>
    )
  }

  return (
    <aside className="flex h-full w-64 shrink-0 flex-col border-r border-border bg-sidebar text-sidebar-foreground">
      {/* Brand Frame */}
      <div className="flex h-14 items-center gap-2.5 border-b border-border px-4">
        <Link to="/projects" title="Back to Projects" className="flex min-w-0 items-center gap-2.5">
          <img src={firmwareguardIcon} alt="FirmwareGuard" className="h-7 w-7 shrink-0 invert" />
          <span className="truncate font-display text-lg font-bold uppercase tracking-[0.08em] text-foreground">
            FirmwareGuard
          </span>
        </Link>
        <button
          type="button"
          onClick={onToggle}
          className="ml-auto rounded-md p-1 text-muted-foreground hover:bg-sidebar-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          title="Collapse sidebar"
          aria-label="Collapse sidebar"
        >
          <PanelLeftClose className="h-4 w-4" />
        </button>
      </div>

      {/* Projects directory header */}
      <div className="px-3 pb-1.5 pt-3">
        <NavLink
          to="/projects"
          end
          className={({ isActive }) =>
            `flex items-center justify-between rounded-md border px-2.5 py-1.5 font-display text-xs font-semibold uppercase tracking-[0.08em] transition-colors ${
              isActive
                ? 'border-border bg-sidebar-accent text-foreground'
                : 'border-transparent text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground'
            }`
          }
        >
          <span className="flex items-center gap-2">
            <FolderOpen className="h-3.5 w-3.5" />
            Projects
          </span>
          <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
            {String(projects.length).padStart(2, '0')}
          </span>
        </NavLink>
      </div>

      {/* Project tree */}
      <nav className="flex-1 overflow-y-auto px-2.5 pb-3 space-y-1">
        {projects.length === 0 && (
          <p className="px-3 py-2 font-mono text-xs text-muted-foreground">No projects yet</p>
        )}
        {projects.map((project) => {
          const isExpanded = expandedId === project.id
          const isActive = activeProjectId === project.id

          return (
            <div key={project.id} className="space-y-0.5">
              <button
                type="button"
                onClick={() => toggleExpand(project.id)}
                className={`flex w-full items-center gap-2 rounded-md border px-2 py-1.5 text-sm transition-colors ${
                  isActive
                    ? 'border-border bg-sidebar-accent/70 text-foreground font-medium'
                    : 'border-transparent text-sidebar-foreground/80 hover:bg-sidebar-accent/40 hover:text-foreground'
                }`}
              >
                <ChevronRight
                  className={`h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform ${
                    isExpanded ? 'rotate-90 text-foreground' : ''
                  }`}
                />
                <span className="min-w-0 flex-1 truncate text-left font-mono text-xs">
                  {project.name}
                </span>
                <SignalLamp tone={projectStatusTone(project.status)} label={`Status: ${project.status}`} />
              </button>

              {isExpanded && (
                <div className="ml-3 space-y-0.5 border-l border-border pl-2 py-1">
                  {projectSubPages.map((page) => (
                    <NavLink
                      key={page.suffix}
                      to={`/projects/${project.id}${page.suffix}`}
                      end={page.suffix === ''}
                      onClick={(e) => {
                        e.stopPropagation()
                        navigate(`/projects/${project.id}${page.suffix}`)
                      }}
                      className={({ isActive: linkActive }) =>
                        `flex items-center justify-between gap-2 rounded-md border px-2 py-1.5 text-xs transition-colors ${
                          linkActive
                            ? 'border-border bg-sidebar-accent text-foreground font-medium'
                            : 'border-transparent text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground'
                        }`
                      }
                    >
                      <span className="flex min-w-0 items-center gap-2">
                        <page.icon className="h-3.5 w-3.5 shrink-0" />
                        <span className="truncate">{page.label}</span>
                      </span>
                      {page.experimental && (
                        <span className="rounded-[3px] border border-border bg-background/60 px-1 py-px font-mono text-[9px] text-muted-foreground">
                          EXP
                        </span>
                      )}
                    </NavLink>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </nav>

      {/* Help Footer */}
      <div className="border-t border-border p-3">
        <NavLink
          to="/help"
          className={({ isActive }) =>
            `flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors ${
              isActive
                ? 'border-border bg-sidebar-accent text-foreground'
                : 'border-transparent text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground'
            }`
          }
        >
          <HelpCircle className="h-3.5 w-3.5" />
          Help &amp; MCP Guide
        </NavLink>
      </div>
    </aside>
  )
}
