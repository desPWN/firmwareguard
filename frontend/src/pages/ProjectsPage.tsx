import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Upload, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { FlapCounter } from '@/components/ui/split-flap'
import ProjectList from '@/components/projects/ProjectList'
import CreateProjectDialog from '@/components/projects/CreateProjectDialog'
import { importProject } from '@/api/exportImport'
import { useProjectStore } from '@/stores/projectStore'

export default function ProjectsPage() {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importError, setImportError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  const projects = useProjectStore((s) => s.projects)
  const fetchProjects = useProjectStore((s) => s.fetchProjects)

  const readyCount = projects.filter((p) => p.status === 'ready').length
  const unpackingCount = projects.filter((p) => p.status === 'unpacking').length
  const errorCount = projects.filter((p) => p.status === 'error').length

  const handleImportClick = () => {
    fileInputRef.current?.click()
  }

  const handleFileSelected = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    e.target.value = ''

    setImporting(true)
    setImportError(null)
    try {
      const project = await importProject(file)
      await fetchProjects()
      navigate(`/projects/${project.id}`)
    } catch (err) {
      const msg =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
          : err instanceof Error
            ? err.message
            : 'Import failed'
      setImportError(msg ?? 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  return (
    <div className="space-y-6 animate-flap-settle">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-2xl font-bold uppercase tracking-[0.05em] text-foreground">
            Firmware Audit Board
          </h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Select a firmware target to inspect unpacked filesystems, secrets, hardening, and CVEs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button type="button" size="sm" variant="outline" onClick={handleImportClick} disabled={importing}>
            {importing ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Upload className="h-3.5 w-3.5" />
            )}
            Import Archive
          </Button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".firmwareguard,.zip"
            className="hidden"
            onChange={handleFileSelected}
          />
          <Button type="button" size="sm" onClick={() => setDialogOpen(true)}>
            <Plus className="h-3.5 w-3.5" />
            New Project
          </Button>
        </div>
      </div>

      {/* Split-Flap Directory Telemetry */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <FlapCounter
          label="Total Targets"
          value={String(projects.length).padStart(2, '0')}
          subtext="Indexed firmware projects"
          tone="neutral"
          lamp={projects.length > 0 ? 'amber' : 'idle'}
        />
        <FlapCounter
          label="Ready for Audit"
          value={String(readyCount).padStart(2, '0')}
          subtext="Rootfs unpacked"
          tone={readyCount > 0 ? 'green' : 'muted'}
          lamp={readyCount > 0 ? 'green' : 'idle'}
        />
        <FlapCounter
          label="Unpacking"
          value={String(unpackingCount).padStart(2, '0')}
          subtext="Active extraction jobs"
          tone={unpackingCount > 0 ? 'amber' : 'muted'}
          lamp={unpackingCount > 0 ? 'amber' : 'idle'}
        />
        <FlapCounter
          label="Extraction Errors"
          value={String(errorCount).padStart(2, '0')}
          subtext="Requires attention"
          tone={errorCount > 0 ? 'red' : 'muted'}
          lamp={errorCount > 0 ? 'red' : 'idle'}
        />
      </div>

      {importError && (
        <div
          role="alert"
          className="rounded-[4px] border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-[#FF7B7F]"
        >
          {importError}
        </div>
      )}

      <ProjectList onCreateClick={() => setDialogOpen(true)} />
      <CreateProjectDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  )
}
