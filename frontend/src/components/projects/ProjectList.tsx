import { useEffect } from 'react'
import { FolderOpen, Plus } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import ProjectCard from './ProjectCard'
import { Button } from '@/components/ui/button'

interface ProjectListProps {
  onCreateClick: () => void
}

export default function ProjectList({ onCreateClick }: ProjectListProps) {
  const { projects, loading, fetchProjects, removeProject } = useProjectStore()

  useEffect(() => {
    fetchProjects()
  }, [fetchProjects])

  const handleDelete = (id: string) => {
    if (window.confirm('Delete this project and all its data?')) {
      removeProject(id)
    }
  }

  if (loading && projects.length === 0) {
    return (
      <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="flap-cell h-36 rounded-md opacity-60" />
        ))}
      </div>
    )
  }

  if (projects.length === 0) {
    return (
      <div className="board-surface flex flex-col items-center gap-4 rounded-md py-16 px-6 text-center">
        <div className="flex h-11 w-11 items-center justify-center rounded-md border border-border bg-secondary">
          <FolderOpen className="h-5 w-5 text-primary" />
        </div>
        <div>
          <p className="font-display text-lg font-semibold uppercase tracking-[0.06em]">
            No Firmware Targets Loaded
          </p>
          <p className="mt-1 text-sm text-muted-foreground">
            Create a project and upload a router or embedded Linux image to start auditing.
          </p>
        </div>
        <Button type="button" size="sm" onClick={onCreateClick}>
          <Plus className="h-3.5 w-3.5" />
          Create First Project
        </Button>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
      {projects.map((p) => (
        <ProjectCard key={p.id} project={p} onDelete={handleDelete} />
      ))}
    </div>
  )
}
