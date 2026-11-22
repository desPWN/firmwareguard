import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

export default function NotFoundPage() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4">
      <div className="flap-cell rounded-md px-8 py-5 text-center">
        <div className="font-display text-xs uppercase tracking-[0.12em] text-muted-foreground">
          Route Status
        </div>
        <h1 className="mt-1 font-mono text-5xl font-bold text-[#FF6B6F] tabular-nums">404</h1>
      </div>
      <p className="text-sm text-muted-foreground">Requested workbench route does not exist.</p>
      <Button variant="outline" asChild>
        <Link to="/projects">Return to Audit Board</Link>
      </Button>
    </div>
  )
}
