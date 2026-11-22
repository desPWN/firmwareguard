import { lazy } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import AppLayout from '@/components/layout/AppLayout'
import AuthGate from '@/components/auth/AuthGate'
import ProjectsPage from '@/pages/ProjectsPage'

const ProjectDetailPage = lazy(() => import('@/pages/ProjectDetailPage'))
const ExplorePage = lazy(() => import('@/pages/ExplorePage'))
const FindingsPage = lazy(() => import('@/pages/FindingsPage'))
const HardeningPage = lazy(() => import('@/pages/HardeningPage'))
const SecretsPage = lazy(() => import('@/pages/SecretsPage'))
const ComponentMapPage = lazy(() => import('@/pages/ComponentMapPage'))
const SbomPage = lazy(() => import('@/pages/SbomPage'))
const EmulationPage = lazy(() => import('@/pages/EmulationPage'))
const FuzzingPage = lazy(() => import('@/pages/FuzzingPage'))
const ComparisonPage = lazy(() => import('@/pages/ComparisonPage'))
const HelpPage = lazy(() => import('@/pages/HelpPage'))
const NotFoundPage = lazy(() => import('@/pages/NotFoundPage'))

export default function App() {
  return (
    <AuthGate>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Navigate to="/projects" replace />} />
          <Route element={<AppLayout />}>
            <Route path="/projects" element={<ProjectsPage />} />
            <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
            <Route path="/projects/:projectId/explore" element={<ExplorePage />} />
            <Route path="/projects/:projectId/findings" element={<FindingsPage />} />
            <Route path="/projects/:projectId/hardening" element={<HardeningPage />} />
            <Route path="/projects/:projectId/secrets" element={<SecretsPage />} />
            <Route path="/projects/:projectId/map" element={<ComponentMapPage />} />
            <Route path="/projects/:projectId/sbom" element={<SbomPage />} />
            <Route path="/projects/:projectId/emulation" element={<EmulationPage />} />
            <Route path="/projects/:projectId/fuzzing" element={<FuzzingPage />} />
            <Route path="/projects/:projectId/compare" element={<ComparisonPage />} />
            <Route path="/help" element={<HelpPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthGate>
  )
}
