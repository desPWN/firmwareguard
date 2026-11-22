import apiClient from './client'
import type {
  ExportSecretsFindingsResponse,
  SecretsHarvestResponse,
  SecretsHarvestSummary,
} from '@/types'

/**
 * Fetch full secrets audit for a project firmware image.
 * Corresponds to GET /api/v1/projects/{projectId}/secrets
 */
export async function getSecretsHarvest(
  projectId: string,
  firmwareId?: string,
  refresh: boolean = false,
): Promise<SecretsHarvestResponse> {
  const params: Record<string, string | boolean> = {}
  if (firmwareId) params.firmware_id = firmwareId
  if (refresh) params.refresh = true
  const { data } = await apiClient.get<SecretsHarvestResponse>(
    `/projects/${projectId}/secrets`,
    { params },
  )
  return data
}

/**
 * Fetch summary KPI metrics for secrets.
 * Corresponds to GET /api/v1/projects/{projectId}/secrets/summary
 */
export async function getSecretsSummary(
  projectId: string,
  firmwareId?: string,
): Promise<SecretsHarvestSummary> {
  const params: Record<string, string> = {}
  if (firmwareId) params.firmware_id = firmwareId
  const { data } = await apiClient.get<SecretsHarvestSummary>(
    `/projects/${projectId}/secrets/summary`,
    { params },
  )
  return data
}

/**
 * Promote discovered high/critical secrets into the project's Findings tracker.
 * Corresponds to POST /api/v1/projects/{projectId}/secrets/export-findings
 */
export async function exportSecretsToFindings(
  projectId: string,
  firmwareId?: string,
  minSeverity: string = 'medium',
): Promise<ExportSecretsFindingsResponse> {
  const { data } = await apiClient.post<ExportSecretsFindingsResponse>(
    `/projects/${projectId}/secrets/export-findings`,
    { firmware_id: firmwareId, min_severity: minSeverity },
  )
  return data
}
