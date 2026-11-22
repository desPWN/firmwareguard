import apiClient from './client'
import type {
  FunctionListResponse,
  ImportsResponse,
  DisassemblyResponse,
  DecompilationResponse,
  CleanedCodeResponse,
  BinaryInfoResponse,
  FirmwareHardeningResponse,
  SecretsHarvestResponse,
  ExportSecretsFindingsResponse,
} from '@/types'

export async function listFunctions(
  projectId: string,
  binaryPath: string,
): Promise<FunctionListResponse> {
  const { data } = await apiClient.get<FunctionListResponse>(
    `/projects/${projectId}/analysis/functions`,
    { params: { path: binaryPath } },
  )
  return data
}

export async function listImports(
  projectId: string,
  binaryPath: string,
): Promise<ImportsResponse> {
  const { data } = await apiClient.get<ImportsResponse>(
    `/projects/${projectId}/analysis/imports`,
    { params: { path: binaryPath } },
  )
  return data
}

export async function disassembleFunction(
  projectId: string,
  binaryPath: string,
  functionName: string,
  maxInstructions: number = 100,
): Promise<DisassemblyResponse> {
  const { data } = await apiClient.get<DisassemblyResponse>(
    `/projects/${projectId}/analysis/disasm`,
    { params: { path: binaryPath, function: functionName, max_instructions: maxInstructions } },
  )
  return data
}

export async function decompileFunction(
  projectId: string,
  binaryPath: string,
  functionName: string,
): Promise<DecompilationResponse> {
  const { data } = await apiClient.get<DecompilationResponse>(
    `/projects/${projectId}/analysis/decompile`,
    { params: { path: binaryPath, function: functionName } },
  )
  return data
}

export async function fetchCleanedCode(
  projectId: string,
  binaryPath: string,
  functionName: string,
): Promise<CleanedCodeResponse> {
  const { data } = await apiClient.get<CleanedCodeResponse>(
    `/projects/${projectId}/analysis/cleaned-code`,
    { params: { path: binaryPath, function: functionName } },
  )
  return data
}

export async function getBinaryInfo(
  projectId: string,
  binaryPath: string,
): Promise<BinaryInfoResponse> {
  const { data } = await apiClient.get<BinaryInfoResponse>(
    `/projects/${projectId}/analysis/binary-info`,
    { params: { path: binaryPath } },
  )
  return data
}

export async function getBinaryHardening(
  projectId: string,
  firmwareId?: string,
  refresh: boolean = false,
): Promise<FirmwareHardeningResponse> {
  const params: Record<string, string | boolean> = {}
  if (firmwareId) params.firmware_id = firmwareId
  if (refresh) params.refresh = true
  const { data } = await apiClient.get<FirmwareHardeningResponse>(
    `/projects/${projectId}/analysis/hardening`,
    { params },
  )
  return data
}

export async function getFirmwareSecrets(
  projectId: string,
  firmwareId?: string,
  refresh: boolean = false,
): Promise<SecretsHarvestResponse> {
  const params: Record<string, string | boolean> = {}
  if (firmwareId) params.firmware_id = firmwareId
  if (refresh) params.refresh = true
  const { data } = await apiClient.get<SecretsHarvestResponse>(
    `/projects/${projectId}/analysis/secrets`,
    { params },
  )
  return data
}

export async function exportSecretsToFindings(
  projectId: string,
  firmwareId?: string,
  minSeverity: string = 'medium',
): Promise<ExportSecretsFindingsResponse> {
  const { data } = await apiClient.post<ExportSecretsFindingsResponse>(
    `/projects/${projectId}/analysis/secrets/export-findings`,
    { firmware_id: firmwareId, min_severity: minSeverity },
  )
  return data
}

