// AccountId is a global type from domain/primitives/index.types.d.ts

// Branded types for type safety
export type ApiTokenId = string & { readonly brand: unique symbol }
export type ApiTokenKeyId = string & { readonly brand: unique symbol }
export type ApiToken = string & { readonly brand: unique symbol }
export type ApiTokenName = string & { readonly brand: unique symbol }
export type ApiTokenHash = string & { readonly brand: unique symbol }

// FIP-07 key format: fk_{keyId}_{randomSecret}
// keyId is 8 hex chars (no base64url "_" so the token parses unambiguously);
// the 64-char base64url secret is never stored — only its SHA-256 hash.
export const API_KEY_PREFIX = "fk"
export const API_KEY_ID_BYTES = 4 // → 8 hex chars
export const API_KEY_SECRET_BYTES = 48 // → 64 base64url chars
export const API_TOKEN_USAGE_LOG_LIMIT = 50

// FIP-07 fine-grained scopes
export const API_TOKEN_SCOPES = [
  "read:wallet",
  "write:wallet",
  "read:transactions",
  "write:transactions",
  "read:user",
  "write:user",
  "admin",
] as const
export type ApiTokenScope = (typeof API_TOKEN_SCOPES)[number]

// FIP-07 lifecycle status (replaces the previous `active` boolean)
export const API_TOKEN_STATUSES = ["active", "revoked", "expired"] as const
export type ApiTokenStatus = (typeof API_TOKEN_STATUSES)[number]

// Per-use audit entry; the model keeps only the most recent
// API_TOKEN_USAGE_LOG_LIMIT entries.
export interface ApiTokenUsageLog {
  timestamp: Date
  ip?: string | null
  userAgent?: string | null
  operation?: string | null
  result?: string | null
}

// Main API token interface
export interface IApiToken {
  id: ApiTokenId
  keyId: ApiTokenKeyId
  accountId: AccountId
  name: ApiTokenName
  hashedKey: ApiTokenHash
  scopes: ApiTokenScope[]
  status: ApiTokenStatus
  ipConstraints: string[]
  metadata: Record<string, unknown>
  usageLogs: ApiTokenUsageLog[]
  lastUsedAt: Date | null
  createdAt: Date
  expiresAt: Date | null
}

// Creation types
export interface NewApiToken {
  keyId: ApiTokenKeyId
  accountId: AccountId
  name: ApiTokenName
  hashedKey: ApiTokenHash
  scopes: ApiTokenScope[]
  ipConstraints?: string[]
  metadata?: Record<string, unknown>
  expiresAt: Date | null
}

export interface CreateApiTokenArgs {
  accountId: AccountId
  name: string
  scopes?: ApiTokenScope[]
  ipConstraints?: string[]
  metadata?: Record<string, unknown>
  expiresIn?: number | null // seconds until expiration
}

export interface CreateApiTokenResult {
  id: ApiTokenId
  keyId: ApiTokenKeyId
  name: ApiTokenName
  token: string // Raw token (fk_{keyId}_{secret}), only returned once
  scopes: ApiTokenScope[]
  expiresAt: Date | null
  warning: string
}

// Validation functions
export const checkedToApiTokenName = (name: string): ApiTokenName | Error => {
  if (!name || name.length < 3) {
    return new Error("API token name must be at least 3 characters")
  }
  if (name.length > 50) {
    return new Error("API token name must be less than 50 characters")
  }
  if (!/^[a-zA-Z0-9-_ ]+$/.test(name)) {
    return new Error(
      "API token name can only contain letters, numbers, spaces, hyphens, and underscores",
    )
  }
  return name as ApiTokenName
}

export const checkedToApiTokenScopes = (scopes: string[]): ApiTokenScope[] | Error => {
  if (!scopes || scopes.length < 1) {
    return new Error("At least one scope is required")
  }
  for (const scope of scopes) {
    if (!(API_TOKEN_SCOPES as readonly string[]).includes(scope)) {
      return new Error(`Invalid scope: ${scope}`)
    }
  }
  return scopes as ApiTokenScope[]
}

const IPV4_CIDR =
  /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)(\/(3[0-2]|[12]?\d))?$/
const IPV6_CIDR = /^[0-9a-fA-F:]+(\/(12[0-8]|1[01]\d|\d?\d))?$/

export const checkedToIpConstraints = (ips: string[]): string[] | Error => {
  for (const ip of ips) {
    if (!IPV4_CIDR.test(ip) && !IPV6_CIDR.test(ip)) {
      return new Error(`Invalid IP/CIDR constraint: ${ip}`)
    }
  }
  return ips
}

export const toApiTokenId = (id: string): ApiTokenId => {
  return id as ApiTokenId
}

export const toApiTokenKeyId = (keyId: string): ApiTokenKeyId => {
  return keyId as ApiTokenKeyId
}

export const toApiTokenHash = (hash: string): ApiTokenHash => {
  return hash as ApiTokenHash
}
