import { createHash, timingSafeEqual } from "crypto"

// AccountId is a global type from domain/primitives/index.types.d.ts
import {
  ApiTokenScope,
  API_KEY_PREFIX,
  toApiTokenKeyId,
} from "@domain/api-tokens/index.types"
import { ApiTokensRepository } from "@services/mongoose/api-tokens"
import { addAttributesToCurrentSpan } from "@services/tracing"
import { getAccount } from "@app/accounts"
import { baseLogger } from "@services/logger"

export interface ApiTokenAuth {
  accountId: AccountId
  scopes: ApiTokenScope[]
  tokenId: string
}

// Matches "fk_{8-hex-keyId}_{secret}" — keyId is hex so the split is unambiguous
const TOKEN_RE = new RegExp(`^${API_KEY_PREFIX}_([0-9a-f]{8})_(.+)$`)

/**
 * Validates an API token from the Authorization header.
 * Returns account information if valid, null otherwise.
 *
 * Note: IP-constraint enforcement and rich usage logging (IP / user-agent /
 * rate-limit metrics) are separate FIP-07 tickets; this performs the keyId
 * lookup + constant-time secret verification and records a minimal usage entry.
 */
export const validateApiToken = async (
  authHeader: string | undefined,
): Promise<ApiTokenAuth | null> => {
  const bearerPrefix = "Bearer "
  if (!authHeader?.startsWith(`${bearerPrefix}${API_KEY_PREFIX}_`)) {
    return null
  }

  try {
    const rawToken = authHeader.substring(bearerPrefix.length)
    const match = TOKEN_RE.exec(rawToken)
    if (!match) {
      return null
    }
    const keyId = match[1]
    const secret = match[2]

    addAttributesToCurrentSpan({
      "auth.apiToken.attempt": true,
      "auth.apiToken.keyId": keyId,
    })

    // Look up by public keyId (single indexed read)
    const apiTokensRepo = ApiTokensRepository()
    const apiToken = await apiTokensRepo.findByKeyId(toApiTokenKeyId(keyId))

    if (apiToken instanceof Error) {
      addAttributesToCurrentSpan({ "auth.apiToken.notFound": true })
      return null
    }

    // Constant-time comparison of the SHA-256 hashes
    const presentedHash = createHash("sha256").update(secret).digest("hex")
    const a = Buffer.from(presentedHash, "hex")
    const b = Buffer.from(apiToken.hashedKey, "hex")
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      addAttributesToCurrentSpan({ "auth.apiToken.badSecret": true })
      return null
    }

    // Expiry check (findByKeyId already filters out non-active tokens)
    if (apiToken.expiresAt && apiToken.expiresAt < new Date()) {
      addAttributesToCurrentSpan({ "auth.apiToken.expired": true })
      return null
    }

    // Record usage asynchronously (best effort): refreshes lastUsedAt and
    // appends a capped usage entry.
    ;(async () => {
      try {
        await apiTokensRepo.recordUsage(apiToken.id, {
          timestamp: new Date(),
          operation: "auth",
          result: "success",
        })
      } catch (err) {
        baseLogger.error(
          { err, apiTokenId: apiToken.id },
          "Failed to record API token usage",
        )
        addAttributesToCurrentSpan({ "auth.apiToken.recordUsageFailed": true })
      }
    })()

    addAttributesToCurrentSpan({
      "auth.apiToken.success": true,
      "auth.apiToken.accountId": apiToken.accountId,
      "auth.apiToken.scopes": apiToken.scopes.join(","),
      "auth.apiToken.tokenId": apiToken.id,
    })

    return {
      accountId: apiToken.accountId,
      scopes: apiToken.scopes,
      tokenId: apiToken.id,
    }
  } catch (err) {
    baseLogger.error(err, "Error validating API token")
    addAttributesToCurrentSpan({
      "auth.apiToken.error": true,
      "auth.apiToken.errorMessage": err instanceof Error ? err.message : "Unknown error",
    })
    return null
  }
}

/**
 * Check if the API token has the required scope for an operation.
 * - `admin` grants everything
 * - `write:X` implies `read:X`
 */
export const hasApiTokenScope = (
  scopes: ApiTokenScope[],
  requiredScope: ApiTokenScope,
): boolean => {
  if (scopes.includes("admin")) {
    return true
  }

  // A write scope implies the matching read scope
  if (requiredScope.startsWith("read:")) {
    const resource = requiredScope.slice("read:".length)
    if (scopes.includes(`write:${resource}` as ApiTokenScope)) {
      return true
    }
  }

  return scopes.includes(requiredScope)
}

/**
 * Get account context from API token authentication
 */
export const getApiTokenAccountContext = async (auth: ApiTokenAuth) => {
  const account = await getAccount(auth.accountId)

  if (account instanceof Error) {
    addAttributesToCurrentSpan({ "auth.apiToken.accountNotFound": true })
    return null
  }

  return {
    domainAccount: account,
    isApiToken: true,
    apiTokenScopes: auth.scopes,
    apiTokenId: auth.tokenId,
  }
}
