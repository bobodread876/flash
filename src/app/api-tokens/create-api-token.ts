import { randomBytes, createHash } from "crypto"

import {
  CreateApiTokenArgs,
  CreateApiTokenResult,
  API_KEY_PREFIX,
  API_KEY_ID_BYTES,
  API_KEY_SECRET_BYTES,
  checkedToApiTokenName,
  checkedToApiTokenScopes,
  checkedToIpConstraints,
  toApiTokenHash,
  toApiTokenKeyId,
} from "@domain/api-tokens/index.types"
import { ApiTokensRepository } from "@services/mongoose/api-tokens"
import { addAttributesToCurrentSpan } from "@services/tracing"
import { DomainError } from "@domain/shared"
import { getApiTokenConfig } from "@config"

export const createApiToken = async ({
  accountId,
  name,
  scopes = ["read:user"],
  ipConstraints = [],
  metadata = {},
  expiresIn = null,
}: CreateApiTokenArgs): Promise<CreateApiTokenResult | DomainError> => {
  // Add tracing
  addAttributesToCurrentSpan({
    "app.apiTokens.create.accountId": accountId,
    "app.apiTokens.create.name": name,
    "app.apiTokens.create.scopes": scopes.join(","),
    "app.apiTokens.create.expiresIn": expiresIn || undefined,
  })

  // Validate inputs
  const checkedName = checkedToApiTokenName(name)
  if (checkedName instanceof Error) {
    return checkedName
  }

  // Validate scopes (fine-grained, at least one required)
  const checkedScopes = checkedToApiTokenScopes(scopes)
  if (checkedScopes instanceof Error) {
    return new DomainError(checkedScopes.message)
  }

  // Validate IP constraints (IP or CIDR)
  const checkedIpConstraints = checkedToIpConstraints(ipConstraints)
  if (checkedIpConstraints instanceof Error) {
    return new DomainError(checkedIpConstraints.message)
  }

  // Get configuration
  const config = getApiTokenConfig()

  // Check token limit per account (prevent abuse)
  const apiTokensRepo = ApiTokensRepository()
  const existingTokens = await apiTokensRepo.findByAccountId(accountId)

  if (!(existingTokens instanceof Error)) {
    const maxTokensPerAccount = config.maxTokensPerAccount || 10
    if (existingTokens.length >= maxTokensPerAccount) {
      return new DomainError(
        `Maximum number of API tokens (${maxTokensPerAccount}) reached. Please revoke unused tokens.`,
      )
    }
  }

  // Generate FIP-07 key: fk_{keyId}_{randomSecret}
  // keyId is hex (no base64url "_") so the token parses unambiguously;
  // only the SHA-256 hash of the secret is persisted.
  const keyId = randomBytes(API_KEY_ID_BYTES).toString("hex")
  const secret = randomBytes(API_KEY_SECRET_BYTES).toString("base64url")
  const fullToken = `${API_KEY_PREFIX}_${keyId}_${secret}`
  const hashedKey = createHash("sha256").update(secret).digest("hex")

  // Calculate expiration date
  const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null // Default: no expiration

  // Create token in database
  const apiToken = await apiTokensRepo.create({
    keyId: toApiTokenKeyId(keyId),
    accountId,
    name: checkedName,
    hashedKey: toApiTokenHash(hashedKey),
    scopes: checkedScopes,
    ipConstraints: checkedIpConstraints,
    metadata,
    expiresAt,
  })

  if (apiToken instanceof Error) {
    addAttributesToCurrentSpan({ "app.apiTokens.create.error": true })
    return apiToken
  }

  addAttributesToCurrentSpan({
    "app.apiTokens.create.success": true,
    "app.apiTokens.create.tokenId": apiToken.id,
  })

  // Return token only once (won't be stored in plain text)
  return {
    id: apiToken.id,
    keyId: apiToken.keyId,
    name: apiToken.name,
    token: fullToken, // Full token: fk_{keyId}_{secret}
    scopes: apiToken.scopes,
    expiresAt: apiToken.expiresAt,
    warning: "Store this token securely. It won't be shown again.",
  }
}
