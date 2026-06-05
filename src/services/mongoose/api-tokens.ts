import { Schema, model } from "mongoose"
import {
  ApiTokenId,
  ApiTokenKeyId,
  ApiTokenName,
  ApiTokenScope,
  ApiTokenStatus,
  ApiTokenUsageLog,
  IApiToken,
  NewApiToken,
  API_TOKEN_SCOPES,
  API_TOKEN_STATUSES,
  API_TOKEN_USAGE_LOG_LIMIT,
  toApiTokenId,
  toApiTokenKeyId,
  toApiTokenHash,
} from "@domain/api-tokens/index.types"
// AccountId is a global type from domain/primitives/index.types.d.ts
import {
  CouldNotFindError,
  RepositoryError,
  UnknownRepositoryError,
} from "@domain/errors"
import { toObjectId, fromObjectId } from "@services/mongoose/utils"

// Capped per-key audit entry (FIP-07 §usageLogs)
const ApiTokenUsageLogSchema = new Schema<ApiTokenUsageLog>(
  {
    timestamp: { type: Date, default: Date.now },
    ip: { type: String, default: null },
    userAgent: { type: String, default: null },
    operation: { type: String, default: null },
    result: { type: String, default: null },
  },
  { _id: false },
)

// MongoDB Schema — FIP-07 ApiKey data model
const ApiTokenSchema = new Schema({
  _id: { type: Schema.Types.ObjectId, auto: true },
  // 8-char public lookup id (the {keyId} in fk_{keyId}_{secret})
  keyId: { type: String, required: true, unique: true, index: true },
  accountId: { type: String, required: true, index: true },
  name: { type: String, required: true },
  // SHA-256 hash of the secret only — the secret itself is never stored
  hashedKey: { type: String, required: true, unique: true },
  scopes: {
    type: [{ type: String, enum: [...API_TOKEN_SCOPES] }],
    validate: {
      validator: (v: string[]) => Array.isArray(v) && v.length > 0,
      message: "At least one scope is required",
    },
  },
  status: {
    type: String,
    enum: [...API_TOKEN_STATUSES],
    default: "active",
    index: true,
  },
  // IP whitelisting — single IPs or CIDR ranges
  ipConstraints: { type: [String], default: [] },
  metadata: { type: Schema.Types.Mixed, default: {} },
  usageLogs: { type: [ApiTokenUsageLogSchema], default: [] },
  lastUsedAt: { type: Date, default: null },
  expiresAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
})

// Compound index for efficient per-account active-key lookups
ApiTokenSchema.index({ accountId: 1, status: 1 })

const ApiTokenModel = model("ApiToken", ApiTokenSchema)

// MongoDB Document interface
interface ApiTokenDocument {
  _id: unknown
  keyId: string
  accountId: string
  name: string
  hashedKey: string
  scopes: string[]
  status: string
  ipConstraints: string[]
  metadata: Record<string, unknown>
  usageLogs: ApiTokenUsageLog[]
  lastUsedAt: Date | null
  expiresAt: Date | null
  createdAt: Date
}

// Translation functions
const translateToApiToken = (doc: ApiTokenDocument): IApiToken => {
  return {
    id: toApiTokenId(fromObjectId(doc._id as never)),
    keyId: toApiTokenKeyId(doc.keyId),
    accountId: doc.accountId as AccountId,
    name: doc.name as ApiTokenName,
    hashedKey: toApiTokenHash(doc.hashedKey),
    scopes: doc.scopes as ApiTokenScope[],
    status: doc.status as ApiTokenStatus,
    ipConstraints: doc.ipConstraints ?? [],
    metadata: (doc.metadata ?? {}) as Record<string, unknown>,
    usageLogs: doc.usageLogs ?? [],
    lastUsedAt: doc.lastUsedAt,
    createdAt: doc.createdAt,
    expiresAt: doc.expiresAt,
  }
}

// Repository interface
export interface IApiTokensRepository {
  create(token: NewApiToken): Promise<IApiToken | RepositoryError>
  findByKeyId(keyId: ApiTokenKeyId): Promise<IApiToken | RepositoryError>
  findByAccountId(accountId: AccountId): Promise<IApiToken[] | RepositoryError>
  updateLastUsed(id: ApiTokenId): Promise<void | RepositoryError>
  recordUsage(id: ApiTokenId, entry: ApiTokenUsageLog): Promise<void | RepositoryError>
  revoke(id: ApiTokenId): Promise<IApiToken | RepositoryError>
  revokeAll(accountId: AccountId): Promise<number | RepositoryError>
}

// Repository implementation
export const ApiTokensRepository = (): IApiTokensRepository => {
  return {
    create: async (token: NewApiToken): Promise<IApiToken | RepositoryError> => {
      try {
        const doc = await ApiTokenModel.create({
          keyId: token.keyId,
          accountId: token.accountId,
          name: token.name,
          hashedKey: token.hashedKey,
          scopes: token.scopes,
          ipConstraints: token.ipConstraints ?? [],
          metadata: token.metadata ?? {},
          expiresAt: token.expiresAt,
          status: "active",
        })

        return translateToApiToken(doc as unknown as ApiTokenDocument)
      } catch (err) {
        return new UnknownRepositoryError(err)
      }
    },

    findByKeyId: async (keyId: ApiTokenKeyId): Promise<IApiToken | RepositoryError> => {
      try {
        const doc = await ApiTokenModel.findOne({ keyId, status: "active" })

        if (!doc) {
          return new CouldNotFindError("API token not found")
        }

        return translateToApiToken(doc as unknown as ApiTokenDocument)
      } catch (err) {
        return new UnknownRepositoryError(err)
      }
    },

    findByAccountId: async (
      accountId: AccountId,
    ): Promise<IApiToken[] | RepositoryError> => {
      try {
        const docs = await ApiTokenModel.find({
          accountId,
          status: "active",
        }).sort({ createdAt: -1 })

        return docs.map((d) => translateToApiToken(d as unknown as ApiTokenDocument))
      } catch (err) {
        return new UnknownRepositoryError(err)
      }
    },

    updateLastUsed: async (id: ApiTokenId): Promise<void | RepositoryError> => {
      try {
        await ApiTokenModel.updateOne(
          { _id: toObjectId(id) },
          { $set: { lastUsedAt: new Date() } },
        )
      } catch (err) {
        return new UnknownRepositoryError(err)
      }
    },

    recordUsage: async (
      id: ApiTokenId,
      entry: ApiTokenUsageLog,
    ): Promise<void | RepositoryError> => {
      try {
        await ApiTokenModel.updateOne(
          { _id: toObjectId(id) },
          {
            $set: { lastUsedAt: entry.timestamp ?? new Date() },
            $push: {
              usageLogs: {
                $each: [entry],
                $slice: -API_TOKEN_USAGE_LOG_LIMIT,
              },
            },
          },
        )
      } catch (err) {
        return new UnknownRepositoryError(err)
      }
    },

    revoke: async (id: ApiTokenId): Promise<IApiToken | RepositoryError> => {
      try {
        const doc = await ApiTokenModel.findOneAndUpdate(
          { _id: toObjectId(id) },
          { $set: { status: "revoked" } },
          { new: true },
        )

        if (!doc) {
          return new CouldNotFindError("API token not found")
        }

        return translateToApiToken(doc as unknown as ApiTokenDocument)
      } catch (err) {
        return new UnknownRepositoryError(err)
      }
    },

    revokeAll: async (accountId: AccountId): Promise<number | RepositoryError> => {
      try {
        const result = await ApiTokenModel.updateMany(
          { accountId, status: "active" },
          { $set: { status: "revoked" } },
        )

        return result.modifiedCount
      } catch (err) {
        return new UnknownRepositoryError(err)
      }
    },
  }
}
