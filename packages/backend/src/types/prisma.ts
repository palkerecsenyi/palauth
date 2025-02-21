import type { PrismaClient } from "../database/generated-models/index.js"
import type { ITXClientDenyList } from "../database/generated-models/runtime/library.js"

export type TransactionType = Omit<PrismaClient, ITXClientDenyList>
