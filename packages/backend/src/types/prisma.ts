import { PrismaClient } from "../database/generated-models/index.js"
import { ITXClientDenyList } from "../database/generated-models/runtime/library.js"

export type TransactionType = Omit<PrismaClient, ITXClientDenyList>
