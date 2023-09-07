import {PrismaClient} from "../database/generated-models";
import {ITXClientDenyList} from "../database/generated-models/runtime/library";

export type TransactionType = Omit<PrismaClient, ITXClientDenyList>