import type {Request} from "express";
import type {User} from "../database/generated-models";

export interface AuthenticatedRequest extends Request {
    user?: User
}

export interface ValidatedRequest extends Request {
    validatedData?: Record<string, string>
}