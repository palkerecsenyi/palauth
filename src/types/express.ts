import type {Request} from "express";
import type {User} from "../database/generated-models/index.js";
import {OIDCFlow} from "../helpers/oidc/oidc-flow.js";
import {OAuthTokenWrapper} from "../database/tokens.js";

export interface AuthenticatedRequest extends Request {
    user?: User
}

export interface ValidatedRequest extends Request {
    validatedData?: Record<string, string>
}

export interface OIDCFlowRequest extends Request {
    oidcFlow?: OIDCFlow
}

export interface BearerTokenRequest extends Request {
    tokenWrapper?: OAuthTokenWrapper
}