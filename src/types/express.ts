import type {Request} from "express";
import {OIDCFlow} from "../helpers/oidc/oidc-flow.js";
import {OAuthTokenWrapper} from "../database/tokens.js";
import {UserControllerUser} from "../database/users.js";

export interface AuthenticatedRequest extends Request {
    user?: UserControllerUser
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