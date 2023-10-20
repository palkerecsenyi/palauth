import type {Request} from "express";
import type {OIDCFlow} from "../helpers/oidc/oidc-flow.js";
import type {OAuthTokenWrapper} from "../database/tokens.js";
import type {UserControllerUser} from "../database/users.js";
import type { OAuthClientController } from "../database/oauth.js";
import IAMController from "../database/iam.js";

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

export interface OIDCSecretRequest extends Request {
    oauthClient?: OAuthClientController
}

export interface IAMRequest extends Request {
    iamController?: IAMController
}
