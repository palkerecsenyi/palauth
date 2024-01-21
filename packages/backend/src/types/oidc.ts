export interface IDToken {
    iss: string
    // user ID
    sub: string
    // oauth client ID
    aud: string
    exp: number
    iat: number
    "https://auth.palk.me/groups": string[]
    auth_time?: number
    nonce?: string
    revoke_id?: string
}

export type IDTokenCustomClaims = Pick<IDToken, "https://auth.palk.me/groups">

export type OIDCPromptType = "login" | "none"
export type OAuthAuthorizationError = "invalid_request"
    | "unauthorized_client"
    | "access_denied"
    | "unsupported_request_type"
    | "invalid_scope"
    | "server_error"
    | "temporarily_unavailable"

export type OAuthAccessTokenError = "invalid_request"
    | "invalid_client"
    | "invalid_grant"
    | "unauthorized_client"
    | "unsupported_grant_type"
    | "invalid_scope"

export interface OAuthAccessTokenErrorResponse {
    error: OAuthAccessTokenError
    error_description?: string
}

export interface OAuthAccessTokenSuccessResponse {
    access_token: string
    refresh_token?: string
    expires_in: number
    id_token: string
    token_type: "Bearer"
}

export type OAuthAccessTokenResponse = OAuthAccessTokenErrorResponse | OAuthAccessTokenSuccessResponse

export interface OIDCUserInfoResponse {
    sub: string
    name?: string
    given_name?: string
    middle_name?: string
    family_name?: string
    nickname?: string
    profile?: string
    website?: string
    preferred_username?: string
    picture?: string
    email?: string
    email_verified?: boolean
    gender?: "female" | "male" | string
    birthdate?: string
    zoneinfo?: string
    locale?: string
    phone_number?: string
    phone_number_verified?: boolean
    updated_at?: number
}

export class OIDCScopes {
    static OpenID = "openid"
    static Profile = "profile"
    static Email = "email"

    static supportedScopes = [
        this.OpenID,
        this.Profile,
        this.Email,
    ]
}

export class OIDCResponseTypes {
    static Code = "code"
    static IDToken = "id_token"

    static supportedResponseTypes = [
        this.Code,
        this.IDToken,
    ]
}
export type OIDCResponseType = "code" | "id_token"
