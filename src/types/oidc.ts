export interface IDToken {
    iss: string
    sub: string
    aud: string
    exp: number
    iat: number
    auth_time?: number
    nonce?: string
}

export type OIDCResponseType = "code"
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