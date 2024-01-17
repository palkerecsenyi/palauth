export class OIDCScopes {
    static OpenID = "openid"
    static Profile = "profile"
    static Email = "email"
    static API = "api"

    static supportedScopes = [
        this.OpenID,
        this.Profile,
        this.Email,
        this.API,
    ]
}
