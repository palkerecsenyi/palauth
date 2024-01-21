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
