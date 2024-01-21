import { OIDCScopes } from "../../types/oidc.js";
import { getProjectOIDCID } from "../constants/hostname.js";

export const getOIDCDiscoveryData = () => {
    const oidcUrl = getProjectOIDCID()
    // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    return {
        issuer: oidcUrl,
        authorization_endpoint: new URL("/oidc/auth", oidcUrl),
        token_endpoint: new URL("/oidc/token", oidcUrl),
        userinfo_endpoint: new URL("/oidc/userinfo", oidcUrl),
        end_session_endpoint: new URL("/oidc/logout", oidcUrl),
        jwks_uri: new URL("/.well-known/jwks.json", oidcUrl),
        scopes_supported: OIDCScopes.supportedScopes,
        response_types_supported: ["code", "id_token"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
    }
}
