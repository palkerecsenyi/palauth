import {getProjectOIDCID} from "../hostname.js";
import {OIDCScopes} from "./scopes.js";

export const getOIDCDiscoveryData = () => {
    const oidcUrl = getProjectOIDCID()
    // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    return {
        issuer: oidcUrl,
        authorization_endpoint: new URL("/oidc/auth", oidcUrl),
        token_endpoint: new URL("/oidc/token", oidcUrl),
        userinfo_endpoint: new URL("/oidc/userinfo", oidcUrl),
        jwks_uri: new URL("/oidc/jwks", oidcUrl),
        scopes_supported: OIDCScopes.supportedScopes,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
    }
}