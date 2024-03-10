import {
    browserSupportsWebAuthn,
    startAuthentication,
} from "@simplewebauthn/browser"
import {
    AuthenticationResponseJSON,
    PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/typescript-types"
import wretch from "wretch"

export const authenticate = (
    options: PublicKeyCredentialRequestOptionsJSON,
    autocomplete?: boolean,
    passkey = autocomplete,
) => {
    return async () => {
        if (autocomplete) {
            let isSupported = false
            // The function _might_ not be defined in older browsers
            // @ts-expect-error
            if (window.PublicKeyCredential?.isConditionalMediationAvailable) {
                isSupported =
                    await PublicKeyCredential.isConditionalMediationAvailable()
            }

            if (!isSupported) {
                console.log("Browser doesn't support PKC CMA")
                return
            }

            console.log("Browser supports PKC CMA")
        }

        if (!browserSupportsWebAuthn()) {
            if (autocomplete) return
            alert("Your browser doesn't support this feature")
            return
        }

        let credential: AuthenticationResponseJSON
        try {
            credential = await startAuthentication(options, autocomplete)
        } catch (e) {
            console.error(e)
            if (!autocomplete) {
                alert("Process cancelled — please try again")
            }
            return
        }

        if (!credential) return

        let url: string
        if (passkey) {
            url = "/auth/signin/key"
        } else {
            url = "/auth/signin/2fa/SecurityKey"
        }

        try {
            await wretch().json(credential).url(url).post().res()
        } catch (e) {
            alert("Something went wrong. Please try a different key.")
            return
        }

        window.location.replace("/auth/continue")
    }
}
