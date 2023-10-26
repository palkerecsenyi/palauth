import { browserSupportsWebAuthn, browserSupportsWebAuthnAutofill, startAuthentication, startRegistration } from "@simplewebauthn/browser"

const enroll = (options: any) => {
    console.log(options)
    return async () => {
        let credential: any
        try {
            credential = await startRegistration(options)
        } catch (e) {
            alert("Process cancelled - please try again")
            return
        }

        if (!credential) return

        try {
            const resp = await fetch("/account/2fa/enroll?type=key", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(credential),
            })

            if (resp.status === 409) {
                alert("You have already enrolled a security key. Please delete the old one first.")
                return
            }

            if (resp.status !== 204) {
                throw new Error()
            }
        } catch (e) {
            alert("Something went wrong. Please try a different key.")
            return
        }

        alert("Successfully enrolled your security key!")
        window.location.href = "/account/2fa"
    }
}

const authenticate = (options: any, autocomplete?: boolean, passkey = autocomplete) => {
    console.log(options)
    return async () => {
        if (autocomplete) {
            if (browserSupportsWebAuthnAutofill()) {
                console.log("Browser supports webauthn autofill")
            } else {
                console.log("Browser doesn't support webauthn autofill")
                return
            }
        }

        if (!browserSupportsWebAuthn()) {
            alert("Your browser doesn't support this feature.")
            return
        }

        let credential: any
        try {
            credential = await startAuthentication(options, autocomplete)
        } catch (e) {
            console.error(e)
            if (!autocomplete) {
                alert("Process cancelled — please reload to try again")
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
            const resp = await fetch(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(credential),
            })

            if (resp.status !== 204) {
                throw new Error()
            }
        } catch (e) {
            alert("Something went wrong. Please try a different key.")
            return
        }

        window.location.replace("/auth/continue")
    }
}


// @ts-ignore
window["PAL_2FA_ENROLL"] = enroll
// @ts-ignore
window["PAL_2FA_AUTHENTICATE"] = authenticate
