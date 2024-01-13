import { browserSupportsWebAuthn, startAuthentication, startRegistration } from "@simplewebauthn/browser"
import { Buffer } from "buffer"

const enroll = (options: any, formElementID: string, buttonID: string, errorID: string) => {
    console.log(options)
    const formElement = document.getElementById(formElementID) as HTMLInputElement
    if (!formElement) throw new Error(`Couldn't find element ${formElementID}`)
    const buttonElement = document.getElementById(buttonID) as HTMLButtonElement
    if (!buttonElement) throw new Error(`Couldn't find element ${buttonID}`)
    const errorElement = document.getElementById(errorID) as HTMLParagraphElement
    if (!errorElement) throw new Error(`Couldn't find element ${errorID}`)

    return async () => {
        errorElement.innerText = ""
        buttonElement.innerText = "Loading..."
        buttonElement.disabled = true

        let credential: any
        try {
            credential = await startRegistration(options)
        } catch (e) {
            console.error(e)
            alert("Process cancelled - please try again")
            buttonElement.innerText = "Click to enroll"
            buttonElement.disabled = false
            errorElement.innerText = e + ''
            return
        }

        if (!credential) return
        formElement.setAttribute(
            "value",
            Buffer.from(
                JSON.stringify(credential)
            ).toString("base64")
        )
        buttonElement.innerText = "Success!"
    }
}

const authenticate = (options: any, autocomplete?: boolean, passkey = autocomplete) => {
    console.log(options)
    return async () => {
        if (autocomplete) {
            let isSupported = false
            // The function _might_ not be defined in older browsers
            // @ts-ignore
            if (window.PublicKeyCredential?.isConditionalMediationAvailable) {
                isSupported = await PublicKeyCredential.isConditionalMediationAvailable()
            }

            if (!isSupported) {
                console.log("Browser doesn't support PKC CMA")
                return
            } else {
                console.log("Browser supports PKC CMA")
            }
        }

        if (!browserSupportsWebAuthn()) {
            if (autocomplete) return
            alert("Your browser doesn't support this feature")
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
