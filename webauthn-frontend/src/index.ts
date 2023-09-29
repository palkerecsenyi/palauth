import {parseCreationOptionsFromJSON, create, get, parseRequestOptionsFromJSON} from "@github/webauthn-json/browser-ponyfill"

const enroll = (options: any) => {
    const parsedOptions = parseCreationOptionsFromJSON({
        publicKey: options,
    })
    console.log(parsedOptions)

    return async () => {
        const credential = await create(parsedOptions)

        if (!credential) {
            alert("Process cancelled - please try again")
            return
        }

        if (credential.type !== "public-key") {
            alert("Something went wrong. Please try again.")
            return
        }

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

const authenticate = (options: any) => {
    const parsedOptions = parseRequestOptionsFromJSON({
        publicKey: options,
    })

    return async () => {
        const credential = await get(parsedOptions)
        if (!credential) {
            alert("Process cancelled — please reload to try again")
            return
        }

        if (credential.type !== "public-key") {
            alert("Something went wrong — please reload to try again")
            return
        }

        try {
            const resp = await fetch("/auth/signin/2fa/SecurityKey", {
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

        document.getElementById("status")!.innerText = "Success! Redirecting..."
        window.location.replace("/auth/continue")
    }
}


// @ts-ignore
window["PAL_2FA_ENROLL"] = enroll
// @ts-ignore
window["PAL_2FA_AUTHENTICATE"] = authenticate
