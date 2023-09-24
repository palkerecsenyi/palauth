import {parseCreationOptionsFromJSON, create} from "@github/webauthn-json/browser-ponyfill"

const enroll = (options: any) => {
    const parsedOptions = parseCreationOptionsFromJSON({
        publicKey: options,
    })

    return async () => {
        const credential = await create(parsedOptions)

        if (!credential) {
            throw new Error("no credential")
        }

        if (credential.type !== "public-key") {
            throw new Error("not public-key")
        }

        await fetch("/account/2fa/enroll?type=key", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(credential),
        })
    }
}


// @ts-ignore
window["PAL_2FA_ENROLL"] = enroll