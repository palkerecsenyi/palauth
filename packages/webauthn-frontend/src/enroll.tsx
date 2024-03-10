import { startRegistration } from "@simplewebauthn/browser"
import {
    PublicKeyCredentialCreationOptionsJSON,
    RegistrationResponseJSON,
} from "@simplewebauthn/typescript-types"
import { Buffer } from "buffer"
import { render, JSX } from "preact"
import { useCallback, useState } from "preact/hooks"

const RenderButton = ({
    options,
}: {
    options: PublicKeyCredentialCreationOptionsJSON
}) => {
    const [loading, setLoading] = useState(false)
    const [credentialValue, setCredentialValue] = useState<string>()

    const onEnrollClick = useCallback(
        async (e: JSX.TargetedEvent<HTMLButtonElement, Event>) => {
            e.preventDefault()
            setLoading(true)
            setCredentialValue(undefined)

            let credential: RegistrationResponseJSON
            try {
                credential = await startRegistration(options)
            } catch (e) {
                console.error(e)
                alert("Process cancelled - please try again")
                setLoading(false)
                return
            }

            if (!credential) return
            setCredentialValue(
                Buffer.from(JSON.stringify(credential)).toString("base64"),
            )
            setLoading(false)
        },
        [],
    )

    return (
        <>
            <button
                type="button"
                className="button"
                disabled={loading || credentialValue !== undefined}
                onClick={onEnrollClick}
            >
                {loading
                    ? "Loading..."
                    : credentialValue !== undefined
                      ? "Success!"
                      : "Click to enroll"}
            </button>
            <input type="hidden" name="key" value={credentialValue} required />
        </>
    )
}

export const enroll = (
    options: PublicKeyCredentialCreationOptionsJSON,
    containerID: string,
) => {
    const containerElement = document.getElementById(
        containerID,
    ) as HTMLDivElement
    render(<RenderButton options={options} />, containerElement)
}
