export const getSecretKeys = () => {
    const secrets = process.env["PAL_SECRETS"]
    if (!secrets) {
        throw new Error("PAL_SECRETS not defined")
    }

    const parsedSecrets = JSON.parse(secrets)
    if (!(parsedSecrets instanceof Array)) {
        throw new Error("PAL_SECRETS was not an array")
    }
    if (parsedSecrets.length === 0) {
        throw new Error("PAL_SECRETS was empty")
    }
    return parsedSecrets as string[]
}