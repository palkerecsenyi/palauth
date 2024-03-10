export const getProjectHostname = () => {
    const h = process.env.PAL_HOSTNAME
    if (!h) throw new Error("PAL_HOSTNAME not specified")
    return h
}

export const getProjectOIDCID = () => {
    const h = process.env.PAL_OIDC_ID
    if (!h) throw new Error("PAL_OIDC_ID not specified")
    return h
}
