import { Request } from "express"

export const valueFromQueryOrBody = (req: Request, key: string) => {
    let val: unknown
    if (req.method === "POST") {
        val = req.body[key]
    } else {
        val = req.query[key]
    }

    if (typeof val !== "string") {
        return undefined
    }

    return val
}
