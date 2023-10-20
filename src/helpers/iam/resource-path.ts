import { NextFunction, Request, Response } from "express";
import { IAMPathRequest } from "../../types/express.js";

export const parseResourcePath = (req: Request, res: Response) => {
    const resourcePathString = req.params[0] as string
    if (!resourcePathString) {
        res.status(400).send("Couldn't parse resource path")
        return false
    }

    const resourcePath = resourcePathString.split("/")
    if (resourcePath.length < 2) {
        res.status(400).send("Not enough components in resource path")
        return false
    }

    const resourceId = resourcePath[resourcePath.length - 1]
    const scopePath = "/" + resourcePath.slice(0, -1).join("/")
    return {resourceId, scopePath}
}

export const parseResourcePathMiddleware = (
    req: IAMPathRequest, 
    res: Response, 
    next: NextFunction
) => {
    const p = parseResourcePath(req, res)
    if (!p) return

    req.parsedPath = {
        scopePath: p.scopePath,
        resourceId: p.resourceId,
    }
    next()
}
