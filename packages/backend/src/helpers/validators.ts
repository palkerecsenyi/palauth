import { NextFunction, Request, Response } from "express"
import { matchedData, validationResult } from "express-validator"
import type { ValidatedRequest } from "../types/express.ts"

export const ensureValidators =
    (failureURL: string | ((req: Request) => string)) =>
    (req: ValidatedRequest, res: Response, next: NextFunction) => {
        const result = validationResult(req)

        if (result.isEmpty()) {
            req.validatedData = matchedData(req)
            next()
            return
        }

        const errors = result.array({
            onlyFirstError: true,
        })

        const error = errors[0]
        if (error.type === "field") {
            req.flash("error", `${error.path}: ${error.msg}`)
        } else {
            req.flash("error", "Invalid data")
        }

        if (typeof failureURL === "string") {
            res.redirect(failureURL)
        } else {
            res.redirect(failureURL(req))
        }
    }
