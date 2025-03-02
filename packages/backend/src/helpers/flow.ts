import type { NextFunction, Request, Response } from "express"
import { getProjectHostname } from "./constants/hostname.js"

export class FlowManager {
    private readonly flowName: string
    constructor(flowName: string) {
        this.flowName = flowName
    }

    static parseDestination(req: Request) {
        const destination = req.query.destination
        if (typeof destination !== "string") {
            throw new Error("destination missing")
        }

        const hostname = req.hostname
        if (hostname !== getProjectHostname()) {
            throw new Error("incorrect hostname in request")
        }

        const parsedDestination = new URL(
            destination,
            `${req.protocol}://${hostname}`,
        )
        if (parsedDestination.hostname !== hostname) {
            throw new Error("destination must be on the same hostname")
        }

        return parsedDestination.toString()
    }

    saveDestination(req: Request) {
        const existingDestination = this.extractDestinationFromSession(req)
        if (existingDestination && !Object.hasOwn(req.query, "destination"))
            return existingDestination

        const destination = FlowManager.parseDestination(req)
        req.session.flow = {
            ...req.session.flow,
            [this.flowName]: destination,
        }
        return destination
    }

    saveDestinationMiddleware(req: Request, res: Response, next: NextFunction) {
        try {
            this.saveDestination(req)
        } catch (e) {
            res.status(400)
            if (e instanceof Error) {
                res.send(e.message)
            } else {
                console.error(e)
                res.send("Something went wrong")
            }
            return
        }

        next()
    }

    private extractDestinationFromSession(req: Request) {
        const destination = req.session.flow?.[this.flowName]
        if (typeof destination !== "string") {
            return undefined
        }
        return destination as string
    }

    ensureCanContinue(failureURL: string) {
        return (req: Request, res: Response, next: NextFunction) => {
            const destination = this.extractDestinationFromSession(req)
            if (!destination) {
                req.flash("error", "Could not find destination in session")
                res.redirect(failureURL)
            } else {
                next()
            }
        }
    }

    continueToDestination(req: Request, res: Response, failureURL: string) {
        const destination = this.extractDestinationFromSession(req)
        if (!destination) {
            req.flash("error", "Could not find destination in session")
            res.redirect(failureURL)
            return
        }

        delete req.session.flow?.[this.flowName]
        res.redirect(destination)
    }
}
