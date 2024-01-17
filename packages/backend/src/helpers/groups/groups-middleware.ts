import type { NextFunction, Response } from "express";
import { AuthenticatedRequest, GroupRequest, GroupsManagementRequest } from "../../types/express.js";
import GroupsController from "../../database/groups.js";

export default function groupsManagementMiddleware(req: AuthenticatedRequest & GroupsManagementRequest, res: Response, next: NextFunction) {
    if (!req.user!.canManageGroups) {
        req.flash("error", "You are not allowed to manage groups.")
        res.redirect("/")
        return
    }

    req.groupsController = GroupsController.forUser(req.user!.id)
    next()
}

export async function getGroupMiddleware(req: GroupsManagementRequest & GroupRequest, res: Response, next: NextFunction) {
    const group = await req.groupsController!.getGroupForRequest(req)
    if (group === null) {
        req.flash("error", "Group not found")
        res.redirect("/groups")
        return
    }

    req.group = group
    next()
}
