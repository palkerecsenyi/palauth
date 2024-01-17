import { TransactionType } from "../types/prisma.js";
import { DBClient } from "./client.js";
import { Prisma } from "./generated-models/index.js";

export type IAMControllerRoleType = Prisma.IAMRoleGetPayload<{
    include: {permissions: true}
}>

export default class IAMController {
    private clientId: string
    private roles: IAMControllerRoleType[]
    private tx: TransactionType
    private constructor(clientId: string, roles: IAMControllerRoleType[], tx: TransactionType) {
        this.clientId = clientId
        this.roles = roles
        this.tx = tx
    }

    static async forOAuthClient(clientId: string, tx: TransactionType = DBClient.getClient()) {
        const scopes = await tx.iAMRole.findMany({
            where: {
                ownerId: clientId,
            },
            include: {
                permissions: true,
            }
        })
        return new IAMController(clientId, scopes, tx)
    }

    listPermissions() {
        return this.tx.iAMPermission.findMany({
            where: {
                ownerId: this.clientId,
            },
        })
    }

    private findRoleByName(roleName: string) {
        return this.roles.find(r => r.name === roleName)
    }

    listRoles() {
        return this.roles
    }

    getRoleById(id: string) {
        return this.roles.find(r => r.id === id)
    }

    listRolesForUser(userId: string) {
        return this.tx.iAMRole.findMany({
            where: {
                assignments: {
                    every: {
                        userId,
                    }
                }
            },
            include: {
                permissions: true,
            }
        })
    }

    listAllUsersWithRoles() {
        return this.tx.user.findMany({
            where: {
                iamRoles: {
                    some: {
                        role: {
                            ownerId: this.clientId,
                        }
                    }
                }
            },
            include: {
                iamRoles: {
                    include: {
                        role: true,
                    },
                    where: {
                        role: {
                            ownerId: this.clientId,
                        }
                    }
                },
            }
        })
    }

    async checkPermission(request: {
        userId: string,
        permissionName: string,
    }) {
        const role = await this.tx.iAMRole.findFirst({
            where: {
                permissions: {
                    some: {
                        name: request.permissionName,
                        ownerId: this.clientId,
                    }
                },
                assignments: {
                    some: {
                        userId: request.userId,
                    }
                },
                ownerId: this.clientId,
            }
        })

        return role !== null
    }

    async createPermission(name: string) {
        const permission = await this.tx.iAMPermission.create({
            data: {
                name,
                ownerId: this.clientId,
            },
        })
        return permission.id
    }

    async createRole(name: string) {
        const role = await this.tx.iAMRole.create({
            data: {
                name,
                ownerId: this.clientId,
            },
        })
        return role.id
    }

    async assignPermissionToRole(permissionId: string, roleId: string) {
        await this.tx.iAMRole.update({
            where: {
                id: roleId,
                ownerId: this.clientId,
            },
            data: {
                permissions: {
                    connect: {
                        id: permissionId,
                    },
                },
            },
        })
    }

    async unassignPermissionFromRole(permissionId: string, roleId: string) {
        await this.tx.iAMRole.update({
            where: {
                id: roleId,
                ownerId: this.clientId,
            },
            data: {
                permissions: {
                    disconnect: {
                        id: permissionId,
                    },
                },
            },
        })
    }

    private resolveRoleByNameOrId(d: {
        roleName?: string,
        roleId?: string,
    }) {
        const { roleName } = d
        let { roleId } = d
        if (!roleId) {
            if (!roleName) {
                throw new Error("No roleId or roleName provided")
            }

            const role = this.findRoleByName(roleName)
            if (!role) {
                throw new Error("Role not found")
            }
            roleId = role.id
        }
        return roleId
    }

    async assignRole(request: {
        userId: string,
        roleName?: string,
        roleId?: string,
    }) {
        const roleId = this.resolveRoleByNameOrId(request)
        await this.tx.iAMRoleAssignment.upsert({
            where: {
                userId_roleId: {
                    userId: request.userId,
                    roleId: roleId,
                }
            },
            update: {},
            create: {
                userId: request.userId,
                roleId: roleId,
            }
        })
    }

    async removeRole(request: {
        userId: string,
        roleName?: string,
        roleId?: string,
    }) {
        const roleId = this.resolveRoleByNameOrId(request)
        await this.tx.iAMRoleAssignment.delete({
            where: {
                userId_roleId: {
                    userId: request.userId, 
                    roleId: roleId,
                }
            }
        })
    }
}
