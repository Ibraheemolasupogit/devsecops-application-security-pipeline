"""Deny-by-default role and permission model."""

from enum import StrEnum

from genomic_research_access_api.domain.enums import ActorRole
from genomic_research_access_api.security.authentication.principal import AuthenticatedPrincipal


class Permission(StrEnum):
    DATASET_LIST = "dataset:list"
    DATASET_READ = "dataset:read"
    DATASET_READ_RESTRICTED = "dataset:read_restricted"
    ACCESS_REQUEST_CREATE = "access_request:create"
    ACCESS_REQUEST_LIST_OWN = "access_request:list_own"
    ACCESS_REQUEST_READ_OWN = "access_request:read_own"
    ACCESS_REQUEST_LIST_ALL = "access_request:list_all"
    ACCESS_REQUEST_READ_ALL = "access_request:read_all"
    ACCESS_REQUEST_APPROVE = "access_request:approve"
    ACCESS_REQUEST_REJECT = "access_request:reject"
    AUDIT_EVENT_READ = "audit_event:read"
    ADMINISTRATION_MANAGE = "administration:manage"


ROLE_PERMISSIONS: dict[ActorRole, frozenset[Permission]] = {
    ActorRole.RESEARCHER: frozenset(
        {
            Permission.DATASET_LIST,
            Permission.DATASET_READ,
            Permission.ACCESS_REQUEST_CREATE,
            Permission.ACCESS_REQUEST_LIST_OWN,
            Permission.ACCESS_REQUEST_READ_OWN,
        }
    ),
    ActorRole.APPROVER: frozenset(
        {
            Permission.DATASET_LIST,
            Permission.DATASET_READ,
            Permission.ACCESS_REQUEST_LIST_ALL,
            Permission.ACCESS_REQUEST_READ_ALL,
            Permission.ACCESS_REQUEST_APPROVE,
            Permission.ACCESS_REQUEST_REJECT,
        }
    ),
    ActorRole.DATA_CUSTODIAN: frozenset(
        {
            Permission.DATASET_LIST,
            Permission.DATASET_READ,
            Permission.DATASET_READ_RESTRICTED,
            Permission.ACCESS_REQUEST_LIST_ALL,
            Permission.ACCESS_REQUEST_READ_ALL,
            Permission.ACCESS_REQUEST_APPROVE,
            Permission.ACCESS_REQUEST_REJECT,
        }
    ),
    ActorRole.SECURITY_AUDITOR: frozenset(
        {
            Permission.ACCESS_REQUEST_LIST_ALL,
            Permission.ACCESS_REQUEST_READ_ALL,
            Permission.AUDIT_EVENT_READ,
        }
    ),
    ActorRole.APPLICATION_ADMIN: frozenset(
        {
            Permission.DATASET_LIST,
            Permission.DATASET_READ,
            Permission.DATASET_READ_RESTRICTED,
            Permission.ACCESS_REQUEST_CREATE,
            Permission.ACCESS_REQUEST_LIST_OWN,
            Permission.ACCESS_REQUEST_READ_OWN,
            Permission.ACCESS_REQUEST_LIST_ALL,
            Permission.ACCESS_REQUEST_READ_ALL,
            Permission.ACCESS_REQUEST_APPROVE,
            Permission.ACCESS_REQUEST_REJECT,
            Permission.AUDIT_EVENT_READ,
            Permission.ADMINISTRATION_MANAGE,
        }
    ),
}


def permissions_for(principal: AuthenticatedPrincipal) -> frozenset[Permission]:
    permissions: set[Permission] = set()
    for role in principal.roles:
        permissions.update(ROLE_PERMISSIONS.get(role, frozenset()))
    return frozenset(permissions)


def has_permission(principal: AuthenticatedPrincipal, permission: Permission) -> bool:
    return permission in permissions_for(principal)
