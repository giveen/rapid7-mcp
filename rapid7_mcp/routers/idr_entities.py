"""InsightIDR entity context router — accounts, users, and assets."""

import logging

from fastapi import APIRouter, Depends, HTTPException

from rapid7_mcp.client import InsightIDRClient, get_idr_client
from rapid7_mcp.models import (
    IdrAccount,
    IdrAccountList,
    IdrAsset,
    IdrAssetList,
    IdrEntitySearchRequest,
    IdrUser,
    IdrUserList,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/accounts/_search",
    response_model=IdrAccountList,
    operation_id="search_idr_accounts",
    summary="Search InsightIDR accounts",
    description=(
        "Search for domain-joined accounts (Active Directory, Okta, etc.) in InsightIDR. "
        "Use this to look up an account by username, domain, or UPN — for example to "
        "verify whether an account signing in from an unusual location is a known "
        "privileged/service account or a contractor. "
        "Search criteria: field (name, domain, accountType), operator EQUALS|CONTAINS|IN, value."
    ),
)
async def search_idr_accounts(
    body: IdrEntitySearchRequest,
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrAccountList:
    try:
        data = await client.post(
            "/idr/v1/accounts/_search",
            body=body.model_dump(exclude_none=True),
            timeout=10.0,
        )
    except HTTPException as exc:
        if exc.status_code in (404, 501, 504):
            raise HTTPException(
                status_code=501,
                detail="InsightIDR accounts API is not available on this tenant.",
            ) from exc
        raise
    return IdrAccountList(**data)


@router.get(
    "/accounts/{account_rrn}",
    response_model=IdrAccount,
    operation_id="get_idr_account",
    summary="Get an InsightIDR account by RRN",
    description=(
        "Returns full detail for a single domain-joined account including account type, "
        "privileged status, lock/disabled state, and last authentication time. "
        "Use search_idr_accounts to find the account RRN first. "
        "This is the key tool to determine whether a sign-in anomaly involves a "
        "privileged account, service account, or contractor."
    ),
)
async def get_idr_account(
    account_rrn: str,
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrAccount:
    if not account_rrn.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full account RRN from search_idr_accounts.",
        )
    try:
        data = await client.get(f"/idr/v1/accounts/{account_rrn}", timeout=10.0)
    except HTTPException as exc:
        if exc.status_code in (404, 501, 504):
            raise HTTPException(
                status_code=501,
                detail="InsightIDR accounts API is not available on this tenant.",
            ) from exc
        raise
    return IdrAccount(**data)


@router.post(
    "/users/_search",
    response_model=IdrUserList,
    operation_id="search_idr_users",
    summary="Search InsightIDR users",
    description=(
        "Search for users tracked in InsightIDR by name, email, or UID. "
        "Returns user risk score, risk priority, and last-seen timestamp. "
        "Use this during investigation triage to check whether a user involved "
        "in an alert has a high risk score or is a repeat offender. "
        "Search criteria: field (name, email, riskPriority), operator EQUALS|CONTAINS|IN, value."
    ),
)
async def search_idr_users(
    body: IdrEntitySearchRequest,
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrUserList:
    try:
        data = await client.post(
            "/idr/v1/users/_search",
            body=body.model_dump(exclude_none=True),
        )
    except HTTPException as exc:
        if exc.status_code == 404:
            raise HTTPException(
                status_code=501,
                detail="InsightIDR users API is not available on this tenant.",
            ) from exc
        raise
    return IdrUserList(**data)


@router.get(
    "/users/{user_rrn}",
    response_model=IdrUser,
    operation_id="get_idr_user",
    summary="Get an InsightIDR user by RRN",
    description=(
        "Returns full detail for a single InsightIDR user including display name, email, "
        "risk score (0–1000), risk priority, and last-seen timestamp. "
        "Use search_idr_users to find the user RRN first. "
        "A high risk score indicates prior suspicious activity that warrants extra scrutiny."
    ),
)
async def get_idr_user(
    user_rrn: str,
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrUser:
    if not user_rrn.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full user RRN from search_idr_users.",
        )
    try:
        data = await client.get(f"/idr/v1/users/{user_rrn}")
    except HTTPException as exc:
        if exc.status_code == 404:
            raise HTTPException(
                status_code=501,
                detail="InsightIDR users API is not available on this tenant.",
            ) from exc
        raise
    return IdrUser(**data)


@router.post(
    "/assets/_search",
    response_model=IdrAssetList,
    operation_id="search_idr_assets",
    summary="Search InsightIDR assets",
    description=(
        "Search for assets tracked in InsightIDR (hostname, IP). "
        "Returns asset name and RRN. Use this to look up whether a host involved "
        "in an investigation is a known managed asset, and then use get_idr_asset "
        "to get its full detail. "
        "Search criteria: field (name), operator EQUALS|CONTAINS|IN, value. "
        "Pass size to control page size (default 20, max 500)."
    ),
)
async def search_idr_assets(
    body: IdrEntitySearchRequest,
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrAssetList:
    data = await client.post(
        "/idr/v1/assets/_search",
        body=body.model_dump(exclude_none=True),
    )
    return IdrAssetList(**data)


@router.get(
    "/assets/{asset_rrn}",
    response_model=IdrAsset,
    operation_id="get_idr_asset",
    summary="Get an InsightIDR asset by RRN",
    description=(
        "Returns details for a single InsightIDR asset by its RRN. "
        "Use search_idr_assets to find the asset RRN first."
    ),
)
async def get_idr_asset(
    asset_rrn: str,
    client: InsightIDRClient = Depends(get_idr_client),
) -> IdrAsset:
    if not asset_rrn.startswith("rrn:"):
        raise HTTPException(
            status_code=400,
            detail="Use the full asset RRN from search_idr_assets.",
        )
    data = await client.get(f"/idr/v1/assets/{asset_rrn}")
    return IdrAsset(**data)
