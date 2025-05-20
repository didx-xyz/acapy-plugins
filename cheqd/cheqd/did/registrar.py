"""DID Registrar for Cheqd."""

import logging
import asyncio
from asyncio import Lock
from time import time

from aiohttp import ClientSession
from pydantic import BaseModel, ValidationError

from ..did.base import (
    BaseDIDRegistrar,
    DidCreateRequestOptions,
    DidDeactivateRequestOptions,
    DIDRegistrarError,
    DidResponse,
    DidUpdateRequestOptions,
    ResourceCreateRequestOptions,
    ResourceResponse,
    ResourceUpdateRequestOptions,
    SubmitSignatureOptions,
)

LOGGER = logging.getLogger(__name__)


class DIDRegistrar(BaseDIDRegistrar):
    """Universal DID Registrar implementation."""

    DID_REGISTRAR_BASE_URL = "http://localhost:9080/1.0/"

    def __init__(self, method: str, registrar_url: str = None) -> None:
        """Initialize the Cheqd Registrar."""
        super().__init__()
        if registrar_url:
            self.DID_REGISTRAR_BASE_URL = registrar_url
        self.method = method
        self._lock = Lock()
        self._last_request_time = 0

    async def _execute_request(self, endpoint: str, options: BaseModel) -> dict:
        """Execute a request to the DID Registrar."""
        async with self._lock:  # Ensure that only one request is processed at a time
            current_time = time()
            time_since_last_request = current_time - self._last_request_time
            if time_since_last_request < 1:
                LOGGER.debug(
                    "Sleeping for %s seconds before next Cheqd DID Registrar request",
                    1 - time_since_last_request,
                )
                await asyncio.sleep(1 - time_since_last_request)
            self._last_request_time = time()

            async with ClientSession() as session:
                return await self._retry_request(session, endpoint, options)

    async def _retry_request(
        self, session: ClientSession, endpoint: str, options: BaseModel, retries: int = 2
    ) -> dict:
        """Retry logic for executing a request."""
        while retries >= 0:
            try:
                async with session.post(
                    f"{self.DID_REGISTRAR_BASE_URL}{endpoint}?method={self.method}",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    res = await self._parse_response(response, endpoint)
                    if self._should_retry(res):
                        if retries > 0:
                            LOGGER.info("Account sequence mismatch, retrying...")
                            await asyncio.sleep(1)
                            retries -= 1
                            continue
                        else:
                            raise DIDRegistrarError(
                                f"cheqd: did-registrar: {endpoint}: "
                                "Account sequence mismatch after retries."
                            )
                    return res
            except (ValidationError, AttributeError):
                raise DIDRegistrarError(
                    f"cheqd: did-registrar: {endpoint}: Response Format is invalid"
                )
            except Exception:
                raise

    async def _parse_response(self, response, endpoint: str) -> dict:
        """Parse the response from the DID Registrar."""
        try:
            res = await response.json()
        except Exception:
            raise DIDRegistrarError(
                f"cheqd: did-registrar: {endpoint}: Unable to parse JSON"
            )
        if not res:
            raise DIDRegistrarError(
                f"cheqd: did-registrar: {endpoint}: Response is None."
            )
        return res

    def _should_retry(self, res: dict) -> bool:
        """Determine if the request should be retried based on the response."""
        return "description" in res and "account sequence mismatch" in res["description"]

    async def create(
        self, options: DidCreateRequestOptions | SubmitSignatureOptions
    ) -> DidResponse:
        """Create a DID Document."""
        LOGGER.debug("Creating DID document %s", options)
        res = await self._execute_request("create", options)
        return DidResponse(**res)

    async def update(
        self, options: DidUpdateRequestOptions | SubmitSignatureOptions
    ) -> DidResponse:
        """Update a DID Document."""
        LOGGER.debug("Updating DID document %s", options)
        res = await self._execute_request("update", options)
        return DidResponse(**res)

    async def deactivate(
        self, options: DidDeactivateRequestOptions | SubmitSignatureOptions
    ) -> DidResponse:
        """Deactivate a DID Document."""
        LOGGER.debug("Deactivating DID %s", options)
        res = await self._execute_request("deactivate", options)
        return DidResponse(**res)

    async def create_resource(
        self, options: ResourceCreateRequestOptions | SubmitSignatureOptions
    ) -> ResourceResponse:
        """Create a DID Linked Resource."""
        LOGGER.debug("Creating resource %s", options)
        res = await self._execute_request("createResource", options)
        LOGGER.debug("Create Resource Response: %s", res)
        return ResourceResponse(**res)

    async def update_resource(
        self, options: ResourceUpdateRequestOptions | SubmitSignatureOptions
    ) -> ResourceResponse:
        """Update a DID Linked Resource."""
        LOGGER.debug("Updating resource %s", options)
        res = await self._execute_request("updateResource", options)
        return ResourceResponse(**res)

    async def deactivate_resource(self, options: dict) -> dict:
        """Deactivate a DID Linked Resource."""
        raise NotImplementedError("This method will not be implemented for did:cheqd.")
