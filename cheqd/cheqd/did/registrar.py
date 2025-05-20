"""DID Registrar for Cheqd."""

import logging
import asyncio
from time import time

from aiohttp import ClientResponse, ClientSession
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
        self._lock = asyncio.Lock()
        self._pending_jobs: dict[str, float] = {}
        self._timeout = 1  # max seconds to wait for SubmitSignatureOptions after initial

    async def _execute_request(self, endpoint: str, options: BaseModel) -> dict:
        """Execute a request to the DID Registrar."""
        if not isinstance(options, SubmitSignatureOptions):
            # Process initial request and block other requests until follow-up SubmitSignatureOptions is received.
            async with self._lock, ClientSession() as session:
                LOGGER.debug("Lock acquired for %s request", endpoint)
                await asyncio.sleep(1)
                response = await self._process_initial_request(session, endpoint, options)
                job_id = response.get("jobId")
                if job_id:
                    LOGGER.debug("Adding jobId to pending jobs: %s", job_id)
                    self._pending_jobs[job_id] = time()
                else:
                    LOGGER.warning(
                        "No jobId returned from initial %s request. Response: %s",
                        endpoint,
                        response,
                    )

        else:
            LOGGER.debug("Submitting SignatureOptions for %s request", endpoint)
            async with ClientSession() as session:
                response = await self._submit_request(session, endpoint, options)
            job_id = options.jobId
            if job_id in self._pending_jobs:
                LOGGER.debug("Removing jobId from pending jobs: %s", job_id)
                del self._pending_jobs[job_id]
            else:
                LOGGER.warning("JobId done but not found in pending jobs: %s", job_id)

        return response

    async def _process_initial_request(
        self, session: ClientSession, endpoint: str, options: BaseModel
    ) -> dict:
        """Process the initial request and block other requests until SubmitSignatureOptions is received."""
        while self._pending_jobs:
            current_time = time()
            for job_id, start_time in list(self._pending_jobs.items()):
                if current_time - start_time > self._timeout:
                    LOGGER.info(
                        "Timeout waiting for %s other pending jobs to complete first...",
                        job_id,
                    )
                    del self._pending_jobs[job_id]
                else:
                    LOGGER.debug("Waiting for %s job id to complete first...", job_id)
            if self._pending_jobs:
                LOGGER.debug("Waiting for other pending jobs to complete first...")
                await asyncio.sleep(self._timeout / 5)

        return await self._submit_request(session, endpoint, options)

    async def _submit_request(
        self, session: ClientSession, endpoint: str, options: BaseModel
    ) -> dict:
        """Execute a request."""
        try:
            LOGGER.debug("Submitting %s request", endpoint)
            response = await session.post(
                f"{self.DID_REGISTRAR_BASE_URL}{endpoint}?method={self.method}",
                json=options.model_dump(exclude_none=True),
            )
            return await self._parse_response(response, endpoint)
        except (ValidationError, AttributeError):
            raise DIDRegistrarError(
                f"cheqd: did-registrar: {endpoint}: Response Format is invalid"
            )
        except Exception as ex:
            LOGGER.error("Error executing %s request: %s", endpoint, ex)
            raise

    async def _parse_response(self, response: ClientResponse, endpoint: str) -> dict:
        """Parse the response from the DID Registrar."""
        LOGGER.debug("Parsing response from %s request", endpoint)
        try:
            res = await response.json()
        except Exception:
            raise DIDRegistrarError(
                f"cheqd: did-registrar: {endpoint}: Unable to parse JSON"
            )
        finally:
            await response.release()
        if not res:
            raise DIDRegistrarError(
                f"cheqd: did-registrar: {endpoint}: Response is None."
            )
        return res

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
