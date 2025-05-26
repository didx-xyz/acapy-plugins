"""DID Registrar for Cheqd."""

import asyncio
import json
import logging
import os
from time import time
from typing import Dict, Optional

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

# Constants for configuration
DEFAULT_REGISTRAR_URL = "http://localhost:9080/1.0/"
DEFAULT_LOCK_PATH = "/tmp/lock/did_registrar.lock"
DEFAULT_GRACE_PERIOD = 1  # seconds
DEFAULT_MAX_RETRIES = 20
DEFAULT_RETRY_DELAY = 5.00  # seconds
DEFAULT_FRESH_TRANSACTION_WINDOW = 0.5  # seconds
DEFAULT_RESPONSE_MATCH_TIMEOUT = 0.5  # seconds


class LockFileContent(BaseModel):
    """Content structure for the lock file."""

    current_job_id: Optional[str] = None
    current_job_start: Optional[float] = None
    current_job_endpoint: Optional[str] = None
    last_transaction_time: Optional[float] = None
    instance_id: str  # Unique identifier for this instance


class DIDRegistrar(BaseDIDRegistrar):
    """Universal DID Registrar implementation with improved sequence management."""

    def __init__(
        self,
        method: str,
        registrar_url: Optional[str] = None,
        lock_path: Optional[str] = None,
        grace_period: float = DEFAULT_GRACE_PERIOD,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_delay: float = DEFAULT_RETRY_DELAY,
        fresh_transaction_window: float = DEFAULT_FRESH_TRANSACTION_WINDOW,
        response_match_timeout: float = DEFAULT_RESPONSE_MATCH_TIMEOUT,
        instance_id: Optional[str] = None,
    ) -> None:
        """Initialize the Cheqd Registrar with configurable parameters."""
        super().__init__()
        self.DID_REGISTRAR_BASE_URL = registrar_url or DEFAULT_REGISTRAR_URL
        self.LOCK_FILE_PATH = lock_path or DEFAULT_LOCK_PATH
        self.method = method
        self._pending_jobs: Dict[str, float] = {}
        self._grace_period = grace_period
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._fresh_transaction_window = fresh_transaction_window
        self._response_match_timeout = response_match_timeout
        self._lock = asyncio.Lock()  # In-memory lock for additional safety
        self._instance_id = instance_id or f"instance_{int(time() * 1000)}"
        self._lock_file_content: Optional[LockFileContent] = None
        self._last_transaction_time: Optional[float] = None
        self._lock_file: Optional[int] = None

    async def _read_lock_file_content(self) -> Optional[LockFileContent]:
        """Read the current content of the lock file."""
        try:
            if os.path.exists(self.LOCK_FILE_PATH):
                with open(self.LOCK_FILE_PATH, "r") as f:
                    try:
                        content = json.load(f)
                        return LockFileContent(**content)
                    except json.JSONDecodeError as e:
                        LOGGER.warning("Invalid JSON in lock file: %s", str(e))
                        # Try to clean up the lock file
                        try:
                            os.remove(self.LOCK_FILE_PATH)
                        except Exception as cleanup_error:
                            LOGGER.error(
                                "Failed to clean up invalid lock file: %s",
                                str(cleanup_error),
                            )
        except Exception as e:
            LOGGER.warning("Error reading lock file content: %s", str(e))
        return None

    async def _write_lock_file_content(self, content: LockFileContent) -> None:
        """Write content to the lock file."""
        if self._lock_file is None:
            LOGGER.error(
                "Attempted to write to lock file without an open file descriptor"
            )
            return

        try:
            content_dict = content.model_dump()
            LOGGER.debug("Writing lock file content: %s", content_dict)

            # Reset file position to start
            os.lseek(self._lock_file, 0, os.SEEK_SET)
            # Truncate the file
            os.ftruncate(self._lock_file, 0)
            # Write new content
            os.write(self._lock_file, json.dumps(content_dict).encode())
            os.fsync(self._lock_file)  # Ensure content is written to disk
        except Exception as e:
            LOGGER.error("Error writing to lock file: %s", str(e))
            raise DIDRegistrarError(f"Failed to write to lock file: {str(e)}")

    async def _acquire_file_lock(self) -> None:
        """Acquire a file lock with retry mechanism and content management."""
        retry_count = 0
        while retry_count < self._max_retries:
            try:
                # flags: O_CREAT: create the file if it doesn't exist, O_EXCL: fail if the file already exists, O_RDWR: open for reading and writing
                flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
                self._lock_file = os.open(self.LOCK_FILE_PATH, flags)
                LOGGER.debug("File lock acquired")

                # Initialize lock file content
                self._lock_file_content = LockFileContent(
                    instance_id=self._instance_id,
                    last_transaction_time=self._last_transaction_time,
                )
                await self._write_lock_file_content(self._lock_file_content)
                return

            except FileExistsError:
                # Try to read existing content
                existing_content = await self._read_lock_file_content()
                if existing_content:
                    current_time = time()
                    if (
                        existing_content.current_job_start
                        and current_time - existing_content.current_job_start
                        > self._grace_period
                    ):
                        # Job has timed out, try to remove the lock file
                        try:
                            os.remove(self.LOCK_FILE_PATH)
                            LOGGER.debug("Lock file removed")
                            continue
                        except Exception as e:
                            LOGGER.error("Error removing lock file: %s", str(e))

                    LOGGER.debug(
                        "Waiting for job %s from instance %s (started %s seconds ago)",
                        existing_content.current_job_id,
                        existing_content.instance_id,
                        current_time - (existing_content.current_job_start or 0),
                    )

                retry_count += 1
                if retry_count >= self._max_retries:
                    LOGGER.info("Failed to acquire file lock after maximum retries")
                    raise DIDRegistrarError(
                        "Failed to acquire file lock after maximum retries"
                    )
                LOGGER.debug("Waiting for %s seconds before retrying", self._retry_delay)
                await asyncio.sleep(self._retry_delay)

    async def _release_file_lock(self) -> None:
        """Release the file lock safely."""
        try:
            if self._lock_file is not None:
                if self._lock_file_content:
                    self._lock_file_content.current_job_id = None
                    self._lock_file_content.current_job_start = None
                    self._lock_file_content.current_job_endpoint = None
                    try:
                        await self._write_lock_file_content(self._lock_file_content)
                    except Exception as e:
                        LOGGER.warning(
                            "Failed to write final lock file content: %s", str(e)
                        )

                LOGGER.debug("Closing lock file")
                os.close(self._lock_file)
                self._lock_file = None
                try:
                    LOGGER.debug("Removing lock file")
                    os.remove(self.LOCK_FILE_PATH)
                except Exception as e:
                    LOGGER.warning("Failed to remove lock file: %s", str(e))
                LOGGER.debug("File lock released")
        except Exception as e:
            LOGGER.error("Error releasing file lock: %s", str(e))
            # Don't raise here to ensure cleanup continues

    async def _handle_initial_request(self, endpoint: str, options: BaseModel) -> dict:
        """Handle the initial request with proper locking and job tracking."""
        async with self._lock:
            try:
                await self._acquire_file_lock()
                LOGGER.debug("Lock acquired for %s request", endpoint)

                response = await self._process_initial_request(endpoint, options)
                job_id = response.get("jobId")

                if job_id:
                    LOGGER.debug("Adding jobId to pending jobs: %s", job_id)
                    self._pending_jobs[job_id] = time()

                    # Update lock file content
                    if self._lock_file_content:
                        self._lock_file_content.current_job_id = job_id
                        self._lock_file_content.current_job_start = time()
                        self._lock_file_content.current_job_endpoint = endpoint
                        await self._write_lock_file_content(self._lock_file_content)
                else:
                    LOGGER.warning(
                        "No jobId returned from initial %s request. Response: %s",
                        endpoint,
                        response,
                    )

                await asyncio.sleep(self._grace_period)
                return response

            finally:
                await self._release_file_lock()
                LOGGER.debug("Lock released for %s request", endpoint)

    async def _handle_signature_request(
        self, endpoint: str, options: SubmitSignatureOptions
    ) -> dict:
        """Handle the signature request and update job tracking."""
        async with self._lock:
            try:
                await self._acquire_file_lock()
                LOGGER.debug("Lock acquired for signature request")

                response = await self._submit_request(endpoint, options)
                job_id = options.jobId

                if job_id in self._pending_jobs:
                    LOGGER.debug("Removing jobId from pending jobs: %s", job_id)
                    del self._pending_jobs[job_id]
                    self._last_transaction_time = time()

                    # Update lock file content if we have it
                    if self._lock_file_content:
                        self._lock_file_content.last_transaction_time = (
                            self._last_transaction_time
                        )
                        if self._lock_file_content.current_job_id == job_id:
                            self._lock_file_content.current_job_id = None
                            self._lock_file_content.current_job_start = None
                            self._lock_file_content.current_job_endpoint = None
                        await self._write_lock_file_content(self._lock_file_content)
                else:
                    LOGGER.warning("JobId done but not found in pending jobs: %s", job_id)

                return response

            finally:
                await self._release_file_lock()
                LOGGER.debug("Lock released for signature request")

    async def _execute_request(self, endpoint: str, options: BaseModel) -> dict:
        """Execute a request to the DID Registrar with improved sequence management."""
        if not isinstance(options, SubmitSignatureOptions):
            return await self._handle_initial_request(endpoint, options)
        return await self._handle_signature_request(endpoint, options)

    async def _wait_for_pending_jobs(self) -> None:
        """Wait for any pending jobs to complete."""
        while self._pending_jobs:
            current_time = time()
            for job_id, start_time in list(self._pending_jobs.items()):
                if current_time - start_time > self._grace_period:
                    LOGGER.info("Timeout waiting for job %s to complete", job_id)
                    del self._pending_jobs[job_id]
                else:
                    LOGGER.debug("Waiting for job %s to complete", job_id)
            if self._pending_jobs:
                await asyncio.sleep(self._grace_period / 5)

    async def _verify_response_match(self, response1: dict, response2: dict) -> bool:
        """Verify that two responses match, considering only relevant fields."""
        # Compare only the essential fields that should match
        essential_fields = ["jobId", "didDocument", "didDocumentMetadata"]
        return all(
            response1.get(field) == response2.get(field)
            for field in essential_fields
            if field in response1 and field in response2
        )

    async def _process_initial_request(self, endpoint: str, options: BaseModel) -> dict:
        """Process the initial request with improved sequence management and double-check."""
        retry_count = 0
        while retry_count < self._max_retries:
            try:
                await self._wait_for_pending_jobs()

                # Check if we're in a fresh transaction window
                is_fresh_transaction = (
                    self._last_transaction_time is not None
                    and time() - self._last_transaction_time
                    < self._fresh_transaction_window
                )

                if is_fresh_transaction:
                    LOGGER.debug("In fresh transaction window, performing double-check")
                    # Make two requests and verify they match
                    response1 = await self._submit_request(endpoint, options)
                    await asyncio.sleep(self._response_match_timeout)
                    response2 = await self._submit_request(endpoint, options)

                    if not await self._verify_response_match(response1, response2):
                        raise DIDRegistrarError(
                            f"cheqd: did-registrar: {endpoint}: Response mismatch in double-check"
                        )
                    return response1
                else:
                    return await self._submit_request(endpoint, options)

            except DIDRegistrarError as e:
                if (
                    "sequence mismatch" in str(e).lower()
                    and retry_count < self._max_retries - 1
                ):
                    retry_count += 1
                    LOGGER.warning(
                        "Sequence mismatch detected, retrying (%d/%d)",
                        retry_count,
                        self._max_retries,
                    )
                    await asyncio.sleep(self._retry_delay)
                else:
                    raise

    async def _submit_request(self, endpoint: str, options: BaseModel) -> dict:
        """Execute a request with improved error handling."""
        try:
            async with ClientSession() as session:
                LOGGER.debug("Submitting %s request", endpoint)
                response = await session.post(
                    f"{self.DID_REGISTRAR_BASE_URL}{endpoint}?method={self.method}",
                    json=options.model_dump(exclude_none=True),
                )
                return await self._parse_response(response, endpoint)
        except (ValidationError, AttributeError) as e:
            raise DIDRegistrarError(
                f"cheqd: did-registrar: {endpoint}: Response Format is invalid: {str(e)}"
            )
        except Exception as ex:
            LOGGER.error("Error executing %s request: %s", endpoint, ex)
            raise

    async def _parse_response(self, response: ClientResponse, endpoint: str) -> dict:
        """Parse the response from the DID Registrar with improved error handling."""
        LOGGER.debug("Parsing response from %s request", endpoint)
        try:
            res = await response.json()
        except Exception as e:
            raise DIDRegistrarError(
                f"cheqd: did-registrar: {endpoint}: Unable to parse JSON: {str(e)}"
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
