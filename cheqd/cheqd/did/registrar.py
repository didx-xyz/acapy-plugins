"""DID Registrar for Cheqd."""

import logging

from aiohttp import ClientSession
from pydantic import ValidationError

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

    async def create(
        self, options: DidCreateRequestOptions | SubmitSignatureOptions
    ) -> DidResponse:
        """Create a DID Document."""
        LOGGER.debug("Creating DID document %s", options)
        async with ClientSession() as session:
            try:
                async with session.post(
                    f"{self.DID_REGISTRAR_BASE_URL}create?method={self.method}",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    try:
                        res = await response.json()
                    except Exception:
                        raise DIDRegistrarError(
                            "cheqd: did-registrar: create: Unable to parse JSON"
                        )
                    if not res:
                        raise DIDRegistrarError(
                            "cheqd: did-registrar: create: Response is None."
                        )

                    return DidResponse(**res)
            except (ValidationError, AttributeError):
                raise DIDRegistrarError(
                    "cheqd: did-registrar: create: Response Format is invalid"
                )
            except Exception:
                raise

    async def update(
        self, options: DidUpdateRequestOptions | SubmitSignatureOptions
    ) -> DidResponse:
        """Update a DID Document."""
        LOGGER.debug("Updating DID document %s", options)
        async with ClientSession() as session:
            try:
                async with session.post(
                    f"{self.DID_REGISTRAR_BASE_URL}update?method={self.method}",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    try:
                        res = await response.json()
                    except Exception:
                        raise DIDRegistrarError(
                            "cheqd: did-registrar: update: Unable to parse JSON"
                        )
                    if not res:
                        raise DIDRegistrarError(
                            "cheqd: did-registrar: update: Response is None."
                        )

                    return DidResponse(**res)
            except (ValidationError, AttributeError):
                raise DIDRegistrarError(
                    "cheqd: did-registrar: update: Response Format is invalid"
                )
            except Exception:
                raise

    async def deactivate(
        self, options: DidDeactivateRequestOptions | SubmitSignatureOptions
    ) -> DidResponse:
        """Deactivate a DID Document."""
        LOGGER.debug("Deactivating DID %s", options)
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "deactivate" + f"?method={self.method}",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    try:
                        res = await response.json()
                    except Exception:
                        raise DIDRegistrarError(
                            "cheqd: did-registrar: deactivate: Unable to parse JSON"
                        )
                    if not res:
                        raise DIDRegistrarError(
                            "cheqd: did-registrar: create_resource: Response is None."
                        )

                    return DidResponse(**res)
            except (ValidationError, AttributeError):
                raise DIDRegistrarError(
                    "cheqd: did-registrar: deactivate: Response Format is invalid"
                )
            except Exception:
                raise

    async def create_resource(
        self, options: ResourceCreateRequestOptions | SubmitSignatureOptions
    ) -> ResourceResponse:
        """Create a DID Linked Resource."""
        LOGGER.debug("Creating resource %s", options)
        async with ClientSession() as session:
            try:
                async with session.post(
                    f"{self.DID_REGISTRAR_BASE_URL}createResource?method={self.method}",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    try:
                        res = await response.json()
                    except Exception:
                        raise DIDRegistrarError(
                            "cheqd: did-registrar: create_resource: Unable to parse JSON"
                        )
                    if not res:
                        raise DIDRegistrarError(
                            "cheqd: did-registrar: create_resource: Response is None."
                        )
                    LOGGER.debug("Create Resource Response: %s", res)
                    return ResourceResponse(**res)
            except (ValidationError, AttributeError):
                raise DIDRegistrarError(
                    "cheqd: did-registrar: create_resource: Response Format is invalid"
                )
            except Exception:
                raise

    async def update_resource(
        self, options: ResourceUpdateRequestOptions | SubmitSignatureOptions
    ) -> ResourceResponse:
        """Update a DID Linked Resource."""
        LOGGER.debug("Updating resource %s", options)
        async with ClientSession() as session:
            try:
                async with session.post(
                    f"{self.DID_REGISTRAR_BASE_URL}updateResource?method={self.method}",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    try:
                        res = await response.json()
                    except Exception:
                        raise DIDRegistrarError(
                            "cheqd: did-registrar: update_resource: Unable to parse JSON"
                        )
                    if not res:
                        raise DIDRegistrarError(
                            "cheqd: did-registrar: update_resource: Response is None."
                        )

                    return ResourceResponse(**res)
            except (ValidationError, AttributeError):
                raise DIDRegistrarError(
                    "cheqd: did-registrar: update_resource: Response Format is invalid"
                )
            except Exception:
                raise

    async def deactivate_resource(self, options: dict) -> dict:
        """Deactivate a DID Linked Resource."""
        raise NotImplementedError("This method will not be implemented for did:cheqd.")
