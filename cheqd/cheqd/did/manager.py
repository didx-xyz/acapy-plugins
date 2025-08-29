"""DID Manager for Cheqd."""

import asyncio
import logging
from typing import Optional, Tuple

from acapy_agent.core.profile import Profile
from acapy_agent.ledger.base import EndpointType
from acapy_agent.protocols.coordinate_mediation.v1_0.route_manager import RouteManager
from acapy_agent.resolver.base import DIDNotFound
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.crypto import validate_seed
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.did_parameters_validation import DIDParametersValidation
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import BLS12381G2, ED25519, KeyType, P256
from acapy_agent.wallet.keys.manager import multikey_to_verkey
from acapy_agent.wallet.routes import format_did_info
from acapy_agent.wallet.util import b58_to_bytes, bytes_to_b64
from aiohttp import web

from ..did.base import (
    BaseDIDManager,
    CheqdDIDManagerError,
    DidCreateRequestOptions,
    DidDeactivateRequestOptions,
    Options,
    Secret,
)
from ..did_method import CHEQD
from ..resolver.resolver import CheqdDIDResolver
from .base import (
    DidActionState,
    DIDDocumentSchema,
    DidErrorState,
    DidSuccessState,
    DidUpdateRequestOptions,
    SubmitSignatureOptions,
)
from .helpers import (
    CheqdNetwork,
    VerificationMethods,
    create_did_payload,
    create_did_verification_method,
    create_verification_keys,
)
from .registrar import DIDRegistrar

LOGGER = logging.getLogger(__name__)


class CheqdDIDManager(BaseDIDManager):
    """DID manager implementation for did:cheqd."""

    registrar: DIDRegistrar
    resolver: CheqdDIDResolver

    def __init__(
        self,
        profile: Profile,
        registrar_url: str = None,
        resolver_url: str = None,
    ) -> None:
        """Initialize the Cheqd DID manager."""
        super().__init__(profile)
        self.registrar = DIDRegistrar("cheqd", registrar_url)
        self.resolver = CheqdDIDResolver(resolver_url)

    async def create(
        self, did_doc: DIDDocumentSchema | None = None, options: dict | None = None
    ) -> dict:
        """Create a new Cheqd DID with retry logic for sequence mismatches."""
        options = options or {}
        seed = self._validate_seed(options)
        network = options.get("network") or CheqdNetwork.Testnet.value
        key_type = ED25519

        did_validation = DIDParametersValidation(self.profile.inject(DIDMethods))
        did_validation.validate_key_type(CHEQD, key_type)

        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            if not wallet:
                LOGGER.error("No wallet available")
                raise WalletError(reason="No wallet available")

            retry_count = 0
            max_retries = 3
            retry_delay = 1.0
            last_error = None

            while retry_count <= max_retries:
                try:
                    did_document, verkey, kid = await self._prepare_did_document(
                        wallet, did_doc, options, network, key_type, seed
                    )
                    return await self._create_and_publish_did(
                        wallet, did_document, network, verkey, kid
                    )
                except CheqdDIDManagerError as e:
                    last_error = e
                    if not self._should_retry(e):
                        LOGGER.error("Should not retry %s", e)
                        raise
                    retry_count += 1
                    if retry_count <= max_retries:
                        LOGGER.warning(
                            "Account sequence mismatch detected, retrying (%d/%d)",
                            retry_count,
                            max_retries,
                        )
                        await asyncio.sleep(retry_delay)
                    else:
                        LOGGER.error(
                            "Max retries exceeded for DID creation: %s", str(last_error)
                        )
                        raise
                except Exception as ex:
                    LOGGER.error("Unexpected error during DID creation: %s", str(ex))
                    raise CheqdDIDManagerError(str(ex))

    def _validate_seed(self, options: dict) -> str | None:
        """Validate and return the seed."""
        seed = options.get("seed")
        if seed and not self.profile.settings.get("wallet.allow_insecure_seed"):
            LOGGER.error("Insecure seed is not allowed")
            raise WalletError("Insecure seed is not allowed")
        return validate_seed(seed) if seed else None

    async def _prepare_did_document(
        self,
        wallet: BaseWallet,
        did_doc: DIDDocumentSchema | None,
        options: dict,
        network: str,
        key_type: KeyType,
        seed: str | None,
    ) -> Tuple[DIDDocumentSchema, str, str]:
        """Prepare the DID document and return it along with verkey and kid."""
        key = await wallet.create_key(key_type, seed)
        verkey = key.verkey
        verkey_bytes = b58_to_bytes(verkey)
        public_key_b64 = bytes_to_b64(verkey_bytes)
        verification_method = (
            options.get("verification_method") or VerificationMethods.Ed255192020
        )

        if did_doc is None:
            verification_keys = create_verification_keys(public_key_b64, network)
            verification_methods = create_did_verification_method(
                [verification_method], [verification_keys]
            )
            did_document = create_did_payload(
                verification_methods,
                [verification_keys],
                endpoint=self.profile.settings.get("default_endpoint"),
            )
        else:
            did_document = did_doc

        did = did_document.get("id")
        return did_document, verkey, did

    async def _create_and_publish_did(
        self,
        wallet: BaseWallet,
        did_document: DIDDocumentSchema,
        network: str,
        verkey: str,
        kid: str,
    ) -> dict:
        """Create and publish the DID."""
        create_request_res = await self.registrar.create(
            DidCreateRequestOptions(
                didDocument=did_document, options=Options(network=network)
            )
        )

        job_id = create_request_res.jobId
        did_state = create_request_res.didState
        if isinstance(did_state, DidActionState):
            if not did_state.signingRequest:
                LOGGER.error("No signing requests available for create.")
                raise CheqdDIDManagerError("No signing requests available for create.")

            signing_request = next(iter(did_state.signingRequest.values()), None)
            kid = signing_request.kid
            await wallet.assign_kid_to_key(verkey, kid)

            signed_responses = await CheqdDIDManager.sign_requests(
                wallet, did_state.signingRequest
            )
            publish_did_res = await self.registrar.create(
                SubmitSignatureOptions(
                    jobId=job_id,
                    options=Options(network=network),
                    secret=Secret(signingResponse=signed_responses),
                )
            )
            publish_did_state = publish_did_res.didState
            if publish_did_state.state != "finished":
                LOGGER.error("Error publishing DID: %s", publish_did_state)
                message = self._get_error_message(publish_did_state)
                raise CheqdDIDManagerError(f"Error registering DID: {message}")

            await wallet.create_public_did(
                CHEQD,
                ED25519,
                seed=None,
                did=did_document["id"],
                metadata={"verkey": verkey},
            )
            await wallet.assign_kid_to_key(verkey, kid)
            return {
                "did": did_document["id"],
                "verkey": verkey,
                "didDocument": publish_did_state.didDocument.model_dump(),
            }
        else:
            LOGGER.error("Unexpected DID state: %s, %s", type(did_state), did_state)
            message = self._get_error_message(did_state)
            raise CheqdDIDManagerError(f"Error registering DID: {message}")

    def _should_retry(self, error: CheqdDIDManagerError) -> bool:
        """Determine if the request should be retried based on the error."""
        return "account sequence mismatch" in str(error)

    async def update(self, did: str, did_doc: dict, options: dict = None) -> dict:
        """Update a Cheqd DID."""

        async with self.profile.session() as session:
            try:
                wallet = session.inject(BaseWallet)
                if not wallet:
                    LOGGER.error("No wallet available")
                    raise web.HTTPForbidden(reason="No wallet available")

                # Resolve the DID and ensure it is not deactivated and is valid
                curr_did_doc = await self.resolver.resolve(self.profile, did)
                if not curr_did_doc or curr_did_doc.get("deactivated"):
                    LOGGER.error("DID is already deactivated or not found: %s", did)
                    raise DIDNotFound("DID is already deactivated or not found.")

                # TODO If registrar supports other operation,
                #       take didDocumentOperation as input
                update_request_res = await self.registrar.update(
                    DidUpdateRequestOptions(
                        did=did,
                        didDocumentOperation=["setDidDocument"],
                        didDocument=[did_doc],
                    )
                )

                job_id = update_request_res.jobId
                did_state = update_request_res.didState

                if isinstance(did_state, DidActionState):
                    signing_requests = did_state.signingRequest
                    if not signing_requests:
                        LOGGER.error("No signing requests available for update.")
                        raise Exception("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )

                    # submit signed update
                    publish_did_res = await self.registrar.update(
                        SubmitSignatureOptions(
                            jobId=job_id,
                            secret=Secret(signingResponse=signed_responses),
                        )
                    )
                    publish_did_state = publish_did_res.didState

                    if publish_did_state.state != "finished":
                        LOGGER.error("Error publishing DID update: %s", publish_did_state)
                        message = self._get_error_message(publish_did_state)
                        raise CheqdDIDManagerError(
                            f"Error publishing DID update: {message}"
                        )
                else:
                    LOGGER.error("Error updating DID: %s", did_state)
                    message = self._get_error_message(did_state)
                    raise CheqdDIDManagerError(f"Error updating DID: {message}")

                # Update new keys to wallet if necessary
                verification_methods = did_doc.get("verificationMethod", [])
                if verification_methods:
                    vm = verification_methods[0]  # Assume first verification method

                    verkey = None
                    if vm.get("type") == "Ed25519VerificationKey2018":
                        verkey = vm.get("publicKeyBase58")
                    elif vm.get("type") == "Ed25519VerificationKey2020":
                        multibase = vm.get("publicKeyMultibase")
                        if multibase:
                            verkey = multikey_to_verkey(multibase)
                    else:
                        LOGGER.error(
                            "Unsupported verification method type: %s", vm.get("type")
                        )

                    if verkey:
                        LOGGER.info("Updating routing for verkey: %s", verkey)
                        try:
                            # Update the DID's verkey with automatic KID reassignment
                            updated_did_info = await wallet.update_local_did_verkey(did, verkey)
                            LOGGER.debug("Updated DID info: %s", updated_did_info)

                            # Update public DID if this is the current public DID
                            public_did = await wallet.get_public_did()
                            if public_did and public_did.did == did:
                                await wallet.set_public_did(updated_did_info)

                            # Update routing
                            route_manager = self.profile.inject(RouteManager)
                            await route_manager.route_verkey(self.profile, verkey)
                        except Exception as e:
                            LOGGER.error("Failed to update verkey in wallet: %s", e)

                    else:
                        LOGGER.error(
                            "No verkey found for verification method: %s", vm
                        )

            except Exception as ex:
                LOGGER.error("Exception occurred during DID update: %s", str(ex))
                raise ex

        return {"did": did, "didDocument": publish_did_state.didDocument.model_dump()}

    async def deactivate(self, did: str, options: dict = None) -> dict:
        """Deactivate a Cheqd DID."""
        LOGGER.debug("Deactivate did: %s", did)

        async with self.profile.session() as session:
            try:
                wallet = session.inject(BaseWallet)
                if not wallet:
                    LOGGER.error("No wallet available")
                    raise web.HTTPForbidden(reason="No wallet available")
                # Resolve the DID and ensure it is not deactivated and is valid
                did_doc = await self.resolver.resolve(self.profile, did)
                if not did_doc or did_doc.get("deactivated"):
                    LOGGER.error("DID is already deactivated or not found: %s", did)
                    raise DIDNotFound("DID is already deactivated or not found.")

                # request deactivate did
                deactivate_request_res = await self.registrar.deactivate(
                    DidDeactivateRequestOptions(did=did)
                )

                job_id: str = deactivate_request_res.jobId
                did_state = deactivate_request_res.didState

                if isinstance(did_state, DidActionState):
                    signing_requests = did_state.signingRequest
                    if not signing_requests:
                        LOGGER.error("No signing requests available for deactivate.")
                        raise WalletError("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )
                    # submit signed deactivate
                    publish_did_res = await self.registrar.deactivate(
                        SubmitSignatureOptions(
                            jobId=job_id,
                            secret=Secret(
                                signingResponse=signed_responses,
                            ),
                        )
                    )

                    publish_did_state = publish_did_res.didState

                    if publish_did_state.state != "finished":
                        LOGGER.error(
                            "Error publishing DID deactivate: %s", publish_did_state
                        )
                        message = self._get_error_message(publish_did_state)
                        raise CheqdDIDManagerError(
                            f"Error publishing DID deactivate: {message}"
                        )
                else:
                    LOGGER.error("Error deactivating DID: %s", did_state)
                    message = self._get_error_message(did_state)
                    raise CheqdDIDManagerError(f"Error deactivating DID: {message}")
                # update local did metadata
                did_info = await wallet.get_local_did(did)
                metadata = {**did_info.metadata, "deactivated": True}
                await wallet.replace_local_did_metadata(did, metadata)
            except Exception as ex:
                LOGGER.error("Exception occurred during DID deactivation: %s", str(ex))
                raise ex
        return {
            "did": did,
            "didDocument": publish_did_state.didDocument.model_dump(),
            "didDocumentMetadata": metadata,
        }

    async def set_did_endpoint(
        self,
        did: str,
        endpoint: str,
        endpoint_type: Optional[EndpointType] = None,
    ) -> dict:
        """Update the endpoint for a DID in the wallet.

        Args:
            did (str): The DID for which to set the endpoint.
            endpoint (str): The endpoint to set. Use None to clear the endpoint.
            endpoint_type (str, optional): The type of the endpoint/service.
                Only endpoint_type 'endpoint' affects the local wallet.

        """
        async with self.profile.session() as session:
            try:
                wallet = session.inject(BaseWallet)
                if not wallet:
                    raise web.HTTPForbidden(reason="No wallet available")
                did_info = await wallet.get_local_did(did)
                if not did_info:
                    raise web.HTTPNotFound(reason="DID not found in wallet")
                if did_info.metadata.get("deactivated"):
                    raise web.HTTPBadRequest(reason="DID is deactivated")
                if did_info.metadata.get("posted"):
                    # Resolve the DID and ensure it is not deactivated and is valid
                    curr_did_doc = await self.resolver.resolve(self.profile, did)
                    if not curr_did_doc or curr_did_doc.get("deactivated"):
                        raise DIDNotFound("DID is already deactivated or not found.")

                    # Prepare the updated DID document with the new service endpoint
                    updated_did_doc = curr_did_doc.copy()

                    # Update or add the service endpoint
                    services = updated_did_doc.get("service", [])
                    endpoint_updated = False
                    service_type = endpoint_type
                    if endpoint_type == EndpointType.ENDPOINT:
                        service_type = "did-communication"
                    for service in services:
                        if service.get("type") == service_type:
                            service["serviceEndpoint"] = endpoint
                            endpoint_updated = True
                            break

                    if not endpoint_updated:
                        # Add a new service if no existing one was found
                        service_id = f"{did}#{endpoint_type}"
                        new_service = {
                            "id": service_id,
                            "type": service_type,
                            "serviceEndpoint": endpoint,
                            "recipientKeys": [
                                curr_did_doc["authentication"][0]
                            ],  # You may need to add appropriate keys
                        }
                        services.append(new_service)
                        updated_did_doc["service"] = services
                    # Update the DID on the ledger
                    result = await self.update(did, updated_did_doc)
                    if not result:
                        raise web.HTTPBadRequest(reason="Failed to update DID on ledger")
                # Update the local wallet with the new endpoint
                metadata = {**did_info.metadata}
                if endpoint_type == EndpointType.ENDPOINT:
                    metadata[endpoint_type.w3c.lower()] = endpoint
                await wallet.replace_local_did_metadata(did, metadata)
            except Exception as ex:
                raise ex
        return {
            "did": did,
            "didDocument": result["didDocument"] | {},
            "didDocumentMetadata": metadata,
        }

    async def import_did(self, did_document: dict, metadata: dict = None) -> dict:
        """Import a DID."""
        metadata = metadata or {}

        async with self.profile.session() as session:
            try:
                wallet = session.inject(BaseWallet)
                if not wallet:
                    raise WalletError(reason="No wallet available")

                did = did_document.get("id")
                if not did:
                    raise WalletError(reason="DID document must contain an 'id' field")

                # Extract verification method (assuming first one for simplicity)
                verification_methods = did_document.get("verificationMethod", [])
                if not verification_methods:
                    raise WalletError(
                        reason="DID document must contain verification methods"
                    )
                # Get the first verification method's public key
                first_vm = verification_methods[0]
                # Handle both publicKeyBase58 and publicKeyMultibase formats
                public_key_base58 = first_vm.get("publicKeyBase58")
                public_key_multibase = first_vm.get("publicKeyMultibase")
                if public_key_base58:
                    # If we have publicKeyBase58, use it directly
                    verkey = public_key_base58
                elif public_key_multibase:
                    # If we have publicKeyMultibase, convert it to verkey format
                    verkey = multikey_to_verkey(public_key_multibase)
                else:
                    raise WalletError(
                        reason=(
                            "Verification method must contain either "
                            "'publicKeyBase58' or 'publicKeyMultibase'"
                        )
                    )
                # Determine key type from verification method
                key_type = ED25519  # Default fallback

                vm_type = first_vm.get("type", "")
                if "Ed25519" in vm_type:
                    key_type = ED25519
                elif "P256" in vm_type or "secp256r1" in vm_type:
                    key_type = P256
                elif "BLS" in vm_type:
                    key_type = BLS12381G2
                LOGGER.debug("Detected key type %s for DID %s", key_type.key_type, did)
                # Determine and validate DID method
                did_methods: DIDMethods = self.profile.inject(DIDMethods)
                method = did_methods.from_did(did)
                did_validation = DIDParametersValidation(did_methods)
                did_validation.validate_key_type(method, key_type)

                # Create DIDInfo object
                did_info = DIDInfo(
                    did=did,
                    verkey=verkey,
                    metadata=metadata,
                    method=method,
                    key_type=key_type,
                )
                stored_info = await wallet.store_did(did_info)

                LOGGER.info("Successfully imported DID: %s", did)
            except Exception as ex:
                raise ex

        return {"result": format_did_info(stored_info)}

    def _get_error_message(
        self, did_state: DidSuccessState | DidActionState | DidErrorState
    ) -> str:
        return (
            did_state.description
            if hasattr(did_state, "description") and did_state.description
            else did_state.reason
        )
