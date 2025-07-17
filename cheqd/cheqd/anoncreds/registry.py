"""DID Cheqd AnonCreds Registry."""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Pattern, Sequence, Tuple, Union
from uuid import uuid4

from acapy_agent.anoncreds.base import (
    AnonCredsRegistrationError,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDef,
    CredDefResult,
    CredDefState,
    CredDefValue,
    GetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevListState,
    RevRegDef,
    RevRegDefResult,
    RevRegDefState,
    RevRegDefValue,
)
from acapy_agent.anoncreds.models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from acapy_agent.anoncreds.models.schema_info import AnonCredsSchemaInfo
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.resolver.base import DIDNotFound
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.jwt import dict_to_b64
from pydantic import BaseModel, Field

from ..did.base import (
    DidUrlActionState,
    DidUrlErrorState,
    DidUrlSuccessState,
    Options,
    ResourceCreateRequestOptions,
    ResourceUpdateRequestOptions,
    Secret,
    SigningRequest,
    SubmitSignatureOptions,
)
from ..did.helpers import CheqdAnonCredsResourceType
from ..did.manager import CheqdDIDManager
from ..did.registrar import DIDRegistrar
from ..resolver.resolver import CheqdDIDResolver
from ..validation import CheqdDID

LOGGER = logging.getLogger(__name__)


class PublishResourceResponse(BaseModel):
    """Publish Resource Response."""

    did_url: str
    content: Union[dict, str] = Field(..., repr=False)


class DIDCheqdRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """DIDCheqdRegistry."""

    registrar: DIDRegistrar
    resolver: CheqdDIDResolver

    def __init__(self):
        """Initialize an instance.

        Args:
            None

        """
        self.registrar = DIDRegistrar(method="cheqd")
        self.resolver = CheqdDIDResolver()

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers regex."""
        return CheqdDID.PATTERN

    @staticmethod
    def make_schema_id(schema: AnonCredsSchema, resource_id: str) -> str:
        """Derive the ID for a schema."""
        return f"{schema.issuer_id}/resources/{resource_id}"

    @staticmethod
    def make_credential_definition_id(
        credential_definition: CredDef, resource_id: str
    ) -> str:
        """Derive the ID for a credential definition."""
        return f"{credential_definition.issuer_id}/resources/{resource_id}"

    @staticmethod
    def make_revocation_registry_id(
        revocation_registry_definition: RevRegDef, resource_id: str
    ) -> str:
        """Derive the ID for a revocation registry definition."""
        return f"{revocation_registry_definition.issuer_id}/resources/{resource_id}"

    @staticmethod
    def split_did_url(schema_id: str) -> Tuple[str, str]:
        """Derive the ID for a schema."""
        ids = schema_id.split("/")
        return ids[0], ids[2]

    async def setup(self, _context: InjectionContext, registrar_url, resolver_url):
        """Setup."""
        self.registrar = DIDRegistrar("cheqd", registrar_url)
        self.resolver = CheqdDIDResolver(resolver_url)
        print("Successfully registered DIDCheqdRegistry")

    async def get_schema(self, _profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        LOGGER.debug("Getting schema %s", schema_id)
        resource_with_metadata = await self.resolver.dereference_with_metadata(
            _profile, schema_id
        )
        schema = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata

        (did, resource_id) = self.split_did_url(schema_id)

        anoncreds_schema = AnonCredsSchema(
            issuer_id=did,
            attr_names=schema["attrNames"],
            name=schema["name"],
            version=schema["version"],
        )
        result = GetSchemaResult(
            schema_id=schema_id,
            schema=anoncreds_schema,
            schema_metadata=metadata,
            resolution_metadata={},
        )
        LOGGER.debug("Fetched schema %s", result)
        return result

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        _options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        resource_type = CheqdAnonCredsResourceType.schema.value
        resource_name = f"{schema.name}"
        resource_version = schema.version
        LOGGER.debug("Registering schema %s", schema)
        try:
            LOGGER.debug("Checking if schema already exists")
            try:
                existing_schema = await self.resolver.dereference_with_metadata(
                    profile,
                    f"{schema.issuer_id}?resourceName={resource_name}&resourceType={resource_type}",
                )
            except DIDNotFound:
                LOGGER.debug("Existing schema not found")
                existing_schema = None
            except Exception as ex:
                raise ex

            # update if schema exists
            if existing_schema is not None:
                LOGGER.debug("Schema already exists, updating")
                cheqd_schema = ResourceUpdateRequestOptions(
                    options=Options(
                        name=resource_name,
                        type=resource_type,
                        versionId=resource_version,
                    ),
                    content=[
                        dict_to_b64(
                            {
                                "name": schema.name,
                                "version": schema.version,
                                "attrNames": schema.attr_names,
                            }
                        )
                    ],
                    did=schema.issuer_id,
                )

                LOGGER.debug("Updating schema to %s", cheqd_schema)
                publish_resource_res = await self._update_and_publish_resource(
                    profile,
                    self.registrar.DID_REGISTRAR_BASE_URL,
                    self.resolver.DID_RESOLVER_BASE_URL,
                    cheqd_schema,
                )
            else:
                LOGGER.debug("Schema does not exist, creating")
                cheqd_schema = ResourceCreateRequestOptions(
                    options=Options(
                        name=resource_name,
                        type=resource_type,
                        versionId=resource_version,
                    ),
                    content=dict_to_b64(
                        {
                            "name": schema.name,
                            "version": schema.version,
                            "attrNames": schema.attr_names,
                        }
                    ),
                    did=schema.issuer_id,
                )

                LOGGER.debug("Creating schema %s", cheqd_schema)
                publish_resource_res = await self._create_and_publish_resource(
                    profile,
                    self.registrar.DID_REGISTRAR_BASE_URL,
                    self.resolver.DID_RESOLVER_BASE_URL,
                    cheqd_schema,
                )

            LOGGER.debug("Published schema response %s", publish_resource_res)

            schema_id = publish_resource_res.did_url
            (_, resource_id) = self.split_did_url(schema_id)
        except Exception as err:
            LOGGER.error("Error registering schema %s", err)
            raise AnonCredsRegistrationError(f"{err}")

        result = SchemaResult(
            job_id=None,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED,
                schema_id=schema_id,
                schema=schema,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
        )
        LOGGER.debug("Schema registered successfully %s", result)
        return result

    async def get_credential_definition(
        self, _profile: Profile, credential_definition_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""
        LOGGER.debug("Getting credential definition %s", credential_definition_id)
        resource_with_metadata = await self.resolver.dereference_with_metadata(
            _profile, credential_definition_id
        )
        credential_definition = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata
        (did, resource_id) = self.split_did_url(credential_definition_id)

        anoncreds_credential_definition = CredDef(
            issuer_id=did,
            schema_id=credential_definition["schemaId"],
            type=credential_definition["type"],
            tag=credential_definition["tag"],
            value=CredDefValue.deserialize(credential_definition["value"]),
        )

        result = GetCredDefResult(
            credential_definition_id=credential_definition_id,
            credential_definition=anoncreds_credential_definition,
            credential_definition_metadata=metadata,
            resolution_metadata={},
        )
        LOGGER.debug("Fetched credential definition %s", result)
        return result

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        _options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        resource_type = CheqdAnonCredsResourceType.credentialDefinition.value
        # TODO: max chars are 31 for resource, on exceeding this should be hashed
        resource_name = f"{credential_definition.tag}"

        cred_def = ResourceCreateRequestOptions(
            options=Options(
                name=resource_name,
                type=resource_type,
                versionId=credential_definition.tag,
            ),
            content=dict_to_b64(
                {
                    "type": credential_definition.type,
                    "tag": credential_definition.tag,
                    "value": credential_definition.value.serialize(),
                    "schemaId": schema.schema_id,
                }
            ),
            did=credential_definition.issuer_id,
        )

        LOGGER.debug("Publishing credential definition resource %s", cred_def)
        publish_resource_res = await self._create_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            cred_def,
        )
        credential_definition_id = publish_resource_res.did_url
        (_, resource_id) = self.split_did_url(credential_definition_id)

        result = CredDefResult(
            job_id=None,
            credential_definition_state=CredDefState(
                state=CredDefState.STATE_FINISHED,
                credential_definition_id=credential_definition_id,
                credential_definition=credential_definition,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            credential_definition_metadata={},
        )
        LOGGER.debug("Credential definition registered successfully %s", result)
        return result

    async def get_revocation_registry_definition(
        self, _profile: Profile, revocation_registry_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        LOGGER.debug("Getting revocation registry definition %s", revocation_registry_id)
        resource_with_metadata = await self.resolver.dereference_with_metadata(
            _profile, revocation_registry_id
        )
        revocation_registry_definition = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata

        (did, resource_id) = self.split_did_url(revocation_registry_id)

        anoncreds_revocation_registry_definition = RevRegDef(
            issuer_id=did,
            cred_def_id=revocation_registry_definition["credDefId"],
            type=revocation_registry_definition["revocDefType"],
            tag=revocation_registry_definition["tag"],
            value=RevRegDefValue.deserialize(revocation_registry_definition["value"]),
        )

        result = GetRevRegDefResult(
            revocation_registry_id=revocation_registry_id,
            revocation_registry=anoncreds_revocation_registry_definition,
            revocation_registry_metadata=metadata,
            resolution_metadata={},
        )
        LOGGER.debug("Fetched revocation registry definition %s", result)
        return result

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        _options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""
        LOGGER.debug(
            "Registering revocation registry definition %s",
            revocation_registry_definition,
        )
        cred_def_result = await self.get_credential_definition(
            profile, revocation_registry_definition.cred_def_id
        )
        cred_def_res = cred_def_result.credential_definition_metadata.get("resourceName")
        # TODO: max chars are 31 for resource name, on exceeding this should be hashed
        resource_name = f"{cred_def_res}-{revocation_registry_definition.tag}"
        resource_type = CheqdAnonCredsResourceType.revocationRegistryDefinition.value

        rev_reg_def = ResourceCreateRequestOptions(
            options=Options(
                name=resource_name,
                type=resource_type,
                versionId=revocation_registry_definition.tag,
            ),
            content=dict_to_b64(
                {
                    "revocDefType": revocation_registry_definition.type,
                    "tag": revocation_registry_definition.tag,
                    "value": revocation_registry_definition.value.serialize(),
                    "credDefId": revocation_registry_definition.cred_def_id,
                }
            ),
            did=revocation_registry_definition.issuer_id,
        )

        LOGGER.debug("Publishing revocation registry definition resource %s", rev_reg_def)
        publish_resource_res = await self._create_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            rev_reg_def,
        )
        revocation_registry_definition_id = publish_resource_res.did_url
        (_, resource_id) = self.split_did_url(revocation_registry_definition_id)

        result = RevRegDefResult(
            job_id=None,
            revocation_registry_definition_state=RevRegDefState(
                state=RevRegDefState.STATE_FINISHED,
                revocation_registry_definition_id=revocation_registry_definition_id,
                revocation_registry_definition=revocation_registry_definition,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            revocation_registry_definition_metadata={},
        )
        LOGGER.debug("Revocation registry definition registered successfully %s", result)
        return result

    async def get_revocation_list(
        self,
        profile: Profile,
        revocation_registry_id: str,
        _timestamp_from: Optional[int] = 0,
        timestamp_to: Optional[int] = None,
    ) -> GetRevListResult:
        """Get a revocation list from the registry."""
        LOGGER.debug("Getting revocation list %s", revocation_registry_id)
        revocation_registry_definition = await self.get_revocation_registry_definition(
            profile,
            revocation_registry_id,
        )
        resource_name = revocation_registry_definition.revocation_registry_metadata.get(
            "resourceName"
        )
        (did, resource_id) = self.split_did_url(revocation_registry_id)

        resource_type = CheqdAnonCredsResourceType.revocationStatusList.value
        epoch_time = timestamp_to or int(time.time())
        dt_object = datetime.fromtimestamp(epoch_time, tz=timezone.utc)

        resource_time = dt_object.strftime("%Y-%m-%dT%H:%M:%SZ")
        resource_with_metadata = await self.resolver.dereference_with_metadata(
            profile,
            f"{did}?resourceType={resource_type}&resourceName={resource_name}&resourceVersionTime={resource_time}",
        )
        status_list = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata

        revocation_list = RevList(
            issuer_id=did,
            rev_reg_def_id=revocation_registry_id,
            revocation_list=status_list.get("revocationList"),
            current_accumulator=status_list.get("currentAccumulator"),
            timestamp=epoch_time,  # fix: return timestamp from resolution metadata
        )

        result = GetRevListResult(
            revocation_list=revocation_list,
            resolution_metadata={},
            revocation_registry_metadata=metadata,
        )
        LOGGER.debug("Fetched revocation list %s", result)
        return result

    async def get_schema_info_by_id(
        self, profile: Profile, schema_id: str
    ) -> AnonCredsSchemaInfo:
        """Get a schema info from the registry."""
        LOGGER.debug("Getting schema info by id %s", schema_id)
        resource_with_metadata = await self.resolver.dereference_with_metadata(
            profile, schema_id
        )
        schema = resource_with_metadata.resource
        (did, resource_id) = self.split_did_url(schema_id)
        anoncreds_schema = AnonCredsSchemaInfo(
            issuer_id=did,
            name=schema["name"],
            version=schema["version"],
        )
        LOGGER.debug("Fetched schema info by id %s", anoncreds_schema)
        return anoncreds_schema

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        _options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        rev_reg_def_id = rev_list.rev_reg_def_id
        LOGGER.debug("Registering revocation list for %s", rev_reg_def_id)
        revocation_registry_definition = await self.get_revocation_registry_definition(
            profile,
            rev_reg_def_id,
        )
        resource_name = revocation_registry_definition.revocation_registry_metadata.get(
            "resourceName"
        )
        resource_type = CheqdAnonCredsResourceType.revocationStatusList.value
        rev_status_list = ResourceCreateRequestOptions(
            options=Options(
                name=resource_name,
                type=resource_type,
                versionId=str(uuid4()),
            ),
            content=dict_to_b64(
                {
                    "revocationList": rev_list.revocation_list,
                    "currentAccumulator": rev_list.current_accumulator,
                    "revRegDefId": rev_reg_def_id,
                }
            ),
            did=rev_reg_def.issuer_id,
        )

        publish_resource_res = await self._create_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            rev_status_list,
        )
        did_url = publish_resource_res.did_url
        (_, resource_id) = self.split_did_url(did_url)

        result = RevListResult(
            job_id=None,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=rev_list,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            revocation_list_metadata={},
        )
        LOGGER.debug("Revocation list registered successfully for %s", rev_reg_def_id)
        return result

    async def update_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        _prev_list: RevList,
        curr_list: RevList,
        _revoked: Sequence[int],
        _options: Optional[dict] = None,
    ) -> RevListResult:
        """Update a revocation list on the registry."""
        LOGGER.debug("Updating revocation list %s", curr_list)
        revocation_registry_definition = await self.get_revocation_registry_definition(
            profile,
            curr_list.rev_reg_def_id,
        )
        resource_name = revocation_registry_definition.revocation_registry_metadata.get(
            "resourceName"
        )
        resource_type = CheqdAnonCredsResourceType.revocationStatusList.value
        rev_status_list = ResourceUpdateRequestOptions(
            options=Options(
                name=resource_name,
                type=resource_type,
                versionId=str(uuid4()),
            ),
            content=[
                dict_to_b64(
                    {
                        "revocationList": curr_list.revocation_list,
                        "currentAccumulator": curr_list.current_accumulator,
                        "revRegDefId": curr_list.rev_reg_def_id,
                    }
                )
            ],
            did=rev_reg_def.issuer_id,
        )

        publish_resource_res = await self._update_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            rev_status_list,
        )
        did_url = publish_resource_res.did_url
        (_, resource_id) = self.split_did_url(did_url)

        result = RevListResult(
            job_id=None,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=curr_list,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            revocation_list_metadata={},
        )
        LOGGER.debug("Revocation list updated successfully %s", result)
        return result

    @staticmethod
    def _should_retry(
        error: AnonCredsRegistrationError,
    ) -> bool:
        """Determine if the request should be retried based on the response state."""
        if not isinstance(error, AnonCredsRegistrationError):
            return False
        return "account sequence mismatch" in str(error)

    @staticmethod
    async def _create_initial_resource(
        cheqd_manager: CheqdDIDManager,
        options: ResourceCreateRequestOptions,
    ) -> Tuple[str, DidUrlActionState]:
        """Create the initial resource and get signing requests."""
        create_request_res = await cheqd_manager.registrar.create_resource(options)

        job_id = create_request_res.jobId
        resource_state = create_request_res.didUrlState

        if not resource_state:
            raise Exception("No signing requests available for update.")

        if not isinstance(resource_state, DidUrlActionState):
            raise AnonCredsRegistrationError(
                f"Unexpected resource state: {resource_state}"
            )

        if not resource_state.signingRequest:
            raise Exception("No signing requests available for update.")

        return job_id, resource_state

    @staticmethod
    async def _sign_and_publish_resource(
        cheqd_manager: CheqdDIDManager,
        wallet: BaseWallet,
        job_id: str,
        signing_requests: Dict[str, SigningRequest],
        options: ResourceCreateRequestOptions,
    ) -> PublishResourceResponse:
        """Sign the requests and publish the resource."""
        LOGGER.debug("Signing requests %s", signing_requests)
        signed_responses = await CheqdDIDManager.sign_requests(wallet, signing_requests)
        LOGGER.debug("Signed responses %s", signed_responses)

        LOGGER.debug("Publishing resource %s", options)
        publish_resource_res = await cheqd_manager.registrar.create_resource(
            SubmitSignatureOptions(
                jobId=job_id,
                secret=Secret(signingResponse=signed_responses),
                did=options.did,
            ),
        )

        resource_state = publish_resource_res.didUrlState

        if resource_state.state != "finished":
            LOGGER.error(
                "Error publishing Resource (not finished): "
                "state: %s, reason: %s, description: %s",
                resource_state.state,
                resource_state.reason,
                resource_state.description,
            )
            message = _get_error_message(resource_state)
            raise AnonCredsRegistrationError(f"Error publishing Resource: {message}")

        return PublishResourceResponse(
            content=resource_state.content,
            did_url=resource_state.didUrl,
        )

    @staticmethod
    async def _create_and_publish_resource(
        profile: Profile,
        registrar_url: str,
        resolver_url: str,
        options: ResourceCreateRequestOptions,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> PublishResourceResponse:
        """Create, Sign and Publish a Resource with retry for sequence mismatches."""
        cheqd_manager = CheqdDIDManager(profile, registrar_url, resolver_url)

        async with profile.session() as session:
            wallet = session.inject_or(BaseWallet)
            if not wallet:
                raise WalletError("No wallet available")

            retry_count = 0
            last_error = None

            while retry_count <= max_retries:
                try:
                    # Create initial resource and get signing requests
                    (
                        job_id,
                        resource_state,
                    ) = await DIDCheqdRegistry._create_initial_resource(
                        cheqd_manager, options
                    )

                    # Sign and publish the resource
                    return await DIDCheqdRegistry._sign_and_publish_resource(
                        cheqd_manager,
                        wallet,
                        job_id,
                        resource_state.signingRequest,
                        options,
                    )

                except AnonCredsRegistrationError as e:
                    last_error = e
                    if not DIDCheqdRegistry._should_retry(last_error):
                        LOGGER.error("Should not retry %s", last_error)
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
                            "Max retries exceeded for resource creation: %s",
                            str(last_error),
                        )
                        raise

                except Exception as e:
                    LOGGER.error("Unexpected error during resource creation: %s", str(e))
                    raise AnonCredsRegistrationError(str(e))

    @staticmethod
    async def _update_and_publish_resource(
        profile: Profile,
        registrar_url: str,
        resolver_url: str,
        options: ResourceUpdateRequestOptions,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> PublishResourceResponse:
        """Update, Sign and Publish a Resource with retry for sequence mismatches."""
        cheqd_manager = CheqdDIDManager(profile, registrar_url, resolver_url)
        async with profile.session() as session:
            wallet = session.inject_or(BaseWallet)
            if not wallet:
                raise WalletError("No wallet available")

            retry_count = 0
            last_error = None

            while retry_count <= max_retries:
                try:
                    # request update resource operation
                    LOGGER.debug("Updating resource %s", options)
                    updated_request_res = await cheqd_manager.registrar.update_resource(
                        options
                    )
                    LOGGER.debug("Updated resource %s", updated_request_res)

                    job_id: str = updated_request_res.jobId
                    resource_state = updated_request_res.didUrlState

                    if isinstance(resource_state, DidUrlActionState):
                        signing_requests = resource_state.signingRequest
                        if not signing_requests:
                            raise Exception("No signing requests available for update.")
                        # sign all requests
                        LOGGER.debug("Signing requests %s", signing_requests)
                        signed_responses = await CheqdDIDManager.sign_requests(
                            wallet, signing_requests
                        )
                        LOGGER.debug("Signed responses %s", signed_responses)
                        # publish resource
                        LOGGER.debug("Updating resource %s", options)
                        publish_resource_res = (
                            await cheqd_manager.registrar.update_resource(
                                SubmitSignatureOptions(
                                    jobId=job_id,
                                    secret=Secret(signingResponse=signed_responses),
                                    did=options.did,
                                ),
                            )
                        )
                        resource_state = publish_resource_res.didUrlState
                        LOGGER.debug("Resource state %s", resource_state)
                        if resource_state.state != "finished":
                            LOGGER.error(
                                "Error publishing Resource (bad state) %s", resource_state
                            )
                            message = _get_error_message(resource_state)
                            raise AnonCredsRegistrationError(
                                f"Error publishing Resource: {message}"
                            )
                        result = PublishResourceResponse(
                            content=resource_state.content,
                            did_url=resource_state.didUrl,
                        )
                        LOGGER.debug("Published resource %s", result)
                        return result
                    else:
                        LOGGER.error(
                            "Error publishing Resource (bad resource state) %s",
                            resource_state,
                        )
                        message = _get_error_message(resource_state)
                        raise AnonCredsRegistrationError(
                            f"Error publishing Resource: {message}"
                        )

                except AnonCredsRegistrationError as e:
                    last_error = e
                    if not DIDCheqdRegistry._should_retry(last_error):
                        LOGGER.error("Should not retry %s", last_error)
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
                            "Max retries exceeded for resource update: %s",
                            str(last_error),
                        )
                        raise

                except Exception as err:
                    LOGGER.error("Unexpected error during resource update: %s", str(err))
                    raise AnonCredsRegistrationError(f"{err}")


def _get_error_message(
    resource_state: DidUrlSuccessState | DidUrlActionState | DidUrlErrorState,
) -> str:
    return (
        resource_state.description
        if hasattr(resource_state, "description") and resource_state.description
        else resource_state.reason
    )
