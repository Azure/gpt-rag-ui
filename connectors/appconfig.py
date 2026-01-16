import os
import logging

from typing import Dict, Any
from azure.identity import ChainedTokenCredential, ManagedIdentityCredential, AzureCliCredential
from azure.identity.aio import ChainedTokenCredential as AsyncChainedTokenCredential, ManagedIdentityCredential as AsyncManagedIdentityCredential, AzureCliCredential as AsyncAzureCliCredential
from azure.appconfiguration import AzureAppConfigurationClient
from azure.core.exceptions import AzureError, ClientAuthenticationError
from azure.appconfiguration.provider import (
    AzureAppConfigurationKeyVaultOptions,
    load,
    SettingSelector
)

from tenacity import retry, wait_random_exponential, stop_after_attempt, RetryError

class AppConfigClient:

    credential = None
    aiocredential = None

    def __init__(self):
        """
        Bulk-loads configuration keys into an in-memory dict.
        """
        # ==== Load all config parameters in one place ====
        try:
            self.tenant_id = os.environ.get('AZURE_TENANT_ID', "*")
        except Exception as e:
            raise e
        
        try:
            self.client_id = os.environ.get('AZURE_CLIENT_ID', "*")
        except Exception as e:
            raise e
        
        self.connected: bool = False

        endpoint = os.getenv("APP_CONFIG_ENDPOINT")

        # Local/dev friendly behavior: if endpoint is not provided, run with env vars only.
        if not endpoint:
            logging.getLogger("gpt_rag_ui.appconfig").warning(
                "APP_CONFIG_ENDPOINT is not set; running with environment variables only."
            )
            self.client = {}
            return

        self.credential = ChainedTokenCredential(
            ManagedIdentityCredential(client_id=self.client_id),
            AzureCliCredential()
        )
        self.aiocredential = AsyncChainedTokenCredential(
            AsyncManagedIdentityCredential(client_id=self.client_id),
            AsyncAzureCliCredential()
        )

        app_label_selector = SettingSelector(label_filter='gpt-rag-ui', key_filter='*')
        base_label_selector = SettingSelector(label_filter='gpt-rag', key_filter='*')
        no_label_selector = SettingSelector(label_filter=None, key_filter='*')

        logger = logging.getLogger("gpt_rag_ui.appconfig")

        try:
            logger.info(
                "Loading Azure App Configuration keys using labels: 'gpt-rag-ui', 'gpt-rag', and <no label>"
            )
            self.client = load(
                selects=[app_label_selector, base_label_selector, no_label_selector],
                endpoint=endpoint,
                credential=self.credential,
                key_vault_options=AzureAppConfigurationKeyVaultOptions(credential=self.credential),
            )
            self.connected = True
        except (ClientAuthenticationError, AzureError) as e:
            # Most common local dev issue: not logged in / no managed identity.
            logger.warning(
                "Azure App Configuration unavailable (auth/network). Running with env vars only. "
                "If using Azure CLI auth, run: az login. Error: %s",
                e,
            )
            self.client = {}
        except Exception as e:
            # Fallback: try connection string if provided, otherwise keep env-only.
            logger.warning(
                "Unable to connect to Azure App Configuration endpoint; trying connection string (if set). Error: %s",
                e,
            )
            try:
                connection_string = os.environ["AZURE_APPCONFIG_CONNECTION_STRING"]
                self.client = load(
                    connection_string=connection_string,
                    key_vault_options=AzureAppConfigurationKeyVaultOptions(credential=self.credential),
                )
                self.connected = True
            except Exception as e2:
                logger.warning(
                    "Azure App Configuration connection string not available/failed; running with env vars only. Error: %s",
                    e2,
                )
                self.client = {}


    def get(self, key: str, default: Any = None, type: type = str) -> Any:
        return self.get_value(key, default=default, allow_none=False, type=type)
    
    def get_value(self, key: str, default: str = None, allow_none: bool = False, type: type = str) -> str:

        if key is None:
            raise Exception('The key parameter is required for get_value().')

        value = None

        if value is None:
            try:
                value = self.get_config_with_retry(name=key)
            except Exception:
                # Config backend unavailable; rely on defaults/env vars.
                pass

        if value is not None:
            if type is not None:
                if type is bool:
                    if isinstance(value, str):
                        value = value.lower() in ['true', '1', 'yes']
                else:
                    try:
                        value = type(value)
                    except ValueError as e:
                        raise Exception(f'Value for {key} could not be converted to {type.__name__}. Error: {e}')
            return value
        else:
            if default is not None or allow_none is True:
                return default
            
            raise Exception(f'The configuration variable {key} not found.')
        
    def retry_before_sleep(self, retry_state):
        # Log the outcome of each retry attempt.
        message = f"""Retrying {retry_state.fn}:
                        attempt {retry_state.attempt_number}
                        ended with: {retry_state.outcome}"""
        if retry_state.outcome.failed:
            ex = retry_state.outcome.exception()
            message += f"; Exception: {ex.__class__.__name__}: {ex}"
        if retry_state.attempt_number < 1:
            logging.info(message)
        else:
            logging.warning(message)

    @retry(
        wait=wait_random_exponential(multiplier=1, max=5),
        stop=stop_after_attempt(5),
        before_sleep=retry_before_sleep
    )
    def get_config_with_retry(self, name):
        try:
            return self.client[name]
        except RetryError:
            pass

    # Helper functions for reading environment variables
    def read_env_variable(self, var_name, default=None):
        value = self.get_value(var_name, default)
        return value.strip() if value else default

    def read_env_list(self, var_name):
        value = self.get_value(var_name, "")
        return [item.strip() for item in value.split(",") if item.strip()]

    def read_env_boolean(self, var_name, default=False):
        value = self.get_value(var_name, str(default)).strip().lower()
        return value in ['true', '1', 'yes']