from collections.abc import Iterator
from azure.storage.blob import ContainerClient, BlobServiceClient, generate_blob_sas, BlobSasPermissions
from azure.identity import ManagedIdentityCredential, AzureCliCredential, ChainedTokenCredential
from azure.core.exceptions import ResourceNotFoundError, AzureError
from urllib.parse import urlparse, unquote, quote
import logging
import os
import time
from datetime import datetime, timedelta, timezone

class BlobClient:
    def __init__(self, blob_url, credential=None):
        """
        Initialize BlobClient with a specific blob URL.
        
        :param blob_url: URL of the blob (e.g., "https://mystorage.blob.core.windows.net/mycontainer/myblob.png")
        :param credential: Credential for authentication (optional)
        """
        # 1. Generate the credential in case it is not provided 
        self.credential = self._get_credential(credential)
        self.file_url = blob_url
        self.blob_service_client = None

        # 2. Parse the blob URL => account_url, container_name, blob_name
        try:
            parsed_url = urlparse(self.file_url)
            self.account_url = f"{parsed_url.scheme}://{parsed_url.netloc}"   # e.g. https://mystorage.blob.core.windows.net
            self.container_name = parsed_url.path.split("/")[1]              # e.g. 'mycontainer'
            # Blob name is everything after "/{container_name}/"
            self.blob_name = unquote(parsed_url.path[len(f"/{self.container_name}/"):])
            logging.debug(f"[blob][{self.blob_name}] Parsed blob URL successfully.")
        except Exception as e:
            logging.error(f"[blob] Invalid blob URL '{self.file_url}': {e}")
            raise EnvironmentError(f"Invalid blob URL '{self.file_url}': {e}")

        # 3. Initialize the BlobServiceClient
        try:
            self.blob_service_client = BlobServiceClient(
                account_url=self.account_url, 
                credential=self.credential
            )
            logging.debug(f"[blob][{self.blob_name}] Initialized BlobServiceClient.")
        except Exception as e:
            logging.error(f"[blob][{self.blob_name}] Failed to initialize BlobServiceClient: {e}")
            raise

    def _get_credential(self, credential):
        """
        Get the appropriate credential for authentication.
        
        :param credential: Credential for authentication (optional)
        :return: Credential object
        """
        if credential is None:
            try:
                client_id = os.environ.get("AZURE_CLIENT_ID", None)
                credential = ChainedTokenCredential(
                    ManagedIdentityCredential(client_id=client_id),
                    AzureCliCredential()
                )
                logging.debug("[blob] Initialized ChainedTokenCredential with ManagedIdentityCredential and AzureCliCredential.")
            except Exception as e:
                logging.error(f"[blob] Failed to initialize ChainedTokenCredential: {e}")
                raise
        else:
            logging.debug("[blob] Initialized BlobClient with provided credential.")
        return credential

    def download_blob(self):
        """
        Downloads the blob data from Azure Blob Storage.

        Returns:
            bytes: The content of the blob.

        Raises:
            Exception: If downloading the blob fails.
        """
        blob_client = self.blob_service_client.get_blob_client(container=self.container_name, blob=self.blob_name)

        try:
            logging.debug(f"[blob][{self.blob_name}] Attempting to download blob.")
            data = blob_client.download_blob().readall()
            logging.info(f"[blob][{self.blob_name}] Blob downloaded successfully.")
            return data
        except ResourceNotFoundError:
            logging.info(
                f"[blob][{self.blob_name}] Blob was not found during download."
            )
            raise
        except Exception as e:
            logging.error(f"[blob][{self.blob_name}] Failed to download blob: {e}")
            raise Exception(f"Blob client error when reading from blob storage: {e}")

    def download_blob_chunks(self) -> tuple[Iterator[bytes], int]:
        """Open the blob as a lazy chunk iterator without buffering it."""

        blob_client = self.blob_service_client.get_blob_client(
            container=self.container_name,
            blob=self.blob_name,
        )
        try:
            downloader = blob_client.download_blob()
            logging.info(
                "[blob][%s] Blob download stream opened successfully.",
                self.blob_name,
            )
            return downloader.chunks(), downloader.size
        except ResourceNotFoundError:
            logging.info(
                "[blob][%s] Blob was not found during stream setup.",
                self.blob_name,
            )
            raise
        except Exception as exc:
            logging.error(
                "[blob][%s] Failed to open blob download stream: %s",
                self.blob_name,
                exc,
            )
            raise RuntimeError(
                "Blob client error when streaming from blob storage."
            ) from exc

    def exists(self) -> bool:
        """Check whether the target blob exists."""
        blob_client = self.blob_service_client.get_blob_client(
            container=self.container_name,
            blob=self.blob_name,
        )
        try:
            blob_client.get_blob_properties()
            return True
        except ResourceNotFoundError:
            logging.debug(f"[blob][{self.blob_name}] Blob not found during existence check.")
            return False
        except AzureError as exc:
            logging.error(f"[blob][{self.blob_name}] Failed to verify blob existence: {exc}")
            raise

    def generate_sas_url(self, expiry: datetime = None, permissions: str = "r") -> str:
        """
        Generate a SAS URL for the blob using user delegation key (works with Managed Identity).
        
        :param expiry: Expiration datetime for the SAS token (default: 1 hour from now)
        :param permissions: Permissions for the SAS token (default: 'r' for read)
        :return: Full blob URL with SAS token
        """
        if expiry is None:
            expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        
        start_time = datetime.now(timezone.utc) - timedelta(minutes=5)  # Start 5 min ago to avoid clock skew
        
        try:
            # Get user delegation key (works with Managed Identity/AAD)
            user_delegation_key = self.blob_service_client.get_user_delegation_key(
                key_start_time=start_time,
                key_expiry_time=expiry
            )
            
            # Generate SAS token
            sas_token = generate_blob_sas(
                account_name=self.blob_service_client.account_name,
                container_name=self.container_name,
                blob_name=self.blob_name,
                user_delegation_key=user_delegation_key,
                permission=BlobSasPermissions(read=True),
                expiry=expiry,
                start=start_time
            )
            
            # Construct full URL with SAS - properly URL-encode the blob name
            # The blob_name is already unquoted from the constructor, so we need to re-encode it
            encoded_blob_name = quote(self.blob_name, safe='/')
            sas_url = f"{self.account_url}/{self.container_name}/{encoded_blob_name}?{sas_token}"
            logging.debug(f"[blob][{self.blob_name}] Generated SAS URL (expires: {expiry})")
            return sas_url
            
        except Exception as e:
            logging.error(f"[blob][{self.blob_name}] Failed to generate SAS URL: {e}")
            # Fallback: return properly encoded URL (will only work if blob is public or client has auth)
            encoded_blob_name = quote(self.blob_name, safe='/')
            return f"{self.account_url}/{self.container_name}/{encoded_blob_name}"

class BlobContainerClient:
    def __init__(self, storage_account_base_url, container_name, credential=None):
        """
        Initialize BlobContainerClient with the storage account base URL and container name.
        
        :param storage_account_base_url: Base URL of the storage account (e.g., "https://mystorage.blob.core.windows.net")
        :param container_name: Name of the container
        :param credential: Credential for authentication (optional)
        """
        try:
            self.credential = self._get_credential(credential)
            self.container_client = ContainerClient(
                account_url=storage_account_base_url,
                container_name=container_name,
                credential=self.credential
            )
            # Verify the container exists
            self.container_client.get_container_properties()
            logging.debug(f"[blob] Connected to container '{container_name}'.")
        except ResourceNotFoundError:
            logging.error(f"[blob] Container '{container_name}' does not exist.")
            raise
        except AzureError as e:
            logging.error(f"[blob] Failed to connect to container: {e}")
            raise


    def _get_credential(self, credential):
        """
        Get the appropriate credential for authentication.
        
        :param credential: Credential for authentication (optional)
        :return: Credential object
        """
        if credential is None:
            try:
                credential = ChainedTokenCredential(
                    ManagedIdentityCredential(),
                    AzureCliCredential()
                )
                logging.debug("[blob] Initialized ChainedTokenCredential with ManagedIdentityCredential and AzureCliCredential.")
            except Exception as e:
                logging.error(f"[blob] Failed to initialize ChainedTokenCredential: {e}")
                raise
        else:
            logging.debug("[blob] Initialized BlobClient with provided credential.")
        return credential

    def upload_blob(self, blob_name, file_path, overwrite=False):
        """
        Upload a local file to a blob within the container.
        
        :param blob_name: Name of the blob
        :param file_path: Path to the local file to upload
        :param overwrite: Whether to overwrite the blob if it already exists
        """
        try:
            blob_client = self.container_client.get_blob_client(blob_name)
            with open(file_path, "rb") as data:
                blob_client.upload_blob(data, overwrite=overwrite)
            logging.info(f"[blob] Uploaded '{file_path}' as blob '{blob_name}'.")
        except AzureError as e:
            logging.info(f"[blob] Failed to upload blob '{blob_name}': {e}")

    def download_blob(self, blob_name, download_file_path):
        """
        Download a blob from the container to a local file.
        
        :param blob_name: Name of the blob
        :param download_file_path: Path to the local file where the blob will be downloaded
        """
        try:
            blob_client = self.container_client.get_blob_client(blob_name)
            with open(download_file_path, "wb") as download_file:
                download_stream = blob_client.download_blob()
                download_file.write(download_stream.readall())
            logging.info(f"[blob] Downloaded blob '{blob_name}' to '{download_file_path}'.")
        except ResourceNotFoundError:
            logging.info(f"[blob] Blob '{blob_name}' not found in container '{self.container_client.container_name}'.")
        except AzureError as e:
            logging.info(f"[blob] Failed to download blob '{blob_name}': {e}")

    def delete_blob(self, blob_name):
        """
        Delete a blob from the container.
        
        :param blob_name: Name of the blob to delete
        """
        try:
            blob_client = self.container_client.get_blob_client(blob_name)
            blob_client.delete_blob()
            logging.info(f"[blob] Deleted blob '{blob_name}' from container '{self.container_client.container_name}'.")
        except ResourceNotFoundError:
            logging.info(f"[blob] Blob '{blob_name}' not found in container '{self.container_client.container_name}'.")
        except AzureError as e:
            logging.info(f"[blob] Failed to delete blob '{blob_name}': {e}")

    def list_blobs(self):
        """
        List all blobs in the container.
        
        :return: List of blob names
        """
        try:
            blobs = self.container_client.list_blobs()
            blob_names = [blob.name for blob in blobs]
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.debug(f"Blobs in container '{self.container_client.container_name}':")
                for name in blob_names:
                    logging.debug(f" - {name}")
            return blob_names
        except AzureError as e:
            logging.info(f"[blob] Failed to list blobs: {e}")
            return []
