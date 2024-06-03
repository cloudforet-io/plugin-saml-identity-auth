from spaceone.core.manager import BaseManager

from plugin.connector.saml_connector import SamlConnector


class ExternalAuthManager(BaseManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.saml_connector: SamlConnector = SamlConnector()

    def init(self, options: dict) -> dict:
        """Check SAML connection using Metadata URL

        Args:
            options:
              'protocol': 'str',
              'identity_provider': 'str',
              'icon': 'str',
              'metadata_url': 'str',
              'sp_metadata_url': 'str',

        Returns:
            'metadata': 'dict'
        """
        metadata = self.saml_connector.init(options)

        return metadata

    def authorize(self, params: dict) -> dict:
        """Get access_token from credentials

        Args:
            params (ExternalAuthAuthorizeRequest): {
                'options': 'dict',          # Required
                'schema_id': 'str',
                'secret_data': 'dict',      # Required
                'credentials': 'dict',      # Required
                'domain_id': 'str'          # Required
                'metadata': 'dict'
            }
        Returns:
            'user_info': 'dict'
        """
        credentials = params["credentials"]
        metadata_url = params["options"].get("metadata_url")
        sp_metadata_url = params["options"].get("sp_metadata_url")
        domain_id = params["domain_id"]
        user_info = self.saml_connector.authorize(
            credentials, metadata_url, sp_metadata_url, domain_id
        )

        return user_info
