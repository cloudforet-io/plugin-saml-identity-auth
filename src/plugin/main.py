from spaceone.identity.plugin.external_auth.lib.server import ExternalAuthPluginServer

from plugin.manager.external_auth_manager import ExternalAuthManager

app = ExternalAuthPluginServer()


@app.route("ExternalAuth.init")
def external_auth_init(params: dict) -> dict:
    """init plugin by options

    Args:
        params (ExternalAuthInitRequest): {
            'options': 'dict',    # Required
            'domain_id': 'str'    # Required
        }

    Returns:
        PluginResponse: {
            'metadata': 'dict'
        }
    """
    options = params["options"]

    external_auth_manager: ExternalAuthManager = ExternalAuthManager()
    metadata = external_auth_manager.init(options)

    return {"metadata": metadata}


@app.route("ExternalAuth.authorize")
def external_auth_authorize(params: dict) -> dict:
    """ExternalAuth authorize

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
        UserResponse: {
            'state': 'str',
            'user_id': 'str',
            'name': 'str',
            'email': 'str',
            'mobile': 'str',
            'group': 'str',
        }
    """
    external_auth_manager = ExternalAuthManager()

    return external_auth_manager.authorize(params)
