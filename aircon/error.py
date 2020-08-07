# TODO make it parent of all exceptions and rename properlys
class Error(Exception):
    """Error class for AC handling."""

    pass


class AuthFailed(Exception):
    """Error class for invalid auth credentials"""

    pass


class NotAuthorized(Exception):
    """Error class for not authorized state"""

    pass


class AuthExpiring(Exception):
    """Authentication expired and needs to be refreshed"""

    pass


class NoDevicesConfigured(Exception):
    """Error class for case when user has no devies set up in the cloud"""

    pass


class KeyIdReplaced(Exception):
    """Error class for key id replacement"""

    def __init__(self, title, message):
        self.title = title
        self.message = message

