# pylint: disable=super-init-not-called


class TapSalesforceExceptionError(Exception):
    pass


class TapSalesforceQuotaExceededError(TapSalesforceExceptionError):
    pass


class SFDCCustomNotAcceptableError(Exception):
    """
    SFDC returned CustomNotAcceptable error with HTTP Error code 406.

    This error is sometimes returned when many discovery calls are made
    in quick succession. There does not seem to be documentation on this error
    on any salesforce documentation page or forum.
    Example Error Message:
    ```
    requests.exceptions.HTTPError: 406 Client Error: CustomNotAcceptable for
    url: https://XXX.salesforce.com/services/data/v53.0/sobjects/XXX/describe
    """


class SFDCServiceUnavailableError(Exception):
    """
    SFDC returned HTTP 503 Service Unavailable.

    Usually means the org tripped a concurrent-request limit or is under
    transient platform throttling. Retryable with exponential backoff.
    """
