from typing import TypedDict, Literal


class BaseIntrospectionResult(TypedDict):
    active: bool
    """
    (required) Whether the token is active or not.
    """
    scope: str | None
    """
    (optional) The scopes of the token.
    
    This is a space separated string.
    """
    client_id: str | None
    """
    (optional) The client ID of the application from whence the token came.
    
    This client_id is unlikely to be the same as the client_id of the app performing the introspection request
    """
    username: str | None
    """
    (optional) The username of the user who owns the token..
    """
    token_type: Literal["bearer", "Bearer", "mac", "MAC"] | None
    """
    (optional) The type of the token.
    """
    exp: int | None
    """
    (optional) The expiration time of the token as a unix timestamp (seconds).
    """
    iat: int | None
    """
    (optional) The time at which the token was issued as a unix timestamp (seconds).
    """
    nbf: int | None
    """
    (optional) The time before which the token is not to be accepted for processing as a unix timestamp (seconds).
    """
    sub: str | None
    """
    (optional) The subject of the token. Usually a username or user ID
    """
    aud: str | list[str] | None
    """
    (optional) The audience of the token. Usually the client ID of the audience application, or client IDs of the audience applications.
    """
    iss: str | None
    """
    (optional) The issuer of the token. Usually the URL of the IdP server.
    """
    jti: str | None
    """
    (optional) The unique identifier of the token.
    """
