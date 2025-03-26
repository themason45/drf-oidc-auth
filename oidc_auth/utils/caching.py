import functools
from typing import Literal, Optional, Any

from django.core.cache import caches

from oidc_auth.settings import api_settings

TokenType = Literal["Bearer", "JWT"]


def get_cache_key(token_type: TokenType, token_id: str) -> str:
    """
    Get the cache key for a token.
    This will group by the type, and store against the token's ID.

    In the case of Bearer tokens, best practice would be to hash the token's value and
    use that as the ID as the token is considered confidential. In the case of a leak from the cache provider, the
    token will be protected this way.
    """
    return f"{api_settings.OIDC_CACHE_PREFIX}.{token_type}/{token_id}"


def get_cached_value(cache_key: str) -> Optional[Any]:
    """
    Get the value from the Django cache specified by the OIDC_CACHE_NAME setting.

    :param cache_key: The key to look up
    :return: The cached value
    """
    current_cache = caches[api_settings.OIDC_CACHE_NAME]
    return current_cache.get(cache_key)


def set_cache_value(cache_key: str, value: str, ttl: Optional[int] = None) -> None:
    """
    Set the value associated with the cache key in the Django cache specified
    by the OIDC_CACHE_NAME setting.

    :param cache_key: The key to store the value against.
    :param value: The value to store.
    :param ttl: The time-to-live for the cache entry in seconds.
    """
    current_cache = caches[api_settings.OIDC_CACHE_NAME]
    current_cache.set(cache_key, value, timeout=ttl)


# noinspection PyPep8Naming
class cache(object):
    """ Cache decorator that memoizes the return value of a method for some time.

    Increment the cache_version everytime your method's implementation changes
    in such a way that it returns values that are not backwards compatible.
    For more information, see the Django cache documentation:
    https://docs.djangoproject.com/en/2.2/topics/cache/#cache-versioning
    """

    def __init__(self, ttl, cache_version=1):
        self.ttl = ttl
        self.cache_version = cache_version

    def __call__(self, fn):
        @functools.wraps(fn)
        def wrapped(this, *args):
            cache = caches[api_settings.OIDC_CACHE_NAME]
            key = api_settings.OIDC_CACHE_PREFIX + '.'.join([fn.__name__] + list(map(str, args)))
            cached_value = cache.get(key, version=self.cache_version)
            if not cached_value:
                cached_value = fn(this, *args)
                cache.set(key, cached_value, timeout=self.ttl, version=self.cache_version)
            return cached_value

        return wrapped
