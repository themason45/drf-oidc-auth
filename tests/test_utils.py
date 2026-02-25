from random import random
from unittest import TestCase
from unittest.mock import patch, Mock, ANY

import oidc_auth.utils.caching as caching_mod
from oidc_auth.settings import api_settings
from oidc_auth.utils import cache


class TestCacheDecorator(TestCase):
    @cache(1)
    def mymethod(self, *args):
        return random()

    @cache(1)
    def failing(self):
        raise RuntimeError()

    @cache(0)
    def notcached(self):
        return random()

    @cache(1)
    def return_none(self):
        return None

    def test_that_result_of_method_is_memoized(self):
        x = self.mymethod('a')
        y = self.mymethod('b')
        self.assertEqual(x, self.mymethod('a'))
        self.assertEqual(y, self.mymethod('b'))
        self.assertNotEqual(x, y)

    def test_that_exceptions_are_raised(self):
        with self.assertRaises(RuntimeError):
            self.failing()

    def test_that_cache_is_disabled_with_low_ttl(self):
        x = self.notcached()
        # This will fail sometimes when the RNG returns two equal numbers...
        self.assertNotEqual(x, self.notcached())

    def test_that_cache_can_store_None(self):
        """None is stored in cache and the underlying function is not re-evaluated."""
        with patch('oidc_auth.utils.caching.caches') as mock_caches:
            mock_caches['default'].get.return_value = caching_mod._CACHE_MISS
            result = self.return_none()
            self.assertIsNone(result)
            # Verify None was written to the cache
            mock_caches['default'].set.assert_called_once()
            stored_value = mock_caches['default'].set.call_args[0][1]
            self.assertIsNone(stored_value)

    def test_that_none_result_is_cached(self):
        """A None return value is retrieved from cache on subsequent calls."""
        from django.core.cache import cache as django_cache
        django_cache.clear()

        counter = [0]

        class Subject:
            @cache(1)
            def get_none(self_inner):
                counter[0] += 1
                return None

        s = Subject()
        self.assertIsNone(s.get_none())
        self.assertIsNone(s.get_none())
        self.assertEqual(counter[0], 1, "Underlying function should only be called once")

    @patch('oidc_auth.utils.caching.caches')
    def test_uses_django_cache_uncached(self, caches):
        caches['default'].get.return_value = caching_mod._CACHE_MISS
        self.mymethod()
        caches['default'].get.assert_called_with(
            'oidc_auth.mymethod', caching_mod._CACHE_MISS, version=1)
        caches['default'].set.assert_called_with('oidc_auth.mymethod', ANY, timeout=1, version=1)

    @patch('oidc_auth.utils.caching.caches')
    def test_uses_django_cache_cached(self, caches):
        return_value = random()
        caches['default'].get.return_value = return_value
        self.assertEqual(return_value, self.mymethod())
        caches['default'].get.assert_called_with(
            'oidc_auth.mymethod', caching_mod._CACHE_MISS, version=1)
        self.assertFalse(caches['default'].set.called)

    @patch.object(api_settings, 'OIDC_CACHE_NAME', 'other')
    def test_respects_cache_name(self):
        caches = {
            'default': Mock(),
            'other': Mock(),
        }
        with patch('oidc_auth.utils.caching.caches', caches):
            self.mymethod()
            self.assertTrue(caches['other'].get.called)
            self.assertFalse(caches['default'].get.called)

    @patch.object(api_settings, 'OIDC_CACHE_PREFIX', 'some-other-prefix')
    @patch('oidc_auth.utils.caching.caches')
    def test_respects_cache_prefix(self, caches):
        caches['default'].get.return_value = caching_mod._CACHE_MISS
        self.mymethod()
        caches['default'].get.assert_called_once_with(
            'some-other-prefix.mymethod', caching_mod._CACHE_MISS, version=1)
        caches['default'].set.assert_called_once_with(
            'some-other-prefix.mymethod',
            ANY,
            timeout=1,
            version=1
        )
