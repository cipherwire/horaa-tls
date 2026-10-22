from typing import Any

# Real Chrome sends Client Hints first, then Upgrade-Insecure-Requests,
# User-Agent, Accept, the Sec-Fetch-* block, then encoding/language. Firefox
# leads with User-Agent. HTTP/2 pseudo-header order is the canonical
# :method, :scheme, :authority, :path for every major browser.
_CHROME_HEADER_ORDER = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
]
_FIREFOX_HEADER_ORDER = [
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "upgrade-insecure-requests",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
]
_SAFARI_HEADER_ORDER = [
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
]
_DEFAULT_PSEUDO_HEADER_ORDER = [":method", ":scheme", ":authority", ":path"]


class UserAgentGenerator:
    """
    Generates aligned User-Agents, default headers, and Client Hints (Sec-Ch-Ua)
    corresponding to specific browser TLS Client Profiles.
    """

    # Static map containing header templates and user agents for each profile
    PROFILE_HEADERS: dict[str, dict[str, Any]] = {
        "chrome_103": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Ch-Ua": '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
            },
        "header_order": _CHROME_HEADER_ORDER,
        "pseudo_header_order": _DEFAULT_PSEUDO_HEADER_ORDER,
        },
        "chrome_110": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Ch-Ua": '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
            },
        "header_order": _CHROME_HEADER_ORDER,
        "pseudo_header_order": _DEFAULT_PSEUDO_HEADER_ORDER,
        },
        "chrome_120": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
            },
        "header_order": _CHROME_HEADER_ORDER,
        "pseudo_header_order": _DEFAULT_PSEUDO_HEADER_ORDER,
        },
        "chrome_133": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Ch-Ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
            },
        "header_order": _CHROME_HEADER_ORDER,
        "pseudo_header_order": _DEFAULT_PSEUDO_HEADER_ORDER,
        },
        "firefox_117": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            },
        "header_order": _FIREFOX_HEADER_ORDER,
        "pseudo_header_order": _DEFAULT_PSEUDO_HEADER_ORDER,
        },
        "firefox_123": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/123.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            },
        "header_order": _FIREFOX_HEADER_ORDER,
        "pseudo_header_order": _DEFAULT_PSEUDO_HEADER_ORDER,
        },
        "firefox_133": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/133.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            },
        "header_order": _FIREFOX_HEADER_ORDER,
        "pseudo_header_order": _DEFAULT_PSEUDO_HEADER_ORDER,
        },
        "safari_16_0": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            },
        "header_order": _SAFARI_HEADER_ORDER,
        "pseudo_header_order": _DEFAULT_PSEUDO_HEADER_ORDER,
        },
        "safari_ios_17_0": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/605.1.15",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            },
        "header_order": _SAFARI_HEADER_ORDER,
        "pseudo_header_order": _DEFAULT_PSEUDO_HEADER_ORDER,
        },
        "opera_90": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36 OPR/90.0.4480.84",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Ch-Ua": '"Chromium";v="104", "Not A(Brand";v="24", "Opera";v="90"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
            },
        "header_order": _CHROME_HEADER_ORDER,
        "pseudo_header_order": _DEFAULT_PSEUDO_HEADER_ORDER,
        },
    }

    @classmethod
    def generate_headers_for_profile(cls, profile: str) -> dict[str, str]:
        """
        Retrieves matching default headers and User-Agent/Client-Hints for the profile.
        Falls back to a standard Chrome 120 profile if the profile is unrecognized.
        """
        normalized_profile = profile.lower()
        profile_data = cls.PROFILE_HEADERS.get(normalized_profile)

        if not profile_data:
            # Standard Chrome 120 fallback
            profile_data = cls.PROFILE_HEADERS["chrome_120"]

        return dict(profile_data["headers"])

    @classmethod
    def _resolve_profile_data(cls, profile: str) -> dict[str, Any]:
        return cls.PROFILE_HEADERS.get(profile.lower(), cls.PROFILE_HEADERS["chrome_120"])

    @classmethod
    def get_header_order_for_profile(cls, profile: str) -> list[str] | None:
        """
        Returns the default HTTP header order for the profile (header names the
        profile actually sends, in real browser order). Anti-bot engines treat
        header order as a fingerprint signal, so it must match the browser.
        """
        return list(cls._resolve_profile_data(profile).get("header_order", [])) or None

    @classmethod
    def get_pseudo_header_order_for_profile(cls, profile: str) -> list[str] | None:
        """Returns the HTTP/2 pseudo-header (":method" etc.) order for the profile."""
        return list(cls._resolve_profile_data(profile).get("pseudo_header_order", [])) or None
