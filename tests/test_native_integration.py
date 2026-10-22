"""Native integration tests exercising the real compiled Go shared library over live TLS networks."""
import horaa_tls
import pytest
from horaa_tls.exceptions import BackendError
from horaa_tls.response import Protocol


@pytest.mark.integration
class TestNativeLiveTLS:
    def test_default_certificate_validation_fails_closed_on_bad_ssl(self):
        """Verifies that untrusted/self-signed certificates fail closed with BackendError by default."""
        session = horaa_tls.Session()
        try:
            with pytest.raises(BackendError):
                session.get("https://self-signed.badssl.com/")
        finally:
            session.close()

    def test_explicit_insecure_skip_verify_allows_self_signed(self):
        """Verifies that explicit insecure_skip_verify=True allows connection to self-signed endpoints."""
        session = horaa_tls.Session(insecure_skip_verify=True)
        try:
            r = session.get("https://self-signed.badssl.com/")
            assert r.status_code == 200
        finally:
            session.close()

    def test_protocol_negotiation_http2_vs_http1(self):
        """Verifies that default ALPN negotiates HTTP/2, and force_http1=True negotiates HTTP/1.1."""
        s_h2 = horaa_tls.Session(force_http1=False)
        try:
            r_h2 = s_h2.get("https://httpbin.org/get")
            assert r_h2.status_code == 200
            assert r_h2.used_protocol == Protocol.HTTP_2
            assert r_h2.protocol == Protocol.HTTP_2
        finally:
            s_h2.close()

        s_h1 = horaa_tls.Session(force_http1=True)
        try:
            r_h1 = s_h1.get("https://httpbin.org/get")
            assert r_h1.status_code == 200
            assert r_h1.used_protocol == Protocol.HTTP_1_1
            assert r_h1.protocol == Protocol.HTTP_1_1
        finally:
            s_h1.close()

    def test_native_response_streaming_direct_to_disk(self, tmp_path):
        """Verifies that stream_output_path streams directly into a local file via Go memory layer."""
        dest_file = tmp_path / "streamed_output.json"
        session = horaa_tls.Session()
        try:
            r = session.get(
                "https://httpbin.org/bytes/4096",
                stream_output_path=str(dest_file),
                stream_output_block_size=1024,
            )
            assert r.status_code == 200
            assert dest_file.exists()
            assert dest_file.stat().st_size == 4096
        finally:
            session.close()

    def test_http3_protocol_racing_and_proxy_guard(self):
        """Verifies that with_protocol_racing=True races HTTP/3 and guards against non-SOCKS5 proxy leaks."""
        # 1. Guard check: HTTP proxy with racing must raise BackendError
        with pytest.raises(BackendError) as exc_info:
            with horaa_tls.Session(proxy="http://127.0.0.1:8080", with_protocol_racing=True) as s:
                s.get("https://example.com")
        assert "SOCKS5 proxy" in str(exc_info.value)

        # 2. Live HTTP/3 negotiation check against http3.is
        with horaa_tls.Session(with_protocol_racing=True, timeout_seconds=20) as s:
            resp = s.get("https://http3.is/")
            assert resp.status_code == 200
            # Protocol racing can settle on HTTP/3 or HTTP/2 depending on network latency
            assert resp.protocol in (Protocol.HTTP_2, Protocol.HTTP_3)
