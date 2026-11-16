import zlib
from functools import partial
from tracemalloc import get_traced_memory
from tracemalloc import start as start_tracemalloc
from tracemalloc import stop as stop_tracemalloc

import pytest

from itsdangerous.encoding import base64_encode
from itsdangerous.exc import BadPayload
from itsdangerous.exc import PayloadTooLarge
from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous.url_safe import URLSafeTimedSerializer
from test_itsdangerous.test_serializer import TestSerializer
from test_itsdangerous.test_timed import TestTimedSerializer

_SERIALIZERS = (URLSafeSerializer, URLSafeTimedSerializer)


def sign_compressed(serializer, raw: bytes) -> bytes:
    """Sign a compressed payload, bypassing ``dumps`` so tests can build
    payloads that the serializer itself would never produce.
    """
    return serializer.make_signer().sign(b"." + base64_encode(zlib.compress(raw)))


def compressed_payload(raw: bytes) -> bytes:
    return b"." + base64_encode(zlib.compress(raw))


class TestURLSafeSerializer(TestSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(URLSafeSerializer, secret_key="secret-key")

    @pytest.fixture(params=({"id": 42}, pytest.param("a" * 1000, id="zlib")))
    def value(self, request):
        return request.param


class TestURLSafeTimedSerializer(TestURLSafeSerializer, TestTimedSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(URLSafeTimedSerializer, secret_key="secret-key")


@pytest.mark.parametrize("serializer_cls", _SERIALIZERS)
class TestDecompressLimit:
    def test_default(self, serializer_cls):
        assert serializer_cls("secret-key").max_decompress_size == 1024 * 1024

    def test_uncompressed_payload_unchanged(self, serializer_cls):
        serializer = serializer_cls("secret-key")
        signed = serializer.dumps({"id": 42})
        assert not signed.startswith(".")
        assert serializer.loads(signed) == {"id": 42}

    def test_compressed_payload_unchanged(self, serializer_cls):
        serializer = serializer_cls("secret-key")
        signed = serializer.dumps("a" * 1000)
        assert signed.startswith(".")
        assert serializer.loads(signed) == "a" * 1000

    def test_at_limit(self, serializer_cls):
        # The JSON form of the value is the quoted string, two bytes longer.
        value = "a" * 999
        serializer = serializer_cls("secret-key", max_decompress_size=1001)
        signed = serializer.dumps(value)
        assert serializer.loads(signed) == value

        serializer = serializer_cls("secret-key", max_decompress_size=1000)

        with pytest.raises(PayloadTooLarge):
            serializer.loads(signed)

    def test_over_limit(self, serializer_cls):
        serializer = serializer_cls("secret-key", max_decompress_size=1000)
        payload = compressed_payload(b'"' + b"a" * 1000 + b'"')

        with pytest.raises(PayloadTooLarge) as exc_info:
            serializer.load_payload(payload)

        assert exc_info.value.limit == 1000
        assert exc_info.value.original_error is not None
        assert isinstance(exc_info.value, BadPayload)

    def test_compressed_bomb_rejected(self, serializer_cls):
        serializer = serializer_cls("secret-key", max_decompress_size=1024)
        raw = b"a" * (64 * 1024 * 1024)
        payload = compressed_payload(raw)
        # The attack works precisely because the compressed form is tiny.
        assert len(payload) < 100_000
        assert len(raw) > 500 * len(payload)

        with pytest.raises(PayloadTooLarge) as exc_info:
            serializer.loads(serializer.make_signer().sign(payload))

        # The stream was stopped at the limit rather than expanded first.
        assert "1024" in str(exc_info.value.original_error)

    def test_bomb_is_stopped_while_streaming(self, serializer_cls):
        # Expanding the bomb before checking the limit would allocate
        # at least 64 MiB. The guard must stop near 1 MiB instead.
        serializer = serializer_cls("secret-key", max_decompress_size=1024 * 1024)
        payload = compressed_payload(b"a" * (64 * 1024 * 1024))

        start_tracemalloc()

        try:
            with pytest.raises(PayloadTooLarge):
                serializer.load_payload(payload)

            _, peak = get_traced_memory()
        finally:
            stop_tracemalloc()

        assert peak < 16 * 1024 * 1024

    def test_uncompressed_payload_ignores_limit(self, serializer_cls):
        # The limit only guards decompression; uncompressed payloads are
        # unchanged even when the limit is smaller than the payload.
        serializer = serializer_cls("secret-key", max_decompress_size=0)
        assert serializer.loads(serializer.dumps({"id": 42})) == {"id": 42}

    def test_trailing_data_ignored(self, serializer_cls):
        # Matches zlib.decompress, which stops after the first complete
        # stream instead of failing on trailing bytes.
        serializer = serializer_cls("secret-key")
        payload = b"." + base64_encode(zlib.compress(b'"abc"') + b"garbage")
        assert serializer.load_payload(payload) == "abc"

    def test_appended_stream_not_expanded(self, serializer_cls):
        # Only the first stream is decoded, as with zlib.decompress. A
        # second stream can neither add to the output nor smuggle a
        # large payload past the limit.
        serializer = serializer_cls("secret-key", max_decompress_size=100)
        bomb = zlib.compress(b"a" * (64 * 1024 * 1024))
        payload = b"." + base64_encode(zlib.compress(b'"abc"') + bomb)

        assert serializer.load_payload(payload) == "abc"

    def test_truncated_stream_is_bad_payload(self, serializer_cls):
        serializer = serializer_cls("secret-key", max_decompress_size=1000)
        compressed = zlib.compress(b'"' + b"a" * 100 + b'"')
        payload = b"." + base64_encode(compressed[:-4])

        with pytest.raises(BadPayload) as exc_info:
            serializer.load_payload(payload)

        assert not isinstance(exc_info.value, PayloadTooLarge)
        assert exc_info.value.original_error is not None

    def test_limit_can_be_disabled(self, serializer_cls):
        serializer = serializer_cls("secret-key", max_decompress_size=None)
        assert serializer.max_decompress_size is None
        signed = serializer.dumps("a" * 100_000)
        assert serializer.loads(signed) == "a" * 100_000

    def test_negative_limit_rejected(self, serializer_cls):
        with pytest.raises(ValueError):
            serializer_cls("secret-key", max_decompress_size=-1)

    def test_signed_token_over_limit(self, serializer_cls):
        serializer = serializer_cls("secret-key", max_decompress_size=100)

        with pytest.raises(PayloadTooLarge):
            serializer.loads(sign_compressed(serializer, b"x" * 1000))
