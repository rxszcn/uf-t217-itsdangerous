from __future__ import annotations

import collections.abc as cabc
import typing as t
import zlib

from ._json import _CompactJSON
from .encoding import base64_decode
from .encoding import base64_encode
from .exc import BadPayload
from .exc import PayloadTooLarge
from .serializer import _PDataSerializer
from .serializer import Serializer
from .timed import TimedSerializer

if t.TYPE_CHECKING:
    from .signer import Signer

#: The default limit, in bytes, on the decompressed size of a payload.
#: Tokens are normally a few kilobytes at most, so this leaves a wide
#: margin while bounding how much memory a single token can allocate.
_DEFAULT_MAX_DECOMPRESS_SIZE = 1024 * 1024

#: Suffix added to the decompressor's ``max_length`` argument so that
#: producing one byte past the limit is enough to detect an overflow.
_OVERFLOW_PROBE = 1

#: Message used when the first zlib stream is incomplete.
_TRUNCATED_MESSAGE = "Error -5 while decompressing data: incomplete or truncated stream"


class _DecompressLimitExceeded(Exception):
    """Internal signal raised while streaming decompression reaches the
    configured limit. Converted to :exc:`.PayloadTooLarge` by
    :meth:`URLSafeSerializerMixin.load_payload`.
    """

    def __init__(self, limit: int) -> None:
        super().__init__(f"decompressed payload exceeds {limit} bytes")
        self.limit = limit


class URLSafeSerializerMixin(Serializer[str]):
    """Mixed in with a regular serializer it will attempt to zlib
    compress the string to make it shorter if necessary. It will also
    base64 encode the string so that it can safely be placed in a URL.

    The decompressed size of a payload is limited to
    ``max_decompress_size`` bytes. The limit is enforced while
    decompressing, so an oversized payload is rejected without being
    fully expanded in memory. As with :func:`zlib.decompress`, only the
    first stream in the payload is decoded, so data appended after it
    cannot add to the output.

    .. versionchanged:: 2.3
        Decompressed payloads are limited to 1 MiB by default. Pass
        ``max_decompress_size`` to change the limit, or ``None`` to
        disable it.
    """

    default_serializer: _PDataSerializer[str] = _CompactJSON

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None = b"itsdangerous",
        serializer: t.Any | None = None,
        serializer_kwargs: dict[str, t.Any] | None = None,
        signer: type[Signer] | None = None,
        signer_kwargs: dict[str, t.Any] | None = None,
        fallback_signers: list[
            dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
        ]
        | None = None,
        *,
        max_decompress_size: int | None = _DEFAULT_MAX_DECOMPRESS_SIZE,
    ) -> None:
        super().__init__(
            secret_key=secret_key,
            salt=salt,
            serializer=serializer,
            serializer_kwargs=serializer_kwargs,
            signer=signer,
            signer_kwargs=signer_kwargs,
            fallback_signers=fallback_signers,
        )

        if max_decompress_size is not None and max_decompress_size < 0:
            raise ValueError("max_decompress_size must be None or non-negative")

        #: The maximum number of bytes a compressed payload may
        #: decompress to. ``None`` means no limit.
        self.max_decompress_size: int | None = max_decompress_size

    def load_payload(
        self,
        payload: bytes,
        *args: t.Any,
        serializer: t.Any | None = None,
        **kwargs: t.Any,
    ) -> t.Any:
        decompress = False

        if payload.startswith(b"."):
            payload = payload[1:]
            decompress = True

        try:
            json = base64_decode(payload)
        except Exception as e:
            raise BadPayload(
                "Could not base64 decode the payload because of an exception",
                original_error=e,
            ) from e

        if decompress:
            try:
                json = _decompress(json, self.max_decompress_size)
            except _DecompressLimitExceeded as e:
                raise PayloadTooLarge(
                    "Could not zlib decompress the payload because the"
                    " decompressed size exceeds the configured limit",
                    original_error=e,
                    limit=e.limit,
                ) from e
            except Exception as e:
                raise BadPayload(
                    "Could not zlib decompress the payload before decoding the payload",
                    original_error=e,
                ) from e

        return super().load_payload(json, *args, **kwargs)

    def dump_payload(self, obj: t.Any) -> bytes:
        json = super().dump_payload(obj)
        is_compressed = False
        compressed = zlib.compress(json)

        if len(compressed) < (len(json) - 1):
            json = compressed
            is_compressed = True

        base64d = base64_encode(json)

        if is_compressed:
            base64d = b"." + base64d

        return base64d


def _decompress(data: bytes, max_size: int | None) -> bytes:
    """Decompress a zlib stream, optionally limiting the output size."""
    if max_size is None:
        # Restore the previous unbounded behavior for callers that opt
        # out of the limit: only the first stream is decompressed, and
        # any trailing data is ignored, exactly like zlib.decompress.
        return zlib.decompress(data)

    return _decompress_limited(data, max_size)


def _decompress_limited(data: bytes, max_size: int) -> bytes:
    """Decompress a zlib stream, never producing more than ``max_size``
    bytes of output.

    Only the first stream is decompressed, exactly like
    :func:`zlib.decompress`; anything after it is ignored and never
    expanded, so concatenated streams cannot add to the output. Output
    is pulled in bounded steps with ``max_length``, so a payload is cut
    off at the limit instead of being expanded in full first. If the
    limit is exceeded, :exc:`_DecompressLimitExceeded` is raised; a
    malformed or truncated stream raises :exc:`zlib.error`.
    """
    decompressor = zlib.decompressobj()
    chunks: list[bytes] = []
    size = 0

    while True:
        chunk = decompressor.decompress(data, max_size - size + _OVERFLOW_PROBE)

        if chunk:
            size += len(chunk)

            if size > max_size:
                raise _DecompressLimitExceeded(max_size)

            chunks.append(chunk)

        if decompressor.eof:
            return b"".join(chunks)

        tail = decompressor.unconsumed_tail

        if not tail:
            raise zlib.error(_TRUNCATED_MESSAGE)

        data = tail


class URLSafeSerializer(URLSafeSerializerMixin, Serializer[str]):
    """Works like :class:`.Serializer` but dumps and loads into a URL
    safe string consisting of the upper and lowercase character of the
    alphabet as well as ``'_'``, ``'-'`` and ``'.'``.
    """


class URLSafeTimedSerializer(URLSafeSerializerMixin, TimedSerializer[str]):
    """Works like :class:`.TimedSerializer` but dumps and loads into a
    URL safe string consisting of the upper and lowercase character of
    the alphabet as well as ``'_'``, ``'-'`` and ``'.'``.
    """
