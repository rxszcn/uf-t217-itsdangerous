.. module:: itsdangerous.url_safe

URL Safe Serialization
======================

Often it is helpful if you can pass these trusted strings in places
where you only have a limited set of characters available. Because of
this, ItsDangerous also provides URL safe serializers:

.. code-block:: python

    from itsdangerous.url_safe import URLSafeSerializer
    s = URLSafeSerializer("secret-key")
    s.dumps([1, 2, 3, 4])
    'WzEsMiwzLDRd.wSPHqC0gR7VUqivlSukJ0IeTDgo'
    s.loads("WzEsMiwzLDRd.wSPHqC0gR7VUqivlSukJ0IeTDgo")
    [1, 2, 3, 4]

Larger values are compressed with zlib before being signed. Because a
token is untrusted input, the decompressed size is limited to 1 MiB by
default. The limit is applied while decompressing, so a small token
that would expand to much more data raises :exc:`.PayloadTooLarge`
without being expanded in memory. As with :func:`zlib.decompress`, only
the first compressed stream in a payload is read, so data appended
after it is ignored. Set ``max_decompress_size`` to a different size,
or to ``None`` to disable the limit.

.. code-block:: python

    s = URLSafeSerializer("secret-key", max_decompress_size=64 * 1024)

.. autoclass:: URLSafeSerializer

.. autoclass:: URLSafeTimedSerializer
