# `PublicKey`

Individual private key class.

### Serialization

`33`-byte or `65`-byte SEC serialization, depending on the `compressed` property.

For `pub.compressed = True` serialized as `33` bytes, first byte is `02` or `03` depending on the sign of the point, `1`-`33` bytes are `x`-coordinate of the point.

For `pub.compressed = False` serialized as `65` bytes, first byte is `04`, bytes `1`-`33` are `x`-coordinate of the point, bytes `34`-`65` are `y`-coordinate.

### String representation

Hex of SEC serialization.

### Constructor arguments
