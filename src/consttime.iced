
exports.is_zero = is_zero = (x) ->
  x = x | 0

  # For nonzero x, either x or -x has the high bit set.
  # For zero, both are zero.So (x | -x) >>> 31 becomes 1.
  # For zero, both x and -x are zero, so it becomes 0.
  # The ^ 1 flips that result.
  (((x | -x) >>> 31) ^ 1) | 0

exports.eq_byte = eq_byte = (a, b) ->
  is_zero(((a ^ b) & 0xff) | 0)

exports.eq_int = eq_int = (a, b) ->
  is_zero(((a | 0) ^ (b | 0)) | 0)

# Normalize x to exactly 0 or 1
exports.normalize = normalize = (x) ->
  if x then 1 else 0

# select_byte returns x if v == 1 and y if v == 0.
# Its behavior is undefined if v takes any other value.
exports.select_byte = select_byte = (v, x, y) ->
  mask = -v | 0 # 1 -> -1 (0xffffffff); 0 -> 0

  rb = x & 0xff
  fb = y & 0xff # "fallback"

  (fb ^ (mask & (fb ^ rb))) & 0xff

# select_int returns x if v == 1 and y if v == 0.
# x and y are treated as signed 32-bit values.
exports.select_int = select_int = (v, x, y) ->
  mask = -v | 0 # 1 -> -1 (0xffffffff); 0 -> 0
  xi = x | 0
  yi = y | 0
  (yi ^ (mask & (yi ^ xi))) | 0

# read_byte reads a byte from buffer but returns 0 if the index is out of
# range.
exports.read_byte = read_byte = (buf, i) ->
  (buf[i] or 0) & 0xff

# read_byte reads an uint16 (big endian) from buffer but returns 0 if the index
# is out of range.
exports.read_uint16_be = read_uint16_be = (buf, i) ->
  ((read_byte(buf, i) << 8) | read_byte(buf, i + 1)) & 0xffff

# select_buffer returns buffer with the contents of x if v == 1 and
# contents of y if v == 0. The buffer will always have length of y
# buffer length.
exports.select_buffer = select_buffer = (v, x, y) ->
  mask = -v | 0
  out = Buffer.alloc(y.length)
  for i in [0...out.length]
    rb = read_byte(x,i) & 0xff
    fb = read_byte(y,i) & 0xff # "fallback"
    out[i] = (fb ^ (mask & (fb ^ rb))) & 0xff
  out
