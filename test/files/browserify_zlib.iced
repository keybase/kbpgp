node_zlib = require 'zlib'
browserify_zlib = require 'browserify-zlib'
{fake_zip_inflate} = require '../../lib/openpgp/packet/compressed'
{is_browser} = require '../util'

# Larger than browserify-zlib's 16KB output buffer, so the limit trips
# while that buffer is full and input remains.
CHUNK = 16 * 1024

inflate = (zlib_impl, raw, cb) ->
  fake_zip_inflate raw, 1, cb, zlib_impl

exports.close_inside_readable = (T, cb) ->
  if is_browser()
    return cb()

  raw = node_zlib.deflateRawSync Buffer.alloc(CHUNK * 4)

  await inflate browserify_zlib, raw, defer err, ret
  T.assert err?
  T.equal err?.toString(), "Error: max length exceeded"
  T.assert not ret?

  await inflate node_zlib, raw, defer err, ret
  T.assert err?
  T.equal err?.toString(), "Error: max length exceeded"
  T.assert not ret?

  cb()
