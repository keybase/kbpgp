bzipDeflate = require '../../contrib/bzip_deflate'

bzip_inflate = (buf, max_length, cb) ->
  err = null
  try
    ret = bzipDeflate buf, max_length
  catch e
    if typeof e is 'string' then err = new Error(e)
    else err = e
  cb err, ret

# 50 MiB of `0x00`, one stream. The zero-run becomes a compact RUNA/RUNB
# sequence (RLE2), and the 50 MiB spans ~59 blocks so it also drives the
# multi-block loop. The incremental output counter should trip mid-decode,
# before 50 MiB is materialized.
bzip_single_stream = "QlpoOTFBWSZTWQ4J4t8BX45AAMAAAAggADCATUZCoCWpCoCXMUFZJlNZ7Px7ZgAyA2AAwAAAAIAIIAAwzAUpplAItioBF4u5IpwoSHh332wA"

# Ten independent 5 MiB-of-zeros streams concatenated. libbzip2 (and most
# decoders) decode concatenated streams back-to-back as one continuous output.
# A per-stream output cap is not enough because each individual stream looks
# modest.
bzip_multi_stream = "QlpoOTFBWSZTWa7N3JMAKChEAMAAAAQACCAAMMwFKaYJAmxCQJ4u5IpwoSFdm7kmQlpoOTFBWSZTWa7N3JMAKChEAMAAAAQACCAAMMwFKaYJAmxCQJ4u5IpwoSFdm7kmQlpoOTFBWSZTWa7N3JMAKChEAMAAAAQACCAAMMwFKaYJAmxCQJ4u5IpwoSFdm7kmQlpoOTFBWSZTWa7N3JMAKChEAMAAAAQACCAAMMwFKaYJAmxCQJ4u5IpwoSFdm7kmQlpoOTFBWSZTWa7N3JMAKChEAMAAAAQACCAAMMwFKaYJAmxCQJ4u5IpwoSFdm7kmQlpoOTFBWSZTWa7N3JMAKChEAMAAAAQACCAAMMwFKaYJAmxCQJ4u5IpwoSFdm7kmQlpoOTFBWSZTWa7N3JMAKChEAMAAAAQACCAAMMwFKaYJAmxCQJ4u5IpwoSFdm7kmQlpoOTFBWSZTWa7N3JMAKChEAMAAAAQACCAAMMwFKaYJAmxCQJ4u5IpwoSFdm7kmQlpoOTFBWSZTWa7N3JMAKChEAMAAAAQACCAAMMwFKaYJAmxCQJ4u5IpwoSFdm7kmQlpoOTFBWSZTWa7N3JMAKChEAMAAAAQACCAAMMwFKaYJAmxCQJ4u5IpwoSFdm7km"

# input is cycling length-255 runs (`0x00` x 255, `0x01` x 255, … `0xFF` x 255,
# repeat). Every run is ≥4 identical bytes, so the final run-length step
# (RLE1: 4 literal bytes + 1 count byte → up to 255 out) does the bulk of the
# expansion, while the 256 distinct symbols force a real Huffman alphabet, MTF,
# and BWT inversion. Use this to confirm your RLE1 expansion is bounded and
# counted — the 900 KB block limit applies to the RLE1-*encoded* data, not to
# RLE1's output, so this is the path that under-counts if you cap on "block
# size" alone.
bzip_rle1_focused = "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"

# 900,000 bytes of a single value `'A'`, one block. Because only one byte value
# is present, the Huffman alphabet collapses to just RUNA, RUNB and EOB — zero
# `mNN` symbol codes. This is the minimal-alphabet edge case the format docs
# call out; good for shaking out off-by-one and empty-symbol-table handling in
# Huffman table construction.
bzip_single_block_degen = "QlpoOTFBWSZTWeR+jIYABuSFAKAAAgAACCAAMMwJqmmUoTapKE8XckU4UJDkfoyG"

# valid BZh9 header, but a run of 20 RUNA symbols decodes to a run length of
# 1,048,575 copies of one byte, over the declared 900,000-byte block maximum.
bzip_overrun_block_content = "QlpoOTFBWSZTWQAAAAAAAAAEACAAIAAgoCgAAAw"

# Compression level is set to valid character, but still create blocks larger than
# allowed.
bzip_blocksize_ff = "Qlpo_zFBWSZTWXbc4eYAAYgEAKAEAAggADDMBSmmCFsQheLuSKcKEg7bnDzA"
bzip_blocksize_00 = "QlpoMDFBWSZTWXbc4eYAAYgEAKAEAAggADDMBSmmCFsQheLuSKcKEg7bnDzA"

bzip_bad_bwt_pointer = "QlpoOTFBWSZTWeR+jIZ///+FAKAAAgAACCAAMMwJqmmUoTapKE8XckU4UJDkfoyG"

# https://github.com/golang/go/blob/master/src/compress/bzip2/bzip2_test.go
bzip_out_of_range_selector = "QlpoOTFBWSZTWU7s6DYAAAJRgAAQQAAGRJCAIAAxBkxBAaeppYC7lDEXckU4UJAAAAAA"
bzip_bad_blocksize = "QlpoMTFBWSZTWTbcVTMAY__AAGAAIAAgpAgwAIsACLi7kinChIG24qmY" # similar to bzip_overrun_block_content
bzip_bad_huffman_delta = "QlpoNjFBWSZTWbH3QEsAAABAAEAAIAAhfRhGgu5IpwoSFj7oCWA"

exports.length_errors = (T, cb) ->
  for payload_str in [bzip_single_stream, bzip_multi_stream, bzip_rle1_focused, bzip_single_block_degen]
    payload = Buffer.from(payload_str, 'base64')
    await bzip_inflate payload, 800000, defer err, ret
    T.assert err?, "got error"
    if err then T.equal err?.message, "Max length exceeded"
    if ret then console.log ret.length

  cb null

exports.multi_stream = (T, cb) ->
  # Our decoder only decodes the first stream.
  #
  # The length limit is still tested for this payload in length_errors test.

  await bzip_inflate Buffer.from(bzip_multi_stream, 'base64'), 10*1024*1024, defer err, ret
  T.no_error err
  T.equal ret?.length, 5242880
  cb null

exports.format_errors = (T, cb) ->
  for payload in [bzip_blocksize_00, bzip_blocksize_ff]
    await bzip_inflate Buffer.from(payload, 'base64'), undefined, defer err
    T.assert err?
    T.assert err?.message.indexOf("Bzip2 blocksize") isnt -1

  do ->
    await bzip_inflate Buffer.from(bzip_overrun_block_content, 'base64'), undefined, defer err
    T.assert err?
    T.equal err?.message, "Block limit exceeded"

  do ->
    await bzip_inflate Buffer.from(bzip_bad_bwt_pointer, 'base64'), undefined, defer err
    T.assert err?
    T.equal err?.message, "Out of bound"

  cb null

exports.bzip_errors = (T, cb) ->
  await bzip_inflate Buffer.from(bzip_out_of_range_selector, 'base64'), undefined, defer err, ret
  T.assert err?
  T.equal err?.message, "Invalid selector"

  await bzip_inflate Buffer.from(bzip_bad_blocksize, 'base64'), undefined, defer err, ret
  T.assert err?
  T.equal err?.message, "Block limit exceeded"

  await bzip_inflate Buffer.from(bzip_bad_huffman_delta, 'base64'), undefined, defer err, ret
  T.assert err?
  T.equal err?.message, "Bzip2 Huffman length code outside range 1..20"

  cb null

