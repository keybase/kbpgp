{make_esc} = require 'iced-error'
{KeyManager,ecc} = require '../../lib/main'
{do_message} = require '../../lib/openpgp/processor'
{burn} = require '../../lib/openpgp/burner'
zlib = require 'zlib'
C = require('../../lib/const').openpgp
Compressed = require('../../lib/openpgp/packet/compressed').Compressed
{uint_to_buffer} = require '../../lib/util'
armor = require '../../lib/openpgp/armor'
parser = require '../../lib/openpgp/parser'
{is_browser} = require '../util'

g_km = null
# Data created offline for bzip2. It decompresses into 6291464 bytes PGP header
# with packet tag 16, chunk header, and zeroes.
BZIP_BAD_PACKET_DATA_BASE64 = "QlpoOTFBWSZTWeGS4s0AwM9AAsAGQAAECCAAUGABSqM9TAoCy/FRBHdpwFAXhdyRThQkOGS4s0A="

create_compressed_packet = (packet_size, zip, cb) ->
  bufs = []

  algo = if zip then C.compression.zip else C.compression.zlib
  func = if zip then zlib.createDeflateRaw else zlib.createDeflate

  call_end = (err) =>
    # console.log 'call_end', err
    if err then return cb err
    buf = Buffer.concat [ uint_to_buffer(8, algo), bufs... ]
    pkt = new Compressed { }
    ret = pkt.frame_packet C.packet_tags.compressed, buf
    # console.log "returning, length: #{buf.length} bytes"
    cb null, ret

  engine = func { level: 9 }
  engine.on 'readable', () ->
    read_buf = engine.read()
    bufs.push read_buf if read_buf?
  engine.on 'end', () ->
    call_end null
  engine.on 'error', (e) ->
    call_end e

  cur_len = 0
  chunk_len = 1 << 20
  zero_chunk = Buffer.alloc chunk_len
  unless packet_size? then packet_size = chunk_len * 64

  # Stream a real new-format OpenPGP packet into zlib. Tag 16 is an
  # ignored COMMENT packet for KBPGP, but its body is still inflated.
  await engine.write Buffer.from([0xc0 | 16]), defer err

  # 0xe0 | n encodes a partial body length chunk of 1 << n bytes.
  while cur_len < packet_size when not err?
    await engine.write Buffer.from([0xe0 | 20]), defer err
    break if err?
    await engine.write zero_chunk, defer err
    cur_len += chunk_len unless err?

  # End the partial body stream with a normal definite-length chunk.
  await engine.write Buffer.from([0]), defer err unless err?

  if err? then call_end err
  else engine.end()
  # console.log "flushed, wrote: #{cur_len} packet body bytes"

create_bzip_compressed_packet = (cb) ->
  algo = C.compression.bzip
  compressed = Buffer.from BZIP_BAD_PACKET_DATA_BASE64, 'base64'
  buf = Buffer.concat [ uint_to_buffer(8, algo), compressed ]
  pkt = new Compressed { }
  cb null, pkt.frame_packet C.packet_tags.compressed, buf

inject_bad_compressed_packets = ({num_packets, packet_size, zip, armored}, cb) ->
  esc = make_esc cb
  [err, msg] = armor.decode armored
  return cb err if err?
  [err, packets] = parser.parse msg.body
  return cb err if err?

  mutated = []
  for packet in packets
    mutated.push packet.replay()
  for i in [0...num_packets]
    await create_compressed_packet packet_size, !!zip, esc defer packet
    mutated.push packet

  raw = Buffer.concat mutated
  cb null, { raw, armored : armor.encode msg.type, raw }

inject_bad_bzip_compressed_packet = (armored, cb) ->
  esc = make_esc cb
  [err, msg] = armor.decode armored
  return cb err if err?
  [err, packets] = parser.parse msg.body
  return cb err if err?

  mutated = []
  for packet in packets
    mutated.push packet.replay()
  await create_bzip_compressed_packet esc defer packet
  mutated.push packet

  raw = Buffer.concat mutated
  cb null, { raw, armored : armor.encode msg.type, raw }

exports.init = (T, cb) ->
  esc = make_esc cb
  await KeyManager.generate_ecc { userid : "test@test.cc" }, esc defer g_km
  await g_km.sign {}, esc defer()
  cb()

exports.packet_max = (T, cb) ->
  esc = make_esc cb
  max_length = 5242880 # 5 MiB
  await create_bzip_compressed_packet esc defer framed1
  await create_compressed_packet max_length*2, false, esc defer framed2
  await create_compressed_packet max_length*2, true, esc defer framed3
  for framed, i in [framed1, framed2, framed3]
    T.waypoint "frame#{i}"
    [err, packets] = parser.parse framed
    return cb err if err?
    packet = packets[0]
    await packet.inflate { max_length }, defer err, ret
    if framed == framed2 and is_browser()
      # Known issue with browserified KBPGP: zlib.inflate does not support
      # maxOutputLength option. Just make sure we don't get a crash /
      # exception here, but the inflate will go through (and probably take
      # a lot of memory until the buffer is discarded later on).
      continue
    T.assert err?
    T.equal err?.toString(), "Error: max length exceeded"
    T.assert not ret?
  cb null

exports.do_message_max_len_1 = (T, cb) ->
  esc = make_esc cb
  plaintext = "hello world"
  await burn { msg : plaintext, sign_with : g_km }, esc defer aout

  # Each compressed packet is less than max_length, but together they are
  # larger (after decompression).
  pgp_max_length = 5242880 # 5 MiB
  for zip in [false, true]
    await inject_bad_compressed_packets {
      num_packets : 5
      packet_size : pgp_max_length/5
      armored : aout
      zip
    }, esc defer { raw, armored : aout2 }
    T.waypoint "Created message with 5 compressed packet, zip: #{zip}, length: #{raw.length}"
    await do_message { armored : aout2, keyfetch : g_km, pgp_max_length }, defer err, msg
    T.assert err?
    T.equal err?.toString(), "Error: max length exceeded"

  cb()

exports.do_message_max_len_2 = (T, cb) ->
  esc = make_esc cb
  plaintext = "hello world"
  await burn { msg : plaintext, sign_with : g_km }, esc defer aout

  for zip in [false, true]
    for num_packets in [1, 5]
      await inject_bad_compressed_packets {
        num_packets
        armored : aout
        zip
      }, esc defer { raw, armored : aout2 }
      T.waypoint "Created message with #{num_packets} compressed packet(s), zip: #{zip}, length: #{raw.length}"
      pgp_max_length = 5242880 # 5 MiB
      await do_message { armored : aout2, keyfetch : g_km, pgp_max_length }, defer err, msg
      T.assert err?
      T.equal err?.toString(), "Error: max length exceeded"

  cb()

exports.do_message_max_len_bzip = (T, cb) ->
  esc = make_esc cb
  plaintext = "hello world"
  await burn { msg : plaintext, sign_with : g_km }, esc defer aout

  pgp_max_length = 5242880 # 5 MiB
  await inject_bad_bzip_compressed_packet aout, esc defer { raw, armored : aout2 }
  T.waypoint "Created message with bzip compressed packet, length: #{raw.length}"
  await do_message { armored : aout2, keyfetch : g_km, pgp_max_length }, defer err, msg
  T.assert err?
  T.equal err?.toString(), "Error: max length exceeded"

  cb()
