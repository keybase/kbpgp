
{parse} = require '../../lib/openpgp/parser'
armor = require '../../lib/openpgp/armor'
C = require '../../lib/const'
{do_message,Message} = require '../../lib/openpgp/processor'
util = require 'util'
{unix_time,katch,ASP} = require '../../lib/util'
{KeyManager} = require '../../'
{import_key_pgp} = require '../../lib/symmetric'
{decrypt} = require '../../lib/openpgp/ocfb'
{PgpKeyRing} = require '../../lib/keyring'
{Literal} = require '../../lib/openpgp/packet/literal'
{burn} = require '../../lib/openpgp/burner'
clearsign = require '../../lib/openpgp/clearsign'
detachsign = require '../../lib/openpgp/detachsign'
hashmod = require '../../lib/hash'

#===============================================================================

data = {
  msg : """
Season of mists and mellow fruitfulness
Close bosom-friend of the maturing sun
Conspiring with him how to load and bless
With fruit the vines that round the thatch-eaves run;
To bend with apples the moss'd cottage-trees,
And fill all fruit with ripeness to the core;
To swell the gourd, and plump the hazel shells
With a sweet kernel; to set budding more,
And still more, later flowers for the bees,
Until they think warm days will never cease,
For Summer has o'er-brimm'd their clammy cells.
Who hath not seen thee oft amid thy store?
Sometimes whoever seeks abroad may find
Thee sitting careless on a granary floor,
Thy hair soft-lifted by the winnowing wind;
Or on a half-reap'd furrow sound asleep,
Drows'd with the fume of poppies, while thy hook
Spares the next swath and all its twined flowers:
And sometimes like a gleaner thou dost keep
Steady thy laden head across a brook;
Or by a cider-press, with patient look,
Thou watchest the last oozings hours by hours.
Where are the songs of Spring? Ay, where are they?
Think not of them, thou hast thy music too,-
While barred clouds bloom the soft-dying day,
And touch the stubble-plains with rosy hue;
Then in a wailful choir the small gnats mourn
Among the river sallows, borne aloft
Or sinking as the light wind lives or dies;
And full-grown lambs loud bleat from hilly bourn;
Hedge-crickets sing; and now with treble soft
The red-breast whistles from a garden-croft;
And gathering swallows twitter in the skies.


""",
  keys : {
    passphrase : "urnsrock",
    ids : [  "69B0017B1C3D9917", "F4317C265F08C3A2" ],
    blocks :  [ """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.14 (GNU/Linux)

lQH+BFJ3A/QBBACukT3BRAH6vVn3KULmWutg5BMzutXyNfd1N53BA+7qAow8HW9Q
IVt1QD4Lw0X31PNvnlr01QinzJ0vK5TiZQtlJIOnjJ3iJ3vlMiPQwe26UkN7g4WZ
kmD/ceGioJa6iM9B2cN6IM/cGO33g7zi+f20I8z7lcvJp2Zt2hHQysSoDQARAQAB
/gMDAtVo6Z0kF21hYDSYOTEoTzS0U9hphymRV5qzfYMyM1cT+Swtj2uUR/chfoH5
m9C3sUb9ykwW7LAsbD2AGgjuGQJRQbvudQR+CApk85uNutq8soLTUNqs7hjE6s7y
qOBBYzubuq2JNc1Dl4wJz5CUV6j8ZTa1qLHVVbFeVLOMbXKygjpGZPtNSImmrB5d
MwcsaeWV8YHlhHzdWllKYzcz9jb7sVOMFxlZiTlOhFAbp675OxHl0qKUFdvSA4m1
dYxacp8x7cwrWvQo6WpWHbdGlDYngTmziAf2MjzL1JNRkUTg738Ya8UC7Gzmwbku
DIdswHfpQk3FsickwE06c/lm4EBK180fAxn0h7Pb5JsANW04w5szVIiD9/t9GyK5
8VWdpix3m9V79pqT00GM5qjjr6Al20ygoC9NWoi50mj99vf8NxoYdHjwcSD3l50w
9c60ULBPXjq099IijQWtVkQc14KcOiFze/3SE6Zo+f5DtCpKb2huIEtlYXRzIChK
b2hubnkpIDxqb2huLmtlYXRzQGdtYWlsLmNvbT6IvgQTAQIAKAUCUncD9AIbAwUJ
OGQJAAYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQabABexw9mReQHAP+MyeG
OHi+qRHmCOejziLBl4DZwBeOiEGo/5SJUfl0E76kkG5TAD15pWZbpd4LcBYH2xQe
cAXbdZEdUYpuGCuBeHTQxD+cVAmq1aguCMT54K13V/h8VNGkF4suWrpeMomWcD7O
5Dtqw9OvW/EV10Bk4KnjtnK7HIVP3f9ddbp+NjadAf4EUncD9AEEAK4xy2sVg5mq
QY5gDBYy1uPtFCd3+8iZGVChRApwLnba2kJx1buO9MqgXZ0wmoEJzLgfN5dVDfAQ
ypfltBJgzCXsxbUFCW6m5NV+GjKhIsF4AtMfCfymIsughig55ySw9rurpKmHKEDe
FDsMzKAcpEnaK/4+VY27nlwNFboW5MbFABEBAAH+AwMC1WjpnSQXbWFgPHyfO1zk
Pt44CsEJ5DlvoMIwg8x662EN+zYY3e8MTKcKgtT5qTsZer3puBe7WHDc6YzzCGJq
9XsBNkwnvxt9s3PCHqCkDll0JV6JLP32R7hGnYVFDj9HbMsc6HC9Rp29Rm2nX7L3
NUrSZEMS6Za7KSURMffxIUJqjm9aq9spRUmL9i2IM3ah5XQdrl7s9dJmDdEKG9un
hcgab9DVEMSoL60QH+YpZf2SKFMq0TJIA7g9WYn6MgHuzNhlFlMC2GBPgu+tvY2z
FUNpL44gmk1wPXpcO2BKlnUNsmfc/5Mz1nsWfFcFaUiipmM75niodXOKZxtmlee7
1Vz4enh7m7SKUHiFsQKnPU3egT49OdPonaAaTW7GyhOEj6onW297A7oaZE3zExcB
Rdv2SxgLLMhK6SxADNnTgKwaUcbXX7lWeGtoabtTn6BR9Z/Ljof1JNQc3MqYqLaw
maHbIcP9kZHPAf2ouO2IpQQYAQIADwUCUncD9AIbDAUJOGQJAAAKCRBpsAF7HD2Z
F7ncA/40tgyKkAQLVO6CUiIqq6Vrmyn/sEEqv7CoaH2lRosAaOVBR0AuUUos26ZB
adQQqGYWu6c8XPIOMUVpeMFbBKBkiJvHh2DNlCE3XhbUF0guwZ/GYihFzf4iRZA8
g75kAuLgjcwnMyBzzDLAjyUlgKLBFT9dubmmVk9YWdvEOiB+2g==
=kzrG
-----END PGP PRIVATE KEY BLOCK-----
""", """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.14 (GNU/Linux)

lQH+BFJ3BJYBBADi3DxAFfX6ZNfwHmzgdrgwwaBdYQ1hWusclf2lVRu7Pj0Ha2OK
vsNBH/yRIRNjv+YAGXGoNwEmYVyFllNUbXYZwJKA+GmoC4ZMtCAT6sS2/6AM1syi
/FxGGvJYzBU0HAgb8KeUmNCBe9WBQQsmWrygjfig1RvhT55Ca0Y+fpcnfwARAQAB
/gMDAkqm8JYGqR9OYAnwLxwv9rH0YKH6JY68Kvy+cnGiDqi2LRW1GC8IyVa/qbxt
Ak2RVlTRy2fYfTMxpZpawpSUOkIi5t8ZOJVcc8lGOYWPF0M2G3Xad7zERBPzNy1Y
aE6UiFNkQSVF04eBBw6AbVAvkMlLewbrznoHhmaWWBtNrig0AD+AnmAkvbZKzBjU
5QmAmlQgjegdWjmt1mS6/uLWXZ2vCir54LidFVeO3Tn7ZZNLoKlQfHz0lkH6NRfe
QIRnSOqwzLqWePqNGKyjn16bBSRQC8sdmLanIC7om86DDoFxu66nGvC5WbixC4La
Mdu4WqKF3yyGYmfdFsHDQF9t2D3BxThe5y+BrUv2SK6cRxcrTCWITibsDU51SBcW
hw5EYlP/HrrS702urC7IJLQ5k39KpA1S+G0KzEm50glJuW8OkbNUIDnWsRIYAEuF
/6wW35HGrGOOqYQBei81Bu5gBKDdNpsQLIuD8X++nY3WtCtXaWxsaWFtIFdvcmRz
d29ydGggKEJpbGx5KSA8d3c3MEBnbWFpbC5jb20+iL4EEwECACgFAlJ3BJYCGwMF
CThkCQAGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEPQxfCZfCMOiWhYD/2Fi
CaiDG1qcNt/dOQ9uRkRuKJUX260PhWB+QzVSLy5v8HaAaefGEQhnCWu/OLSjQyku
fVTjydTqn9kNtPAumXOd20x5i3dRzvTUAEEtjVtR1wAfSdcKgpGYwakbMTGAe/QS
gfjTyV2aMfSrrSRLI4hSYqmbkk2zixmKNa4cFuzGnQH9BFJ3BJYBBADFc2tuLtBX
FgOXQgarKa3EMM3I6QdmbDde15Tr7Cm8jb+JGl5lT3gMqLb5gRkbdIrDEFblhTbG
A+ZeUyWe2bf3EeV6h7v4uYVmXDI+B4ej4qy1kyb2hezheDgkd94qG5/ccjBqT/rg
gZwGn+nSB3tOxVxJwvQUVJ2icRfaDUnqSQARAQAB/gMDAkqm8JYGqR9OYAO4FR6T
RpHtyJWgE8ycC50IdlKTJBnnj1IcSbbFZfHg/z97NIATq+UMZrd+kuvb9o4DiV5h
f4XKB+WAe8ZWT48XNyw2JZnuE65JINkpkBFgZPPBmkaR9bz3Zk94sagaVPo2z3FU
uwrr1KPcKQU/hslGyr9yu/B06UQ419ZaeXyrTUaVmi4fBDAYTT6+gdH+Ae8GCgMF
+p+AZM22vi4bSlTg88YCEZ/g5F9D0Uatz1XxpcAE88CwbWZJ2kPyVa23bQqJdttf
RDXUk3EBmO8rbvHSGaubjexCALsR7ve9qYIkUGgMo2c8akvIrNai8v/fEU+hKUbY
7MDSvfDzLziwONHo9FmZNKWaunFiN0xr6TIV//u+nPQH5FXZGVlGV+oJIRCBQNKa
yr6vUm5Y6CGDazMH9roPCFfKASyJhgXNsnWiFmd0qcR9fDoOzM/ytM7j+NFPw0io
+zvizUF/LjaUfPhh2tuIpQQYAQIADwUCUncElgIbDAUJOGQJAAAKCRD0MXwmXwjD
olo1A/9gvmuwrKuqepO9/5gRei8vM1S3JmWjtRIRaf+RL3BNVQC9YUBDQ1Q/kLTO
bgfb9tUj1ukZ/e5y5hIC0y9zKJmJ7yFPucnRwQ9fTdx3vibCm86sv9PPs2aA2SwP
puPX3hq9W6Ojdj8mG9DksKH5C9f2bCeNL8aa0gHa6ZrzMof5uQ==
=ieHK
-----END PGP PRIVATE KEY BLOCK-----
"""] } }

#===============================================================

load_keyring = (T,cb) ->
  ring = new PgpKeyRing()
  asp = new ASP {}
  for b in data.keys.blocks
    await KeyManager.import_from_armored_pgp { raw : b, asp }, defer err, km
    T.no_error err
    T.waypoint "imported decryption key"
    await km.unlock_pgp { passphrase : data.keys.passphrase }, defer err
    T.no_error err
    T.waypoint "unlocked decryption key"
    ring.add_key_manager km
  cb ring

#===============================================================

ring = literals = null
exports.init = (T,cb) ->
  await load_keyring T, defer tmp
  ring = tmp
  literals = [ new Literal {
    data : new Buffer(data.msg)
    format : C.openpgp.literal_formats.utf8
    date : unix_time()
  }]
  cb()

#===============================================================

# Also test various new-line scenarios.
exports.clear_sign_1 = (T,cb) -> clear_sign data.msg, T, cb
exports.clear_sign_2 = (T,cb) -> clear_sign "foo\nbar", T, cb
exports.clear_sign_3 = (T,cb) -> clear_sign "foo\nbar\n\n\n", T, cb
exports.clear_sign_4 = (T,cb) -> clear_sign "foo", T, cb
exports.clear_sign_5 = (T,cb) -> clear_sign "foo\n\n\n\nbar", T, cb

# And dash-encoding
exports.clear_sign_6 = (T,cb) -> clear_sign "-what\n-is\n---up?", T, cb
exports.clear_sign_7 = (T,cb) -> clear_sign "- what\n- is\n- up?", T, cb
exports.clear_sign_8 = (T,cb) -> clear_sign "-----------------word", T, cb

clear_sign = (msg, T,cb) ->
  key_id = new Buffer data.keys.ids[1], 'hex'
  flags = C.openpgp.key_flags.sign_data
  await ring.find_best_key { key_id, flags }, defer err, signing_key
  T.no_error err
  msg = new Buffer msg, 'utf8'
  await clearsign.sign { signing_key, msg }, defer err, outmsg
  T.no_error err
  await do_message { keyfetch : ring, armored : outmsg }, defer err, literals
  T.no_error err
  cb()

#===============================================================

exports.detached_sign_wholesale = (T, cb) ->
  key_id = new Buffer data.keys.ids[1], 'hex'
  flags = C.openpgp.key_flags.sign_data
  await ring.find_best_key { key_id, flags }, defer err, signing_key
  T.no_error err
  msg = new Buffer data.msg, 'utf8'
  await detachsign.sign { signing_key, data : msg }, defer err, outmsg
  throw err if err?
  T.no_error err
  await do_message { data : msg, keyfetch : ring, armored : outmsg }, defer err
  throw err if err?
  T.no_error err
  cb()

#===============================================================

exports.detached_sign_streaming = (T, cb) ->
  key_id = new Buffer data.keys.ids[1], 'hex'
  flags = C.openpgp.key_flags.sign_data
  await ring.find_best_key { key_id, flags }, defer err, signing_key
  T.no_error err
  msg = new Buffer data.msg, 'utf8'
  hash_streamer = hashmod.streamers.SHA384()
  hash_streamer.update(msg)
  await detachsign.sign { hash_streamer, signing_key }, defer err, outmsg
  throw err if err?
  T.no_error err
  await do_message { data : msg, keyfetch : ring, armored : outmsg }, defer err
  throw err if err?
  T.no_error err
  cb()

#===============================================================

exports.encrypt = (T,cb) ->
  key_id = new Buffer data.keys.ids[0], 'hex'
  flags = C.openpgp.key_flags.encrypt_comm
  await ring.find_best_key { key_id, flags}, defer err, encryption_key
  T.no_error err
  await burn { literals, encryption_key }, defer err, armored, ctext
  T.no_error err
  proc = new Message { keyfetch : ring }
  await proc.parse_and_process { body : ctext }, defer err, out
  T.no_error err
  T.assert (not out[0].get_data_signer()?), "wasn't signed"
  T.equal data.msg, out[0].toString(), "message came back right"
  cb()

#===============================================================

exports.sign = (T,cb) ->
  key_id = new Buffer data.keys.ids[1], 'hex'
  flags = C.openpgp.key_flags.sign_data
  await ring.find_best_key { key_id, flags}, defer err, signing_key
  T.no_error err
  await burn { literals, signing_key }, defer err, armored, ctext
  T.no_error err
  proc = new Message { keyfetch : ring }
  await proc.parse_and_process { body : ctext}, defer err, out
  T.no_error err
  T.assert (out[0].get_data_signer()?), "was signed!"
  T.equal data.msg, out[0].toString(), "message came back right"
  cb()

#===============================================================

exports.encrypt_and_sign = (T,cb) ->
  key_id = new Buffer data.keys.ids[0], 'hex'
  flags = C.openpgp.key_flags.encrypt_comm
  await ring.find_best_key { key_id, flags}, defer err, encryption_key
  key_id = new Buffer data.keys.ids[1], 'hex'
  flags = C.openpgp.key_flags.sign_data
  await ring.find_best_key { key_id, flags}, defer err, signing_key
  T.no_error err
  await burn { literals, encryption_key, signing_key }, defer err, armored, ctext
  T.no_error err
  proc = new Message { keyfetch : ring }
  await proc.parse_and_process { body : ctext}, defer err, out
  T.no_error err
  T.assert (out[0].get_data_signer()?), "was signed!"
  T.equal data.msg, out[0].toString(), "message came back right"
  cb()

#===============================================================

exports.encrypt_and_sign_armor = (T,cb) ->
  key_id = new Buffer data.keys.ids[0], 'hex'
  flags = C.openpgp.key_flags.encrypt_comm
  await ring.find_best_key { key_id, flags}, defer err, encryption_key
  key_id = new Buffer data.keys.ids[1], 'hex'
  flags = C.openpgp.key_flags.sign_data
  await ring.find_best_key { key_id, flags}, defer err, signing_key
  T.no_error err
  await burn { literals, encryption_key, signing_key }, defer err, actext, ctext
  T.no_error err
  [err,msg] = armor.decode actext
  T.no_error err
  proc = new Message { keyfetch : ring }
  await proc.parse_and_process msg, defer err, out
  T.no_error err
  T.assert (out[0].get_data_signer()?), "was signed!"
  T.equal data.msg, out[0].toString(), "message came back right"
  cb()

#===============================================================
