
{armor,KeyManager,kb} = require '../../'
{keys} = require('../data/keys.iced')

km = null

msg = """
The night attendant, a B.U. sophomore,
rouses from the mare's-nest of his drowsy head
propped on The Meaning of Meaning.
He catwalks down our corridor.
"""

sig = null
se = null

exports.generate = (T,cb) ->
  await KeyManager.generate_ecc { userid : "tester@test.cc" }, T.esc(defer(tmp), cb)
  km = tmp
  cb()

exports.box = (T,cb) ->
  se = km.make_sig_eng()
  await se.box msg, T.esc(defer(tmp), cb)
  sig = tmp
  cb()

exports.unbox = (T,cb) ->
  [ err, raw ] = armor.decode sig.pgp
  T.no_error err
  await se.unbox raw, T.esc(defer(tmp), cb)
  T.equal tmp.toString('utf8'), msg, "the right message came back out"
  cb()

exports.pgp_get_unverified_payload = (T,cb) ->
  await se.get_body_and_unverified_payload { armored : sig.pgp }, T.esc(defer(_, payload), cb)
  T.equal payload.toString('utf8'), msg, "the right message came back out"
  cb()

exports.kb_generate = (T,cb) ->
  await kb.KeyManager.generate {}, T.esc(defer(tmp), cb)
  km = tmp
  cb()

exports.kb_box = (T,cb) ->
  se = km.make_sig_eng()
  await se.box msg, T.esc(defer(tmp), cb)
  sig = tmp
  cb()

exports.kb_unbox = (T,cb) ->
  await se.unbox sig.armored, T.esc(defer(tmp), cb)
  T.equal tmp.toString('utf8'), msg, "the right message came back out"
  cb()

exports.kb_get_unverified_payload = (T,cb) ->
  await se.get_body_and_unverified_payload { armored : sig.armored }, T.esc(defer(_, payload), cb)
  T.equal payload.toString('utf8'), msg, "the right message came back out"
  cb()

#------------------

bcrypt_sig = """-----BEGIN PGP MESSAGE-----

owJ4nJvAy8zAxXhhd4KZ89+bbxhPH1iZxBBsyb62WikpP6VSyapaKTsVTKVl5qWn
FhUUZeaVKFkpJaWkmqeYGlgYJyUZm6amJJsnmpklpViaG1tYJKcaGVmmJSabWySn
mSvpKGXkF4N0AI1JSixO1cvMB4oBOfGZKUBRoHpnV6B6N0dncwtnN5D6UrCERYq5
kVmikalhcqqlQaqlRZppcpplsqmJsXGymYGFgQFIYXFqUV5ibirIOclFlQUlSrU6
SkCxsszkVJCLoXIl5ZklJalFuDSUVBaABMpTk+KheuOTMvNSgL4F6ihLLSrOzM9T
sjIEqkwuyQTpNTS2NDMyMTMxMdVRSq0oyCxKjc8EqTA1NwO6y8BAR6mgKLVMySqv
NCcH5J7CvHygLNCixHSgPcWZ6XmJJaVFqUq1nYwyLAyMXAxsrEygEGfg4hSAxcPj
Lg6GVdJc+ev6hFZIWG/OSv7Jxsy+4mm/uL1O9PePJhan7Y2DOZ0ccu4qM35/uzLd
6EdfxHLucsZFYnc03yd++fYh5vqsPV9KhNtmTfzZd4RRYPqP1K3R995tX7BIm//p
QbkEbdFMLuFujp7YhXWX/1QeORfRniTPd/7z6/SaI49OmjOe2mI4U7FdbvbFw//N
zs92+tQVq8LcHTm5be/kmJKKFnXx9J1/OTc/jHxxOrvleHbOt/4vyRF31qxs8Tl0
5mZj7jOez9e3/q+9OXNq+dPclxF3tLpNHhzatTintPu+rbbYl5j9i099OyDg+fHm
rf+MJwz/S3Syv7Pze3/795qjpaJT3yxIuaYtP+2m5pzIeAA1rQep
=h3a4
-----END PGP MESSAGE-----"""

exports.pgp_unbox_bcrypt = (T,cb) ->
  opts = { time_travel : true }

  # First attempt to import bcrypt's key should warn about the expired subkeys
  await KeyManager.import_from_armored_pgp { armored : keys.bcrypt }, T.esc(defer(km, warnings), cb)
  w = (w for w in warnings.warnings() when not w.match /Skipping signature by another issuer/)
  T.assert (w.length is 15), "15 expired signatures at time now"

  await KeyManager.import_from_armored_pgp { armored : keys.bcrypt, opts }, T.esc(defer(km, warnings), cb)
  w = (w for w in warnings.warnings() when not w.match /Skipping signature by another issuer/)
  T.assert (w.length is 0), "no warnings aside from lots of cross-sigs"

  sig_eng = km.make_sig_eng()
  await sig_eng.unbox bcrypt_sig, defer err
  T.assert err?, "an error came back"
  exp = 1407614008
  rxx = new RegExp "PGP key bde7d5083bb35edc7a66bd97388ce229fac78cf7 expired at #{exp} but we checked for time (\\d+)"
  T.assert err.toString().match(rxx), "right error message (got: #{err.toString()}"
  await sig_eng.unbox bcrypt_sig, T.esc(defer(), cb), { now : exp - 100 }

  cb()
