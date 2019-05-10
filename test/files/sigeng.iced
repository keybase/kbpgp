
{armor,KeyManager,kb,util} = require '../../'
{keys} = require('../data/keys.iced')
{make_esc} = require 'iced-error'
{asyncify} = util
{unbox_decode,encode} = kb

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
  await se.box msg, defer(err), { prefix : "foo" }
  T.assert err?, "an error when using prefixes with PGP"
  T.equal err.message, "prefixes cannot be used with PGP", "right error message"
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

exports.sigeng_verify_encrypt_msg = (T,cb) ->
  esc = make_esc cb, "sigeng_verify_encrypt_msg"
  armored = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EWT7YPwEEAMpf5t3pNShLAEy1zSnhS9uTZwna5aVFcox5FPHkBHMKCpd7RjJp
R0TfVM+kfvCjJlwpcn/uznVLU9TSsfiikDGo6Rltrj0lTqhz0zRBkwID1D76KhSG
IYtoGO8JvA6OjRFZ31YUzOkdv7EioNHj0wNGhzyojmKtEFiKq7qP8/wNABEBAAG0
KkZvb3IgODgzICh0ZXN0KSA8dGhlbWF4K2Zvb3I4ODNAZ21haWwuY29tPoi4BBMB
AgAiBQJZPtg/AhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRAyPbtU2NuF
vPf5A/4hfMgB2FKbiQTES8Ic4Qmr4FlNh64z+N0rDpmVNGPHUKcg2UbRJx54jV0o
JJ6kWbTW2N5QVVoUZMv5RK1FGYMAhmT8xIJayobDj60ZkP/iiLFkwior8RxBd1Qu
uZ+JeT2xMjOs1z6sVkwV7tBmyw6hAaVxTN8Wv3/6ciZ4ZYGN57iNBFk+2D8BBACf
tcEN+wW06lWieM+CM9DOwr8DE7heQm/BfQgPSTIwYj/TqWLkpCFWOVM1CY2Qm2VP
C22txzqctKmMvRhKVjsl5k/k8/TIOo/3mIOkgnS5O9t/CWLuXyM7IF3mNSeOfbIX
e497NdXK/viEeemb02d5aa3b6uf28lJa2eN2adhbawARAQABiJ8EGAECAAkFAlk+
2D8CGwwACgkQMj27VNjbhbz76QP/fLSo1QvegCPweqgVgn7FDN13ea9Fbid6qTKJ
ZSu083+zJnG3WYQClrLjuZ9gapN3MplRuAzIZANQ9zqlGXzwqbJXs+ifZez5vorH
9fz+WhakUkUPfBG8xAsc7Nqm+Q5RyPEyklJuekk3U+Mw4R3LS1RDO06DVV/mqZ+/
jr19hIg=
=05rq
-----END PGP PUBLIC KEY BLOCK-----"""
  msg = """-----BEGIN PGP MESSAGE-----

hIwDnASvG86Bd98BBACQ7QjQNuyQJ+gjHEydJ2gNFbGwtFvs5W2aNw8GMv2WY2gV
mPa4BN9mShG++DnMxvaINV4WHb5GK87YgDc4nB1tva4OUPqt11xVzlLPfD643hGL
3lkXk62j2LyLwFa4v8lk2UtRlg9X9L7hzMRljpwR8OkFuvtr4/zP0/JPI7LHpdLp
AV+f1Uuw/9CZHw0nMDUDzW4W4Mr++B441RnjQjuIgSgD8croGDGJZkXHSwmrx6Ry
852gPKVNSv4sQnAhRU9/n9Tk5vO1TK9QpM5eDVz6cTMUkFrvvEv5w7dC6hdgwRiE
uiGkIyFRsW8GTZYQh1E7ygHUb83Du8bipi9LG0s+A0upqR4nxetAc3ZdghRwU3Zx
VKstH2wTgdNPcUzzssRZP2N8AdfLKfouvzwBftbDUOK2OPtwSXP3fi507HfRwpau
djNjwGF6o+vS5VLnuE0Bd+Un59aJpFB3hf1EJJe7nNFqoV+rKAYXQzfhrcjbJR2Q
ImEb+DTF/QTLWdJHzDYtZtcaR5+OjySAoprWwBgFd/5jO7QxFAYsK0KB+qYORhPS
mA8E2krlh4qhVzolYazAin4Q4qkbfatHS2UrWH21RlqL4RbbmxFmczCI9nR1BIuG
8vYdAy54Dprka6JavrrBGBlJcf/19REwEoXrid7fJta3fXYQzGVm6cJXlsYAdXUP
5txUdrUsv95jOM2VQxJn1CBlAVtwXRQ41UR476QAO52ShDMrzy1dCSewQIk2nrbZ
rT3tA/jpRZBEamYqXQ67JqNsEqe9nfIn7PszKOoz3PaoLUOAIfIc0/XU6WzfldSS
vog49ozvkIgTtkG+Yu1eHOKc1b1qEBz+9Gn2U6Dxh0F3uLyC30gPNaApCDX+4n1p
bxLxH8ynQ0tN65Nog67RE8zzwhlifWLi4C6nO4ma02rqy/VaBT2BhnTZC6SZfmvQ
KVz0tO9vcnWOkH1nA6iTJPxduAzCxDmVx3XaoVj9LPjajlROyWyMogdnZ5u0vP+l
Kn2YXxcsF30=
=iWKX
-----END PGP MESSAGE-----"""

  await KeyManager.import_from_armored_pgp { armored }, esc defer km
  sig_eng = km.make_sig_eng()
  await sig_eng.unbox msg, defer err
  T.assert err?, "should fail"
  T.assert err.toString().indexOf("can't peform the operation -- maybe no secret key material (op_mask=2)") >= 0, "find right msg"
  cb()

exports.kb_generate_with_prefix = (T,cb) ->
  esc = make_esc cb
  await kb.KeyManager.generate {}, esc defer pkm
  psig_eng = pkm.make_sig_eng()
  pmsg = Buffer.from("Of Man's First Disobedience, and the Fruit Of that Forbidden Tree, whose mortal taste", "utf8")
  prefix = Buffer.from("milton-x-1", "utf8")
  await psig_eng.box(pmsg, esc(defer(psig)), { prefix })
  await psig_eng.unbox(psig.kb, esc(defer()))
  await psig_eng.unbox(psig.kb, defer(err), { prefix : Buffer.from("should-fail") })
  T.assert err?, "should get an error that we failed to verify with the wrong prefix"
  T.equal err.message, "Signature failed to verify", "right error"
  await asyncify unbox_decode({armored : psig.kb}), esc defer packet

  delete packet.prefix
  packed = packet.frame_packet()
  sealed = encode.seal { obj : packed, dohash : false }
  armored = sealed.toString('base64')
  await psig_eng.unbox(armored, defer(err))
  T.assert err?, "should fail since wrong prefix"
  T.equal err.message, "Signature failed to verify", "right error"

  packet.prefix = prefix
  packed = packet.frame_packet()
  sealed = encode.seal { obj : packed, dohash : false }
  armored = sealed.toString('base64')
  # should work
  await psig_eng.unbox(armored, esc(defer()))

  packet.prefix = Buffer.from("sidney-for-life-1")
  packed = packet.frame_packet()
  sealed = encode.seal { obj : packed, dohash : false }
  armored = sealed.toString('base64')
  await psig_eng.unbox(armored, defer(err))
  T.assert err?, "should fail since wrong prefix"
  T.equal err.message, "Signature failed to verify", "right error"

  cb()
