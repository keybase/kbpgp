testing_unixtime = Math.floor(new Date(2026, 12, 1)/1000)

{parse} = require '../../lib/openpgp/parser'
armor = require '../../lib/openpgp/armor'
C = require '../../lib/const'
{do_message,Message} = require '../../lib/openpgp/processor'
util = require 'util'
{katch,ASP} = require '../../lib/util'
{KeyManager} = require '../../'
{import_key_pgp} = require '../../lib/symmetric'
{decrypt} = require '../../lib/openpgp/ocfb'
{PgpKeyRing} = require '../../lib/keyring'
{make_esc} = require 'iced-error'

exports.direct_sig_empty_payload = (T, cb) ->
  key = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v2.1.20
Comment: https://keybase.io/crypto

xm8Eav3SJhMFK4EEACIDAwSbEbKHCFZ1LU4WIH9Hdg1+FQFrEAdNdFkSvJU5JElk
qpnHHYmCYi75CQdsQcrDY3oLCHvKBK46IdU8AEaboiK06C425Q7z6om4fKQj2vxs
yqfGMUORxB1KCTOZMwwzXADNDnVzZXJAbG9jYWxob3N0wpYEExMKAB4FAmr90iYC
GwEDCwkHAxUKCAIeAQIXgAMWAgECGQEACgkQT+Ex/aPdxdW5OAGA4y3Mp3DI1JmY
+frnNW9ohOwcTX+dyYt6IueLiSwFmBUgmHHqT0iIrdFljOQPhnmzAXwImpx/8jCF
h4jDoO02Ouuwcigu9ogQ/xcEYY2ocfNxh7SVemJe/u7Nd3jyYuHic47OVgRq/dIm
EggqhkjOPQMBBwIDBD54atDqP58VYke5zmx+mCwshUpCprhC+yz68BY3iob5jvlo
Ba90nDz1SlfNZRlH6pfU9dA1k3qh8BVcoR6p6GIDAQoJwocEGBMKAA8FAmr90iYF
CQ8JnAACGwwACgkQT+Ex/aPdxdU5KQF/U0M14O+o2c2DGAYwvLJ+vjiQycaBu9Z+
w1ALX/qERR7fDZMgoDlrUQiI47Z7NvnuAYDTwGVANoDpphWs9m5Z8pLT9jWklgUY
KtTNHyT64IckwKuWtdrhx6kJrxPFv8VMGFfOUgRq/dImEwgqhkjOPQMBBwIDBGJO
tlTKxsWcU/Zi7Ees8CTIkZknHbAIlUF+ywFknIhFYk0CmtN3hx5fin+kns/HbJTo
0lVQzGHWLEtAyYu+IpjCwCcEGBMKAA8FAmr90iYFCQ8JnAACGyIAagkQT+Ex/aPd
xdVfIAQZEwoABgUCav3SJgAKCRDS3UiYq+5jeCbMAQCqIMHcC7KLSu4LSRFu2QqS
PjFiY3SP1eKpLVCthX64wAEAtG2lsxf/6bcdWLOQq4Y0uYmTw2kUqt7bZAq6JECr
u6V9TwGAtI6zlIVFRcj+vgbWNINcm2Dhei5GjRjvct0eAhhT6ywT+XY47++Pabax
OAI1729JAX0QNDynkbnOEJ0QD5FMUk9nF+LUsnKAyPRm5wHV4bmfuuhkkJuoCzm7
IcDm2JDWTu8=
=Ls+X
-----END PGP PUBLIC KEY BLOCK-----
"""
  
  msg = """-----BEGIN PGP MESSAGE-----
Version: Keybase OpenPGP v2.1.20
Comment: https://keybase.io/crypto

xA0DHwoTT+Ex/aPdxdUBwn4EHxMKAAYFAmr90iYACgkQT+Ex/aPdxdWtEAGAjOyz
SPaZjEXsbu96FBFCDqUTJ+lNTB+K6tqOdQHnw+vUbQndZBF31JyiJihOL0mfAX94
c8PFFdqfOKF52G47Usrs7jrjf5TlpPqfS6FFj3R6g1U3M6RoVjLHWZj6iCg1t74=
=lp5e
-----END PGP MESSAGE-----
  """

  esc = make_esc cb
  opts = now: testing_unixtime
  await KeyManager.import_from_armored_pgp { armored : key, opts }, esc defer km
  await do_message { armored : msg, keyfetch : km }, defer err
  T.assert err?
  T.equal err?.message, "Need a primary key for direct signature"
  # Make sure SignatureEngine.unbox does not fail (goes through similar code
  # path as do_message).
  await km.make_sig_eng().unbox msg, defer err
  T.assert err?
  T.equal err?.message, "Need a primary key for direct signature"
  cb null
