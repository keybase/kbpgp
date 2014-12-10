{KeyManager} = require '../../'
{bufferify,ASP} = require '../../lib/util'
{make_esc} = require 'iced-error'
util = require 'util'
{box} = require '../../lib/keybase/encode'
{Encryptor} = require 'triplesec'
{base91} = require '../../lib/basex'
{burn} = require '../../lib/openpgp/burner'
{do_message} = require '../../lib/openpgp/processor'

#---------------------------------------------

pub = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - http://gpgtools.org

mI0EU1RicwEEAKldegqFSs6QnotGAD3pg5rjv1ftzFINTEbf+JkdVPhWT8NkiNne
NOWUxAtS1Pez9NpL+LUpk1AkImzFCtrgLrT+445hX9kKNN17JZeUNiR9lgujB+El
BL0h2WUYiE3Q99BuHiTRoZZzRagy0/VylwHOb2cW2IUeTN5uK+MgjHk1ABEBAAG0
IExvcmQgQnlyb24gPGxvcmQuYnlyb25Ab3guYWMudWs+iL4EEwECACgFAlNUYnMC
GwMFCRLMAwAGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEFFfVrvfaDdkvOwD
/iyPjFVN4g4WepZ7lYpb6qnOakUmKDBbcNYa3hxgdkjOm/jEpQcrGEDpGTGbenqP
+f6qkOd+lJIfsYn2IVcxJkFZXXGwfdzlE9d3J6hvPu83oymkKAiqNyKd1SiYPr2u
lEnzFpohJvt4O/Re8eGY37dWGUBtjno/oir3/LCT/jrjuI0EU1RicwEEAJ04fU18
TSn7P8ikQf7BiQOUYbV2oFXDE3fznIwzM5qtrrAtkxPS/B+ePf5dGogMcD1dsrvz
2NYo82p6NqKJaIXR1VQgmuAET+8oIvOqYIPx7M/LqvMcc2LAAgpRdlUfF0eYOIEg
PKBaDQ1zy0jeBlB6Ra8MzYm/ZJccgXFtGcrDABEBAAGIpQQYAQIADwUCU1RicwIb
DAUJEswDAAAKCRBRX1a732g3ZC7PA/9r0AiqjZ4/GpvE0x1W7AunmyInqUJ65I3x
twHxL77b3YvJIr1NGhJ9DeZ5bGEaeOnTX4Re7dmflbWH4Vk8VDgofWQaka/OwV0U
j2Wn+ky5ADTpBl7IpYA42en+pbQmANQ6gBZHjJUEVvfXGOGx5CE3fkLkRP6Cubfd
00NXPp5/QbiNBFNUYogBBAC8fMFFbX7dRvmfKROkvsvNs+VxKFeEjumUTtSZZAEF
EHiA90yHUH3raRvi0IFQryZGyACLO1V+G6Dw2hpFTfdFRDe9cyABgi+/CJFSIDcE
OP5MatLDfgKXRRebn/yq2KumaH3mBCVvLgP8+j32JVoXv4XxazWHA5DTGxzVNYY6
IQARAQABiQFDBBgBAgAPBQJTVGKIAhsCBQkSzAMAAKgJEFFfVrvfaDdknSAEGQEC
AAYFAlNUYogACgkQI7FF74NRBFSG4wP+IQch2GhpG2+x+QKntDm8BIb7LUbW2qUM
ffa8laIyV0mYmDVsnqpKWbPHyrp+oRoxivILdqt7z/w4gRjdilHeL0IThTGyApgb
ijrsL/4D2jsrJpNSU1xwZ/5FxN68htuQ8glqRES6P7o3+Dcx5l9mJbr05RHHRjMn
1BHR3TZzLYAcZQP/e4+4H2G6qYUe7hox1G6dpabaHLVVhpWlXace3BAWjUsllF6z
qSGrD7biTyYJq2RqrjUCt0y+UyNy+rpWvGqcvkzdax5flksQ0rOldj7S4tdIjwQv
pZjpPs9s/v/mzM8zsP3L5KdlMApDGdQq8GAyCJ41MytvG7Yp3gIMIpkECkE=
=HaQc
-----END PGP PUBLIC KEY BLOCK-----
"""

#------------

priv = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - http://gpgtools.org

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
QxnUKvBgMgieNTMrbxu2Kd4CDCKZBApB
=5Yn3
-----END PGP PRIVATE KEY BLOCK-----
"""

#------------

canto_I = """
I want a hero: an uncommon want,
  When every year and month sends forth a new one,
Till, after cloying the gazettes with cant,
  The age discovers he is not the true one;
Of such as these I should not care to vaunt,
  I'll therefore take our ancient friend Don Juan—
We all have seen him, in the pantomime,
Sent to the devil somewhat ere his time.
"""

#------------

passphrase = "adonais"
km = null
km_priv = null

#------------

exports.load_pub = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : pub }, defer err, tmp, warnings
  km = tmp
  T.no_error err
  T.assert km?, "got a key manager back"
  cb()

#------------

exports.load_priv = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : priv }, defer err, tmp, warnings
  km_priv = tmp
  T.no_error err
  throw err if err?
  T.assert km_priv, "got a private key manager back"
  cb()

#------------

exports.unlock_priv = (T,cb) ->
  await km_priv.unlock_pgp { passphrase }, defer err
  T.no_error err
  cb()

#------------

exports.merge = (T,cb) ->
  await km.merge_pgp_private { raw : priv }, defer err
  T.no_error err
  cb()

#------------

exports.unlock_merged = (T,cb) ->
  await km.unlock_pgp { passphrase }, defer err
  T.no_error err
  cb()

#------------

armored_sig = null
armored_ctext = null

exports.sign = (T,cb) ->
  sk = km.find_signing_pgp_key()
  await burn { msg : canto_I, signing_key : sk }, defer err, tmp
  armored_sig = tmp
  T.no_error err
  cb()

#------------

exports.verify = (T,cb) ->
  await do_message { armored : armored_sig, keyfetch : km }, defer err, literals
  T.no_error err
  T.equal literals[0].toString(), canto_I, "canto I of Don Juan came back"
  T.assert literals[0].get_data_signer()?, "was signed"
  cb()

#------------

exports.encrypt_and_sign = (T,cb) ->
  sk = km.find_signing_pgp_key()
  ek = km.find_crypt_pgp_key()
  await burn { msg : canto_I, signing_key : sk, encryption_key : ek }, defer err, tmp
  armored_ctext = tmp
  T.no_error err
  cb()

#------------

exports.decrypt_and_verify = (T,cb) ->
  await do_message { armored : armored_ctext, keyfetch : km }, defer err, literals
  T.no_error err
  T.equal literals[0].toString(), canto_I, "canto I of Don Juan came back"
  T.assert literals[0].get_data_signer()?, "was signed"
  cb()

#------------

tsenc = null
p3skb = null

exports.encrypt_private_to_server = (T,cb) ->
  tsenc = new Encryptor { key : (new Buffer 'A heart whose love is innocent', 'utf8')}
  await km.sign {}, defer err
  T.no_error err, "signing worked"
  await km.export_private_to_server { tsenc }, defer err, tmp
  p3skb = tmp
  T.no_error err
  T.assert p3skb?, "a plausible answer came back from the server"
  cb()

#------------

exports.decrypt_private_from_sever = (T,cb) ->
  await KeyManager.import_from_p3skb { raw : p3skb }, defer err, tmp
  T.no_error err, "import from p3skb worked"
  km2 = tmp
  T.assert km2?, "km came back"
  T.assert km2.has_p3skb_private(), "has a private part"
  T.assert km2.is_p3skb_locked(), "is locked"
  await km2.unlock_p3skb { tsenc }, defer err
  T.waypoint "unlocked"
  T.no_error err
  T.assert not(km2.is_p3skb_locked()), "no longer locked"
  await do_message { armored : armored_ctext, keyfetch : km2 }, defer err, literals
  T.no_error err
  T.equal literals[0].toString(), canto_I, "canto I of Don Juan came back"
  T.assert literals[0].get_data_signer()?, "was signed"
  T.waypoint "decryption still worked"
  sk = km2.find_signing_pgp_key()
  T.assert sk?, "still has a signing key"
  cb()

#------------
