
{KeyManager,box,unbox} = require '../..'

#=================================================================

pubkm = null
seckm = null
ctext = null
ptext = null

exports.import_public = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : pub }, T.esc(defer(tmp, warnings), cb, "import_public")
  T.assert (warnings.warnings().length is 0), "didn't get any warnings"
  pubkm = tmp
  cb()

#=================================================================================

exports.import_private = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : priv }, T.esc(defer(tmp, warnings), cb, "import_private")
  T.assert (warnings.warnings().length is 0), "didn't get any warnings"
  seckm = tmp
  T.waypoint "about to s2k with very big parameters..."
  T.assert seckm.has_pgp_private(), "has a private key"
  await seckm.unlock_pgp { passphrase }, T.esc(defer())
  cb()

#=================================================================================

exports.encrypt = (T, cb) ->
  ptext = """"
That is no country for old men. The young
In one another’s arms, birds in the trees
—Those dying generations—at their song,
The salmon-falls, the mackerel-crowded seas,
Fish, flesh, or fowl, commend all summer long
Whatever is begotten, born, and dies.
Caught in that sensual music all neglect
Monuments of unageing intellect.
"""
  await box { msg : ptext, encrypt_for : pubkm }, T.esc(defer(aout, raw), cb, "encrypt")
  ctext = aout
  cb()

#=================================================================================

exports.decrypt = (T, cb) ->
  await unbox { keyfetch : seckm, armored : ctext }, T.esc(defer(literals, warnings, esk), cb, "decrypt")
  T.equal ptext, literals[0].toString(), "ciphertext came back OK"
  T.equal warnings.warnings().length, 0, "no warnings"
  T.equal esk.get_fingerprint().toString("hex"), good_subkey, "encrypted with the right subkey"
  cb()

#=================================================================================

pub = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2
Comment: GPGTools - https://gpgtools.org

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
uJWPkuBbJCRf
=32Wp
-----END PGP PUBLIC KEY BLOCK-----
"""

priv = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2
Comment: GPGTools - https://gpgtools.org

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
8LiVj5LgWyQkXw==
=VQP1
-----END PGP PRIVATE KEY BLOCK-----
"""

passphrase = "asdf"
good_subkey = "94A0 6B09 0623 2D4F 4D4C  45F1 729A CF60 BEC2 95CC".split(/\s+/).join('').toLowerCase()

#=================================================================================

