
pgp = require './openpgp/keymanager'
pgp_sig = require './openpgp/sigeng'
kb = require './keybase/hilev'

#==========================================================================

# Import a public key either in KB or OpenPGP form,
# and allocate the correct KeyManager as a result.
exports.import_armored_public = ({armored, asp, opts}, cb) ->
  warnings = null
  if armored.match /^-{5}BEGIN PGP PUBLIC KEY BLOCK-{5}/
    await pgp.KeyManager.import_from_armored_pgp { armored, asp, opts }, defer err, ret, warnings
  else
    await kb.KeyManager.import_public { hex : armored }, defer err, ret
  cb err, ret, warnings

#==========================================================================

exports.decode_sig = ({armored}) ->
  if armored.match /^-{5}BEGIN PGP MESSAGE-{5}/
    return pgp_sig.decode_sig {armored}
  else
    return kb.decode_sig {armored}
