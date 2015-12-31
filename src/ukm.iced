
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

is_pgp_sig = (x) -> x.match /^-{5}BEGIN PGP MESSAGE-{5}/

exports.decode_sig = ({armored}) ->
  if is_pgp_sig armored
    return pgp_sig.decode_sig {armored}
  else
    return kb.decode_sig {armored}

#==========================================================================

exports.get_sig_body = ({armored}) ->
  if is_pgp_sig(armored) then pgp_sig.get_sig_body {armored}
  else kb.get_sig_body {armored}

