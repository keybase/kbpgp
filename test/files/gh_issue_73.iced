{KeyManager} = require '../..'

exports.github_issue_73 = (T,cb) ->
  await KeyManager.generate_ecc {'userid' : 'test'}, T.esc(defer(km1), cb)
  await km1.sign {}, T.esc(defer(), cb)
  T.assert km1.has_pgp_private()
  await km1.export_pgp_private {}, T.esc(defer(armored), cb)
  await KeyManager.import_from_armored_pgp {armored}, T.esc(defer(km2), cb)
  await km2.sign {}, T.esc(defer(), cb)
  await km2.export_pgp_public {}, T.esc(defer(armored), cb)
  await KeyManager.import_from_armored_pgp { armored }, T.esc(defer(km3), cb)
  T.assert not(km3.has_pgp_private()), "should not have PGP private material"
  cb()
