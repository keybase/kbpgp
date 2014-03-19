
{KeyManager} = require '../../lib/keymanager'
{PgpKeyRing} = require '../../lib/keyring'
{do_message} = require '../../lib/openpgp/processor'

#==================================================================================================

# Compressed with bzip2 
msg = """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

owNCWmg2MUFZJlNZhNKFqQAAa3///7fTt0s18FriG7/332/987/n+e5//n6y6Ov8
qPf/cycwAPssHCaANDJoANA0bUNDQDQAAAAAZA0AAaA9RpkDQNAZA0aaB4mFPJPE
KqBkAyaaADQaaNABiAyAaaMjRkMjIxDQ00xNBkAyGm1Ghpp6RpkZDIyGhoPSFVP1
TNT0hoMIAaNBoADRpkMgyAHpGgAGTTBGIGQ0aAD1NDQNMQyA0aGmgAjBiDjYyEXH
Fd9vIWBEBNmP4BY2Tk4UmwihAZwKIxTAXfpASdfkrzZQyx73ZXUMiJ4L9eP21jfl
nS3mmUaUSmeyBt2BPOAvCBHZOhB4asYItgeuAb3RlP3/iLktAWZlCIL1QnAQaBPD
M6Dm/ZZFN/Iev4DWoF0nJZgG+mdaQFSkBDhuWd2qCVaEq8flxS+u5abW9lj777Ms
CIIuN1OEuI+ga6CfseccLZrIDOvEKBAG1bWMuedWTOtG5egRrrSBgPVCuGRTQXch
jiJdxOIsfj5l5OaJiNb90oS+be5bJhChnrwf0YO2jZkiFBrR/pyHgDHVuguTtAkk
/SMVf8pyKovyDZSr2xSKqaAcilmiqTyYEXFI7UX/NDlpekK7JKANIAIMCQG4903X
pwCzGxtrHxxx2LuSKcKEhCaULUg=
=Qpgh
-----END PGP MESSAGE-----
"""

#==================================================================================================

key = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

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
/6eFUsNDH74yMw==
=97ae
-----END PGP PUBLIC KEY BLOCK-----
"""

#==================================================================================================

exports.process = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key }, defer err, km
  T.no_error err
  ring = new PgpKeyRing()
  ring.add_key_manager km
  await do_message { keyfetch : ring, armored : msg }, defer err, literals
  T.no_error err
  cb()

#==================================================================================================
