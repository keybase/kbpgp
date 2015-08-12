{KeyManager} = require '../../lib/main'
{do_message} = require '../../lib/openpgp/processor'
{burn} = require '../../lib/openpgp/burner'
km = 'test@test.pl'
top = require '../../lib/main'

#=================================================================

exports.import_brainpool_key_with_private_gen_by_gnupg = (T, cb) ->

  key = """-----BEGIN PGP PRIVATE KEY BLOCK-----
  Version: GnuPG v2
  
  lgAAAQYEVbntaBMJKyQDAwIIAQENBAMEClYR5Dou8NQJDo19vC+d2HgojkPliqOK
  Dj1O6Mz14Odf5JIhl/xviZ56fpMysfWuN8xW1q5zqFEbGr4S6W0cfxtlm65TWqIx
  SvdFhG/oYQh6FRiGxfdAm2ZieUR91kaq07vuaYSU3ACe/Et8pHF9bPPlaQnYaXSB
  pCLz0MuML9v+BwMCNy1sIxjV72zR5/RdXNkT2QZVM3VkdcL2cb/0EM1zcRjFCYv0
  hkeliB3wE9eaCnTYoyvxyLF2At4daD6l3TN72sSm6Hjeql6UtdOh1mRqjXh2rjb5
  vN4dMhhi72m4jJsEB4kBPcJdt9lKesbo0d2stCJUZXN0IFRlc3Rvd3kgKFRFU1Qp
  IDx0ZXN0QHRlc3QucGw+iLkEExMKACEFAlW57WgCGwMFCwkIBwIGFQgJCgsCBBYC
  AwECHgECF4AACgkQnUhzF+emi0nqMQH6AjNC0EmVqAquwMSHgR09iRl72W+zzQyL
  O1nAZyzBkugk8PpAbYxD6XpNOdIdXUoD905dkN53QeuJxqDfApXIqwH/ZYSqATuo
  eFZhXxughzXEJY5HGirJ0MykdeN0TG4plwKXEixQ6XkVIt6HHKPDih7rdsH57dDO
  zJ4IaVJFAd8YW54AAAEKBFW57WgSCSskAwMCCAEBDQQDBKpeDaEx+FDX19w7JI6R
  aLIRl53QvRVhk7OcefBQv3dOPYmQUZn/L9D8DWlS7+9N+MRBaHc+AyDjmK2VOPOl
  PeMrzLRDwglLjFk+IV4KASU78ZsNpktum+loR08RkQ6lgDctAKXURS0QWuq5WoDW
  eCXXi5vfF4tTSvzQMkTvZQu8AwEKCf4HAwJjwyagdrKbBNH6ujNLdCA3bL5lGO3L
  CzNhbjmc/QEEZ1rfp/BiO3QFK9Ie4GQWE5GUHsJkpEL2RsmCOlulmbR1iZsgVSED
  htfm+YcwsxNg7kJsw+U+OsEs6I0iBbRBpAIM6kfgjcvS5jQ9ES5qTGqIoQQYEwoA
  CQUCVbntaAIbDAAKCRCdSHMX56aLSaaYAf9chUcVPnpUa+9QCtntNDk8uc+8QULC
  b9mwHve4YTdMbyBC628Cm7HQRXcHe2FxBkHVyxNUKs4fCSR2BFYpQ75+Af9yt9Rv
  nfUttSw5ISrR5E4o3c7ttksKwSekC5ZEIhsHZbMEXgUiFAm1RGO//kaKtLIp2pMq
  uTtzjBJvad3u79Ta
  =RoWF
  -----END PGP PRIVATE KEY BLOCK-----"""

  await KeyManager.import_from_armored_pgp { raw : key }, defer err, tmp, warnings
  T.no_error err
  T.assert tmp?, "a key manager returned"
  T.assert (warnings.warnings().length is 0), "didn't get any warnings"
  km = tmp
  cb()

#=================================================================

exports.unlock_private = (T,cb) ->
  T.assert km.has_pgp_private(), "has a private key"
  await km.unlock_pgp { passphrase : '1234' }, defer err
  T.no_error err
  cb()

#=================================================================

exports.decrypt_brainpool = (T,cb) ->

  msg = """-----BEGIN PGP MESSAGE-----
  Version: GnuPG v2
  
  hL4DoZKnCZVkeswSBAMEJn1u0Wd8Ll0zntlrSJm1IDDIJtznYXkaNUIOljEonUAz
  CbPLgOa1wByJ1dIW4MVdHBXN3WSuWIvO9xkv03MmtmLpieMT9aJ8ZL6GX2JXF9ef
  2lF9uYUaV3oVkfqqRnC4oqPJU25sQGhAXJM+UvvFbnlYL04CppJbYptmCoOxdh8w
  g1U19YlRtsP2G9lWtCg+KWHuKzqv+Xm27BUop9tyQIgwKhVBUuTmohTLJRXvfqqn
  0k4BIj5BuEV37A+81jEiFrGAg450pFhqu3MbxgpJaf0O0OLYlbfe+Lc9QXlpW5AA
  pQZCJm0R3K9PgOK3RtkXmiyDu483nXmY8ioY7l3pVU0=
  =gSGw
  -----END PGP MESSAGE-----
  """
  await do_message { armored : msg, keyfetch : km }, defer err, msg
  T.no_error err
  T.equal msg[0].toString(), "hello world\n", "got the right plaintext"
  cb()

#=================================================================

exports.roundtrip_brainpool = (T,cb) ->

  plaintext = """
The Aquarium is gone. Everywhere,
giant finned cars nose forward like fish;
a savage servility
slides by on grease.
"""
  await burn { msg : plaintext, encrypt_for : km }, defer err, aout, raw
  T.no_error err
  await do_message { armored : aout, keyfetch : km }, defer err, msg
  T.no_error err
  T.equal plaintext, msg[0].toString(), "roundtrip worked!"
  cb()

#=================================================================

roundtrip_sig_crypt_brainpool = (T,km,cb) ->
  plaintext = """
The Aquarium is gone. Everywhere,
giant finned cars nose forward like fish;
a savage servility
slides by on grease.
"""
  await burn { msg : plaintext, encrypt_for : km, sign_with : km }, defer err, aout, raw
  T.no_error err
  await do_message { armored : aout, keyfetch : km }, defer err, msg
  T.no_error err
  T.equal plaintext, msg[0].toString(), "roundtrip worked!"
  T.assert (msg[0].get_data_signer()?), "was signed!"
  sign_fp = msg[0].get_data_signer().sig.key_manager.get_pgp_fingerprint()
  start_fp = km.get_pgp_fingerprint()
  T.equal sign_fp.toString('hex'), start_fp.toString('hex'), "signed by the right person"
  cb()

#======================================================================

exports.roundtrip_sig_crypt_brainpool = (T,cb) -> roundtrip_sig_crypt_brainpool T, km, cb

#=================================================================
