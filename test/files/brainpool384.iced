{KeyManager} = require '../../lib/main'
{do_message} = require '../../lib/openpgp/processor'
{burn} = require '../../lib/openpgp/burner'
km = null
top = require '../../lib/main'

#=================================================================

exports.import_brainpool384_key_with_private_gen_by_gnupg = (T, cb) ->

  key = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2

lNYEVcxnrxMJKyQDAwIIAQELAwMEUJgB6OlAqOFOsLsW1kG9NbqVZyPITd5H1dvX
quD399rUXy16WKTCOBv8Rtk8pJMfLoyPQfN4BbysZTOYYp1Uw3gBQV2KahVxokyx
TXo5DqramOvTpdXK8aALac3nxUWP/gcDAkMjTh8avKR10UNX9QpHiyZqQROwLYEI
nhRW18mK5LO/AiH+0mpxK4rMbVAGy4FJAvt6JDaM7/mDbBaAMiY6sV9b38o1Wtnv
uqVfwx6jSsbaSKtkVE+5LZuAbN699xrLtCdUZXN0IEJyYWlucG9vbCAzODQgPDM4
NEBicmFpbnBvb2wudGVzdD6ImQQTEwkAIQUCVcxnrwIbAwULCQgHAgYVCAkKCwIE
FgIDAQIeAQIXgAAKCRA6fAaeW5nT4aBsAX92gkhndQfkRkYnuC60EziSYgMGBTZy
8SpkXknpqbWO9T+oKVrkyKki57mSItYSeYwBfigPprgIH2KLk2Il+A4+BeqRSl+B
AQdzeD0eF/QnfG9+yq4KsMZ0Z9yRh4W0gGoPaJzaBFXMZ68SCSskAwMCCAEBCwMD
BBn/EkKMcC9krkjgDlX+5tW2hiZ2WZm67lg4HnupledTswaduRGC/rLTgCpGdXbC
7yzVl4XNQ98r9Ekfxw1S0D02wWTg0IJDGFNPHoPR+NRbmO0KN/6KXkDdlhCBRQtD
NwMBCQn+BwMCOzl83dZLYYnR5NmFFm1bsHF+ENgmQhiUXcHv2GRNOirxlRAdevwU
1RFsoYnnmI0qhqAEGiWDjzzgNIBROsa6/s7a+yA2G4xtzDYYKc2chtW+8Onmdu2G
9uGaoQ2HNeyIgQQYEwkACQUCVcxnrwIbDAAKCRA6fAaeW5nT4S/bAXwI8fgkDlME
fjm5TWDPqN9n6/zbuhyqaHBXfoPjHgEbPYV4mX4xOALakgbDELhUtkEBf1FbYONg
EQ5OkgXBM+G54PL6nWmABbb08ZoZ6TZc1epnVv39+OSKom828SEyGjsdaA==
=4K/l
-----END PGP PRIVATE KEY BLOCK-----"""

  await KeyManager.import_from_armored_pgp { raw : key }, defer err, tmp, warnings
  T.no_error err
  T.assert tmp?, "a key manager returned"
  T.assert (warnings.warnings().length is 0), "didn't get any warnings"
  km = tmp
  cb()

#=================================================================

exports.unlock_private_brainpool384 = (T,cb) ->
  T.assert km.has_pgp_private(), "has a private key"
  await km.unlock_pgp { passphrase : '384' }, defer err
  T.no_error err
  cb()

#=================================================================

exports.decrypt_brainpool384 = (T,cb) ->

  msg = """-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

hJ4DZABmfiqEGAcSAwMEf4K2BzfsqaF/teXLF4l1vuUP6EMyPx4Cibsmh41DmdDR
bpqqf2143HA6tIAK1GcPCNcBe8R44SGBa1mAeEEgmx6voxkLr+gF3f+0Jb4tuUci
dEH0y3I05Fo0ZGIRl569MHG/3ClOfGJMYanw5b1gwrAlhq8iWCfo9+eZ6p2vroIh
8iRxXRcoFK3Px8cT+ZZaAdJhAbIg07NzK4N3Me4oL4h1Pi0IjwqhV8Nck9SbXAWy
E3jcPzLTn4PgLhSew70QrbhTyr7nR9TlgDfz+aKYqSbqYf4OiGzeuYRpQ1n4shKH
Gwhg5h7s7T5VJDrC6GwdRfL7gA==
=SZA+
-----END PGP MESSAGE-----"""
  await do_message { armored : msg, keyfetch : km }, defer err, msg
  T.no_error err
  T.equal msg[0].toString(), "hello world (Brainpool 384)\n", "got the right plaintext"
  cb()

#=================================================================

exports.roundtrip_brainpool384 = (T,cb) ->

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

roundtrip_sig_crypt_brainpool384 = (T,km,cb) ->
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

exports.roundtrip_sig_crypt_brainpool384 = (T,cb) -> roundtrip_sig_crypt_brainpool384 T, km, cb

#=================================================================
