{KeyManager} = require '../../lib/main'
{do_message} = require '../../lib/openpgp/processor'
{burn} = require '../../lib/openpgp/burner'
km = null
top = require '../../lib/main'

#=================================================================

exports.import_brainpool512_key_with_private_gen_by_gnupg = (T, cb) ->

  key = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2

lgAAAQYEVcxneRMJKyQDAwIIAQENBAMEKTuXDuEoTy1rG7iUm/llXg28H7xTPS+R
ROnsD6h2Kh6iy15YR2m1YIJuIhx5RYYyE2KNn89PXToah1//+9uSRh2e+TveGkuE
Pd4Hu8LFBP2ofXxk5D2f3vmjoyOhNUEe+9uaSftFZmLs/r4oaZ/u8eGlx7s47wRS
G2kPDKUO6/D+BwMCMMuaL5lfhQ3Rj8R0akKIcueYulMCQg66Uo06IUf2Yf+1acJK
KLwAeL8aBXg8M7cjGFeSxBoD/LGvl/s32Txag4xYLvIyaey+xN9JjrFjHI7nMi3V
mEzMUIR6gn8t+NwTLDcBQJ7N6gmC6jLrce3EtCdUZXN0IEJyYWlucG9vbCA1MTIg
PDUxMkBicmFpbnBvb2wudGVzdD6IuQQTEwoAIQUCVcxneQIbAwULCQgHAgYVCAkK
CwIEFgIDAQIeAQIXgAAKCRCzkTIRepX4U3gjAgCmz5YQ0IOrLilXfS6hJqF18qf0
k2PhfYif8n+FZShxZRK8FnU/EuQYCW3nZNAH8UJSaxO3xBuUxybFDo+d3yEiAf9h
Flwe1NLIi1YtlglaGJIAKilvvwj7smx64Ew7rdwO8/blePEHQfZEwkok0JrMMPZw
QPe10Xdn3X8Fx7EQcwffngAAAQoEVcxneRIJKyQDAwIIAQENBAMEn4OX7LOmIRWY
jkosy1Xj0I25LmTzGP+i5pgcWyMQ0HFlSr1HVrIlo4h8/7nk8WIdKAdP+uhrXT4n
IR3iqDZcMzjDymvs6xncJ/dn3dhrKSCcLiAV6GyF9OkpEKtTHuhYf5/spjHTJOVT
N0pLRrDaQlFqyny9dLnU/+pl8Sf0Ge4DAQoJ/gcDAlYwAymPvwe70eUdPHnhm1yh
EtlyRqAsn8c+QaFUuhcpIi8u2dEM++F8t/fEx1pLOgUaofgVU/XKgVaUhoJfTkP7
d1ktWFzwkjrpsLKdFq+YxaCmLxABTFeHTJZjzuaOOgH3YbXabFqVRjQVOLJyVIih
BBgTCgAJBQJVzGd5AhsMAAoJELORMhF6lfhTp6oB/0l4psW7ffH4fTgKUncDpOSZ
UqyZD5jpOCbQ6wf2yNc+yLbMsGSRX9mQzbCR+maQkue36qPJCMdaH2wybYN0k+0B
/3RFzWht7gsAugNADo/gjKp949Ohbe76IMTi+3EwUvLPcsK/fDEiq3nArIHZAv3e
xFIuT92JQth9XYDN35WFfjw=
=vZw8
-----END PGP PRIVATE KEY BLOCK-----"""

  await KeyManager.import_from_armored_pgp { raw : key }, defer err, tmp, warnings
  T.no_error err
  T.assert tmp?, "a key manager returned"
  T.assert (warnings.warnings().length is 0), "didn't get any warnings"
  km = tmp
  cb()

#=================================================================

exports.unlock_private_brainpool512 = (T,cb) ->
  T.assert km.has_pgp_private(), "has a private key"
  await km.unlock_pgp { passphrase : '512' }, defer err
  T.no_error err
  cb()

#=================================================================

exports.decrypt_brainpool512 = (T,cb) ->

  msg = """-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

hL4D9Syf+g/66VoSBAMEp0cp/Z8KXi6HNN+9SdBUmFM+yI+N/4wqnNGjJL/yJvu5
s1thg65tdbyB/WPv3wKqzd8rO8egA0t6qbiaEC0GKiJwtOwkTa662u7UpY4VtbAW
SrZObyNoggX9xfnKCNSJWYDpmPlO2H8lMWRc7UYRWKUavYod8ald3pdhrNp9DFMw
9QgFnZ7M2PjrK/6ehVbht8GlaZMygZzrS2wnn62LFa3es4Yn35JNSC5XIfyazmbq
0mEBSbFk6hyFSqeU/c2DNApnDmB60xfd4LcxD747GnuuTCJ4QGvFi+JNQebEUq+u
izG4MHAkcWoSOm03VB8StW3UwUDlbUlFK1FZa4jCCKUm3zfDWxuFlkedMt9dlVnT
HSXu
=3zMR
-----END PGP MESSAGE-----"""
  await do_message { armored : msg, keyfetch : km }, defer err, msg
  T.no_error err
  T.equal msg[0].toString(), "hello world (Brainpool 512)\n", "got the right plaintext"
  cb()

#=================================================================

exports.roundtrip_brainpool512 = (T,cb) ->

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

roundtrip_sig_crypt_brainpool512 = (T,km,cb) ->
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

exports.roundtrip_sig_crypt_brainpool512 = (T,cb) -> roundtrip_sig_crypt_brainpool512 T, km, cb

#=================================================================
