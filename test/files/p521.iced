{KeyManager} = require '../../lib/main'
{do_message} = require '../../lib/openpgp/processor'
{burn} = require '../../lib/openpgp/burner'
km = null
top = require '../../lib/main'

exports.import_private_nistp521_key_from_gpg = (T, cb) ->
  priv_key = """-----BEGIN PGP PRIVATE KEY BLOCK-----

lNkEWAJ/HhMFK4EEACMEIwQBX1achVr3ad6/1AYQM0Xpb0yOch0Va2+d1WjAi/TU
lVMYFq3Sv1HRgwz87iaEGv2lViKTZ2Zbqh68ndyBoAY9CpQAzHrEnFozvQBQxSHe
JaWxdiJIF3ZtLRrxMm+SBSKcQge2TwXmFr/coEKU3uS6PNHz9/1qKvOflbLwgiP6
PWt01HYAAgUeo/x+60pfXvYBT/YwzYtEpMgY3ahEM64gNzCSwbggGdCK02H53Rir
hQc4NHL/N/dYachvcGllNP2yi5ygNeSjYiDxtCRuaXN0IGtleSB0ZXN0ZXIgPG0r
dGVzdGluZ0B6YXB1Lm5ldD6IvQQTEwoAIQUCWAJ/HgIbAwULCQgHAgYVCAkKCwIE
FgIDAQIeAQIXgAAKCRDwOj0LJyvhfR5OAgkBhXIMxYkE8EuBDPjtHG7DliwBt+Ht
++KWGHxWqkAFWQitjGK33JANOyuMjMr8ealisUsbRO4io51vsOa6BVrvQVsCCQEn
VHpmetF7urR2j+V/Qr3SmT01sj0opToya52YoM1eS7+bSJRtPYyz4GomHSbMe76m
zxqcXBu7xS1moh/HQP4gW5zeBFgCfx4SBSuBBAAjBCMEAP1NEe5jGggGOhGr99OX
zwvBPLbcsyIf7cpqDi1IAHCxcnoYzVIoBJEjkdyHpuTQAvjddSF+SNGk48O4z+Ev
tmlAAI1ChPg4ZLEk1fLqq/mxsyc3HT5Ny6cKYMeW3cfCAVLlmcLYPMt5ELCOBWj+
Iy6fp22eVsMaL2S2teDJ+ZsN2abeAwEKCQACCQFm8eXql6OnFxTUQ1ODtW0ub4MM
BNz1lcGW5PV06vXOwxKEcS1H3HK/ALqD3c7F+mQOAiWnmCXpNRgqKEfd1Rsz1SHH
iKMEGBMKAAkFAlgCfx4CGwwACgkQ8Do9Cycr4X3dmAIHUn62iaxtsJ3/FlSZhXxy
d8fW4Z3NhFlCLVL6p4NijQUJQPZMcDyh9fPvSdLE1CvBMtzow2qvEVUWiunus7nl
mPwCBioXoB7rOhvEz59qnTLAjPLMOw9ib+IEjthSzrGJpfQVn1n/izJbfeG7Ghg+
FAvmbYconl4Q0uWVJFs6Ys23JuUn
=IypP
-----END PGP PRIVATE KEY BLOCK-----
  """

  await KeyManager.import_from_armored_pgp { armored: priv_key }, defer err, tmp, warnings
  T.no_error err
  T.assert tmp?, "a key manager returned"
  T.assert (warnings.warnings().length is 0), "didn't get any warnings"
  km = tmp
  cb()

exports.roundtrip_nistp521 = (T, cb) ->
  plaintext = """ 
  And it happened all the time that the compromise between two
  perfectly rational alternatives was something that made no sense at
  all.
  """

  await burn { msg: plaintext, encrypt_for: km }, defer err, aout, raw
  T.no_error err
  await do_message { armored: aout, keyfetch: km }, defer err, msg
  T.no_error err
  T.equal plaintext, msg[0].toString(), "decrypted text matches plaintext"
  cb()

exports.decrypt_padded_v_521 = (T, cb) ->
  ###
  This weird message (notice the "AAAAAA..." in payload) is a valid
  ECDH encrypted message, but the secret coordinates are encoded with
  a lot more bits that the curve's coordinate size. GPG and go-crypto
  take this message without problems, but KBPGP is a bit more strict
  and fails with:

  Error: Need 1059 bits for this curve; got 1459
  at Curve.exports.Curve.Curve._mpi_point_from_slicer_buffer

  istack:
   [ 'Priv::decrypt',
     'Message::decrypt',
     'Message:process',
     'Message::parse_and_process' ] }
  ###

  armored_msg = """-----BEGIN PGP MESSAGE-----
Version: Keybase OpenPGP v2.0.58
Comment: https://keybase.io/crypto

wcA0A6pi0WoSlxTXEgWzBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ZTuFZa3
go5bAv8SLZd5vTQzjQiqiXfaQUX3dQu+zytgEeiugIshlJ7JykTPGhdQFVSiKQYe
a4RKpgbn8SkNhyIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaR1kL+5vnf9E0wv
vGDKg1jo0uEGYVodxTwk8QuqbxWiCT/jOH9kybjECSPlkDkbUIOezOfaTlwde0Wo
XUNWZ/WrMOJHerpQvMvPNjEwMSGnsIZPh8/Hafj7j8OauMG5EWgCrzsxv1mgsRXP
QkNog/5dM9JIAcT8RpDaFecdhRag6ZPuRKmNuhiFtR7o0spcqX2UkJ3FPB7UydX3
ch9PkTNL1BVD++JqYQE9eaIqlCTAsHwCgO6pQkQqPUvB
=y7cW
-----END PGP MESSAGE-----


"""

  await top.unbox { armored: armored_msg, keyfetch: km }, defer err, plain
  T.no_error err
  T.equal "purpleschala", plain[0].toString(), "decrypted text matches plaintext"
  cb()
