kbpgp = require '../../'
{KeyManager} = kbpgp
{make_esc} = require 'iced-error'
{PgpKeyRing} = require '../../lib/keyring'
{burn} = require '../../lib/openpgp/burner'
{PKESK,SEIPD,MDC} = require '../../lib/openpgp/packet/sess'
{parse} = require '../../lib/openpgp/parser'
{do_message} = require '../../lib/openpgp/processor'
{export_key_pgp,get_cipher} = require '../../lib/symmetric'
{encrypt} = require '../../lib/openpgp/ocfb'
{buffer_to_ui8a} = require '../../lib/util'
{nbs} = require '../../lib/bn'
{WordArray} = require 'triplesec'

C = kbpgp.const.openpgp

EXPECTED_ERROR = "Unable to decrypt"
RSA_BITS = 1024
ELGAMAL_PASSPHRASE = "mmpp"
TEST_TIME = Math.floor(new Date(2014, 2, 21)/1000)

ELGAMAL_KEY = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)

lQHhBFMGAboRBAC6X5nu5PxK9eaTRTGI1PUu89SYaDCNf4P82ADVwBy2gQSHZAlH
d1esdd5QI2TYvfLBYHelTLk6nfO/JsPFFTPAKiyCA84GO3MBXebs8JBd5VPl3PuY
YXk+xUVui/oE2bnS2PzUIPIilWwN1g6O4Olz+D70uuoGV8Og2krKUkzsRwCg+KcF
fiJsfgw7to/VXdD651DSZ/0D/3N5l1kiFZvttYSu6VymG76NBnPgbRKH3sYguGPj
c8E6GtJ1HrGQiGoiKN3jfYEQcOqil6/A780Yz/3yW6QK3OIJ9mIpNA8uJghWdk9E
3xhm0QrC4e3ECqQgAp5wGTfTaepsvjZxRyvu+xTQje/QMwEk3ElSOfjfq1nzjoE8
15YcBACzroFdReanDhMeRb2xjv8fjr98WqMGVjifPwJ2UEwtV8wPPGDNN63BbhYL
RyRxSrUdP3LDKnnNVocNOjOEGzrRtdKRf3S1cB7b+Tc2rphublG1yGIjDeNZ9E9g
mTrxr+mBm3WyFlBU3vEE+UJ3YLPQ37ai83CItaT22OY5FNAW3v4DAwIBuwNTyCVg
19Z/bQbO5Vv7myq59sSwfpLCcnjaII3oYjRYum32OrmIl1a2qPzOGpF1BfeyfT43
kin3XbQ1TWF4IFBsYW5jayAocGFzc3dvcmQgaXMgJ21tcHAnKSA8cGxhbmNrQGJl
cmxpbi5hYy5kZT6IaAQTEQIAKAUCUwYBugIbAwUJEswDAAYLCQgHAwIGFQgCCQoL
BBYCAwECHgECF4AACgkQkQqdjReS9VtG9ACeKf/N+cRCTEjARwbAWl9VAndRTvIA
mQE+l+Mv2PF8F3TUVVYl9aAXc3JHnQFYBFMGAboQBADSFqRZ8S7vJLXKW7a22iZR
4ezEGM4Rj+3ldbsgs+BHG3qrtILdWFeiXRfh+0XgSJyhZpRfPYeKdF42I0+JvFzF
QE/9pX5LsjeIgeB3P6gMi7IPrF47qWhixQ3F9EvBymlFFCXnJ/9tQsHytIhyXsZH
LD9Vti6bLyz8zkuXbRT8CwADBgP+LPUlmmIuuUu7kYMCLDy5ycRGv/x8WamSZlH3
6TBY44+6xIpzOGf1Aoag+e7b+5pJE5+dFfWhfvZpGn9tdLdimA7DVxl/YCeTxoXL
25YCnOhlqVFfWMnVr7Ml3hX0Hl3WXqRQT45ZR7qzfR+8xUvl6jTwYZzYElGIJxa5
hPreyJv+AwMCAbsDU8glYNfWXpn3WV1KYjnXsZwPA1zOth8DoZBvsNFgpJCxQpfI
PCeAcnTQQaF0NEEfXtNGKsbwYFdHTD7aXvAs2h05FReITwQYEQIADwUCUwYBugIb
DAUJEswDAAAKCRCRCp2NF5L1Wx7xAJ0a2tmT1WhB9+7IEHVkwm0b97EbJQCfcoDT
ZbLGiqgjXIjfEuNACFhveec=
=66In
-----END PGP PRIVATE KEY BLOCK-----
"""

state = null
original_seipd_decrypt = SEIPD::decrypt

make_key = (byte, len) -> Buffer.from(byte for i in [0...len])

modulus_byte_length = () -> state.encryption_key.key.max_value().mpi_byte_length()

valid_session_key = () ->
  export_key_pgp C.symmetric_key_algorithms.AES256, state.session_key

bad_checksum_session_key = () ->
  ret = Buffer.from valid_session_key()
  ret[ret.length - 1] ^= 1
  ret

unknown_cipher_session_key = () ->
  Buffer.concat [
    Buffer.from [0xff]
    make_key 0x11, 32
    Buffer.from [0, 0]
  ]

wrong_cipher_session_key = () ->
  export_key_pgp C.symmetric_key_algorithms.AES128, make_key 0x24, 16

eme_with_payload = (payload) ->
  k = modulus_byte_length()
  ps_len = k - payload.length - 3
  throw new Error "payload too long for RSA modulus" unless ps_len >= 8
  Buffer.concat [
    Buffer.from [0, 2]
    make_key 0x7f, ps_len
    Buffer.from [0]
    payload
  ]

bad_header_eme = () ->
  ret = eme_with_payload valid_session_key()
  ret[1] = 1
  ret

missing_separator_eme = () ->
  ret = make_key 0x7f, modulus_byte_length()
  ret[0] = 0
  ret[1] = 2
  ret

bad_checksum_eme = () -> eme_with_payload bad_checksum_session_key()

unknown_cipher_eme = () -> eme_with_payload unknown_cipher_session_key()

wrong_cipher_eme = () -> eme_with_payload wrong_cipher_session_key()

# This is a syntactically valid session key, but it does not match state.edat,
# which was produced by burn() with a different random session key.
wrong_session_key_eme = () -> eme_with_payload valid_session_key()

short_ps_eme = () ->
  k = modulus_byte_length()
  payload = valid_session_key()
  ps = Buffer.from [0x7f]
  pad_len = k - payload.length - ps.length - 3
  throw new Error "payload too long for RSA modulus" unless pad_len >= 0
  Buffer.concat [
    Buffer.from [0, 2]
    ps
    Buffer.from [0]
    make_key 0, pad_len
    payload
  ]

empty_session_key_eme = () -> eme_with_payload Buffer.from []

short_session_key_eme = () ->
  eme_with_payload Buffer.from [ C.symmetric_key_algorithms.AES256 ]

trailing_junk_session_key = () ->
  Buffer.concat [
    valid_session_key()
    Buffer.from [0x99]
  ]

trailing_junk_eme = () -> eme_with_payload trailing_junk_session_key()

packet_for_eme = (eme, cb) ->
  msg = nbs buffer_to_ui8a(eme), 256
  key = state.encryption_key.key
  if key.type is C.public_key_algorithms.ELGAMAL
    await key.pub.encrypt msg, defer c_mpis
    ekey = key.export_output { c_mpis }
  else
    await key.encrypt msg, defer ciphertext
    ekey = key.export_output { y_mpi : ciphertext }
  pkt = new PKESK {
    crypto_type : key.type
    key_id : state.encryption_key.get_key_id()
    ekey
  }
  await pkt.write defer err, ret
  cb err, ret

check_variant = ({T, name, eme, data_packet}, cb) ->
  esc = make_esc cb, name
  await packet_for_eme eme, esc defer pkesk
  data_packet or= state.edat.replay()
  raw = Buffer.concat [ pkesk, data_packet ]
  decrypt_calls = 0
  SEIPD::decrypt = (args, cb) ->
    decrypt_calls++
    original_seipd_decrypt.call @, args, cb
  await do_message {
    raw
    msg_type : C.message_types.generic
    keyfetch : state.ring
  }, defer err, out
  SEIPD::decrypt = original_seipd_decrypt
  T.assert err?, "#{name} failed"
  T.equal err?.message, EXPECTED_ERROR, "#{name} uses generic decrypt error"
  T.equal decrypt_calls, 1, "#{name} attempted encrypted data decrypt"
  T.assert not(out?), "#{name} returned no plaintext"
  cb()

make_cipher = () ->
  cipher_info = get_cipher C.symmetric_key_algorithms.AES256
  new cipher_info.klass WordArray.from_buffer state.session_key

encrypted_data_packet = (plaintext, cb) ->
  cipher = make_cipher()
  prefixrandom = make_key 0x55, cipher.blockSize
  await encrypt { cipher, plaintext, prefixrandom }, defer err, ciphertext
  unless err?
    pkt = new SEIPD { ciphertext }
    await pkt.write defer err, ret
  cb err, ret

mdc_mismatch_data_packet = (cb) ->
  plaintext = Buffer.concat [
    Buffer.from "not a packet"
    MDC.header
    make_key 0, 20
  ]
  encrypted_data_packet plaintext, cb

missing_mdc_header_data_packet = (cb) ->
  plaintext = Buffer.concat [
    Buffer.from "not a packet"
    make_key 0x33, 22
  ]
  encrypted_data_packet plaintext, cb

exports.init = (T, cb) ->
  esc = make_esc cb, "padding_oracle init"
  F = C.key_flags
  session_key = make_key 0x42, 32
  await KeyManager.generate {
    userid : "padding oracle test"
    nbits : RSA_BITS
    nsubs : 1
    primary_flags : F.certify_keys | F.sign_data
    sub_flags : [ F.encrypt_comm | F.encrypt_storage ]
  }, esc defer km
  await km.sign {}, esc defer()
  ring = new PgpKeyRing()
  ring.add_key_manager km
  encryption_key = km.find_crypt_pgp_key()
  T.assert encryption_key?, "found encryption key"
  await burn {
    msg : "padding oracle regression"
    encryption_key
  }, esc defer armored, raw
  [err, packets] = parse raw
  T.no_error err
  T.equal packets.length, 2, "encrypted message has two packets"
  edat = packets[1].to_enc_data_packet()
  T.assert edat?, "found encrypted data packet"

  state = { km, ring, encryption_key, edat, session_key }
  cb()

exports.rsa_bad_pkcs1_header = (T, cb) ->
  check_variant { T, name : "bad PKCS#1 header", eme : bad_header_eme() }, cb

exports.rsa_missing_pkcs1_separator = (T, cb) ->
  check_variant { T, name : "missing PKCS#1 separator", eme : missing_separator_eme() }, cb

exports.rsa_bad_session_key_checksum = (T, cb) ->
  check_variant { T, name : "bad session-key checksum", eme : bad_checksum_eme() }, cb

exports.rsa_unknown_session_cipher = (T, cb) ->
  check_variant { T, name : "unknown session-key cipher", eme : unknown_cipher_eme() }, cb

exports.rsa_valid_padding_wrong_session_cipher = (T, cb) ->
  check_variant { T, name : "valid padding with wrong session-key cipher", eme : wrong_cipher_eme() }, cb

exports.rsa_valid_padding_wrong_session_key = (T, cb) ->
  check_variant { T, name : "valid padding with wrong session key", eme : wrong_session_key_eme() }, cb

exports.rsa_short_pkcs1_padding_string = (T, cb) ->
  check_variant { T, name : "short PKCS#1 padding string", eme : short_ps_eme() }, cb

exports.rsa_empty_session_key_packet = (T, cb) ->
  check_variant { T, name : "empty session-key packet", eme : empty_session_key_eme() }, cb

exports.rsa_short_session_key_packet = (T, cb) ->
  check_variant { T, name : "short session-key packet", eme : short_session_key_eme() }, cb

exports.rsa_session_key_trailing_junk = (T, cb) ->
  check_variant { T, name : "session-key trailing junk", eme : trailing_junk_eme() }, cb

exports.rsa_mdc_mismatch = (T, cb) ->
  esc = make_esc cb, "rsa MDC mismatch"
  await mdc_mismatch_data_packet esc defer data_packet
  check_variant {
    T
    name : "MDC mismatch"
    eme : wrong_session_key_eme()
    data_packet
  }, cb

exports.rsa_mdc_missing_header = (T, cb) ->
  esc = make_esc cb, "MDC missing header crasher"
  await missing_mdc_header_data_packet esc defer data_packet
  check_variant {
    T
    name : "RSA MDC missing header"
    eme : wrong_session_key_eme()
    data_packet
  }, cb


# ------

exports.elgamal_setup = (T, cb) ->
  esc = make_esc cb, "elgamal setup"
  opts = now : TEST_TIME
  session_key = make_key 0x42, 32
  await KeyManager.import_from_armored_pgp {
    raw : ELGAMAL_KEY
    opts
  }, esc defer km
  await km.unlock_pgp { passphrase : ELGAMAL_PASSPHRASE }, esc defer()
  ring = new PgpKeyRing()
  ring.add_key_manager km
  encryption_key = km.find_crypt_pgp_key()
  T.assert encryption_key?, "found ElGamal encryption key"
  await burn {
    msg : "elgamal padding oracle regression"
    encryption_key
  }, esc defer armored, raw
  [err, packets] = parse raw
  T.no_error err
  T.equal packets.length, 2, "ElGamal encrypted message has two packets"
  edat = packets[1].to_enc_data_packet()
  T.assert edat?, "found ElGamal encrypted data packet"

  state = { km, ring, encryption_key, edat, session_key }
  cb()

exports.elgamal_bad_pkcs1_header = (T, cb) ->
  check_variant { T, name : "ElGamal bad PKCS#1 header", eme : bad_header_eme() }, cb

exports.elgamal_missing_pkcs1_separator = (T, cb) ->
  check_variant { T, name : "ElGamal missing PKCS#1 separator", eme : missing_separator_eme() }, cb

exports.elgamal_bad_session_key_checksum = (T, cb) ->
  check_variant { T, name : "ElGamal bad session-key checksum", eme : bad_checksum_eme() }, cb

exports.elgamal_unknown_session_cipher = (T, cb) ->
  check_variant { T, name : "ElGamal unknown session-key cipher", eme : unknown_cipher_eme() }, cb

exports.elgamal_valid_padding_wrong_session_cipher = (T, cb) ->
  check_variant { T, name : "ElGamal valid padding with wrong session-key cipher", eme : wrong_cipher_eme() }, cb

exports.elgamal_valid_padding_wrong_session_key = (T, cb) ->
  check_variant { T, name : "ElGamal valid padding with wrong session key", eme : wrong_session_key_eme() }, cb

exports.elgamal_short_pkcs1_padding_string = (T, cb) ->
  check_variant { T, name : "ElGamal short PKCS#1 padding string", eme : short_ps_eme() }, cb

exports.elgamal_empty_session_key_packet = (T, cb) ->
  check_variant { T, name : "ElGamal empty session-key packet", eme : empty_session_key_eme() }, cb

exports.elgamal_short_session_key_packet = (T, cb) ->
  check_variant { T, name : "ElGamal short session-key packet", eme : short_session_key_eme() }, cb

exports.elgamal_session_key_trailing_junk = (T, cb) ->
  check_variant { T, name : "ElGamal session-key trailing junk", eme : trailing_junk_eme() }, cb

exports.elgamal_mdc_mismatch = (T, cb) ->
  esc = make_esc cb, "elgamal MDC mismatch"
  await mdc_mismatch_data_packet esc defer data_packet
  check_variant {
    T
    name : "ElGamal MDC mismatch"
    eme : wrong_session_key_eme()
    data_packet
  }, cb

exports.elgamal_mdc_missing_header = (T, cb) ->
  esc = make_esc cb, "MDC missing header crasher"
  await missing_mdc_header_data_packet esc defer data_packet
  check_variant {
    T
    name : "ElGamal MDC missing header"
    eme : wrong_session_key_eme()
    data_packet
  }, cb
