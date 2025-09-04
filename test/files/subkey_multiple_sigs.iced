C = require('../../lib/const').openpgp
{KeyManager} = require '../../lib/main'
{do_message} = require '../../lib/openpgp/processor'
{Message} = require '../../lib/openpgp/armor'
{make_esc} = require 'iced-error'

# Keep key in parts that we concatenate in different ways to get different
# result.

keyAndIdsPackets = 'c652045b6f142613082a8648ce3d030107020304a54bdb6b6f7c145f584c3cf33ba9894b16708b3707310df27625546d2b10310a4ac4b23c516c8ceb4f38aa96a21e02c8717480c831095a2a287317d8e03e3c22cd264d69636861c582205067702054657374203c6e6f742d7a617075406b6579626173652e696f3ec2640413130a001605025b6f14260910433b1545547b718c021b03021901000034cf00ff68b1c1c4abded838df365ce8bec751ff2de8b58cf474b39cef708ac9790db30d0100a8702072316854172daff68dc0167c9e66b2159bca936087a30a8f7054ef20a8'
subkeyPacket = 'ce6d045b6f1426010300b97dfbd29467121a7f621d2eff9c78ad8f90017f2074c94f1999ae9956b7e2169af0bcf9d3021421b88e9166d11a2e3153d8ccd9c85d59525af654e4e4c63166273dc365a04ac40d8abce2397aa3058433ce76afba7c7362d130cd395e4e1f0d0011010001'

# Signature with Flags=Sign, valid cross-signature, and expiring 4 years from
# now.
signSigPacket = 'c2c01b0418130a001905025b6f14260910433b1545547b718c021b0205090784ce00007473200419010a000605025b6f14260000863803006e73fb2763cb717761b4c8cda9306037c58715454f92d4c39004cf7adffdfc25ea79b85d65840a13bb8eb1d8db455a2f72207195aeed8f6a37e6dfcd35ef5985de539f3bf17358841ad7581fc2cb5844dbb0b2d206e6ae6e99447fcb7f9306517a6100fe396ab483e28ccc6f55e9129c9c209e92eca03560c4baf3156e454347a8c4d27f00fe216749fa6aadb5018c00699b71040f3404572c257772b71751de234f361edaf7'

# Signature with Flags=Encrypt, no cross-signature (not needed), and never
# expiring. When both are present in bundle, this one will win and key will
# become encryption key.
encryptSigPacket = 'c2610418130a001305025b6f14260910433b1545547b718c021b0c000013aa0100b42663de14cbf358a84d96c997450fc7911426b4eff49aa36bcc532b352618e800ff5953423ce1f82b35ed8b421c3d9a3b3f4f02d0aa05bfa8f99c5b8711b1f290b4'

# Signature with Flags=Encrypt, cross-certified. This binding makes key expire
# after 4 years, so if it's combined with binding with no-expiration, it should
# lose.
encryptXSignPacket = 'c2c01b0418130a001905025b6f14260910433b1545547b718c021b0c05090784ce00007473200419010a000605025b6f14260000863803006e73fb2763cb717761b4c8cda9306037c58715454f92d4c39004cf7adffdfc25ea79b85d65840a13bb8eb1d8db455a2f72207195aeed8f6a37e6dfcd35ef5985de539f3bf17358841ad7581fc2cb5844dbb0b2d206e6ae6e99447fcb7f930651f00200ff785d955a6c2a10bded5f7033ba6fa9b38b58dcbf17039bf593fd060a4735e3ef00fd12376c99eb14665d8620c90debc5993be492dbb163e9bc364d52b2b8acc11c68'

# Signature with Flags=Sign, not cross-certified. Provides no-expiration for the,
# so it would win against encryptXSignPacket. 
signSigNoXSignPacket = 'c2610418130a001305025b6f14260910433b1545547b718c021b020000ca2f00ff7c5d366c584ca03ea27cd0dad841f8adda24fc7efa212550ec773effc418136300fe32160c17b36a3a13be3ca6058d35dc7da89bfbb857753e6db45994183e58ed6d'

armoredMessage = """
-----BEGIN PGP MESSAGE-----

xA0DAAoBRFStQ5saN6IBy+F0AOIAAAAA5GhlbGxvIGNyb3NzIHNpZ27jZWQgd29y
bGQAwnwEAAEKABAFAluX8qYJEERUrUObGjeiAADPOgMAaAUjgKY0r+vsO4bxXr5d
F99ostfQWReex/tkPGqvQRrwEVMKgymQ8zerQdu+30nl+UibIXu9LSvxPbQkPcWN
xC/ywM5zfa/WOMD1zrOjoCpUktnyMZN8H4P4bF8Az4aj
=7UNF
-----END PGP MESSAGE-----

"""

make_key_from_parts = (parts, cb) ->
  keyBuf = Buffer.from(parts.join(''), 'hex')
  msg = new Message { body : keyBuf, type : C.message_types.public_key }
  KeyManager.import_from_pgp_message { msg }, cb

exports.load_multi_binding_key_and_verify = (T, cb) ->
  esc = make_esc cb, "load_multi_binding_key_and_verify"
  await make_key_from_parts [keyAndIdsPackets, subkeyPacket, signSigPacket, encryptSigPacket], esc defer km
  await do_message { armored : armoredMessage, keyfetch : km }, defer err, msg
  T.assert err?, "have error"
  T.assert err?.toString().indexOf("We don't have a key for the requested PGP ops") isnt -1, "have right message"
  T.assert not(msg?), "should not return msg"
  cb null

exports.load_with_only_right_sig_then_verify = (T, cb) ->
  cb null
  # FIXME
  # esc = make_esc cb, "load_with_only_right_sig_then_verify"
  # # Only concat flagSignSig - if we don't add encryptSig, it won't
  # # "win over" signSig, so this key will actually function as a 
  # # signing subkey.
  # await make_key_from_parts [keyAndIdsPackets, subkeyPacket, signSigPacket], esc defer km
  # await do_message { armored : armoredMessage, keyfetch : km  }, defer err, msg
  # T.assert not(err?), "no error #{err}"
  # T.assert (msg?[0]?.get_data_signer()?), "was signed!"
  # T.equal msg?[0]?.data.toString(), "hello cross signed world", "right message came back"

  # cb null
  
exports.do_not_merge_crosscertify = (T, cb) ->
  cb null
  # FIXME
  # esc = make_esc cb, "do_not_merge_crosscertify"
  # # Pass two bindings: one x-certified with flags=encrypt, and another one
  # # *not x-certified* with flags=sign. Subkey should become cross-certified
  # # signing subkey.
  # await make_key_from_parts [keyAndIdsPackets, subkeyPacket, encryptXSignPacket, signSigNoXSignPacket], esc defer km, w
  # # Right now, KBPGP will throw that subkey completely. This happens because
  # # the second binding "wins" (because it provides indefinite key lifetime),
  # # but then in _check_subkeys it is found out that the binding provides no
  # # cross cerfitication, so subkey is deemed invalid.
  # T.assert w.warnings().length is 1, "expecting a warning"
  # T.assert w.warnings()[0]?.indexOf("Subkey 0 was invalid") isnt -1, "found the right warning"
  # await do_message { armored : armoredMessage, keyfetch : km  }, defer err, msg
  # T.assert err?, "expecting an error"
  # T.assert not(msg?), "do not return message"
  # cb null
