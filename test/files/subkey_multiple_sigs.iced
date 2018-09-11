C = require('../../lib/const').openpgp
{KeyManager} = require '../../lib/main'
{do_message} = require '../../lib/openpgp/processor'
{Message} = require '../../lib/openpgp/armor'
{make_esc} = require 'iced-error'

# Keep key in parts that we concatenate in different ways to get different
# result.

keyAndIds = 'c652045b6ddf5c13082a8648ce3d0301070203048045029015d8888429bacbb832095232fe6486260846e828dc24f4e3b935bc0c21876e13d2a083416247b96b14a4c4de39b2011c8c133248a3a83f0af47528f3cd264d69636861c582205067702054657374203c6e6f742d7a617075406b6579626173652e696f3ec2640413130a001605025b6ddf5c09102d2bdc8ff918a03b021b0302190100004f7e00fb071eb0b897ceca4652667d9a4e958d23e89f41e355ef244876de389ed21561ca00fe2fc2b260e39c5cf7fb2fdb8d0aa126d85f4c07a0ca3f91c26e0e3dcfde9ba4bb'
subkey = 'ce6d045b6ddf5c010300ef5ba59300be1cb017b7c9e1f1646766c162b51c1193bbe892277488b0554998758e88741aac10202f27cd48bf464c1e6982b703e4b3202d807e256d01a0d6e738aae332b0a1f79da3602fa092c11ffbc89b9a2dde1583811f51883870c57fcf0011010001'

# Signature with Flags=Sign, valid cross-signature, and expiring 4 years from
# now.
flagSignSig = 'c2c01b0418130a001905025b6ddf5c09102d2bdc8ff918a03b021b0205090784ce00007473200419010a000605025b6ddf5c0000499d0300c5e7a9740421c674cca7374422e802dcdc6e85b6312c389f19232f2df812a137795508f91144edab7e166a421657f2dd8ec9b9d3453102ba7ec5e41387bcbf0d095f8fedd95ccf01148efdace5117c94aaea177ffbc70c4c3ba12fb6fd5415f283040100b2bcb6f4a7861c162ce7fdae50ba5017fb779026b49260ad8158f61449a753ef010081ba0a267c641c18d6f01fd59966cc19e4eec68457dc5acbb120137f5abbda5c'

# Signature with Flags=Encrypt, no cross-signature (not needed), and never
# expiring. When both are present in bundle, this one will win and key will
# become encryption key.
flagEncryptSig = 'c2610418130a001305025b6ddf5c09102d2bdc8ff918a03b021b0c0000ff2c00ff7ca3194202858f9904c939551425b8943b646b3348f57d149fb4500f2ecf2c520100cad11801d70bd362b7ed0ce890582550fd09b167afefdff73c75eae223e9808a'

pgpSignedMsg = """
-----BEGIN PGP MESSAGE-----

xA0DAAoB8yxD5M0JBc0By+F0AOIAAAAA5GhlbGxvIGNyb3NzIHNpZ27jZWQgd29y
bGQAwnwEAAEKABAFAluWvdwJEPMsQ+TNCQXNAADlxgMArqKsm9evebQFpSxk3oRy
eNVGDxPDX+p4/60hgoYAijP4BFZ8r1DedFDih+fU/qYYgb88A9dlADOuWMTrqIVH
h6YAkkaVK7Y2qx2pubRJShMhiVhnFgDX+8ABfGPWKoTD
=ipmT
-----END PGP MESSAGE-----

"""

exports.load_multi_binding_key_and_verify = (T, cb) ->
  esc = make_esc cb, "load_multi_binding_key_and_verify"
  keyBuf = Buffer.from([keyAndIds, subkey, flagSignSig, flagEncryptSig].join(''), 'hex')
  msg = new Message { body : keyBuf, type : C.message_types.public_key }
  await KeyManager.import_from_pgp_message { msg }, esc defer km
  await do_message { armored : pgpSignedMsg, keyfetch : km }, defer err, msg
  T.assert err?, "have error"
  T.assert err?.toString().indexOf("We don't have a key for the requested PGP ops") isnt -1, "have right message"
  cb null

exports.load_with_only_right_sig_then_verify = (T, cb) ->
  esc = make_esc cb, "load_with_only_right_sig_then_verify"
  # Only concat flagSignSig - if we don't add encryptSig, it won't
  # "win over" signSig, so this key will actually function as a 
  # signing subkey.
  keyBuf = Buffer.from([keyAndIds, subkey, flagSignSig].join(''), 'hex')
  msg = new Message { body : keyBuf, type : C.message_types.public_key }
  await KeyManager.import_from_pgp_message { msg }, esc defer km
  await do_message { armored : pgpSignedMsg, keyfetch : km  }, defer err, msg
  T.assert not(err?), "no error"
  T.assert (msg[0]?.get_data_signer()?), "was signed!"
  T.equal msg[0]?.data.toString(), "hello cross signed world", "right message cae back"
  cb null
  