
exports.openpgp = 
  public_key_algorithms :
    RSA : 1
  symmetric_key_algorithms :
    CAST5 : 3
    AES128 : 7
    AES192 : 8
    AES256 : 9
  hash_algorithms :
    SHA1   : 2
    SHA256 : 8
    SHA384 : 9
    SHA512 : 10
    SHA224 : 11
  sig_subpacket:
    creation_time : 2
    issuer : 16
  message_types :
    public_key : 4
    private_key : 5
  s2k :
    plain : 0
    salt : 1
    salt_iter : 3
  packet_tags :
    signature : 2
    secret_key : 5
    public_key : 6
    userid : 13
  versions :
    keymaterial : V4 : 4
    signature : V4 : 4
  signatures :
    key : 0x99
    userid : 0xb4

exports.kb =
  key_encryption:
    none : 0
    triplesec_v1 :  1
