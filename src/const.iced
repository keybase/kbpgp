
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
  subpacket_types :
    issuer : 16
  message_types :
    public_key : 4
    private_key : 5
  s2k :
    plain : 0
    salt : 1
    salt_iter : 3
  packet_tags :
    secret_key : 5
    public_key : 6

exports.kb =
  key_encryption:
    triplesec_v1 :  1
