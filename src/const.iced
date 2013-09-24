
exports.openpgp = 
  public_key_algorithms :
    RSA : 1
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
