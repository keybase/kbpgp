
exports.openpgp = openpgp =
  public_key_algorithms :
    RSA : 1
    RSA_ENCRYPT_ONLY : 2
    RSA_SIGN_ONLY : 3
    ELGAMAL : 16
    DSA : 17
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
    expiration_time : 3
    exportable_certificate : 4
    trust_signature : 5
    regular_expression : 6
    revocable : 7
    key_expiration_time : 9
    preferred_symmetric_algorithms : 11
    revocation_key : 12
    issuer : 16
    notation_data : 20
    preferred_hash_algorithms : 21
    preferred_compression_algorithms : 22
    key_server_preferences : 23
    preferred_key_server : 24
    primary_user_id : 25
    policy_uri : 26
    key_flags : 27
    signers_user_id : 28
    reason_for_revocation : 29
    features : 30
    signature_target : 31
    embedded_signature : 32
  sig_types :  # See RFC 4880 5.2.1. Signature Types
    issuer : 0x10
    persona : 0x11
    casual : 0x12
    positive : 0x13
    subkey_binding : 0x18
    primary_binding : 0x19
  message_types :
    public_key : 4
    private_key : 5
  s2k :
    plain : 0
    salt : 1
    salt_iter : 3
    gnu : 101
  s2k_convention :
    none : 0
    checksum : 255
    sha1 : 254
  packet_tags :
    signature : 2
    secret_key : 5
    public_key : 6
    secret_subkey : 7
    public_subkey : 14
    userid : 13
  versions :
    keymaterial : V4 : 4
    signature : 
      V3 : 3
      V4 : 4
  signatures :
    key : 0x99
    userid : 0xb4

exports.kb =
  key_encryption:
    none : 0
    triplesec_v1 : 1
  json_encoding :
    plain : 0
    msgpack : 1
  packet_tags :
    signature : 0x002
    secret_key : 0x005
    public_key : 0x006
    secret_subkey : 0x007
    public_subkey : 0x00d 
    public_key_bundle : 0x101
    private_key_bundle : 0x102
  sig_types : openpgp.sig_types
  public_key_algorithms : openpgp.public_key_algorithms
  versions :
    V1 : 1
  signatures :
    self_sign_key_pgp_username : 1
    self_sign_key_keybase_username : 2
    subkey : 3
  padding :
    EMSA_PCKS1_v1_5 : 3
    RSASSA_PSS : 4
  key_defaults:
    primary :
      expire_in : 24*60*60*365*10
      len: 4096
    sub :
      expire_in : 24*60*60*365
      len : 2048
  kid : 
    version : 1
    trailer : 0x0a
    len : 20

exports.header =
  version : "Keybase OpenPGP JS 0.0.1"
  comment : "https://keybase.io"
