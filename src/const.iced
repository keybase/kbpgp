
exports.openpgp = openpgp =
  public_key_algorithms :
    RSA : 1
    RSA_ENCRYPT_ONLY : 2
    RSA_SIGN_ONLY : 3
    ELGAMAL : 16
    DSA : 17
    ECDH : 18
    ECDSA : 19
    ELGAMAL_SIGN_AND_ENCRYPT : 20
    EDDSA : 22
  symmetric_key_algorithms :
    CAST5 : 3
    AES128 : 7
    AES192 : 8
    AES256 : 9
  hash_algorithms :
    MD5    : 1
    SHA1   : 2
    RIPEMD160 : 3
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
    experimental_low : 101
    experimental_high : 110
  sig_types :  # See RFC 4880 5.2.1. Signature Types
    binary_doc : 0x00
    canonical_text : 0x01
    issuer : 0x10
    persona : 0x11
    casual : 0x12
    positive : 0x13
    subkey_binding : 0x18
    primary_binding : 0x19
    direct : 0x1f
    key_revocation : 0x20
    subkey_revocation : 0x28
    certificate_revocation : 0x30
  message_types :
    generic : 0
    public_key : 4
    private_key : 5
    signature : 8
    clearsign : 9
  s2k :
    plain : 0
    salt : 1
    salt_iter : 3
    gnu : 101
    gnu_dummy : 1001
  s2k_convention :
    none : 0
    checksum : 255
    sha1 : 254
  ecdh :
    param_bytes : 3
    version : 1
  packet_tags :
    PKESK : 1
    signature : 2
    one_pass_sig: 4
    secret_key : 5
    public_key : 6
    secret_subkey : 7
    compressed : 8
    literal : 11
    public_subkey : 14
    userid : 13
    user_attribute : 17
    SEIPD : 18
    MDC : 19
  literal_formats :
    binary : 0x62
    text : 0x74
    utf8 : 0x75
  versions :
    PKESK : 3
    SEIPD : 1
    one_pass_sig : 3
    keymaterial : V4 : 4
    signature : 
      V2 : 2
      V3 : 3
      V4 : 4
  signatures :
    key : 0x99
    userid : 0xb4
    user_attribute : 0xd1
  key_flags : 
    certify_keys : 0x1
    sign_data : 0x2
    encrypt_comm : 0x4
    encrypt_storage : 0x8
    private_split : 0x10
    auth : 0x20
    shared : 0x80
  features:
    modification_detection : 0x1
  key_server_preferences:
    no_modify : 0x80
  compression : 
    none : 0
    zip  : 1
    zlib : 2
    bzip : 3

exports.kb =
  key_encryption:
    none : 0
    triplesec_v1 : 1
    triplesec_v2 : 2
    triplesec_v3 : 3
  packet_tags :
    p3skb : 0x201
    signature : 0x202
    encryption : 0x203
  public_key_algorithms :
    NACL_EDDSA: 0x20
    NACL_DH: 0x21
  versions :
    V1 : 1
  padding :
    EMSA_PCKS1_v1_5 : 3
    RSASSA_PSS : 4
  key_defaults:
    primary :
      expire_in : 0
      nbits : 
        RSA : 4096
        ECDSA : 384
        DSA : 2048
    sub :
      expire_in : 24*60*60*365*8
      nbits : 
        RSA : 2048
        ECDH : 256
        ECDSA : 256
        DSA : 2048
        ELGAMAL : 2048
  kid : 
    version : 1
    trailer : 0x0a
    algo : 8
    len : 32

exports.ops = 
  encrypt : 0x1
  decrypt : 0x2
  verify  : 0x4
  sign    : 0x8

exports.header =
  version : "Keybase OpenPGP"
  comment : "https://keybase.io/crypto"

config = 
  default_key_expire_in: 24*60*60*365*4

(exports[k] = v for k,v of config)
