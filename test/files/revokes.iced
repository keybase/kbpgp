{KeyManager,box,unbox} = require '../..'
{PgpKeyRing} = require '../../lib/keyring'
C = require '../../lib/const'

exports.fetch_subkey_from_revoked_bundle = (T,cb) ->
  # Entire key bundle is revoked, trying to fetch subkey should not
  # succeed.
  await KeyManager.import_from_armored_pgp { raw : revokedKey1stParty }, defer err, entity, warnings
  T.no_error err
  T.assert warnings.warnings().length is 0, "didn't get any warnings"
  T.assert entity.is_pgp_revoked(), 'bundle is revoked'
  await entity.fetch [ Buffer.from('f6ad54717fa42a6e', 'hex') ], C.ops.encrypt, defer err, km, i
  T.assert err?.name is 'RevokedKeyError', 'Got revoked key error'
  cb()

exports.fetch_subkey_from_revoked_bundle_with_keyring = (T, cb) ->
  class KeyRing extends PgpKeyRing
    fetch: (key_ids, ops, cb) ->
      await KeyManager.import_from_armored_pgp { raw: revokedKey1stParty }, defer err, km
      @add_key_manager km
      super key_ids, ops, cb

  keyring = new KeyRing()
  await keyring.fetch [ Buffer.from('f6ad54717fa42a6e', 'hex') ], C.ops.encrypt, defer err, km, i
  T.assert err?.name is 'RevokedKeyError', 'Got revoked key error'
  cb()

exports.revoked_identity = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : revokedIdentityKey }, defer err, entity, warnings
  T.no_error err
  T.assert warnings.warnings().length is 0, "didn't get any warnings"
  T.assert entity.userids.length is 2, "got two userids"
  userids = {}
  userids[uid.utf8()] = uid for uid in entity.userids
  T.assert not userids['This One WIll be rev0ked'].revocation?, "one uid was not revoked"
  T.assert userids['Hello AA'].revocation?, "one uid was revoked"
  cb()

exports.designated_revocation = (T, cb) ->
  await KeyManager.import_from_armored_pgp { raw : designatedRevokedKey }, defer err, entity, warnings
  T.no_error err
  T.assert warnings?.warnings().length is 0, "didn't get any warnings"
  desig_revokes = entity.get_pgp_designated_revocations()
  T.assert desig_revokes.length is 1, "one designated revocation"
  T.assert desig_revokes[0].get_issuer_key_id().toString('hex') is '9ad4c1f7c4ee24fe', 'expected issued id'

  cb()

exports.designated_revocation2 = (T, cb) ->
  # Import key manager with key with 3rd party revocation signature
  await KeyManager.import_from_armored_pgp { raw : designatedRevokedKey2 }, defer err, entity, warnings
  T.no_error err
  T.assert (warnings?.warnings().length is 0), "no warnings"
  desig_revokes = entity.get_pgp_designated_revocations()
  T.assert desig_revokes.length is 1, "one designated revocation"
  T.assert desig_revokes[0].get_issuer_key_id().toString('hex') is '9086605e0b5c4673', 'expected issued id'

  # Import key manager with designated revoker key
  await KeyManager.import_from_armored_pgp { raw : designatedRevoker1 }, defer err, entity2, warnings
  T.no_error err
  T.assert warnings?.warnings().length is 0, "no warnings"

  # Test Signature::_third_party_verify
  sig = desig_revokes[0]
  await sig._third_party_verify entity.primary._pgp, defer err
  T.assert err.toString().indexOf('Error: Key id does not match') is 0, "expected specific error"
  await sig._third_party_verify entity2.primary._pgp, defer err
  T.no_error err

  # Test KeyManager::find_verified_designated_revoke
  await entity.find_verified_designated_revoke entity, defer sig
  T.assert not sig?
  await entity.find_verified_designated_revoke entity2, defer sig
  T.assert sig == desig_revokes[0]

  cb()

exports.test_designated_bad_sig = (T, cb) ->
  await KeyManager.import_from_armored_pgp { raw : designatedRevokedKey2 }, defer err, entity, warnings
  T.no_error err
  T.assert warnings?.warnings().length is 0, "no warnings"
  desig_revokes = entity.get_pgp_designated_revocations()
  T.assert desig_revokes.length is 1, "one designated revocation"
  T.assert desig_revokes[0].get_issuer_key_id().toString('hex') is '9086605e0b5c4673', 'expected issued id'

  await KeyManager.import_from_armored_pgp { raw : designatedRevoker1 }, defer err, entity2, warnings
  T.no_error err
  T.assert warnings?.warnings().length is 0, "no warnings"

  sig = desig_revokes[0]
  sig.sig[0][0] = 0x00 # Break the signature, expect failure.
  await sig._third_party_verify entity2.primary._pgp, defer err
  T.assert err.toString().indexOf('Error: Signature failed to verify') is 0, 'expected specific error'

  await entity.find_verified_designated_revoke entity2, defer sig
  T.assert not sig?

  cb()

exports.test_designated_bad_revoker = (T, cb) ->
  await KeyManager.import_from_armored_pgp { raw : designatedRevokedKey2 }, defer err, entity, warnings
  T.no_error err

  pgp = entity.primary._pgp
  # Change designated fingerprint, so get_designated_revocations()
  # returns empty list.
  pgp.desig_revokers[0].fingerprint[19] = 0x00

  desig_revokes = pgp.get_designated_revocations()
  T.assert desig_revokes.length is 0, "expected 0 third party revocations"

  cb()

exports.key_without_unverified_revocations = (T, cb) ->
  await KeyManager.import_from_armored_pgp { raw : designatedRevoker1 }, defer err, entity, warnings
  T.no_error err
  T.assert warnings?.warnings().length is 0, "no warnings"
  T.assert entity.get_pgp_designated_revocations().length is 0, "expected no designated revocation"
  await entity.find_verified_designated_revoke entity, defer sig
  T.assert not sig?
  cb()

exports.test_misplaced_revocation = (T, cb) ->
  await KeyManager.import_from_armored_pgp { raw : keyMisplacedRevocation }, defer err, entity, warnings
  T.no_error err
  T.assert warnings?.warnings()[0] is 'Signature failure in packet 2: verification failed (397f35a71b1830c4)'
  uid = entity.userids[0]
  T.assert uid?, 'has userid'
  T.assert not uid?.is_revoked(), 'is not revoked'
  cb()

# First-party revoked, regular key.
revokedKey1stParty = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mQFCBFj3GqwRAwC922rw75mP/WuF/wdZOcAPVfqukqGd5S5x7ajUGi77sXqqhAnr
j+XsneekldcHqlJuti7IHxMcbOZQN0rYinpk6ODfB3J1ShcHTC2IpWsngzt+tL6V
zSIXbR5rLUGg2RMAoPMi18hqBq8xQQDG2rEWCRybRvnvAv0axMy37OAeye6Ky8m2
0l1vDFeNO7/OH9eO5oNEwNuVG/shjZkGTD/YuB8huPvcyMR3xxs6Qmjn0XRfUWxt
xPvfctP9HS7MPeDqa/DsMZ5hh7B1eiwmk2cj5E6ZOFk2G8sC/jtcA3wVF7eHsJvA
CL14MLeQ9g+04CT7VhvPt2f3X3GF7XQ/2pgBfnzDi26VU9ND75NBmwVulbJw8QG7
JOpMi3FeHhsWtbQGcZg3Vcw8IamnqhEaFJ9Nb/hV4rKm0IXfgohJBCARAgAJBQJY
9xqvAh0AAAoJEDl/NacbGDDEyDYAn3QKeWn52B9lHes3pNlRqFS4/VlvAJ9DP+Kf
Ec8PxRr9qYH8KpacyYWua7QFQWxpY2WIYQQTEQIAIQUCWPcarAIbAwULCQgHAgYV
CAkKCwIEFgIDAQIeAQIXgAAKCRA5fzWnGxgwxB00AJ4inWM/H4FuFxd8A2TmmN1J
nb/W7ACgozlKd8s90o72ccJq4zxLLOC/ik25AQ0EWPcarBAEAMNfbgy0zfpDz6zi
kU+9ysCnQPaAQjNrFCu3JnJ29TGTRjGq95NOYgaU3/guAf8d1QSBAPzC+c+o/TWQ
2+y6qKJnZbsvFzVjBiJW6zpFDyWvupfATzKE3rsWYeyCwdPfwHTejWGXeoJKkSAy
em+0wm2VI6CKRsrf88UCwD9wk7VrAAMFBAC1+2hcC1TcJuZwwhDd3xllXgrMHGyG
I92RmaTjttJgOvlN5Pyz6q5HgB5EFkzbW3YCGm/YY+KTXKWUp9u2Eh9cc8R9Pm7c
HzJlEINC+VMe/+Nzd15ceySNGNIUW6D9OTtzMmgrkXCvRnZ0DDsnexVOM4pI6Up4
afCdmQfHhocmZ4hJBBgRAgAJBQJY9xqsAhsMAAoJEDl/NacbGDDEsCgAn2RJ+SJB
i7W/Rh1FjTXpL+d7zPqzAJ0Vzhg3SkrLt8/VGRRSJRUMpb4bPw==
=w/2P
-----END PGP PUBLIC KEY BLOCK-----
"""

# Public key that has two identities, one of which is revoked.
revokedIdentityKey = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWOIZOBYJKwYBBAHaRw8BAQdAOw15aNPr+v1ACWdSwaKmT+vAfpZJu2aiX/ED
NR70fYm0GFRoaXMgT25lIFdJbGwgYmUgcmV2MGtlZIh5BBMWCAAhBQJY4hlKAhsD
BQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEIUbNJhCKy361LQBAPH+mCf0r0z9
SZXw4B8fJ+jCl//0ato6Nk8bsedA2MyjAP4tx/h9XHjmANhKpue9YCyUFdV2NSKs
TIJ/EpNwz1QjArQISGVsbG8gQUGIYQQwFggACQUCWOIZcgIdIAAKCRCFGzSYQist
+nW9AQCaXyyTOmUw9gaw0SsS27NLtsYcu/affY4KLYQRW2ZjlgD9GLR5IKYtlX21
n/8Gw7KAuHaIQLK+wcbXnFabzM7TYA2IeQQTFggAIQUCWOIZOAIbAwULCQgHAgYV
CAkKCwIEFgIDAQIeAQIXgAAKCRCFGzSYQist+lGFAP9EFlJ0BCgOe6ART8xk93f3
fF+wOdMzdQ+6hni8wqW3OQEAq3VufchOPYJSL4fA+Oq7uEw5Z5Q9tBViES2Br7+I
1Au4OARY4hk4EgorBgEEAZdVAQUBAQdAAfA2+lbpmA1YXqHefB8gShHq201PsJmA
AQ2EB67c/XcDAQgHiGEEGBYIAAkFAljiGTgCGwwACgkQhRs0mEIrLfqOYwD/TaDI
Y81Z5IXtMVSMjg7sgNI93W9+xY5u0fHH5KThko4BAM7utt+MrMl67IrSLj0HLtVt
iO3AEa577DoHC0fseUgG
=uJYe
-----END PGP PUBLIC KEY BLOCK-----
"""

# Key that has a designated revoker direct sig and also a designated
# revocation signature.
designatedRevokedKey = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWN6JhRYJKwYBBAHaRw8BAQdA6NMRLTcnG9zXYIlH8aTxXttm6Ibnd+JcdnZR
7ZaarAOIYQQgFggACQUCWN6J+wIdAwAKCRCa1MH3xO4k/kqzAQCJRWV9XtLuBALs
pLfqb3V8+dumX9dNZhzrJejoOyNwIwEAzjpTdaSApbvfdon0ndf05UB+hkR2Sal5
bDXHANjltAiIeQQfFggAIQUCWN6J0RcMgBbsLs6ylR7EOEBNML2a1MH3xO4k/gIH
AAAKCRA/xm2vd7dAgxE6AP45XxRMDBG4MSvyqZw3zQ3XT0DzZyDfwmh4bNd2FZJg
lgD9ErTgyWuxVo4c/k/W6vowu6tV0rhMjH9MfwxmzY20igu0B1Jldm9rZWWIeQQT
FggAIQUCWN6JhQIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRA/xm2vd7dA
g0wmAPwOALfHBhKEiMTxCtAJ4ynJLiVXYmb+AdxLb6Q+ISmNuAEAt6uDcdM9pfX8
BjB78WoVjkxwRZpIMM3tcjz6VcR15w+4OARY3omFEgorBgEEAZdVAQUBAQdApcyK
X+duQaFIZV882qD8PZd3b9qS/ZN1EJSBOkJNiWQDAQgHiGEEGBYIAAkFAljeiYUC
GwwACgkQP8Ztr3e3QIO2KAD+NUOcZekVrfgx7STVdx2N9/zaK8cZSVgp2dWJ4DKE
1PsA+gM9O4+vwInhP8xGtH816FXJtGiw/mAyxCUeRTgi8KEH
=qbn3
-----END PGP PUBLIC KEY BLOCK-----
"""

designatedRevokedKey2 = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWPY5DhYJKwYBBAHaRw8BAQdATJ1ECHK+nn/iRBTSJ+tGAVn9TtlOzAQeSNIh
FCbqkmSIYQQgFggACQUCWPY52gIdAgAKCRCQhmBeC1xGcwULAQDH4ohXPkNND4Ez
LRyXPNhCSC7IW8bfHqLWj0VH/cXBFwD/ci+R1C/pNXKzawLDw2k2Kqd1gn5Gd16C
RAU/0Q4MWAqIeQQfFggAIQUCWPY5TxcMgBbJcZz6AbUchwVji8mQhmBeC1xGcwIH
AAAKCRAYEqe7+/Ynv5hkAP0YaIHYyP55EVqiM/8JZJYK/A8x273QpfttY7KG8op0
cAD+J0nz4RnGJfhrfZGa1EwFNlQ6uyF8/BAJeat42x6w5gW0CEpvaG4gRG9liHkE
ExYIACEFAlj2OQ4CGwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQGBKnu/v2
J7+B3QEAlnd3pLw0X8ccY/J7q0lvsZqhjg5JUCHE/VhHv9ff804BAN+9pttBx91G
AK/J0xl/dFxg4nAb+MrJabMlFJBfU2cKuDgEWPY5DhIKKwYBBAGXVQEFAQEHQNIf
z8EWK30QHiLVcO0yNlXRKpsygbQR9TnCzySnZlV/AwEIB4hhBBgWCAAJBQJY9jkO
AhsMAAoJEBgSp7v79ie/rccA/2JVMMi0lCB+pgNXtsy+VsGQN1Wn93hMtp96jTH6
ZXu5AP9gPV6r//WSuvfLl0yO4agWaa+lersoYwyovTEkqe0UAQ==
=hUOq
-----END PGP PUBLIC KEY BLOCK-----
"""

# Revoker key that signed revocation of designatedRevokedKey2.
designatedRevoker1 = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWPY5HxYJKwYBBAHaRw8BAQdAS7VZfelXtQ13zj/1vC9w6KijlYF5Q0wknInU
7vXikhe0DEphY2sgUmV2b2tlcoh5BBMWCAAhBQJY9jkfAhsDBQsJCAcCBhUICQoL
AgQWAgMBAh4BAheAAAoJEJCGYF4LXEZzF+AA/3yM9sepkr7FXXOWd+fx+R4/0iMZ
HE4ykX7nhRsXE72BAQDRt/5NrJg5jdGgaE9ho9aXEv854Dx1FJxBxiQomKLmArg4
BFj2OR8SCisGAQQBl1UBBQEBB0A3KqdTAoZN2mMJfwvKwbC8Ibv7cDjHL+2zGm+R
/ur3PAMBCAeIYQQYFggACQUCWPY5HwIbDAAKCRCQhmBeC1xGcyDJAQDG9QqWpV4c
Sm3K1NCp/0bIlRI/aFycA65lhHNoIZgPZwEApkjPInTzm1ZyVl4zgZxFltLgPbnU
J25shXYSVsIQJQ0=
=wIyY
-----END PGP PUBLIC KEY BLOCK-----
"""

# In this bundle, key revocation packet appears after identities.
# gpg2 does not mark that key as revoked, we are more flexible in
# uid/subkey parsing so we happen to mark that key as revoked.
keyMisplacedRevocation = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xsCCBFj3GqwRAwC922rw75mP/WuF/wdZOcAPVfqukqGd5S5x7ajUGi77sXqqhAnr
j+XsneekldcHqlJuti7IHxMcbOZQN0rYinpk6ODfB3J1ShcHTC2IpWsngzt+tL6V
zSIXbR5rLUGg2RMAoPMi18hqBq8xQQDG2rEWCRybRvnvAv0axMy37OAeye6Ky8m2
0l1vDFeNO7/OH9eO5oNEwNuVG/shjZkGTD/YuB8huPvcyMR3xxs6Qmjn0XRfUWxt
xPvfctP9HS7MPeDqa/DsMZ5hh7B1eiwmk2cj5E6ZOFk2G8sC/jtcA3wVF7eHsJvA
CL14MLeQ9g+04CT7VhvPt2f3X3GF7XQ/2pgBfnzDi26VU9ND75NBmwVulbJw8QG7
JOpMi3FeHhsWtbQGcZg3Vcw8IamnqhEaFJ9Nb/hV4rKm0IXfgs0FQWxpY2XCYQQT
EQIAIQUCWPcarAIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRA5fzWnGxgw
xB00AJ4inWM/H4FuFxd8A2TmmN1Jnb/W7ACgozlKd8s90o72ccJq4zxLLOC/ik3C
SQQgEQIACQUCWPcarwIdAAAKCRA5fzWnGxgwxMg2AJ90Cnlp+dgfZR3rN6TZUahU
uP1ZbwCfQz/inxHPD8Ua/amB/CqWnMmFrmvOwE0EWPcarBAEAMNfbgy0zfpDz6zi
kU+9ysCnQPaAQjNrFCu3JnJ29TGTRjGq95NOYgaU3/guAf8d1QSBAPzC+c+o/TWQ
2+y6qKJnZbsvFzVjBiJW6zpFDyWvupfATzKE3rsWYeyCwdPfwHTejWGXeoJKkSAy
em+0wm2VI6CKRsrf88UCwD9wk7VrAAMFBAC1+2hcC1TcJuZwwhDd3xllXgrMHGyG
I92RmaTjttJgOvlN5Pyz6q5HgB5EFkzbW3YCGm/YY+KTXKWUp9u2Eh9cc8R9Pm7c
HzJlEINC+VMe/+Nzd15ceySNGNIUW6D9OTtzMmgrkXCvRnZ0DDsnexVOM4pI6Up4
afCdmQfHhocmZ8JJBBgRAgAJBQJY9xqsAhsMAAoJEDl/NacbGDDEsCgAn2RJ+SJB
i7W/Rh1FjTXpL+d7zPqzAJ0Vzhg3SkrLt8/VGRRSJRUMpb4bPw==
=riYc
-----END PGP PUBLIC KEY BLOCK-----
"""
