## 0.1.0  (2014-03-24)

Nits:

  - Better header comments
  - Bump to v0.1.0, first minor release.

## 0.0.28 (2014-03-23)

Bugfixes:

  - Version lockdown in package.json
  - Upgrade to keybase-compressjs@v1.0.1-c without test junk

## 0.0.27 (2014-03-19)

Bugfixes:

  - Fix broken firefox, which was caused by keybase-compressjs@v1.0.1-a w/ console.assert
    not being defined.

## 0.0.25 (2014-03-19)

Bugfixes:

  - Close #36 -- bzip2 support for inflation.  Leave deflation out for now to save CPU...

## 0.0.24 (2014-03-18)

Bugfixes:

  - Fix bug in parsing EmbeddedSignature subpackets.
    Address keybase/keybase-issues#289

## 0.0.23 (2014-03-18)

Bugfixes:
 
  - Close #38 - Handle ElGamal encrypt and sign. Throw it away, don't puke
    - Close keybase/keybase-issues#273 as well.

## 0.0.22 (2014-03-17)

Bugfixes:

  - Upgrade to pgp-utils@v0.0.18 to address keybase/keybase-issues#269

## 0.0.21 (2014-03-14)

Features:
 
  - Figure out which keyid is primary

Bugfixes:

  - Be a bit more liberal when compute key flags; infer for ElGamal and DSA.
    See keybase/keybase-issues#247

## 0.0.20 (2014-03-11)

Bugfixes:

  - Fix broken handling of NotationData signature subpacket
    See keybase/keybase-issues#133

## 0.0.19 (2014-03-11)

Bugfixes:

  - Address keybase/keybase-issues#219: upgrade to pgp-utils v0.0.15
    which has more robust message decoding

## 0.0.18 (2014-03-11)

Bugfixes:

  - Close keybase/keybase-issues#196: better support for v3 signatures mixed in 
    with v4 signatures in public key blocks.

## 0.0.17 (2014-03-11)

Bugfixes:

  - Close keybase/keybase-issues#133: Parse (and ignore) experimental subpackets.
  - Support MD5 via triplesec v3.0.7 (see keybase/keybase-issues#111 for problem key)

## 0.0.16 (2014-03-11)

Bugfixes:

  - keybase/keybase-issues#194: verify version 3 signatures on upload of key proof.

## 0.0.15 (2014-03-06)

Bugfixes:

  - Get 8192-RSA keys works. Close keybase/keybase-issues#128

## 0.0.14 (2014-03-06)

Bugfixes:

  - Fix some bugs in exporting classes via main
  - Change the signature type of self-signed key to `positive` rather than `issuer`
  - Fixes to key expirations in generated keys

## 0.0.13 (2014-03-05)

Bugfixes:

  - Address keybase/keybase-issues#101: loosen failure model on expired
    subkeys.  Just warn and discard the key.

## 0.0.12 (2014-2-28)

Bugfixes:

  - Ignore signatures that are expired, don't fail to accept key, so long as
    there is a good signature. (closes keybase/keybase-issues#59,
    and keybase/keybase-issues#42)
  - More tests for good and expired signatures within keys

## 0.0.11 (2014-2-25)

Bugfixes:

  - Finish support for v3 Signatures, and close #34
  - Fix bug in Revocation Key sub packets (type=12), in which we weren't reading in any bytes of the signature.
  - Upgrade to PGP-utils v0.0.15 to handle null email addresses in UserIds

Features

  - Support signature type 0x1F ("signature directly on a key")
  - Support signature type 0x28 ("Subkey revocation"). See keybase/keybase-issues#27

## 0.0.10 (2014-2-21)

Bugifxes:

  - Upgrade to pgp-utils v0.0.14 to close keybase/node-client#106

## 0.0.9 (2014-2-21)

Bugfixes:

  - Upgrade to triplesec v3.0.6 for windows IE 11 support

## 0.0.8 (2014-2-20)

Bugfixes:

  - Close keybase/keybase-issues#11 - Signatures certification revocations

## 0.0.7

Features:

  - DSA and ElGamal support

## 0.0.5 (2014-2-14)

Bugfixes:

   - Fixed a bug with validating clearsign signatures, which was causing the
     crypto form on the site to barf on them, if they were generated from
     the CLI

Features:

   - Inaugural Changelog!
