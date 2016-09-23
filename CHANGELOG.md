## 2.0.58 (2016-09-22)

Feature:
  - Typed error message for wrong signing key in SigEngine::unbox
  - Recompile with new ICS (108.0.11)
  - Fix some wonky tests

## 2.0.57 (2016-09-19)

Security bugfix:
  - Disclose less info in error messages; we don't know how it might be used

## 2.0.56 (2016-08-16)

Bugfixes:
  - Fix bug in eror path in unknown GNU S2K

## 2.0.55 (2016-08-03)

Feature:
  - slightly more specific error

## 2.0.54 (2016-05-02)

Feature:
  - Expose the `bn` library via exports.

## 2.0.53 (2016-03-30)

Bugfixes:
  - Upgrade pgp-utils to 0.0.30 to fix bug in recognizing bad PGP armor

## 2.0.52 (2016-02-26)

Bugfixes:
  - Use `iced-lock` class rather than buggy reimplementation via copy/paste

## 2.0.51 (2016-02-11)

Security upgrade:
  - force cross-signatures on signing subkeys unless strict:false is supplied

## 2.0.50 (2015-12-31)

Feature:
  - General `get_sig_body` function that works for KB or OpenPGP

## 2.0.49 (2015-11-14)

Bugfix:
  - Use the best encryption subkey if there are multiple possibilities
     - See https://github.com/keybase/keybase-issues/issues/1853

## 2.0.48 (2015-10-09)

Bugfixes:
  - Signal an error if you try to merge a PGP private key and nothing happens

## 2.0.47 (2015-09-28)

Bugfixes:
 - Yet another rework of key expiration. Use the UID that expires
   furthest into the future.
 - Correct parsing of V3 subkeys.

## 2.0.46 (2015-09-10)

Bugfix:
  - `pgp_full_hash` gives `null` for a non-PGP-key

## 2.0.45 (2015-09-08)

Feature:
  - New `pgp_full_hash` method on openpgp KeyManager, which generates the
    SHA256 hash of the armored public key

## 2.0.44 (2015-09-02)

Security fix:
  - Upgrade to purepack@1.0.4 and use strict unpacking;
    to lessen chance of semantic disagrements over signature meanings

## 2.0.43 (2015-08-19)

Feature:
  - Stash passphrase generation in P3SKB packets, so we can keep track of which
    locked secret keys are encrypted with which version of a user's passphrase.

## 2.0.42 (2015-08-14)

Bugfix:
  - Another error in computing subkey expiration; use the creation time
    of the subkey, and not creatinon of the primary.  This isn't a security
    bug, since it's too conversative in computing the expire time.  It just
    prevents people from getting their work done.

## 2.0.41 (2015-08-13)

Enhancements:
  - Add merge_userids() and merge_everything() to KeyManager.

## 2.0.40 (2015-08-14)

Enhancements:
  - Back out previous changes to export_pgp_public, and also
    add some new virtualization layers there.

## 2.0.39 (2015-08-14)

Features:
  - Brainpool curve support. Thanks to @jkolo on GitHub

## 2.0.38 (2015-08-13)

Features:
  - More changes to the export_pgp_public

## 2.0.37 (2015-08-12)

Features:
  - Export pgp public can be called in an sync context

## 2.0.36 (2015-08-10)

Features:
  - Initial EdDSA support; parse keys and verify signatures.
    - See Issue #55

## 2.0.35 (2015-07-30)

Bugfixes:
 - PGP key merge methods now ignore key revocations. (These are probably not
   safe to use on signatures that aren't provably timestampted. We plan to move
   away from them in general in favor of more exact key pinning.)

## 2.0.34 (2015-07-26)

Bugfixes:
 - Fix ECDSA p521: bug in hash -> int conversion (close #80)

## 2.0.33 (2015-07-24)

Bugfixes:
  - Merge public keys too, not just subkeys. This means pushing back primary key
    expirations too.  Close #81

## 2.0.32 (2015-07-24)

Tweaks:
  - Slightly improved error messages for inability to find the needed subkey
    in verification.

## 2.0.31 (2015-07-24)

Bugfixes:
  - Fix primary key expiration computation
  - Clean up key v sig expriation
  - Get time-travel signatures working better, and accounting
    for primary key expiration as above (close #82)

## 2.0.30 (2015-07-24)

Bugfixes:
  - The change in 2.0.29 was a mistake. Revert.

## 2.0.29 (2015-07-21)

Bugfixes:
  - Calculate PGP key creation times properly. (keybase/keybase-issues#1686)

## 2.0.28 (2015-07-18)

Bugfixes:
  - Improved subkey merge system, for keybase/node-client#203
    - I have several key bundles updated, some with subkeys that
      have expired, and others with that same subkey's lifetime extended.
      So play my key sequence forward and backwards and make sure it's
      possible to verify with that subkey in either case.

## 2.0.27 (2015-07-06)

Features:
  - Add a rudimentary subkey merge system

## 2.0.26 (2015-07-05)

Features:
  - Expose openpgp SignatureEngine
  - Expose get_all_pgp_ids() via key manager

## 2.0.25 (2015-07-03)

Bugfix:
  - pass more options through to ukm

## 2.0.24 (2015-07-03)

Bugfix:
  - For reviewing signatures that were signed deep in the past,
    we have an issue that the subkey that signed the sig might have
    been valid at the time but has since expired. The ugly way to deal
    with this situation would be require the KeyManager to be repeatedly
    reimported if reviewing multiple signatures. Instead, we allow for
    keys to be imported with "time_travel : true" mode, in which
    subkeys are allowed to be imported even though they're currently
    expired.  The question of whether the subkey is expired is then postponed
    until the actual signature check.  Get this working, and then add a test
    case that brought the issue to our attention.

## 2.0.23 (2015-07-02)

Bufix:
  - When considering several self-signed key expiry times, take
    the **maximum** and not the **minimum**. GPG appears to
    work this way.

## 2.0.22 (2015-07-01)

Cleanups:
  - better code refactoring from the preivous commit
  - more sensisble API

## 2.0.21  (2015-07-01)

Features:
  - extract unverfied payload bodies from signatures

## 2.0.20 (2015-06-29)

Bugfix:
  - Second half of the below commit

## 2.0.19 (2015-06-29)

Bugfix:
  - Set signed flag on imported PGP blocks.

## 2.0.18 (2015-06-28)

Cleanup:
  - Remove the "ephemeral" bit from encryption/decryption via NaCl DH
    in the keybase packet system.

## 2.0.17 (2015-06-26)

Features:
  - Better DH/EDDSA import/export

## 2.0.16 (2015-06-25)

Features:
  - Utility functions for exporting/importing NaCl secret keys,
    mainly useful now for testing.

## 2.0.15 (2015-06-23)

Bugfixes:
  - Stop returning default 4yr expiration times for non-expiring PGP keys.

## 2.0.14 (2015-06-21)

Bugfixes:
  - Specify compression algorithms in key generation (otherwise RFC4880 says zip by default).

## 2.0.13 (2015-06-12)

Features:
  - ukm.decode_sig() method

## 2.0.12 (2015-06-05)

Features:
  - get_body() for signatures, for computing sigIds without verifying sigs.

## 2.0.11 (2015-05-17)

Features:
  - Can pass `opts = { now : 333 }` to `SignatureEngine.unbox`.  It's a 3rd arg
  - NaCl signatures operations can be native via sodium wrapper (in keybase-nacl)

Bugfixes:
  - Pass buffers, not strings to box.  Enforce with bufferify

## 2.0.10 (2015-04-30)

Features:
  - A simpler bzip2 implementation

## 2.0.9 (2015-03-18)

Feature:
  - KMI can_encrypt(), can_decrypt(), can_sign() methods
Bugfix:
  - `ophelia`'s key expired, so implement a "time travel" feature for
    reading in keys as if it were 10-Dec-2014, when everything worked.

## 2.0.8 (2015-02-26)

Bugfixes:
  - Support of raw parameter in unbox{} was broken; fix and test
    - Close: https://github.com/keybase/keybase-issues/issues/1415

## 2.0.7 (2015-02-24)

Features:
  - Add a `no_check_keys` to KeyManager import routines for PGP.  Needed in
    the case of replacing an expired key.
     - See here: https://github.com/keybase/keybase-issues/issues/1410

## 2.0.6 (2015-02-19)

Features:
  - Add get_fp2() and get_fp2_formatted() to KeyManager.  For PGP it's
    the same as a regular fingerprint, but for NaCl, it's base64-encoding
    of the whole key.
  - Add get_type() to KeyManager so make further display decisions.

## 2.0.5 (2015-02-12)

Bugfixes:
  - Update reg tests; my subkey had expired, so I just refreshed it.
  - Node.js changed zlib, which can now return empty buffers.

## 2.0.4 (2015-02-10)

Bugfix
  - Fix bug in DH NACL KeyManager, it's not able to verify

## 2.0.3 (2015-02-05)

Bugfix:
  - `can_Sign()` is a misleading name, better to have `can_verify()`, which says
     whether or not this key is a sign/verify keypair, and makes no indications about
     whether it has a privkey or not.

## 2.0.2 (2015-01-29)

Bugfix:
  - Fix error condition in kb.SignatureEngine.unbox
    in which we didn't handle a wrong public key properly

## 2.0.1 (2014-12-22)

  - get_ekid() implementation for openpgp KeyManagers
  - SignatureEngine.box for keybase and openpgp-style packets
  - generate EdDSA keys from deterministic seed (#59)
  - wrap DH as we do EdDSA (#60)
  - allow split key-generation for server-assists
  - Partially address #62, a bug in EC point output (improper padding)
  - SignatureEngine::decode now does some of the work for unbox,
    on a per-sig-eng basis (different from openpgp and kb)

## 2.0.0 (2014-12-10)

  - Vbump to 2.0.0; we changed where the SignatureEngine is, thereby
    breaking API compatibility.

## 1.2.0 (2014-12-10)

New features:

  - NaCl support for keybase-formatted signatures
    - OpenPGP EdDSA support still to come...
    - Most work done on Issue #48
  - Fix #53 -- get keymanagers back from detached sigs
    - Slight hack for "streaming data" in which it doesn't make
      sense to have a literal.  So have an empty placeholder
      literal instead

## 1.1.9 (2014-12-09)

Bugfix:

  - Fix for previous bugfix (#47).  Better check for e < 2^32.

## 1.1.8 (2014-12-08)

Bugfix:

  - Relax exponent e requirement, don't require it to be prime or <2^16+1. See #47.

## 1.1.7 (2014-11-24)

Performance:

  - Speed up Iterated S2K by caching results (since subkeys need
    to reuse the result from the primary).  And by not allocating
    the buffer in one huge chunk

## 1.1.6 (2014-11-18)

SECURITY BUGFIX
 - Don't use revoked subkeys

## 1.1.5 (2014-10-20)

Bufixes:
 - Primary userid flag on the first user ID given
 - generate_rsa and generate_ecc also get userids parameters

## 1.1.4 (2014-10-20)

Feature:

 - KeyManager.generate() takes userids vector, for multiple UIDs in key
   - Closes #45

## 1.1.3 (2014-10-08)

Bugfixes:
 - After merging a private key, try to "unlock" it if it's not
   PW-protected. We were already doing the same for import, but
   need it here for keybase's key_path.iced

## 1.1.2 (2014-10-04)

Bugfixes:
  - I can't find it in the RFC, but it seems as if we need to assume all reasonable
    key flags for a primary if none were specified.
      - This should address keybase/keybase-issues#1110

## 1.1.1 (2014-10-03)

Nit:

  - Expose keyring.KeyRing, equivalent to keyring.PgpKeyRing

## 1.1.0 (2014-09-25)

Feature:

  - The `encrypt_for` parameter to `box` can handle mutliple parties,
    meaning messages can be encrypted for your friend(s) and yourself.
    ( this one was a long-time coming....)

## 1.0.5 (2014-09-18)

Bugfix:

  - Expose RipeMD160
     - Address keybase/keybase-issues#1020

## 1.0.4 (2014-09-17)

Feature:

  - Changes to unbox (in response to #42)
    - Can pass `{ strict : false }` to `unbox`, and it won't crap out if it can't
      verify signatures.
    - Now calls back with an `err, Array<Literals>, Warnings` triple.

## 1.0.3 (2014-09-10)

Security upgrade:

  - Run various validity checks in incoming PGP keys;
    - See this thread for more info: http://www.metzdowd.com/pipermail/cryptography/2014-September/022758.html

## 1.0.2 (2014-08-21)

Bugfixes:

  - Fix bug in `export_pgp_private` wrapper routine...

## 1.0.1 (2014-08-18)

Bugfixes:

  - Address errant iced-coffee-script inclusion via triplesec@3.0.18 upgrade

## 1.0.0 (2014-08-18)

  - Official release!

## 0.3.2 (2014-08-16)

Bugfixes:

  - Strip out stray debug message
  - Use 'armored' rather than 'raw' in KeyManager interface, for consistency's sake.
    Still allow 'raw' but mark it as DEPRECATED.
  - Don't require unlock_pgp() to be called on an unlocked key. Do it internally
    so as not to confuse people.
  - Upgrade to Triplesec v3.0.18 for less-wasteful entropy generation

Features:

  - ASPs now accepted and supported in box/unbox operations
  - API streamlining: easier to get the key_manager from a packetsig

## 0.3.1 (2014-08-06)

Tweaks:

  - Rename generate_std to generate_rsa
  - Alias KeyManager.export_pgp_private

Bugfixes:

  - Close keybase/keybase-issues#921 -- fix a zip/browserify bug by ignoring
    an error that seems harmless.  This might break in the future, so keep
    on eye on it. The break will be that valid messages refuse to decrypt
    and inflate.

## 0.3.0

Tweaks:

  - Change the KeyFetcher::fetch interface.  Callback now callsback
    with (err, key_manager, index) triple rather than the shmorgasbord
    of parameters we had before.  Do a minor version update to show lack
    of compatibility with previous 0.2.0 release

## 0.2.0

Features:

  - RFC 6637: ECC crypto: ECDSA and ECDH. Experimental and not recommended,
    since more GPG clients do not support it.
  - Add new API entrance points for cleaner code and consistent metaphors.
    Don't throw away the old entrance points just yet

## 0.1.23 (2014-07-08)

Optimizations:

  - Switch to bigint squaring, rather than modPowInt(2), and expose a few
    more features of bn to make this work.
  - Upgrade to the newest version of bn, @v1.0.0

Bugfix:

  - Fix a bug in clearsign parsing; we were being to liberal in our understanding
    of BEGIN PGP blocks.  They have to start at the beginning of a line, as made
    explicit in the "clearsign your public key" test case.
      - Fix via upgrade to pgp-utils@

## 0.1.22 (2014-06-10)

Bugfix:

  - Fix a bug in clearsign dash-encoding
     - Address keybase/keybase-issues#768

## 0.1.21 (2014-06-04)

Bugfix:

  - Fix incorrect dependencies, and loosen them up....

## 0.1.20 (2014-06-03)

Bugfix:

  - We broke the high-level interface, fix it.  We need regtests too...

## 0.1.19 (2014-06-03)

Features:

  - Browserified release
  - New interface to KeyManager.generate, you can provide primary and subkeys, each of which
    have nbits, expire_in and flags fields.
  - Expose interior hash wrapper class
  - Better API for burner
  - Upgrade to ICS v1.7.1-c for refactored runtime

Documentation:

  - Fixes for KeyManager.generate and burner.burn

Bugfixes:

  - Fix bugs with 5-byte signature subpacket lengths
      - Address keybase/keybase-issues#752

## 0.1.18 (2014-05-27)

Features:

  - Detached signature generation and verification.

## 0.1.17 (2014-05-23)

Bugfixes:

  - Slight change in the hiding interface to burn.
  - Pass `expire_in` through to `KeyManager.generate`
  - get_issuer_key_id looks in either signed or unsigned subpackets
     - Address keybase/keybase-issues#304

Features:
  - dirsign!

## 0.1.16 (2014-05-20)

Features:

  - Add an RSA hiding feature, to hide what the public key is.  Also, blind the output ciphertext.

## 0.1.15 (2014-05-15)

Bugfixes:

  - iced-error is a dependency
  - @terinjokes points out ICS is a real dep and not a devDep

Features:

  - Expose nbits() on public keys

## 0.1.14 (2014-05-01)

Bugfixes:

  - Handle "critical" subpackets properly; address keybase/keybase-issues#682

## 0.1.13 (2014-04-26)

Bugfixes:

  - Strip out some profane debugging info (sorry)
  - Allow unlocking of keys that were not actually locked.

## 0.1.12 (2014-04-24)

Bugfixes:

  - Handle v2 signatures, which are the same as v3 signatures.
    See the [ancient RFC 1991](https://tools.ietf.org/html/rfc1991#section-6.2)
    fore more details.  This closes keybase/keybase-issues#572

## 0.1.11 (2014-04-21)

Bugfixes:

  - Fix has_pgp_private() --- it's good enough to have one private,
    don't need all of them....

## 0.1.10 (2014-04-21)

Bugfixes:

  - Better versions of fulfills_flags that take into account whether there's
    an available unlocked secret key to do it.
  - Better handle a secret key export in which no primary key is exported, and
    no signing subkey is available (since typically, only the primary can sign).
  - Able to write out partial secret keys in P3SKB mode (via reversing the
    GNU dummy extension).

## 0.1.9 (2014-04-21)

Bugfixes:

  - Better support for private key merging --- don't require an exact-key-for-key
    match, but rather, allow only some of the secret subkeys (and not the primary) to
    be merged. This addresses [Keybase Issue #216](https://github.com/keybase/keybase-issues/issues/216)

## 0.1.8 (2014-04-14)

Bugfixes:

  - Remove debugging code

## 0.1.7 (2014-04-14)

Bugfixes:

  - Upgrade to Triplesec v3.0.10 for SHA384 and SHA224 bugfix

## 0.1.6 (2014-04-13)

Features:

  - Upgrade to Triplesec v3.0.8 for SHA384

## 0.1.5 (2014-04-07)

Bugfixes:

  - Support slightly relaxed header parsing for clearsign messages; Can have spaces in the
    separator between Hash: and the text.
  - MD5 is the default, so use that if nothing was specified.
  - Don't crash on an unknown hash algorithm, raise an exception
  - MD5 ASN headers included so that MD5 can work.
  - Upgrade to pgp-utils@v0.0.20

Test cases

  - Integrate some of OpenPGP.Js's test cases, included as a result of
     [their audit](https://github.com/openpgpjs/openpgpjs/wiki/Cure53-security-audit).

## 0.1.4 (2014-04-04)

Bugfixes:

  - Key ID can be either in hashed or unhashed sig subpackets, so look for it in either place.

## 0.1.3 (2014-04-03)

Bugfixes:

  - compile for the below

## 0.1.2 (2014-04-03)

Bugfixes:

  - Do not crash on malformed signatures (with a null open or close key id)

## 0.1.1

No change, npm failure.

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
