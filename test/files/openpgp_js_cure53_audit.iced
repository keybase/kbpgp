
#
# See here for more details:
#
#  https://github.com/openpgpjs/openpgpjs/wiki/Cure53-security-audit
#

{do_message,Message} = require '../../lib/openpgp/processor'
{PgpKeyRing} = require '../../lib/keyring'
{KeyManager} = require '../../'
{decode} = require('pgp-utils').armor

#===============================================================================

key = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

mQENBFM9bqwBCADPDhFyVqlMDoIP34Tk1xEqcu3EpM36Q2ls4Rv0wlwsdCcmhh3x
OIjlP+jzR6cnQm3f+b46bXGgrl3Gis8CjceHmmcp4NAyRxsMYfSWNl6w46vKbjFZ
UbpmXJY4L80EJ3kUnnIf2U8DdpHGy+sXPeBoNT/S3zuFmYw0EEYl3EkiRwqrL2PA
iTEH2zqJKctFuja4NE01GLXU9XPl9EiAzmPQOgjRbJk1cz8eReTjDwnafLYamZfr
5xzUeAKyASA/784wbocmteRyu3ph7rJMFpv3/VBy/PgaCB4JmdtdqimofPFv+bPo
S5LQw4z/9FETFyxF7mcffd+TTodsYojYxvHxABEBAAG0Hk1heCAzMDkgPHRoZW1h
eCszMDlAZ21haWwuY29tPokBPQQTAQoAJwUCUz1urAIbAwUJEswDAAULCQgHAwUV
CgkICwUWAgMBAAIeAQIXgAAKCRDXB+6Ch7YlFCvnB/94453NRlRMfcXGN/goIzGs
rsP6YNDGLErftxPCUd3ve4qUIw+2vniokIcAWYQLgUlGmasp5B64h+6woMZBfP9G
Klz0R7LRu0bBnlRvq2DkRItPIZBF79bE6HUfsRfJloyshexPYiOWkmSGKbeBT+R2
5hCzab8KLpAsM1tAaOqNX02NclMtKlzHt2XWoIpKbB/n+JXaj6+S3m6l+SFAYQz1
jn5bV3xbNPLHMgz+5spKuQBrS2tsZQYYzFQhL9vSnw00uvmOApWahizx/eZc7sxb
aFcRwknx7zkUAMnEXWdkKmCCRljMSVuaqZhSb8cEMPl7mtqxhKG3svYbVBJXNHq/
uQENBFM9bqwBCACzl2QZcxs0/Hf21Y/N4G7IucUQTBuxrOXvQyL0ra1OAEsgoVox
YWS5j0HKGmEH7lVxDz+8j3HdW0B+0n/6tErDfIPUAfd/fiJ5WHiFbD1b5La98ahk
sDSiyxPnoT1mlpE2+9/XHtid0JKluWlzp9Nsr6sXXkUIp2CMUKMPAbwpgNvveoaQ
5l8+4j5eqgzU2TOuLJOhjU9PpNx05EtMz2ZUCSYokcEd9jIC5LuqbXnptQ8COsdt
r+BARE++TO8FT6JtvJAF+ya/d6NABxLREIC1Xc/bC/clCufG1gu6rxizAvbFn0RI
XpuhYyYNycOHCN0W+dTkSDQZdTAVVQaNhppvABEBAAGJASUEGAEKAA8FAlM9bqwC
GwwFCRLMAwAACgkQ1wfugoe2JRQHGgf+L2KfPWleZ2YF19t5fvkr/WoTf8vHeGSt
rhcXuOEZ6958KDDc9YRL9FiRJif+vzjy/KBobb2f/7dJYoLWV/3wip8YOhwMUMAQ
XFfDUFVrfiK2yYZ/gOHROhl5CdJ4qihT5AH5yyqMNpiTlGxzPkVnVaO7oufX330w
9g82evapQ+VidksCWG6TSQVYUh9QnBIwlO+Nx2Fn4mnyXb4eeRFF5OfFfFPhB7Nm
iSFt2y3redHUHU/rqiss2b8+99d0Qjur6Mpn9aofzl4M81Ehcofxo3++B8QbxKag
EbI/F53ALAWVs1gB85WnO6CBxHHkzZ89O7QwB0ue6KdHkGF0O2F7RA==
=pwsn
-----END PGP PUBLIC KEY BLOCK-----
"""
ring = new PgpKeyRing()

#================================================================================

exports.init = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key }, defer err, km
  T.no_error err
  ring = new PgpKeyRing()
  ring.add_key_manager km
  cb()

#===============================================================================

exports.op_01_019 = (T,cb) ->
  lines = [
    '-----BEGIN PGP SIGNED MESSAGE\u2010\u2010\u2010\u2010\u2010\nHash:SHA1\n\nIs this properly-----',
    '',
    'sign this',
    '-----BEGIN PGP SIGNATURE-----',
    'Version: GnuPG v2.0.22 (GNU/Linux)',
    '',
    'iJwEAQECAAYFAlMrPj0ACgkQ4IT3RGwgLJfYkQQAgHMQieazCVdfGAfzQM69Egm5',
    'HhcQszODD898wpoGCHgiNdNo1+5nujQAtXnkcxM+Vf7onfbTvUqut/siyO3fzqhK',
    'LQ9DiQUwJMBE8nOwVR7Mpc4kLNngMTNaHAjZaVaDpTCrklPY+TPHIZnu0B6Ur+6t',
    'skTzzVXIxMYw8ihbHfk=',
    '=e/eA',
    '-----END PGP SIGNATURE-----' ]
  msg = lines.join '\n'

  await do_message { keyfetch : ring, armored : msg }, defer err, outmsg
  T.assert err?, "Got an error on malformed header"
  cb()

#===============================================================================

exports.op_01_009 = (T,cb) ->

  get_msg = (headers)  ->

    body = """

sign this
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iQEcBAEBCgAGBQJTQprhAAoJENcH7oKHtiUUs6EH+wf2TM9dhVnwwp5PgOsmCO+W
91pudWHCiSWzPdk32ck8N2bdTviuav2nZKYb6TNu8JRwsDesJHxMIs9pBop92k7B
Mx22O6DMQ8irnBJBvQqP76hwJ7hkcaiy1QbYZQZZUtDDPWljV2YTtLhCc4KRZFGz
OSUWScDGUtkHvJCUIqWNioZbnHv1y2LpeonbS1pWy4M5rSTwhhPnJkkzpJa3tRgN
s3fYMkuJh5u2lQlvrr5EO1E7Nj4ab3PYh0DFZ8jjPteag+cj3WZ9iB4LtVPnV2Bq
7r0rnEyv0zndZXoeqs9a2bJyG9DfAWKACcWpHaHCxqtNWBESHtOThgUQwUiP8dE=
=jYzT
-----END PGP SIGNATURE-----
"""
    return [ '-----BEGIN PGP SIGNED MESSAGE-----'].concat(headers).concat(body).join("\n")

  #----------

  x = get_msg "Hash: SHA512"
  await do_message { keyfetch : ring, armored : x }, defer err, outmsg
  T.no_error err, "Simple clearsign verification worked"
  T.assert outmsg[0].to_literal()?.get_data_signer()?, "was a signed literal"
  T.waypoint "success 1"

  #----------

  x = get_msg("Hash: SHA256")
  await do_message { keyfetch : ring, armored : x }, defer err, outmsg
  T.assert err?, "Got a hash mismatch error"
  T.assert (err.message.indexOf("missing ASN header for SHA256") >= 0), "didn't try to run SHA256"
  T.waypoint "fail 1"

  #----------

  x = get_msg()
  await do_message { keyfetch : ring, armored : x }, defer err, outmsg
  T.assert err?, "Got a hash mismatch error"
  T.assert (err.message.indexOf("missing ASN header for MD5") >= 0), "didn't try to run MD5"
  T.waypoint "fail 2"

  #----------

  x = get_msg("Hash: LAV750")
  await do_message { keyfetch : ring, armored : x }, defer err, outmsg
  T.assert err?, "Got a failure"
  T.assert (err.message.indexOf("Unknown hash algorithm: LAV750") >= 0), "didn't find LAV750"
  T.waypoint "fail 3"

  #----------

  # For now, don't support multiple hash values
  x = get_msg("Hash: SHA1, SHA512")
  await do_message { keyfetch : ring, armored : x }, defer err, outmsg
  T.assert err?, "Got a failure"
  T.assert (err.message.indexOf("Unknown hash algorithm: SHA1, SHA512") >= 0), "didn't find SHA1,SHA512"
  T.waypoint "fail 4"

  #----------

  # For now, don't support multiple hash values, just use the first
  x = get_msg(["Hash: SHA1", "Hash: SHA512"])
  await do_message { keyfetch : ring, armored : x }, defer err, outmsg
  T.no_error err, "last hash wins"
  T.waypoint "success 2"

  #----------

  # For now, don't support multiple hash values, just use the first
  x = get_msg(["Hash: SHA512", "Comment: No comments allowed!"])
  await do_message { keyfetch : ring, armored : x }, defer err, outmsg
  T.assert err?, "no comments allowed"
  T.assert err.message.indexOf("Unallowed header: comment") >= 0, "found an header not allowed"
  T.waypoint "fail 5"

  #----------

  # Wrong guy in last is a problem
  x = get_msg(["Hash: SHA512", "Hash: SHA1"])
  await do_message { keyfetch : ring, armored : x }, defer err, outmsg
  T.assert err?, "Got a failure"
  T.assert (err.message.indexOf("missing ASN header for SHA1") >= 0), "multiple order matters"
  T.waypoint "fail 6"

  #----------

  x = """
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512
\u000b\u00a0
sign this
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iQEcBAEBCgAGBQJTQprhAAoJENcH7oKHtiUUs6EH+wf2TM9dhVnwwp5PgOsmCO+W
91pudWHCiSWzPdk32ck8N2bdTviuav2nZKYb6TNu8JRwsDesJHxMIs9pBop92k7B
Mx22O6DMQ8irnBJBvQqP76hwJ7hkcaiy1QbYZQZZUtDDPWljV2YTtLhCc4KRZFGz
OSUWScDGUtkHvJCUIqWNioZbnHv1y2LpeonbS1pWy4M5rSTwhhPnJkkzpJa3tRgN
s3fYMkuJh5u2lQlvrr5EO1E7Nj4ab3PYh0DFZ8jjPteag+cj3WZ9iB4LtVPnV2Bq
7r0rnEyv0zndZXoeqs9a2bJyG9DfAWKACcWpHaHCxqtNWBESHtOThgUQwUiP8dE=
=jYzT
-----END PGP SIGNATURE-----
"""
  await do_message { keyfetch : ring, armored : x }, defer err, outmsg
  T.no_error err, "we're somewhat loosey-goosey ignoring spaces in the clearsign header"
  T.waypoint "success 3"

  #----------

  for h in [ 'Hash:SHA512', '<script>: SHA256', 'Hash SHA512' ]
    x = get_msg h
    await do_message { keyfetch : ring, armored : x }, defer err, outmsg
    T.assert err?, "Got a failure"
    T.assert (err.message.match /Bad line in clearsign header|Unallowed header/), "bad line"
    T.waypoint "fail #{h}"

  #----------

  cb()

#===============================================================================


