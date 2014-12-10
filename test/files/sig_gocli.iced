{KeyManager} = require '../../'
{do_message,Processor} = require '../../lib/openpgp/processor'

#==================================================================

sigs = [
  {
    sig : """
-----BEGIN PGP MESSAGE-----
Version: Keybase Go client (OpenPGP version 0.1.0)

xA0DAAIBnGEbwJfFZzABrQIPYgBTPsOMeyJib2R5Ijp7ImNsaWVudCI6eyJuYW1l
IjoiS2V5YmFzZSBHbyBjbGllbnQiLCJ2ZXJzaW9uIjoiMS4wLjAifSwia2V5Ijp7
ImZpbmdlcnByaW50IjoiYWQ1ZTRhODkzYTMwYmUxYzA0MDgxYjRkOWM2MTFiYzA5
N2M1NjczMCIsImhvc3QiOiJrZXliYXNlLmlvIiwia2V5X2lkIjoiMDEwMTQ0MjFl
MDM0OTkzZjk1NDQ3NjZiYWZjM2EzNTkxOWRiNjQ3YjRkNWFkMjQyNzU3ZWU1MTM3
OGEzZTJkY2M1MGIwYSIsInVpZCI6ImJmNzM4ZDI2MWFiODc0OTQ5YmU4NTI4YjNm
OTBlMzAwIiwidXNlcm5hbWUiOiJoZXJiX2tpdGNoIn0sInNlcnZpY2UiOnsibmFt
ZSI6InR3aXR0ZXIiLCJ1c2VybmFtZSI6InRhY292b250YWNvIn0sInR5cGUiOiJ3
ZWJfc2VydmljZV9iaW5kaW5nIiwidmVyc2lvbiI6MX0sImNyZWF0ZWQiOjEzOTY2
MjIyMTgsImV4cGlyZV9pbiI6MTU3NjgwMDAwLCJzZXFubyI6MTcsInByZXYiOiIy
NGExOTA1MjI0NjU3NTRmMTQ1Njk0NTAzYTNmOGUxODA3NDYzZDNiMDY5NWNjOTdh
YmM5YTE1MTA5YTlhNjA5In3CwVwEAAECABAFAlM+w4wJEJxhG8CXxWcwAAC/RhAA
J8pe+ZT5aGemOM7m0lhchvtXHTQPbXhLFgX6Mz9K7CH2UCsLdpojObO2RkjM/WwZ
9kMgTlLV2NcavNgQeN9JnEGJAhZ6xeF+T0ysJS8hkrgp5XPqyHQ1ihuKgE0yxP50
p+k2qL2Fd92npxOSEHhUJCTSAzG/Qqzecb7Dy5427h8SGTJ0JXtLf6YTsZEwnJ0/
XhcvC8vI5KgY99dzLxGs6cebZycXrpxB/LT8WAUlK/dggbnq+JYhKouzKGhiLnQi
8j+Uay3EjdwXzt6zRSBq+hhGQD9EUf4q50D62yhq6YGdqPdn591uXLnyr9PEq4tW
EcSgEUsXzcbc4jdWi17OssmD0m0Q2W1aTi2X+A9RWM4yGVGVzBGHQ3jYAtWWIy+2
283g1fZkzzzbiw8peXdOCw9J9L9dDiMf47cCRCNgFXRWS9cqqkK48Q5spGmnlMtv
9nXoM5o96/4TSydX9XkktouP4HguFJs6Mu2qE9EkNpgZUAwN2uqjcRFr0e09myHM
AWUnbou0bDkiypuNC3B2qG/xQqmx1d7LMp/r+SGHeBobYC4aULVA2NtbV/K4eONt
KshzAAbvkubZAD+WlHCr4GzrKaX96Z9YPmCqMRaKnzoJMlEtuMoCS0FtCY8JLvFE
qFd18S+Phr28d/PT1WcR/wltm8qUlPt2Mk6/LrRjhtI=
=H4wc
-----END PGP MESSAGE-----
""",
    key : """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

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
=QW5d
-----END PGP PUBLIC KEY BLOCK-----
"""
  }
]

#==================================================================

verify = ({sig,key}, T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key }, defer err, km
  T.no_error err
  await do_message { armored : sig , keyfetch : km }, defer err
  T.no_error err
  cb()

#--------------------------------

exports.verify = (T,cb) ->
  for sig in sigs
    await verify sig, T, defer()
  cb()

#==================================================================

