
{KeyRing,box,unbox,KeyManager} = require '../..'


# This sig has a subpacket 33 issuer fingerprint:
#
# > echo "hello" | gpg --sign -a -u  9A82C74B75E3410C1C00338CF4C7E8F4AC11D4F3 | gpg --list-packets
#
# # off=0 ctb=a3 tag=8 hlen=1 plen=0 indeterminate
# :compressed packet: algo=1
# # off=2 ctb=90 tag=4 hlen=2 plen=13
# :onepass_sig packet: keyid F4C7E8F4AC11D4F3
#   version 3, sigclass 0x00, digest 8, pubkey 1, last=1
# # off=17 ctb=cb tag=11 hlen=2 plen=12 new-ctb
# :literal data packet:
#   mode b (62), created 1481135087, name="",
#   raw data: 6 bytes
# # off=31 ctb=89 tag=2 hlen=3 plen=307
# :signature packet: algo 1, keyid F4C7E8F4AC11D4F3
#   version 4, created 1481135087, md5len 0, sigclass 0x00
#   digest algo 8, begin of digest dd 5a
#   hashed subpkt 33 len 21 (issuer fpr v4 9A82C74B75E3410C1C00338CF4C7E8F4AC11D4F3)
#   hashed subpkt 2 len 4 (sig created 2016-12-07)
#   subpkt 16 len 8 (issuer key ID F4C7E8F4AC11D4F3)
#   data: [2048 bits]
#
sig0 = """-----BEGIN PGP MESSAGE-----

owEBUwGs/pANAwAIAfTH6PSsEdTzAcsMYgBYSEwKaGVsbG8KiQEzBAABCAAdFiEE
moLHS3XjQQwcADOM9Mfo9KwR1PMFAlhITAoACgkQ9Mfo9KwR1PNK2AgA4cTQNfnu
F6vfIfmLrnuNm+OFSffkgQmDQc48RV2ppA35r0dDJDi1lF/UBei+RZVNP2zntZ2z
glxivl4qM7qdqojI1HZxP9cT25GuQNWZI3M0LXsderQtv6z4M6q8wj5OjI6kNMN3
QoBLL+cVcqEy0ocW1+oQ4NGemiQ4TLnH3or83OVoUXHSbtM6jBmedqs2taReRx20
RYl5iEr6kQGHmqYt1K142QORPrjYyvGJl8k8cKDjRxOo65ufTB+iztG312cVTnnJ
/gCEVjvAARdrDuroooJwxqx5BFpi7Z5qb4osmxJwdib9lrt1r/fV7QwY1LrCn5eF
YcO0GnR3O1jT9w==
=YRAG
-----END PGP MESSAGE-----
"""

key0 = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFhIScUBCADp3DNt8ENU2U4kuWzdIe6SXQQ9klLyOcm4MzRWJa4kvHjVvaG8
CFHeluTITvXk+HYS06a+w4h7uDj6bQRiQTu+byvj2NuvWjgfiVvkD2BLZ5gsgM7N
IKXlHm+mbTK2FdCCzM7cRiphlySPjL7lflpjOz+iMf2E6phLh6uTsD3js8sxu5Hk
9EJ9sUKDBgLpJf92wL0FaxADP6BLPqn1DzEAe/NE4O6nY6ITqLziNv2UBxdfACe9
06ZPetOJhb/HFHGMkpZNS13BZS60rvMPxtHmzGsTqxP9hdrVqQx/Yi1PrH3UTZRR
/dEty1hHCMbY/gWzDmOxUcV64BxhKztsFxvJABEBAAG0FlRhY28gVGVzdCA8dGFj
b0B0ZS5zdD6JAU4EEwEIADgWIQSagsdLdeNBDBwAM4z0x+j0rBHU8wUCWEhJxQIb
AwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRD0x+j0rBHU8wuvCACWnqhXhMkc
ZxQQ5PebCWt2q1xAEYEbdHWglAnbbsBmJz8aKyfMx5BRVKl3/9efNbBvlM+e3oUo
J40uhTCeGdmmZteM4PUQPCCl+sGYZ4aZuTD8BDnUo79V2ymFMGvYmk8vw79TVjcT
7OGF7jQiJwYycqhOri2FT+jEPSYlLsn7G9PIa40DQcbKQBqSzzt9H5C8hPLQX2b1
OfL+TDv/wa8i6stx/SYn6a1drnFFtyoRTxFwdryPEkRTotS70+Cb4Mg+QH9WgL+D
AppZVBYzZNPWX1bGL5FC7Er/cVeluHEmnfpMURgvtWK87ZW53imbgYixnnbZ2peC
iLgltpS95wFJuQENBFhIScUBCAC5psaWkHr6sJTVEa66t7uWsivvrohoQO1luOjL
QVJcHpGHnSeP8ZFx1B1vseXokMeBDZ9yRowOusiBHve4Tov0bwgp70TCcNZjeB6q
NqtJK7//mPuXBR51JKSlaO9DHi5k3RQ8DjeWm+I5FbDOhfz3vorPcNmrtUZRHjTE
W6Vqaf+Lv6EyLlkD7QRvE/FYbAVQ/+Ht/0pvxeZbVW076YD7tVm+J7AyeMK5u6t9
S7F0K4l/dNpBtoiRToG19BwfsNbjjJh/UDjUGaEgD0gGyhzzrpM2LiwJTmv13yGt
oK8/Wc8hpbT1yp0vSVagJ0FJ50cbqAI8H5LOLHSRroZwpWVtABEBAAGJATYEGAEI
ACAWIQSagsdLdeNBDBwAM4z0x+j0rBHU8wUCWEhJxQIbDAAKCRD0x+j0rBHU8wnB
CACs3EwT0En//ItF/GJdjdrpZyZkcSkOiGFWY/TeTi5SGjAIinJcJWFYDibLKbWx
dbBirDm+ep93VCyGT8CbUjSL5f6zt67tJA4SM+djTW0luCTh8X5RgDntz36tVo6G
pyWSAatyMOmsJqTKYuksIhvkVaJQHLzFBer/5ltzJkTkVZJuuGxqNMP4VUcBXoJG
WIieaZJUW8cNgP3jAR4sa0dSQE+hWBRnsZlWVOdsO1BucoqHz/ytvposCWRPaf83
dDhhp617omZLdCQGFDov0uE0MvIkwQxQIAaQVRfB5ZGH67K3ebyrFxOu6xdoArAF
gdDIgUoBsCGhjerF6Qvcj1dx
=rJOL
-----END PGP PUBLIC KEY BLOCK-----
"""

test = ({T,sig,key},cb) ->
  await KeyManager.import_from_armored_pgp { armored : key }, T.esc(defer(km), cb, "load key taco test")
  T.waypoint "loaded key"
  await unbox { keyfetch : km, armored : sig }, T.esc(defer(literals), cb, "verify")
  T.assert (literals[0].get_data_signer()?), "was signed!"
  fp1 = literals[0].get_data_signer()?.get_key_manager()?.get_pgp_fingerprint()?.toString("hex")
  fp2 = km.get_pgp_fingerprint().toString("hex")
  T.equal fp1, fp2, "Fingerprint was right"
  cb()

exports.test_subpacket33 = (T,cb) -> test { T, key: key0, sig : sig0 }, cb
