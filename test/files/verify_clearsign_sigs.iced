{PgpKeyRing} = require '../../lib/keyring'
{KeyManager} = require '../../'
{do_message} = require '../../lib/openpgp/processor'

#=================================================

good_sigs = [ """
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wFwACgkQ9DF8Jl8Iw6IDlwP9Gu/s/jKGGkozQ5i/EWAcY/Au
8IIdhOhm1LuWP++y5S4ttM3lTP110Cp8ARQLitph86qvWoV3SkYRrRdQ6G0krElb
hvujbG38E8AauK6gl48YK9QYzD99zbv+mkLVc+Da5vtBIYqJKBOS4Ryk+tYc1eti
HuWJ6zfGw5ZgWU9BWqs=
=pfI+
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wGMACgkQ9DF8Jl8Iw6KttgQAvb4Utc48Q+tu/NKarBQQ2Kuz
C7nYBWGiw/Co0q6pouWH02AiuNHuGMGPsFVunPLixmo3LlVYNfnNpvaNtlsdhw19
xtrQA2mNzjBpK0RRZvT7UaWMx9gDFjo+HusAbytpBE6+fGB3SCJicSpSCmIzkBve
hGyCdW5211eXGmcOQG0=
=xqM1
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo

-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wGcACgkQ9DF8Jl8Iw6LzvwP/WHzScg4f+Egf3ammjnjNgNmD
Q5gA/7vN47yv9q7FNkIBBlUaUwUR2TLSJQuIUFCMfcoTgMiRqmJycbTPAIUTbSxJ
bmY1oLnD50hJoX0olJyXRWXH4xYn/yYsWfDFs3SY0Isd0PptpMjQTqHup+YEgXJb
l47I0mrACkvVAApnLyE=
=nJxV
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo

bar
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wG0ACgkQ9DF8Jl8Iw6L16gQAhvR4NNQV3Eq/MhyWJ4u83CGx
hRgofGV4lspiXJtuIg7+1ROFyuQWKX/JLm5XXtQr2x6h4MLAcLcsoIQeu4RcZAY5
do/21pGqWsB96UZG5T62qUCbQewbQhfLl6vIJfcd/32HJHMk/1HMWxuw6RmltJzV
RoJRv8Ck8EOoaAHC5cc=
=LXYp
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo

bar
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wHIACgkQ9DF8Jl8Iw6K+MwQA36YhZy7ruNclMWowvkyWHT8h
2QjuJmkGUhK2ofIEOT70vNbKdBSP5d6s6x9+JcDjA8b6qr7z3PLvKNUdxPUoVr6e
8EGGudHettV4Lfm/jvgE8KDEUchLoT2D1N7VO7kDYToxxFuUlA1xKqeRJQfDZE2Y
+fuEFkjRSybtlV1dBjU=
=mUhF
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo

bar



-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wHgACgkQ9DF8Jl8Iw6JyLAP8Dpx73JwUsv15xZAm5fee92vh
fg5H0DQy1bMKNrDiz27o12BTanHl53L/n47gbmk+/63pNjneRbWITcLfgM/9wC2W
4bCm52Nnpd6ZWgdSlxfBIQOr1xZVJVU4X1UlbgPZlpu6EPF55ERLbgRPv8tdHFGZ
ws8RiA+KkK4rLalHbs8=
=C7Re
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo

bar



-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7xWIACgkQ9DF8Jl8Iw6KeUgP/SFhuqLmDCrmky6JVUV4jCo/B
aQI4zMiHuY3wptMN+q4nbyx5ZB0eRQ6s39Uqhz5YA1Njul77y+h5Ip3h6FXUi/a+
UGYUQQNOTxwbsFzb/Xhd7OVGIftvKBQ5NFKu/yYSW7QPFwD9twduxi9y1qI9jlwT
PpaXajnbRgVUvMdCBvM=
=6UB2
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo\tblahb

bar



-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7xhUACgkQ9DF8Jl8Iw6JWMQQA4r2y/gYkYzQ3kfM/pAh796f3
R2NgCWh88F0mHeLUS9OwyeHm7bOp04MucouY6AylsXFQLCvnzKOhxqHQTHBvZCjt
SO4xGNFaMiSE6d8YLPPRXOh8+1lPAYoYmzY4UXX7dZVkgYm9KKAAuUnmsT5Uyygw
lxFPI/49blu5ACnJVFs=
=ZO33
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

This is my other key.

- -----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

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
=GZcJ
- -----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iJwEAQECAAYFAlO72JwACgkQ7lwS6m4V25I+xwP/RwQqg00p3sVIJlQDi1zY8djV
PLxGQ45YCET1cxhjS6VwM6ZUEGDxvqQrnxQkD8ir1PhNwDtLfD9GPY1+2NwJR89a
iPznfFHQwhPrMab/kyCS+eW3qd/3CPozV9CnBrJeRybbaDZxgpnCVfPHOfp2ryt7
/IPlxDUGvqHQFEqWBFQ=
=ZflZ
-----END PGP SIGNATURE-----
"""
]

#========================================================================

bad_sigs = [ """
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foop
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wFwACgkQ9DF8Jl8Iw6IDlwP9Gu/s/jKGGkozQ5i/EWAcY/Au
8IIdhOhm1LuWP++y5S4ttM3lTP110Cp8ARQLitph86qvWoV3SkYRrRdQ6G0krElb
hvujbG38E8AauK6gl48YK9QYzD99zbv+mkLVc+Da5vtBIYqJKBOS4Ryk+tYc1eti
HuWJ6zfGw5ZgWU9BWqs=
=pfI+
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

ifoo
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wGMACgkQ9DF8Jl8Iw6KttgQAvb4Utc48Q+tu/NKarBQQ2Kuz
C7nYBWGiw/Co0q6pouWH02AiuNHuGMGPsFVunPLixmo3LlVYNfnNpvaNtlsdhw19
xtrQA2mNzjBpK0RRZvT7UaWMx9gDFjo+HusAbytpBE6+fGB3SCJicSpSCmIzkBve
hGyCdW5211eXGmcOQG0=
=xqM1
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo
i
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wGcACgkQ9DF8Jl8Iw6LzvwP/WHzScg4f+Egf3ammjnjNgNmD
Q5gA/7vN47yv9q7FNkIBBlUaUwUR2TLSJQuIUFCMfcoTgMiRqmJycbTPAIUTbSxJ
bmY1oLnD50hJoX0olJyXRWXH4xYn/yYsWfDFs3SY0Isd0PptpMjQTqHup+YEgXJb
l47I0mrACkvVAApnLyE=
=nJxV
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo
i
bar
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wG0ACgkQ9DF8Jl8Iw6L16gQAhvR4NNQV3Eq/MhyWJ4u83CGx
hRgofGV4lspiXJtuIg7+1ROFyuQWKX/JLm5XXtQr2x6h4MLAcLcsoIQeu4RcZAY5
do/21pGqWsB96UZG5T62qUCbQewbQhfLl6vIJfcd/32HJHMk/1HMWxuw6RmltJzV
RoJRv8Ck8EOoaAHC5cc=
=LXYp
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo

bari
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wHIACgkQ9DF8Jl8Iw6K+MwQA36YhZy7ruNclMWowvkyWHT8h
2QjuJmkGUhK2ofIEOT70vNbKdBSP5d6s6x9+JcDjA8b6qr7z3PLvKNUdxPUoVr6e
8EGGudHettV4Lfm/jvgE8KDEUchLoT2D1N7VO7kDYToxxFuUlA1xKqeRJQfDZE2Y
+fuEFkjRSybtlV1dBjU=
=mUhF
-----END PGP SIGNATURE-----
""","""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

foo

bar
i


-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iJwEAQEKAAYFAlL7wHgACgkQ9DF8Jl8Iw6JyLAP8Dpx73JwUsv15xZAm5fee92vh
fg5H0DQy1bMKNrDiz27o12BTanHl53L/n47gbmk+/63pNjneRbWITcLfgM/9wC2W
4bCm52Nnpd6ZWgdSlxfBIQOr1xZVJVU4X1UlbgPZlpu6EPF55ERLbgRPv8tdHFGZ
ws8RiA+KkK4rLalHbs8=
=C7Re
-----END PGP SIGNATURE-----
""" ]

keys = [ """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

mI0EUncElgEEAOLcPEAV9fpk1/AebOB2uDDBoF1hDWFa6xyV/aVVG7s+PQdrY4q+
w0Ef/JEhE2O/5gAZcag3ASZhXIWWU1RtdhnAkoD4aagLhky0IBPqxLb/oAzWzKL8
XEYa8ljMFTQcCBvwp5SY0IF71YFBCyZavKCN+KDVG+FPnkJrRj5+lyd/ABEBAAG0
K1dpbGxpYW0gV29yZHN3b3J0aCAoQmlsbHkpIDx3dzcwQGdtYWlsLmNvbT6IvgQT
AQIAKAUCUncElgIbAwUJOGQJAAYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQ
9DF8Jl8Iw6JaFgP/YWIJqIMbWpw23905D25GRG4olRfbrQ+FYH5DNVIvLm/wdoBp
58YRCGcJa784tKNDKS59VOPJ1Oqf2Q208C6Zc53bTHmLd1HO9NQAQS2NW1HXAB9J
1wqCkZjBqRsxMYB79BKB+NPJXZox9KutJEsjiFJiqZuSTbOLGYo1rhwW7Ma4jQRS
dwSWAQQAxXNrbi7QVxYDl0IGqymtxDDNyOkHZmw3XteU6+wpvI2/iRpeZU94DKi2
+YEZG3SKwxBW5YU2xgPmXlMlntm39xHleoe7+LmFZlwyPgeHo+KstZMm9oXs4Xg4
JHfeKhuf3HIwak/64IGcBp/p0gd7TsVcScL0FFSdonEX2g1J6kkAEQEAAYilBBgB
AgAPBQJSdwSWAhsMBQk4ZAkAAAoJEPQxfCZfCMOiWjUD/2C+a7Csq6p6k73/mBF6
Ly8zVLcmZaO1EhFp/5EvcE1VAL1hQENDVD+QtM5uB9v21SPW6Rn97nLmEgLTL3Mo
mYnvIU+5ydHBD19N3He+JsKbzqy/08+zZoDZLA+m49feGr1bo6N2PyYb0OSwofkL
1/ZsJ40vxprSAdrpmvMyh/m5
=0e9R
-----END PGP PUBLIC KEY BLOCK-----
""",
"""
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mI0EUqpp2QEEANFByr3uPGsG5DqmV3kPLsTEmew5d8NcD3SqASas342LB5sDE0D6
0fTDvjLYAiCTgVlZrSIx+SeeskygKH/AwnTCBK04V0HgpR0tyw+dGIV5ujFIo236
O8XvIqaVoR1/zizy8fOSaFqr8rPQf3JYWxQn8IMLUS+ricOUZS/YSgNVABEBAAG0
M0dhdmlyaWxvIFByaW5jaXAgKHB3IGlzICdhJykgPGdtYW5AdGhlYmxhY2toYW5k
LmlvPoi+BBMBAgAoBQJSqmnZAhsDBQkSzAMABgsJCAcDAgYVCAIJCgsEFgIDAQIe
AQIXgAAKCRDuXBLqbhXbknHWBACGwlrWuJyAznzZ++EGpvhVZBdgcGlU3CK2YOHC
M9ijVndeXjAtAgUgW1RPjRCopjmi5QKm+YN1WcAdf6I+mnr/tdYhPYnRE+dNsEB7
AWGsiwZOxQbwtCOIR+5AU7pzIoIUW1GsqQK3TbiuSRYI5XG6UdcV5SzQI96aKGvk
S6O6uLiNBFKqadkBBADW31A7htB6sJ71zwel5yyX8NT5fD7t9xH/XA2dwyJFOKzj
R+h5q1KueTPUzrV781tQW+RbHOsFEG99gm3KxuyxFkenXb1sXLMFdAzLvBuHqAjQ
X9pJiMTCAK7ol6Ddtb/4cOg8c6UI/go4DU+/Aja2uYxuqOWzwrantCaIamVEywAR
AQABiKUEGAECAA8FAlKqadkCGwwFCRLMAwAACgkQ7lwS6m4V25IQqAQAg4X+exq1
+wJ3brILP8Izi74sBmA0QNnUWk1KdVA92k/k7qA/WNNobSZvW502CNHz/3SQRFKU
nUCByGMaH0uhI6Fr1J+pjDgP3ZelZg0Kw1kWvkvn+X6aushU3NHtyZbybjcBYV/t
6m5rzEEXCUsYrFvtAjG1/bMDLT0t1AA25jc=
=59sB
-----END PGP PUBLIC KEY BLOCK-----
"""]
ring = new PgpKeyRing()

#==========================================

exports.init = (T,cb) ->
  ring = new PgpKeyRing()
  for key in keys
    await KeyManager.import_from_armored_pgp { raw : key }, defer err, km
    T.no_error err
    ring.add_key_manager km
  cb()

#==========================================

exports.verify_good_sigs = (T,cb) ->
  for sig,i in good_sigs
    await do_message { keyfetch : ring, armored : sig }, defer err, outmsg
    T.no_error err, "#{i}th sig worked'"
    T.waypoint "Sig #{i} checked out" unless err?
  cb()

#==========================================

exports.reject_bad_sigs = (T,cb) ->
  for sig,i in bad_sigs
    await do_message { keyfetch : ring, armored : sig }, defer err, outmsg
    T.assert err, "#{i}th sig failed"
    T.waypoint "Sig #{i} failed" if err?
  cb()

#==========================================
