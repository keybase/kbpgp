{PgpKeyRing} = require '../../lib/keyring'
{KeyManager} = require '../../lib/keymanager'
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
"""]

#========================================================================

key = """
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
"""

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

key = """
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
"""
ring = new PgpKeyRing()

#==========================================

exports.init = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key }, defer err, km
  T.no_error err
  ring = new PgpKeyRing()
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
