from Crypto.Cipher import CAST,AES

key = "583d18c32d8857a627ea3e86d6feada8".decode("hex")
iv = 'fe40e836b0e9b193'.decode('hex')
iv = 'fe40e836b0e9b193aabbccdd11223344'.decode('hex')
dat = "8bb2a710bb8418711d987be3dce7ae416cf2357994fa7f70259b08691101c8c5".decode("hex")
cipher = AES.new(key, AES.MODE_ECB, iv)
msg = cipher.encrypt(dat)
print msg.encode('hex')

