try:
	from hashlib import hmac_sha512, pbkdf2_hmac_sha512, ripemd160
except:
	from .pyhashlib import hmac_sha512, pbkdf2_hmac_sha512, ripemd160

from hashlib import *