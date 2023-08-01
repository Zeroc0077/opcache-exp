from hashlib import md5

version = '8.2.8'

api = 'API420220829,NTS'

Bin = 'BIN_4888(size_t)8'

systemid = md5((version + api + Bin).encode() + b'\x02').hexdigest()

print(systemid)