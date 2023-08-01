from hashlib import md5

version = "7.4.33"

api = "API320190902,NTS"

Bin = "BIN_48888"

modules = [
    "Core",
    "date",
    "libxml",
    "openssl",
    "pcre",
    "sqlite3",
    "zlib",
    "ctype",
    "curl",
    "dom",
    "fileinfo",
    "filter",
    "ftp",
    "hash",
    "iconv",
    "json",
    "mbstring",
    "SPL",
    "PDO",
    "pdo_sqlite",
    "session",
    "posix",
    "Reflection",
    "standard",
    "SimpleXML",
    "Phar",
    "tokenizer",
    "xml",
    "xmlreader",
    "xmlwriter",
    "mysqlnd",
    "apache2handler",
    "sodium",
    "Zend OPcache"
]

context = version + api + Bin
for i in modules:
    if i == 'Core':
        context += i + "3.4.0"
    elif i == 'dom':
        context += i + "20031129"
    elif i == 'mysqlnd':
        context += i + "mysqlnd 7.4.33"
    else:
        context += i + version

print(md5(context.encode()).hexdigest())