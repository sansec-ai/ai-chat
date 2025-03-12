import base64
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5208, rfc5915  # 新增RFC 5915
from gmssl import sm3, func, sm2

def load_private_key_hex(file_path):
    # 读取PEM文件
    with open(file_path, 'r') as f:
        pem_data = f.read()

    # 提取私钥部分（代码保持不变）
    private_key_pem = None
    in_private_key = False
    for line in pem_data.split('\n'):
        if line == '-----BEGIN PRIVATE KEY-----':
            in_private_key = True
            private_key_pem = []
        elif line == '-----END PRIVATE KEY-----':
            in_private_key = False
        elif in_private_key:
            private_key_pem.append(line)

    if private_key_pem is None:
        raise ValueError("Private key not found in PEM file")

    # 合并私钥部分并解码
    private_key_der = base64.b64decode(''.join(private_key_pem))

    # 第一步：解析PKCS#8的PrivateKeyInfo
    private_key_info, _ = decoder.decode(
        private_key_der,
        asn1Spec=rfc5208.PrivateKeyInfo()
    )

    # 第二步：提取内层的ECPrivateKey
    ec_private_key_der = bytes(private_key_info['privateKey'])
    ec_private_key, _ = decoder.decode(
        ec_private_key_der,
        asn1Spec=rfc5915.ECPrivateKey()  # 关键修正点
    )

    # 第三步：提取32字节裸私钥
    private_key_bytes = bytes(ec_private_key['privateKey'])
    pkey_len = len(private_key_bytes)

    if pkey_len != 32:
        raise ValueError(f"Private key is not 32 bytes: {pkey_len}")
    
    return private_key_bytes.hex()

def load_pub_key_hex(file_path):    
    # 读取PEM文件
    with open(file_path, 'r') as f:
        pem_data = f.read()

    # 提取公钥部分
    public_key_pem = []
    in_public_key = False
    for line in pem_data.split('\n'):
        if line == '-----BEGIN PUBLIC KEY-----':
            in_public_key = True
        elif line == '-----END PUBLIC KEY-----':
            in_public_key = False
        elif in_public_key:
            public_key_pem.append(line)

    # 解码DER数据
    public_key_der = base64.b64decode(''.join(public_key_pem))

    # 直接定位BIT STRING内容（跳过ASN.1解析）
    # 通过OpenSSL验证已知公钥结构：
    # 总长度=89字节，其中：
    # - 前23字节为算法标识
    # - 后66字节为BIT STRING（含1字节填充位+65字节公钥数据）
    bit_str_start = 23  # 根据ASN.1解析结果定位
    public_key_bitstr = public_key_der[bit_str_start:]

    # public_key_bitstr = b'\x03B\x00\x04\x0e0\x7f{\x19\x9c?\x9b\xcd\xe45l\xfd\x17\xd7?\xde\x90\xaei\x1d\xb3\x10\xcfD\xa4\xf2\xcbz\x000Z\x15\xc71|C\xcd^\xec\x1f\xdcP\x8e&NW\xba\xdc\xed\xba\x9c\x19fi\xed8\x1a\xe1\x04\xc0\x90\xdcu'
    # 提取公钥裸数据（格式：04 + X + Y）
    # 结构：[填充位(0x00)][04][32字节X][32字节Y]
    public_key_data = public_key_bitstr[3:]  # 跳过填充位
    if public_key_data[0] != 0x04:
        raise ValueError(f"非未压缩公钥格式, : {public_key_data[0]}")

    # 提取64字节核心数据
    raw_public_key = public_key_data[1:65]  # 跳过04后取64字节 
    return raw_public_key.hex()
def load_sm2_private_key(private_file_path, pub_file_path):
    pri_key_hex = load_private_key_hex(private_file_path)
    pub_key_hex = load_pub_key_hex(pub_file_path)
    
    return sm2.CryptSM2(public_key=pub_key_hex, private_key=pri_key_hex)
def load_sm2_public_key(pub_file_path):
    pub_key_hex = load_pub_key_hex(pub_file_path)
    
    return sm2.CryptSM2(public_key=pub_key_hex, private_key=None)
def pem_to_hex(pem_key):
    """
    将 PEM 格式的密钥字符串转换回十六进制字符串。

    :param pem_key: PEM 格式的密钥字符串。
    :return: 十六进制编码的密钥字符串。
    """
    pem_header_public = '-----BEGIN PUBLIC KEY-----'
    pem_header_private = '-----BEGIN PRIVATE KEY-----'
    pem_footer = '-----END '
    is_private = True

    # 确定密钥类型并提取 Base64 编码的主体部分
    if pem_header_public in pem_key:
        pem_header = pem_header_public
        pem_footer += 'PUBLIC KEY-----\n'
        is_private = False
    elif pem_header_private in pem_key:
        pem_header = pem_header_private
        pem_footer += 'PRIVATE KEY-----\n'
    else:
        raise ValueError("Invalid PEM key: Unrecognized header.")

    try:
        pem_body = pem_key[pem_key.index(pem_header) + len(pem_header):pem_key.index(pem_footer)].strip()
    except ValueError as e:
        print(f"Error extracting PEM body: {e}")
        return None
    if pem_body == '':
        raise ValueError("Invalid PEM data: Empty body.")

    # Base64 解码
    # print(f'pem_body={pem_body}')
    bin_key = base64.b64decode(pem_body)
    
    hex_key = bin_key.hex().upper()

    return hex_key
def get_test_sm2key():
    private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

    sm2_crypt = sm2.CryptSM2( public_key=public_key, private_key=private_key)
    return sm2_crypt

#private_key_bytes = load_sm2_private_key("sm2.key")
#print("SM2 私钥的32字节:", private_key_bytes)