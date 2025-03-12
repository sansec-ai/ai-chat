from gmssl import sm3, func, sm2
import base64
from cryptography.hazmat.primitives import serialization
from asn1crypto.core import Sequence, Integer
import json
import sm2key

class SM2Verifier:
    def __init__(self, private_key=None, public_key=None):
        """
        初始化 SM2Verifier 类，支持传入私钥和公钥。
        
        :param private_key: SM2 私钥，十六进制字符串格式
        :param public_key: SM2 公钥，十六进制字符串格式
        """
        # 检查私钥和公钥文件是否存在，如果存在则加载私钥和公钥文件的内容
        # private_key = None
        # public_key = None
        # if pri_keyfile is not None:
        #     private_key = sm2key.load_sm2_private_key(pri_keyfile)
        # if pub_keyfile is not None:
        #     public_key = sm2key.load_sm2_public_key(pub_keyfile)

        self.sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)

    def verify_signature_with_sm2(self, plaintext, sign_hex):
        """
        使用 SM2 公钥进行验签。
        
        :param plaintext: 原始数据
        :param sign_hex: 签名数据
        :return: 验签结果，True 或 False
        """
        if self.public_key is None:
            print("Failed to load SM2 public key.")
            return False

        # 使用 SM2 公钥进行验签
        is_valid = self.sm2_crypt.verify(plaintext, sign_hex)
        return is_valid

    def verify_signature(self, signature, content):
        """
        验证签名。
        
        :param signature: 签名数据，包含 sm3, timestamp, signatory, value 等字段
        :param content: 原始内容
        :return: 验签结果，True 或 False
        """
        if self.sm2_crypt is None:
            print("Failed to load SM2 public key.")
            return False

        # 计算 SM3 哈希
        sm3_hash = sm3.sm3_hash(func.bytes_to_list(content.encode('utf-8')))

        # 提取签名字段
        sign_sm3 = signature.get("sm3")
        sign_time = signature.get("timestamp")
        sign_signatory = signature.get("signatory")

        # 组合原文
        plaintext = (sign_sm3 + sign_time + sign_signatory).encode('utf-8')
        #print(f"plaintext: {plaintext}")
        plain_hex_str = self.sm2_crypt._sm3_z(plaintext)  # SM3带ID预处理过程
        plain_e = bytes.fromhex(plain_hex_str)

        sign_value = signature.get("value")
        try:
            sign_der = bytes.fromhex(sign_value)  # 十六进制 → 字节
            sign_hex_str = self.parse_der_signature(sign_der)  # DER → 裸签名
        except Exception as e:
            print(f"Base64 解码错误: {e}")
            return False

        # 使用 SM2 进行验签
        is_valid = self.sm2_crypt.verify(sign_hex_str, plain_e)
        return is_valid

    @staticmethod
    def parse_der_signature(der_bytes):
        """
        解析 DER 编码的签名，返回 r 和 s 的裸拼接值。
        
        :param der_bytes: DER 编码的签名
        :return: r 和 s 的裸拼接值
        """
        seq = Sequence.load(der_bytes)
        if len(seq) != 2:
            raise ValueError("无效的DER签名格式")
        r = seq[0].native.to_bytes(32, 'big').hex()  # 转换为Hex
        s = seq[1].native.to_bytes(32, 'big').hex()
        return r + s

    def test_sign_verify(self):
        """
        测试签名和验签功能。
        """
        if self.sm2_crypt is None:
            print("Private key or public key is not set.")
            return

        data = b"111"
        print("-----------------test sign and verify---------------")
        random_hex_str = func.random_hex(self.sm2_crypt.para_len)
        sign = self.sm2_crypt.sign(data, random_hex_str)
        print('sign:%s' % sign)
        verify = self.sm2_crypt.verify(sign, data)
        print('verify:%s' % verify)

if __name__ == '__main__':
    # 示例：使用测试密钥对初始化并测试
    private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
    
    # private_key = sm2key.load_private_key_hex('sm2.key')
    # public_key = sm2key.load_pub_key_hex('sm2.pub')
    verifier = SM2Verifier(private_key=private_key, public_key=public_key)
    verifier.test_sign_verify()