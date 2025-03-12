from flask import Flask, render_template, request, jsonify, Response
import requests
import json
import re
from gmssl import sm3, func, sm2
import base64
import sm2verify,sm2key
import argparse

app = Flask(__name__)

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='AI Chat with SM2 Signature Verification')
    parser.add_argument('--public-key', type=str, help='Path to the SM2 public key file')
    parser.add_argument('--private-key', type=str, help='Path to the SM2 private key file')
    return parser.parse_args()

# 解析命令行参数
args = parse_args()
private_key = None
public_key = None
if args.public_key:
    public_key = sm2key.load_pub_key_hex(args.public_key)
if args.private_key:
    private_key = sm2key.load_private_key_hex(args.private_key)
# 初始化 SM2Verifier
verifier = sm2verify.SM2Verifier(private_key, public_key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    content = data.get('content')
    api_url = data.get('apiUrl') + "/api/chat"
    api_key = data.get('apiKey')
    model_name = data.get('modelName')

    # 调用大模型API，使用流式请求
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    payload = {
        'model': model_name,
        'messages': [{'role': 'user', 'content': content}]
    }
    try:
        response = requests.post(api_url, headers=headers, json=payload, verify=False, stream=True)
        response.raise_for_status()
        
        def generate():
            buffer = ""
            signature = None
            content_buffer = ""  # 用于拼接所有content
            print(f"开始接收数据......")
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    buffer += chunk.decode('utf-8')
                    while True:
                        match = re.search(
                                r'\{.*?"model":"[^"]*".*?"done":(true|false).*?\}\s*', 
                                buffer, 
                                re.DOTALL
                                )
                        if match:
                            json_chunk = match.group(0)
                            re_buffer = buffer[match.end():]
                            try:
                                json_data = json.loads(json_chunk)
                                buffer = re_buffer
                            except json.JSONDecodeError as e:
                                try:
                                    json_data = json.loads(buffer)
                                    buffer = ""
                                except json.JSONDecodeError as e:
                                    print(f"    \nJSON数据解析错误: {buffer}")  # 调试日志
                                    continue
                            
                            content = json_data.get('message', {}).get('content', '')
                            content_buffer += content  # 拼接content
                            done = json_data.get('done', False)
                            #print(content, end='')
                            content = content.replace('<think>', '&lt;think&gt;').replace('</think>', '&lt;/think&gt;')
                            if content or done:
                                yield content
                            if done:
                                # 检查是否有签名属性，并进行验签
                                signature = json_data.get('signature', None)
                                if signature is None:
                                    content_buffer = ""
                                    yield json.dumps("")
                                    break
                                is_signature_valid = verifier.verify_signature(signature, content_buffer)
                                #is_signature_valid = sm2verifyBak.verify_signature(signature, content_buffer )
                                #print(f"\n验签结果: {is_signature_valid}")
                                content_buffer = ""

                                buffer = ""
                                yield json.dumps({'signature': {'value': signature.get("value"), 'sm3': signature.get("sm3"), 
                                                'timestamp': signature.get("timestamp"), 'signatory': signature.get("signatory"),
                                                'valid': is_signature_valid}})
                                break
                        else:
                            break

        return Response(generate(), content_type='text/plain')
    except requests.RequestException as e:
        return jsonify({'content': f"请求大模型API失败: {str(e)}", 'is_valid': False})

if __name__ == '__main__':
    app.run(debug=True, port=9090)