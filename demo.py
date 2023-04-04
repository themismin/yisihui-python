# -*- coding: utf-8 -*-
# @Time    : 19-8-28 下午2:29
# @Author  : huanghaohao
# @Email   : haohao.huang@easytransfer.cn
# @File    : demo.py
# @Software: PyCharm
import os, sys
lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libs')
sys.path.insert(0, lib_path)
import requests
from sign_helper import splice_sign_text
from datetime import datetime
import random
import json
from rsa_utils import rsa_utils
from aes_utils import aes_utils



key_base_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'key')
merchant_number = 'ET82009'
sub_merchant_number = 'ET82009S001'
aes_key = aes_utils.get_random_key(16)

request_data = dict()

serial_number = datetime.now().strftime('%Y%m%d%H%M%S') + str(random.randint(111111, 999999)) + merchant_number
merchant_info = {
     'pri_key_file': sub_merchant_number + '-pri.pem',
     'et_public_key_file': sub_merchant_number + '-et-pub.pem'
}
sensitive_data = json.dumps([])
request_data['serial_number'] = serial_number
request_data['merchant_number'] = merchant_number
request_data['sub_merchant_number'] = sub_merchant_number
request_data['server_type'] = 'get_institutions'
request_data['callback_process'] = ''
request_data['version'] = '2.0.0'
request_data['data'] = json.dumps({
        "search_key": "",
        "count": 0,
        "institution_type": 1
})

request_data['return_info'] = ''
request_data['extend_info'] = ''

pub_file_path = os.path.join(key_base_path, f'{merchant_info.get("et_public_key_file")}')
pri_file_path = os.path.join(key_base_path, f'{merchant_info.get("pri_key_file")}')
with open(pub_file_path, 'r+') as f:
    pub_key = f.read()

with open(pri_file_path, 'r+') as f:
    pri_key = f.read()

# 加密 sensitive_data
sensitive_data_chiper = aes_utils.encrypt(raw=sensitive_data, key=aes_key, iv=aes_key)
request_data['sensitive_data'] = sensitive_data_chiper

# 加密aes_key
aes_key_chiper = rsa_utils.rsa_encrypt(key=pub_key, text=aes_key)
request_data['aeskey'] = str(aes_key_chiper, encoding='utf-8')
# 签名
raw_sign_text = bytes(splice_sign_text(info=request_data), 'utf-8')
sign_text = rsa_utils.sign(key=pri_key, text=raw_sign_text)
request_data['sign'] = str(sign_text, encoding='utf-8')


# ---------------------------------请求返回值
# TODO url请替换成文档里面的url
response = requests.post(url='http://127.0.0.1:8877/server', data=json.dumps(request_data))

text = response.text
response_data = json.loads(text)
return_sign = response_data.pop('sign')
sign_text = bytes(return_sign, encoding='utf-8')
raw_sign_text = bytes(splice_sign_text(info=response_data), 'utf-8')

result = rsa_utils.verify(key=pub_key, text=raw_sign_text, sign_text=sign_text)
print('验签结果', result)

aes_key = response_data['aeskey']

aes_key = rsa_utils.rsa_decrypt(key=pri_key, chiper_text=aes_key)
print('返回aes_key', aes_key)

sensitive_data = response_data['sensitive_data']
sensitive_data = aes_utils.decrypt(enc=sensitive_data, key=aes_key, iv=aes_key)

print('敏感数据', sensitive_data)







