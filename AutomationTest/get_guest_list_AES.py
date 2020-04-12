import unittest
import requests
import json
from Crypto.Cipher import AES
import base64

class get_guest_list_AES_test(unittest.TestCase):
    def setUp(self):
        self.host = 'http://192.168.50.36'
        self.port = '8086'
        self.api = '/api/get_guest_list'
        self.url = self.host + ':' + self.port + self.api
        BS = 16
        self.pad = lambda s : s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        self.app_key = 'W7v4D60fds2Cmk2U'

    def encryptBase64(self, src):
        return base64.urlsafe_b64encode(src)

    def encryptAES(self, src, key):
        iv = b'1172311105789011'
        cryptor = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cryptor.encrypt(self.pad(src))
        return self.encryptBase64(ciphertext)

    def test_get_event_list_eid_phone_success(self):
        payload = {'eid': 9, 'phone': '18514428813'}
        j = json.dumps(payload)
        encoded = self.encryptAES(j, self.app_key).decode()
        print(encoded)
        print(self.url)
        print(j)
        print(self.app_key)
        r = requests.post(self.url, data={'data': encoded})
        print(r)
        result = r.json()
        print(result)

if __name__ == '__main__':
    unittest.main()
