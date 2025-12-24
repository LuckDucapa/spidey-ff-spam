from flask import Flask, request, jsonify
import threading
import jwt
import random
import json
import requests
import socket
import time
import base64
import os
import sys
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.timestamp_pb2 import Timestamp

# --- VERCEL PATH FIX ---
# This ensures imports work on Vercel's file system
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import MajorLoginRes_pb2
    from protobuf_decoder.protobuf_decoder import Parser 
    from important_zitado import *
    from byte import *
except ImportError:
    pass

app = Flask(__name__)

# ==========================================
# ⚡ CONFIGURATION (FILL THIS!) ⚡
# ==========================================
# If bot.txt fails, the bot will use these credentials.
# PUT YOUR BOT ACCOUNT DETAILS HERE TO BE SAFE:
MANUAL_UID = "4312332290"
MANUAL_PASS = "33830EFA752A56D36D9123B6E3F43292FF835191BFA7CC89B6836FCAF4893EDD"
# ==========================================

def get_credentials():
    # Try to load from bot.txt using absolute path
    try:
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_path = os.path.join(base_path, 'bot.txt')
        
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                creds = json.load(file)
                uid = list(creds.keys())[0]
                return uid, creds[uid]
    except Exception as e:
        print(f"File Load Error: {e}")
    
    # Fallback to Manual
    return MANUAL_UID, MANUAL_PASS

# --- HELPERS ---
def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    key_b = bytes.fromhex(key) if isinstance(key, str) else key
    iv_b = bytes.fromhex(iv) if isinstance(iv, str) else iv
    cipher = AES.new(key_b, AES.MODE_CBC, iv_b)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def dec_to_hex(ask):
    final_result = hex(ask)[2:]
    return "0" + final_result if len(final_result) % 2 != 0 else final_result

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain_text, AES.block_size)).hex()

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        return json.dumps(parse_results(parsed_results))
    except: return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {"wire_type": result.wire_type, "data": result.data}
        if result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

# --- CORE LOGIC ---
class FF_ONE_TIME_RUNNER:
    def __init__(self, uid, password):
        self.id = uid
        self.password = password
        self.key = None
        self.iv = None

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            return MajorLogRes.kts, MajorLogRes.ak.hex(), MajorLogRes.aiv.hex(), MajorLogRes.token
        except: return None

    def nmnmmmmn(self, data):
        key_b = bytes.fromhex(self.key) if isinstance(self.key, str) else self.key
        iv_b = bytes.fromhex(self.iv) if isinstance(self.iv, str) else self.iv
        cipher = AES.new(key_b, AES.MODE_CBC, iv_b)
        return cipher.encrypt(pad(bytes.fromhex(data), AES.block_size)).hex()

    def request_join_squad(self, idplayer):
        # 4096 = Moderator Badge Logic
        same_value = 4096 
        fields = {
            1: 33, 
            2: {
                1: int(idplayer), 2: "IND", 3: 1, 4: 1, 
                5: bytes([1, 7, 9, 10, 11, 18, 25, 26, 32]), 
                6: "iG:[C][B][FF0000] SPIDY", 7: 330, 8: 1000, 10: "IND", 
                11: bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56, 97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53]), 
                12: 1, 13: int(idplayer), 
                14: {1: 2203434355, 2: 8, 3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"}, 
                16: 1, 17: 1, 18: 312, 19: 46, 23: bytes([16, 1, 24, 1]), 
                24: 902048021, 26: "", 28: "", 
                31: {1: 1, 2: same_value}, 32: same_value, 
                34: {1: int(idplayer), 2: 8, 3: bytes([15,6,21,8,10,11,19,12,17,4,14,20,7,2,1,5,16,3,13,18])}
            }, 
            10: "en", 13: {2: 1, 3: 1}
        }
        packet = create_protobuf_packet(fields).hex()
        header = dec_to_hex(len(encrypt_packet(packet, self.key, self.iv)) // 2)
        return bytes.fromhex("0515" + "0" * (8 - len(header)) + header + self.nmnmmmmn(packet))

    def leave_s(self):
        packet = create_protobuf_packet({1: 7, 2: {1: 12480598706}}).hex()
        header = dec_to_hex(len(encrypt_packet(packet, self.key, self.iv)) // 2)
        return bytes.fromhex("0515" + "0" * (8 - len(header)) + header + self.nmnmmmmn(packet))

    def changes(self, num):
        packet = create_protobuf_packet({1: 17, 2: {1: 12480598706, 2: 1, 3: int(num), 4: 62, 5: "\u001a", 8: 5, 13: 329}}).hex()
        header = dec_to_hex(len(encrypt_packet(packet, self.key, self.iv)) // 2)
        return bytes.fromhex("0515" + "0" * (8 - len(header)) + header + self.nmnmmmmn(packet))

    def execute(self, target_uid):
        # 1. Login Logic
        url_guest = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers_guest = {"User-Agent": "GarenaMSDK/4.0.19P4", "Content-Type": "application/x-www-form-urlencoded"}
        data_guest = {"uid": self.id, "password": self.password, "response_type": "token", "client_type": "2", "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3", "client_id": "100067"}
        
        try:
            r = requests.post(url_guest, headers=headers_guest, data=data_guest).json()
        except Exception as e:
            return False, f"Guest Login Network Error: {str(e)}"

        if 'access_token' not in r: 
            return False, f"Guest Login Failed. Response: {str(r)}"
        
        access_token, open_id = r['access_token'], r['open_id']
        
        # 2. Major Login
        # Hex Payload Template
        payload_template = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
        
        now = str(datetime.now())[:19]
        # Replace Dummy with Real
        payload = payload_template.replace(b"2025-07-30 11:02:51", now.encode())
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", open_id.encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", access_token.encode())
        
        headers = {'X-Unity-Version': '2018.4.11f1', 'ReleaseVersion': 'OB53', 'User-Agent': 'Dalvik/2.1.0', 'Content-Type': 'application/x-www-form-urlencoded'}
        
        try:
            r = requests.post("https://loginbp.ggblueshark.com/MajorLogin", headers=headers, data=bytes.fromhex(encrypt_api(payload.hex())), verify=False)
        except Exception as e:
            return False, f"Major Login Network Error: {str(e)}"

        if r.status_code != 200:
            return False, f"Major Login Failed. HTTP {r.status_code}. Content: {r.text[:50]}"

        parsed = self.parse_my_message(r.content)
        if not parsed: return False, "Major Login Protobuf Parse Failed"
        timestamp, key, iv, token = parsed
        self.key, self.iv = key, iv

        # 3. Get IP
        PAYLOAD = encrypt_api(payload.hex())
        headers['Authorization'] = f'Bearer {token}'
        headers['Host'] = 'clientbp.common.ggbluefox.com'
        
        try:
            r = requests.post("https://client.ind.freefiremobile.com/GetLoginData", headers=headers, data=bytes.fromhex(PAYLOAD), verify=False)
        except:
            return False, "GetLoginData Network Error"

        parsed_res = json.loads(get_available_room(r.content.hex()))
        try:
            online_addr = parsed_res['14']['data']
            ip, port = online_addr[:-6], int(online_addr[-5:])
        except:
            return False, "Failed to get Server IP"

        # 4. Construct Final Token
        decoded = jwt.decode(token, options={"verify_signature": False})
        encoded_acc = hex(decoded.get('account_id'))[2:]
        time_hex = hex(timestamp)[2:].zfill(2)
        base64_tok = token.encode().hex()
        head = dec_to_hex(len(encrypt_packet(base64_tok, key, iv)) // 2)
        zeros = '0' * (17 - len(encoded_acc)) if len(encoded_acc) < 10 else '0' * (16 - len(encoded_acc))
        final_token = f'0115{zeros}{encoded_acc}{time_hex}00000{head}' + encrypt_packet(base64_tok, key, iv)

        # 5. Connect and Spam
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((ip, port))
            sock.send(bytes.fromhex(final_token))
            time.sleep(0.5)
            
            # Sequence
            sock.send(self.leave_s())
            time.sleep(0.2)
            sock.send(self.changes(1))
            time.sleep(0.2)
            
            packet = self.request_join_squad(target_uid)
            for _ in range(35):
                sock.send(packet)
                time.sleep(0.02)
                
            sock.send(self.leave_s())
            sock.close()
            return True, "Success"
        except Exception as e:
            return False, f"Socket Error: {str(e)}"

# --- API ENDPOINT ---
@app.route('/spam', methods=['GET'])
def spam_handler():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"status": "Error", "message": "Please provide ?uid="}), 400

    # Load Credentials
    bot_uid, bot_pass = get_credentials()
    
    if bot_uid == "YOUR_BOT_UID_HERE":
        return jsonify({"status": "Config Error", "message": "Please configure MANUAL_UID in index.py or upload bot.txt correctly"}), 500

    runner = FF_ONE_TIME_RUNNER(bot_uid, bot_pass)
    success, msg = runner.execute(uid)

    response = {
        "status": "Success" if success else "Failed",
        "message": "Moderator Badge Join Request Sent Successfully" if success else msg,
        "target": uid,
        "owner": "@spidey_abd",
        "Join": "https://t.me/TubeGroww"
    }
    return jsonify(response)

# For Local Testing
if __name__ == '__main__':
    app.run(debug=True)
