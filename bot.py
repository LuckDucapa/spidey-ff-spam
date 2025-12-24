import threading
import jwt
import random
import json
import requests
import socket
import sys
import psutil
import time
import re
import base64
import urllib3
import logging
import os
import telebot # pip install pyTelegramBotAPI
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.timestamp_pb2 import Timestamp
import MajorLoginRes_pb2
from protobuf_decoder.protobuf_decoder import Parser 
from important_zitado import *
from byte import *

# --- Config ---
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s [%(levelname)s] %(message)s', 
    handlers=[logging.StreamHandler(sys.stdout)]
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global list to hold active clients for Telegram control
active_clients = []

# --- Spam Type Definitions ---
SPAM_TYPES = {
    1: {"val": 4096,    "name": "Moderator Badge"},
    2: {"val": 32768,   "name": "New V-Badge"},
    3: {"val": 32768,   "name": "New V-Badge 2"}, # Same val, kept for compatibility
    4: {"val": 64,      "name": "Small V-Badge"},
    5: {"val": 1048576, "name": "Craftland Badge"},
    6: {"val": 8192,    "name": "Old V-Badge"},
    7: {"val": 16384,   "name": "New V-Badge 3"}
}

# --- Helpers ---
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
    except Exception:
        return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {"wire_type": result.wire_type, "data": result.data}
        if result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def restart_program():
    logging.warning("RESTARTING SCRIPT...")
    time.sleep(1)
    python = sys.executable
    os.execl(python, python, *sys.argv)

def fix_num(num):
    return ''.join([c + ("[c]" if (i + 1) % 3 == 0 and c.isdigit() else "") for i, c in enumerate(str(num))])

def get_random_avatar():
    return '902048021'

# --- Client Class ---
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.start_time = time.time()
        self.daemon = True
        self.online_socket = None 
        self.is_connected = False

    def run(self):
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            return MajorLogRes.kts, MajorLogRes.ak.hex(), MajorLogRes.aiv.hex(), MajorLogRes.token
        except Exception as e:
            logging.error(f"Failed to parse MajorLogin response: {e}")
            return None

    def nmnmmmmn(self, data):
        key_b = bytes.fromhex(self.key) if isinstance(self.key, str) else self.key
        iv_b = bytes.fromhex(self.iv) if isinstance(self.iv, str) else self.iv
        cipher = AES.new(key_b, AES.MODE_CBC, iv_b)
        return cipher.encrypt(pad(bytes.fromhex(data), AES.block_size)).hex()

    # --- Packets ---
    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {1: 1, 2: {1: 12947146032, 2: Enc_Id, 3: 2, 4: str(Msg), 5: int(datetime.now().timestamp()), 7: 2, 9: {1: " PROTO", 2: int(get_random_avatar()), 3: 901048020, 4: 330, 5: 1001000003, 8: "Friend", 10: 1, 11: 1, 13: {1: 2, 2: 1}, 14: {1: 11017917409, 2: 8, 3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"}}, 10: "IND", 13: {1: "https://graph.facebook.com/v9.0/253082355523299/picture?width=160&height=160", 2: 1, 3: 1}, 14: {1: {1: random.choice([1, 4]), 2: 1, 3: random.randint(1, 180), 4: 1, 5: int(datetime.now().timestamp()), 6: "IND"}}}}
        packet = create_protobuf_packet(fields).hex()
        header = dec_to_hex(len(encrypt_packet(packet, self.key, self.iv)) // 2)
        return bytes.fromhex("1215" + "0" * (8 - len(header)) + header + self.nmnmmmmn(packet))

    def generate_spam_packet(self, idplayer, type_id):
        # Default to 4096 if type invalid
        val = SPAM_TYPES.get(type_id, {"val": 4096})["val"]
        
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
                24: int(get_random_avatar()), 26: "", 28: "", 
                31: {1: 1, 2: val}, 32: val, 
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

    # --- ACTION METHOD (Used by both Game and Telegram) ---
    def execute_spam(self, target_uid, spam_type_id=7):
        if not self.online_socket:
            return False, "Socket not connected"
        try:
            spam_name = SPAM_TYPES.get(spam_type_id, {}).get("name", "Unknown")
            logging.info(f"Executing {spam_name} on {target_uid}")
            
            # 1. Leave any existing group
            self.online_socket.send(self.leave_s())
            time.sleep(0.3)
            
            # 2. Set to Solo Mode
            self.online_socket.send(self.changes(1))
            time.sleep(0.3)
            
            # 3. Generate and Spam Packet
            packet = self.generate_spam_packet(target_uid, spam_type_id)
            for i in range(1, 41): # 40 Packets
                self.online_socket.send(packet)
                time.sleep(0.05)
                
            # 4. Cleanup
            self.online_socket.send(self.leave_s())
            return True, f"Sent 40x {spam_name}"
        except Exception as e:
            logging.error(f"Spam Error: {e}")
            return False, str(e)

    # --- Networking ---
    def sockf1(self, tok, online_ip, online_port):
        self.online_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.online_socket.connect((online_ip, int(online_port)))
        self.online_socket.send(bytes.fromhex(tok))
        logging.info("Online Server Socket Connected")
        self.is_connected = True
        
        while True:
            try:
                data = self.online_socket.recv(4096)
                if not data: 
                    logging.warning("Online socket closed.")
                    self.is_connected = False
                    break
                if time.time() - self.start_time > 600: restart_program()
            except: 
                self.is_connected = False
                break

    def connect(self, tok, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.connect((whisper_ip, int(whisper_port)))
        clients.send(bytes.fromhex(tok))
        
        t = threading.Thread(target=self.sockf1, args=(tok, online_ip, online_port))
        t.daemon = True
        t.start()
        
        logging.info("Bot Fully Connected! Ready.")

        while True:
            try:
                data = clients.recv(4096)
                if not data: 
                    logging.error("Main socket closed. Restarting.")
                    restart_program()
                
                hex_data = data.hex()
                
                # GAME CHAT LISTENER
                if "1200" == hex_data[0:4]: 
                    try:
                        json_str = get_available_room(hex_data[10:])
                        if not json_str: continue
                        parsed = json.loads(json_str)
                        uid = parsed["5"]["data"].get("1", {}).get("data")
                        
                        # --- In-Game Help Command ---
                        if b'/help' in data:
                            msg = """[C][B][FFFF00]COMMAND LIST:
[00FF00]/s1 <UID> [FFFFFF]Moderator Badge
[00FF00]/s2 <UID> [FFFFFF]New V-Badge
[00FF00]/s3 <UID> [FFFFFF]New V-Badge 2
[00FF00]/s4 <UID> [FFFFFF]Small V-Badge
[00FF00]/s5 <UID> [FFFFFF]Craftland Badge
[00FF00]/s6 <UID> [FFFFFF]Old V-Badge
[00FF00]/s7 <UID> [FFFFFF]New V-Badge 3"""
                            if uid: clients.send(self.GenResponsMsg(msg, uid))

                        # --- In-Game Spam Commands ---
                        for i in range(1, 8):
                            cmd = f"/s{i}"
                            if cmd.encode() in data:
                                try:
                                    parts = re.split(cmd.encode(), data)[1].decode(errors='ignore').strip()
                                    target_match = re.search(r'\d+', parts)
                                    if target_match:
                                        target = target_match.group()
                                        if uid: clients.send(self.GenResponsMsg(f"[C][B]Processing /s{i} on {target}...", uid))
                                        success, res = self.execute_spam(target, i)
                                        if uid: clients.send(self.GenResponsMsg(f"[C][B]{res}", uid))
                                except: pass

                    except: pass
            except: restart_program()

    # --- Authentication ---
    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        
        now = datetime.now()
        now = str(now)[:19] 
        
        payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
        payload = payload.replace(b"2025-07-30 11:02:51", str(now).encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        
        PAYLOAD = encrypt_api(payload.hex())
        whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN, bytes.fromhex(PAYLOAD))
        return whisper_ip, whisper_port, online_ip, online_port

    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://client.ind.freefiremobile.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        try:
            response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
            x = response.content.hex()
            json_result = get_available_room(x)
            parsed_data = json.loads(json_result)
            whisper_address = parsed_data['32']['data']
            online_address = parsed_data['14']['data']
            return whisper_address[:len(whisper_address) - 6], int(whisper_address[len(whisper_address) - 5:]), online_address[:len(online_address) - 6], int(online_address[len(online_address) - 5:])
        except Exception as e:
            logging.critical(f"Failed to get server IP: {e}")
            restart_program()

    def TOKEN_MAKER(self, OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033')
        data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        
        RESPONSE = requests.post("https://loginbp.ggblueshark.com/MajorLogin", headers=headers, data=Final_Payload, verify=False)
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        
        if RESPONSE.status_code == 200:
            whisper_ip, whisper_port, online_ip, online_port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1)
            self.key = key
            self.iv = iv
            return BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port
        else:
            return False

    def get_tok(self):
        token_data = self.guest_token(self.id, self.password)
        if not token_data:
            logging.critical("Failed to get token data. Restarting.")
            restart_program()
        
        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = token_data
        
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            encoded_acc = hex(decoded.get('account_id'))[2:]
            time_hex = hex(Timestamp)[2:].zfill(2)
            
            BASE64_TOKEN_ = token.encode().hex()
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            
            zeros = '00000000'
            if length == 9: zeros = '0000000'
            elif length == 8: zeros = '00000000'
            elif length == 10: zeros = '000000'
            elif length == 7: zeros = '000000000'
            
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            self.connect(final_token, key, iv, whisper_ip, whisper_port, online_ip, online_port)
        except Exception as e:
            logging.error(f"Token construction error: {e}")
            restart_program()

    def guest_token(self, uid, password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com", "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)", "Content-Type": "application/x-www-form-urlencoded"}
        data = {"uid": f"{uid}", "password": f"{password}", "response_type": "token", "client_type": "2", "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3", "client_id": "100067"}
        try:
            response = requests.post(url, headers=headers, data=data)
            data = response.json()
            return self.TOKEN_MAKER("ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", data['access_token'], "996a629dbcdb3964be6b6978f5d814db", data['open_id'], uid)
        except Exception as e:
            logging.critical(f"Guest token error: {e}")
            restart_program()

# --- TELEGRAM BOT LOGIC ---
API_TOKEN = '8292738024:AAHjghTZvUZmLKV091qGe3A5yr_OdFIYv8I' # <--- PLACE YOUR TOKEN HERE
bot = telebot.TeleBot(API_TOKEN)

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    help_text = """🔥 *FF Hybrid Spam Bot* 🔥

👇 **Click to copy command** 👇

🔹 `/s1 <UID>` : `Moderator Badge`
🔹 `/s2 <UID>` : `New V-Badge`
🔹 `/s3 <UID>` : `New V-Badge 2`
🔹 `/s4 <UID>` : `Small V-Badge`
🔹 `/s5 <UID>` : `Craftland Badge`
🔹 `/s6 <UID>` : `Old V-Badge`
🔹 `/s7 <UID>` : `New V-Badge 3`

💡 *Or just send the UID to trigger /s7 default!*
"""
    bot.reply_to(message, help_text, parse_mode="Markdown")

@bot.message_handler(func=lambda message: True)
def handle_message(message):
    text = message.text.strip()
    
    # Check for active game clients
    if not active_clients or not active_clients[0].is_connected:
        bot.reply_to(message, "⚠️ Game Client Disconnected or Login Pending. Please wait.")
        return
        
    client = active_clients[0]
    
    # 1. Parse Command (e.g., /s1 12345)
    spam_type = 7 # Default to s7
    target_uid = ""
    
    match_cmd = re.match(r"^/s(\d)\s+(\d+)$", text)
    match_uid = re.match(r"^(\d+)$", text)
    
    if match_cmd:
        type_id = int(match_cmd.group(1))
        target_uid = match_cmd.group(2)
        if 1 <= type_id <= 7:
            spam_type = type_id
        else:
            bot.reply_to(message, "❌ Invalid Type. Use 1-7.")
            return
    elif match_uid:
        target_uid = match_uid.group(1)
        spam_type = 7 # Default
    else:
        bot.reply_to(message, "❌ Invalid Format. Send /help")
        return

    # 2. Execute
    spam_name = SPAM_TYPES[spam_type]["name"]
    bot.reply_to(message, f"🚀 Sending *{spam_name}* to `{target_uid}`...", parse_mode="Markdown")
    
    success, msg = client.execute_spam(target_uid, spam_type)
    
    if success:
        bot.reply_to(message, f"✅ *Success!* Sent to `{target_uid}`", parse_mode="Markdown")
    else:
        bot.reply_to(message, f"❌ Failed: {msg}")

def start_telegram():
    try:
        logging.info("Starting Telegram Polling...")
        bot.infinity_polling()
    except Exception as e:
        logging.error(f"Telegram Error: {e}")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    try:
        with open('bot.txt', 'r') as file:
            data = json.load(file)
        
        # Start Game Clients
        for uid, pwd in data.items():
            client = FF_CLIENT(uid, pwd)
            client.start()
            active_clients.append(client)
            time.sleep(2)
            
        # Start Telegram Bot in Main Thread
        start_telegram()
        
    except Exception as e:
        logging.critical(f"Critical error: {e}")
        restart_program()
