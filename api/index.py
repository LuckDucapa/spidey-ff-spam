from flask import Flask, request, jsonify
import os
import asyncio
# You must include 'telethon' in your requirements.txt
from telethon import TelegramClient
from telethon.sessions import StringSession

app = Flask(__name__)

# ==========================================
# ⚡ CONFIGURATION ⚡
# ==========================================

# 1. Telegram API Credentials (from my.telegram.org)
API_ID = 32835279 # Replace with your API ID (Integer)
API_HASH = "910f180788d480b936f5e09c0da202c7" # Replace with your API Hash

# 2. The Long String you got from Step 1
SESSION_STRING = "1BVtsOK8Buw3DIhgQn5ZeYoNolWCFg77KKOEzmMrMVmzRy_u6rMzwqZb0RxB4UDgIdadjWEozlr26BrVXhdKuJLRNN-rsKQaODOubpmUpcksUvp1w0gBvR08-PulJHyXqsoybmaIpgn5993PVJKM-djpqFrafDnA_ozYBZKvwpS4gqGFCWHY8lgWCUvomxdm7MynGR5NKHpkEsJGSYHCZ6Tzv2jgq6z0pXpFfndvVgt7xS0GlTsk4T-qZZwaPWW7TCFWGYyjrhl65N4Eq5T0OT8hJ86xIBl61ra2mmwbIzMNDab177y6xi4-jPs6F5o75LQg1NU0WWes_ZOBF8FAdPTKvaanMqxk="

# 3. The Group ID (Target Chat)
# Ensure it's an integer (e.g., -100123456789)
ADMIN_CHAT_ID = -1003690232509 

# ==========================================

async def send_as_user(command):
    try:
        # Connect using the saved session (Logs in as YOU)
        async with TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH) as client:
            await client.send_message(ADMIN_CHAT_ID, command)
    except Exception as e:
        print(f"Telethon Error: {e}")

@app.route('/spam', methods=['GET'])
def spam_handler():
    # 1. Get UID from Link
    uid = request.args.get('uid')
    
    if not uid:
        return jsonify({
            "status": "Error",
            "message": "Please provide ?uid=",
            "owner": "@spidey_abd",
            "Join": "https://t.me/TubeGroww"
        }), 400

    # 2. Send Command to Telegram (AS USER)
    command = f"/s7 {uid}"
    
    # Run the async Telethon function within Flask
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_as_user(command))
        loop.close()
    except Exception as e:
        # Fail silently regarding the Telegram part, as requested, 
        # but print to Vercel logs for debugging
        print(f"Execution Error: {e}")

    # 3. Return Success JSON
    response = {
        "status": "Success",
        "message": "Moderator Badge Join Request Sent Successfully",
        "target": uid,
        "owner": "@spidey_abd",
        "Join": "https://t.me/TubeGroww"
    }
    return jsonify(response)

# For Local Testing
if __name__ == '__main__':
    app.run(debug=True)
