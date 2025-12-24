from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)

# ==========================================
# ⚡ CONFIGURATION (FILL THIS!) ⚡
# ==========================================
# 1. Your Bot Token from BotFather
TG_BOT_TOKEN = "8292738024:AAHjghTZvUZmLKV091qGe3A5yr_OdFIYv8I" 

# 2. Your Personal Telegram User ID (So the bot sends the command to the chat where Termux is listening)
ADMIN_CHAT_ID = "8570505434"
# ==========================================

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

    # 2. Send Command to Telegram
    # This sends "/s7 <uid>" to your Telegram Chat.
    # Your Termux Bot (which is polling) will read this and execute the spam.
    try:
        command = f"/s7 {uid}"
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": ADMIN_CHAT_ID,
            "text": command
        }
        requests.post(url, json=data)
    except:
        pass # Fail silently, user still gets success message

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
