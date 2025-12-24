from pyrogram import Client, filters
import subprocess
import os
import signal
import threading
import time

# ----- तुम्हारी Telegram जानकारी -----
API_ID = 33880685
API_HASH = "84c92fbf29e78cc834743e218a55ec8d"
BOT_TOKEN = "8286890369:AAFGM0IEUuEwFMmt88o9Su0u2yKzCAzNxog"
# -------------------------------------

BOT_FILE = "app.py"  # ← यहाँ अपनी TCP Bot फाइल का नाम डालो

app = Client("tcp_host_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

process = None
monitor_stop = threading.Event()


# ⚙️ अगर app.py बंद हो जाए तो दोबारा चालू करने वाला सिस्टम
def monitor_process(chat_id):
    global process
    while not monitor_stop.is_set():
        if process:
            ret = process.poll()
            if ret is not None:
                app.send_message(chat_id, "⚠️ app.py बंद हो गया है, 5 सेकंड में दोबारा चालू किया जाएगा...")
                time.sleep(5)
                restart_bot(chat_id)
        time.sleep(2)


def restart_bot(chat_id):
    global process
    try:
        python_exec = os.getenv("PYTHON", "python")
        process = subprocess.Popen([python_exec, BOT_FILE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        app.send_message(chat_id, "🔁 app.py दोबारा चालू कर दिया गया ✅")
    except Exception as e:
        app.send_message(chat_id, f"❌ Restart Error: {e}")


# /start command
@app.on_message(filters.command("start"))
def start(_, msg):
    msg.reply_text(
        "👋 नमस्ते!\n\n"
        "मैं तुम्हारा *Free Fire TCP Hosting Bot* हूँ।\n\n"
        "Commands:\n"
        "🚀 /run - app.py चालू करो\n"
        "🛑 /stop - app.py बंद करो\n"
        "📊 /status - स्थिति देखो\n"
        "🔴 /shutdown - Hostbot बंद करो",
    )


# /run command
@app.on_message(filters.command("run"))
def run_bot(_, msg):
    global process, monitor_thread, monitor_stop
    chat_id = msg.chat.id

    if process is None:
        msg.reply_text("🚀 app.py को चालू किया जा रहा है...")
        try:
            python_exec = os.getenv("PYTHON", "python")
            process = subprocess.Popen([python_exec, BOT_FILE])
            msg.reply_text("✅ app.py सफलतापूर्वक चालू हो गया!")
        except Exception as e:
            msg.reply_text(f"❌ Error: {e}")
            return

        monitor_stop.clear()
        monitor_thread = threading.Thread(target=monitor_process, args=(chat_id,), daemon=True)
        monitor_thread.start()
    else:
        msg.reply_text("⚙️ app.py पहले से चालू है!")


# /stop command
@app.on_message(filters.command("stop"))
def stop_bot(_, msg):
    global process, monitor_stop
    if process:
        msg.reply_text("🛑 app.py को बंद किया जा रहा है...")
        try:
            process.terminate()
            process = None
            monitor_stop.set()
            msg.reply_text("✅ app.py बंद कर दिया गया!")
        except Exception as e:
            msg.reply_text(f"⚠️ Stop Error: {e}")
    else:
        msg.reply_text("❌ app.py अभी चालू नहीं है।")


# /status command
@app.on_message(filters.command("status"))
def status(_, msg):
    if process:
        msg.reply_text("✅ app.py अभी चल रहा है।")
    else:
        msg.reply_text("❌ app.py बंद है।")


# /shutdown command → Hostbot खुद को बंद करेगा
@app.on_message(filters.command("shutdown"))
def shutdown(_, msg):
    msg.reply_text("🔴 Hostbot बंद किया जा रहा है...")
    os.kill(os.getpid(), signal.SIGTERM)


if __name__ == "__main__":
    print("✅ Hostbot चालू हो गया! Telegram में /start भेजो।")
    app.run()
