import re
import imaplib
import email
import pyotp
import requests
import urllib.parse
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

# ✅ Email Account & Passwords
YANDEX_ACCOUNTS = {
    "cambo.ads@yandex.com": "jgexgxxedmqheewx",
    "n4.ra@yandex.com": "xiipvzmwomunjvnl",
}

ZOHO_ACCOUNTS = {
    "cambo.ads@zohomail.com": "zoho_app_1",
    "cambo.ads2@zohomail.com": "zoho_app_2",
}

# ✅ User Data Maps
user_alias_map = {}
user_secrets = {}
user_context = {}

def get_reply_keyboard():
    return ReplyKeyboardMarkup(
        [["📤 QR Secret", "📲 OTP", "📩 Mail OTP"]],
        resize_keyboard=True
    )

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        '''👋 Welcome!

• ផ្ញើ alias email (ឧ. cambo.ads+123456@yandex.com ឬ cambo.ads+123@zohomail.com)
• ឬផ្ញើ QR / Secret Key (manual)
''',
        reply_markup=get_reply_keyboard()
    )

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()

    if "+" in text and ("@yandex.com" in text or "@zohomail.com" in text):
        user_alias_map[user_id] = text
        await update.message.reply_text(f"✅ Alias `{text}` ត្រូវបានកំណត់។", parse_mode="Markdown", reply_markup=get_reply_keyboard())
        return

    elif re.fullmatch(r'[A-Z2-7]{16,}', text.upper()):
        secret = text.upper()
        user_secrets[user_id] = secret
        user_context[user_id] = {"label": "Manual Entry", "service": "Manual 2FA"}
        await update.message.reply_text("✅ Secret Key saved.", reply_markup=get_reply_keyboard())
        return

    elif text == "📲 OTP":
        secret = user_secrets.get(user_id)
        if secret:
            otp = pyotp.TOTP(secret).now()
            await update.message.reply_text(f"🔐 OTP: `{otp}`", parse_mode="Markdown")
        else:
            await update.message.reply_text("⚠️ No Secret Key saved.")

    elif text == "📩 Mail OTP":
        alias = user_alias_map.get(user_id)
        if not alias:
            await update.message.reply_text("❌ សូមផ្ញើ alias email មុនសិន!")
            return

        base_email = alias.split("+")[0] + alias[alias.index("@"):]
        provider = "yandex" if "@yandex.com" in alias else "zoho"
        account_list = YANDEX_ACCOUNTS if provider == "yandex" else ZOHO_ACCOUNTS

        if base_email not in account_list:
            await update.message.reply_text(f"❌ Email {base_email} មិនបានគាំទ្រ!")
            return

        email_pass = account_list[base_email]
        otp = fetch_otp(alias_email=alias, login_email=base_email, password=email_pass, provider=provider)

        if otp:
            await update.message.reply_text(f"🔐 OTP សម្រាប់ `{alias}` គឺ: `{otp}`", parse_mode="Markdown")
        else:
            await update.message.reply_text("❌ មិនមាន OTP សម្រាប់ alias នេះ")

    elif text == "📤 QR Secret":
        secret = user_secrets.get(user_id)
        c = user_context.get(user_id, {})
        if secret:
            await update.message.reply_text(
                f"✅ {c.get('service','2FA')} for *{c.get('label','Unknown')}*
🔐 Secret: `{secret}`",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text("⚠️ No Secret Key saved.")

    else:
        await update.message.reply_text("⚠️ Input មិនត្រឹមត្រូវ។")

async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    file = await update.message.photo[-1].get_file()
    file_path = "qr.jpg"
    await file.download_to_drive(file_path)
    with open(file_path, "rb") as f:
        r = requests.post("https://api.qrserver.com/v1/read-qr-code/", files={"file": f})
    try:
        data = r.json()[0]["symbol"][0]["data"]
        if data:
            m = re.search(r'secret=([A-Z2-7]{16,})', data, re.IGNORECASE)
            if m:
                secret = m.group(1).upper()
                label_match = re.search(r'otpauth://totp/([^?]+)', data)
                label = urllib.parse.unquote(label_match.group(1).split(':')[-1]) if label_match else "Unknown"
                user_secrets[user_id] = secret
                user_context[user_id] = {"label": label, "service": detect_service(label)}
                await update.message.reply_text(
                    f"✅ {detect_service(label)} for *{label}*
🔐 Secret: `{secret}`",
                    parse_mode="Markdown",
                    reply_markup=get_reply_keyboard()
                )
            else:
                await update.message.reply_text("❌ No valid Secret in QR.")
        else:
            await update.message.reply_text("❌ QR unreadable.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error reading QR: {str(e)}")

def detect_service(label):
    l = label.lower()
    if 'facebook' in l: return "Facebook 2FA"
    if 'gmail' in l or 'google' in l: return "Gmail 2FA"
    if 'yandex' in l: return "Yandex 2FA"
    if 'zoho' in l: return "Zoho 2FA"
    return "Other 2FA"

def fetch_otp(alias_email, login_email, password, provider="yandex"):
    try:
        imap_host = "imap.yandex.com" if provider == "yandex" else "imap.zoho.com"
        mail = imaplib.IMAP4_SSL(imap_host)
        mail.login(login_email, password)
        mail.select("inbox")

        result, data = mail.search(None, "ALL")
        mail_ids = data[0].split()[-20:]

        for num in reversed(mail_ids):
            result, msg_data = mail.fetch(num, "(RFC822)")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            all_headers = [
                msg.get("To", ""), msg.get("Delivered-To", ""), msg.get("X-Envelope-To", ""),
                msg.get("X-Yandex-Forward", ""), msg.get("Cc", ""), msg.get("Bcc", "")
            ]
            header_str = " ".join([h.lower() for h in all_headers if h])

            if alias_email.lower() not in header_str:
                continue

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode(errors='ignore')
                        break
            else:
                body = msg.get_payload(decode=True).decode(errors='ignore')

            subject = msg.get("Subject", "")
            otp = extract_otp(subject) or extract_otp(body)
            if otp:
                return otp
        return None
    except Exception as e:
        print("Error:", e)
        return None

def extract_otp(text):
    match = re.search(r'\b\d{4,8}\b', text)
    return match.group(0) if match else None

# ✅ Run the Bot
BOT_TOKEN = "7845423216:AAHE0QIJy9nJ4jhz-xcQURUCQEvnIAgjEdE"
app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
app.add_handler(MessageHandler(filters.PHOTO, handle_photo))

print("🤖 Final bot is running with full OTP logic, UI buttons & alias fallback...")
app.run_polling()
