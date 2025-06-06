import re
import imaplib
import email
import pyotp
import requests
import urllib.parse
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

# ✅ Email accounts (edit here)
EMAIL_ACCOUNTS = {
    "yandex.com": [
        {"email": "cambo.ads@yandex.com", "password": "jgexgxxedmqheewx", "imap": "imap.yandex.com"},
        {"email": "n4.ra@yandex.com", "password": "xiipvzmwomunjvnl", "imap": "imap.yandex.com"},
    ]
}

user_aliases = {}
user_secrets = {}
user_context = {}

def get_domain(email):
    return email.split('@')[-1].lower()

def get_reply_keyboard():
    return ReplyKeyboardMarkup(
        [["📤 QR Secret", "📲 OTP", "📩 Mail OTP"]],
        resize_keyboard=True
    )

def detect_service(label):
    l = label.lower()
    if 'facebook' in l: return "Facebook 2FA"
    if 'yandex' in l: return "Yandex 2FA"
    return "Other 2FA"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Welcome! \n\n"
        "• ផ្ញើ alias email (ឧ. cambo.ads+123456@yandex.com)\n"
        "• ឬផ្ញើ QR / Secret Key (manual)\n",
        reply_markup=get_reply_keyboard()
    )

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()

    if "+" in text and text.endswith("@yandex.com"):
        user_aliases[user_id] = text
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
        alias = user_aliases.get(user_id)
        if not alias:
            await update.message.reply_text("❌ សូមផ្ញើ alias email មុនសិន!")
            return
        domain = get_domain(alias)
        result = await fetch_mail_otp(alias, domain, debug_update=update)
        if result:
            await update.message.reply_text(f"✉️ Mail OTP: `{result}`", parse_mode="Markdown")
        else:
            await update.message.reply_text("❌ មិនមាន OTP សម្រាប់ alias នេះ។ (បានបង្ហាញសារ Debug ខាងក្រោម)")

    elif text == "📤 QR Secret":
        secret = user_secrets.get(user_id)
        context_info = user_context.get(user_id, {})
        if secret:
            await update.message.reply_text(
                f"✅ {context_info.get('service','2FA')} for *{context_info.get('label','Unknown')}*\n🔐 Secret: `{secret}`",
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
                service = detect_service(label)
                user_secrets[user_id] = secret
                user_context[user_id] = {"label": label, "service": service}
                await update.message.reply_text(
                    f"✅ {service} for *{label}*\n🔐 Secret: `{secret}`",
                    parse_mode="Markdown",
                    reply_markup=get_reply_keyboard()
                )
            else:
                await update.message.reply_text("❌ No valid Secret in QR.")
        else:
            await update.message.reply_text("❌ QR unreadable.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error reading QR: {str(e)}")

def extract_otp(text):
    match = re.search(r'\b(\d{3}[-\s]?\d{3,5})\b', text)
    return match.group(1).replace('-', '').replace(' ', '') if match else None

async def fetch_mail_otp(alias_email, domain, debug_update=None):
    accounts = EMAIL_ACCOUNTS.get(domain)
    if not accounts:
        return None
    for acc in accounts:
        try:
            mail = imaplib.IMAP4_SSL(acc['imap'])
            mail.login(acc['email'], acc['password'])
            result, folders = mail.list()
            if result != 'OK':
                mail.logout()
                continue
            for f in folders:
                folder_name = f.decode().split('"/')[-1].strip('"')
                if any(k in folder_name.lower() for k in ["inbox", "social", "facebook", "network", "notification"]):
                    mail.select(f'"{folder_name}"')
                    result, data = mail.search(None, "ALL")
                    ids = data[0].split()
                    for num in reversed(ids[-25:]):
                        result, msg_data = mail.fetch(num, "(RFC822)")
                        raw_email = msg_data[0][1]
                        msg = email.message_from_bytes(raw_email)

                        headers = [(h, msg.get(h, "")) for h in ["To", "Delivered-To", "Subject"]]
                        header_str = " ".join([h[1].lower().replace(" ", "") for h in headers if h[1]])
                        alias_check = alias_email.lower().replace(" ", "")
                        base_check = alias_check.split("+")[0] + "@" + alias_check.split("@")[-1]

                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    body = part.get_payload(decode=True).decode(errors="ignore")
                                    break
                        else:
                            body = msg.get_payload(decode=True).decode(errors="ignore")

                        if alias_check not in header_str and base_check not in header_str and alias_check not in body.lower() and base_check not in body.lower():
                            continue

                        otp = extract_otp(msg.get("Subject", "")) or extract_otp(body)
                        if otp:
                            mail.logout()
                            return otp

                        # ✅ Always show debug info even if no OTP
                        if debug_update:
                            debug_msg = "\n".join([f"{h[0]}: {h[1]}" for h in headers])
                            preview = (body[:300] + "...") if len(body) > 300 else body
                            await debug_update.message.reply_text(f"🔎 [DEBUG] No OTP matched.\n\n📨 Headers:\n{debug_msg}\n\n📄 Body:\n{preview}")
            mail.logout()
        except Exception:
            continue
    return None

# ✅ Run Bot
BOT_TOKEN = "7845423216:AAHE0QIJy9nJ4jhz-xcQURUCQEvnIAgjEdE"
app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
app.add_handler(MessageHandler(filters.PHOTO, handle_photo))

print("🤖 Bot is running with enhanced alias, fallback & debug preview...")
app.run_polling()
