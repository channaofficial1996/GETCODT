import re
import imaplib
import email
import pyotp
import requests
import urllib.parse
import asyncio
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

EMAIL_ACCOUNTS = {
    "yandex.com": [
        {"email": "cambo.ads@yandex.com", "password": "jgexgxxedmqheewx", "imap": "imap.yandex.com"},
        {"email": "n4.ra@yandex.com", "password": "xiipvzmwomunjvnl", "imap": "imap.yandex.com"},
    ],
    "zoho.com": [
        {"email": "cambo.ads@zohomail.com", "password": "zoho_app_1", "imap": "imap.zoho.com"},
        {"email": "cambo.ads2@zohomail.com", "password": "zoho_app_2", "imap": "imap.zoho.com"},
    ],
}

user_aliases = {}
user_secrets = {}
user_context = {}
user_alias_set_time = {}
user_last_otp = {}

def get_reply_keyboard():
    return ReplyKeyboardMarkup(
        [["📤 QR Secret Key", "📲 2FA OTP", "📩 Mail OTP"]],
        resize_keyboard=True
    )

def detect_service_from_secret(secret):
    if secret.startswith("JBSW"): return "Google 2FA"
    if secret.startswith("ZT"): return "Zoho 2FA"
    if secret.startswith("MFRG") or secret.startswith("MZXW"): return "Facebook 2FA"
    if secret.startswith("QTMT") or "FB" in secret: return "Meta/Facebook"
    if "TELE" in secret or secret.startswith("TD"): return "Telegram 2FA"
    if secret.startswith("GAXG") or "GMAIL" in secret: return "Gmail 2FA"
    return "Manual 2FA"

def detect_service(label):
    l = label.lower()
    if 'facebook' in l: return "Facebook 2FA"
    if 'yandex' in l: return "Yandex 2FA"
    if 'zoho' in l: return "Zoho 2FA"
    return "Other 2FA"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Welcome!\n\n• ផ្ញើ alias email (ឧ. cambo.ads+123456@yandex.com)\n• ឬផ្ញើ QR / Secret Key (manual)",
        reply_markup=get_reply_keyboard()
    )

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

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()

    if "+" in text and ("@yandex.com" in text or "@zohomail.com" in text):
        text = text.lower()
        old_alias = user_aliases.get(user_id, "")
        if old_alias == text:
            await update.message.reply_text(f"✅ Alias `{text}` ត្រូវបានកំណត់រួចម្តងហើយ។", parse_mode="Markdown", reply_markup=get_reply_keyboard())
            return
        user_aliases[user_id] = text
        user_alias_set_time[user_id] = context.application.loop.time()
        await update.message.reply_text(f"✅ Alias `{text}` ត្រូវបានកំណត់។\nសូមរងចាំ 10 វិនាទី មុនចុច Mail OTP", parse_mode="Markdown", reply_markup=get_reply_keyboard())
        return

    elif re.fullmatch(r'[A-Z2-7]{16,}', text.upper()):
        secret = text.upper()
        user_secrets[user_id] = secret
        source = detect_service_from_secret(secret)
        user_context[user_id] = {"label": source, "service": source}
        await update.message.reply_text(f"✅ Secret Key saved for *{source}*", parse_mode="Markdown", reply_markup=get_reply_keyboard())
        return

    elif text == "📲 2FA OTP":
        secret = user_secrets.get(user_id)
        c = user_context.get(user_id, {})
        if secret:
            otp = pyotp.TOTP(secret).now()
            await update.message.reply_text(f"📲 {c.get('service','2FA')} OTP:\n🔐 `{otp}`", parse_mode="Markdown")
        else:
            await update.message.reply_text("⚠️ No Secret Key saved.")

    elif text == "📩 Mail OTP":
        alias = user_aliases.get(user_id)
        if not alias:
            await update.message.reply_text("❌ សូមផ្ញើ alias email មុនសិន!")
            return

        now = context.application.loop.time()
        if user_id in user_alias_set_time and now - user_alias_set_time[user_id] < 10:
            wait_sec = int(10 - (now - user_alias_set_time[user_id]))
            await update.message.reply_text(f"⏳ សូមរងចាំ {wait_sec} វិនាទី មុនចុច Mail OTP")
            return

        domain = alias.split("@")[1].lower()
        result = await fetch_mail_otp(alias, domain, user_id, debug_update=update)
        if result:
            await update.message.reply_text(result, parse_mode="Markdown")
        else:
            await update.message.reply_text("❌ មិនមាន OTP សម្រាប់ alias នេះ។ (ប្រាកដថាសារមាន Debug ចង់ស្រាវជ្រាវ)")

    elif text == "📤 QR Secret Key":
        secret = user_secrets.get(user_id)
        c = user_context.get(user_id, {})
        if secret:
            await update.message.reply_text(
                f"✅ {c.get('service','2FA')} for *{c.get('label','Unknown')}*\n🔐 Secret: `{secret}`",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text("⚠️ No Secret Key saved.")

    else:
        await update.message.reply_text("⚠️ Input មិនត្រឹមត្រូវ។")

def extract_otp(text):
    return re.search(r'\b\d{4,8}\b', text).group(0) if re.search(r'\b\d{4,8}\b', text) else None

async def fetch_mail_otp(alias_email, domain, user_id, debug_update=None):
    accounts = EMAIL_ACCOUNTS.get(domain)
    if not accounts:
        return None

    for acc in accounts:
        try:
            mail = imaplib.IMAP4_SSL(acc["imap"])
            mail.login(acc["email"], acc["password"])
            mail.select("inbox")

            result, data = mail.search(None, "ALL")
            mail_ids = data[0].split()[-25:]

            for num in reversed(mail_ids):
                result, msg_data = mail.fetch(num, "(RFC822)")
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                headers = [(h, msg.get(h, "")) for h in ["From", "To", "Delivered-To", "Subject"]]
                header_str = " ".join([h[1].lower().replace(" ", "") for h in headers if h[1]])
                base_check = alias_email.lower().replace(" ", "").split("+")[0] + "@" + alias_email.lower().split("@")[1]
                if alias_email.lower().replace(" ", "") not in header_str and base_check not in header_str:
                    continue

                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode(errors="ignore")
                            break
                else:
                    body = msg.get_payload(decode=True).decode(errors="ignore")

                otp = extract_otp(msg.get("Subject", "")) or extract_otp(body)
                if otp:
                    sender = msg.get("From", "Unknown")
                    reason = "ប្រតិបត្តិការសុវត្ថិភាព" if "login" in body.lower() else "សំណើប្តូរពាក្យសម្ងាត់" if "change" in body.lower() else "សំណើផ្ទៀងផ្ទាត់"
                    key = f"{user_id}:{otp}:{sender}"
                    if user_last_otp.get(user_id) == key:
                        continue
                    user_last_otp[user_id] = key
                    return f"📩 OTP: `{otp}`\nFrom: `{sender}`\nប្រភព: {reason}"

        except Exception:
            continue
    return None

BOT_TOKEN = "7845423216:AAHE0QIJy9nJ4jhz-xcQURUCQEvnIAgjEdE"
app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
print("🤖 Bot is running...")
app.run_polling()
