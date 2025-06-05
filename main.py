# ✅ Telegram 2FA Bot with Alias Email OTP + QR Secret Key

import re
import imaplib
import email
import pyotp
import requests
import urllib.parse
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

# ✅ Multiple email accounts per domain
EMAIL_ACCOUNTS = {
    "gmail.com": [
        {"email": "your.email@gmail.com", "password": "your_app_pwd", "imap": "imap.gmail.com"},
    ],
    "yandex.com": [
        {"email": "your.yandex@yandex.com", "password": "your_yandex_pwd", "imap": "imap.yandex.com"},
    ],
    "zoho.com": [
        {"email": "your.zoho@zohomail.com", "password": "your_zoho_pwd", "imap": "imap.zoho.com"},
    ],
    "hotmail.com": [
        {"email": "your.hotmail@hotmail.com", "password": "your_hotmail_pwd", "imap": "imap-mail.outlook.com"},
    ],
}

user_aliases = {}
user_secrets = {}

def get_domain(email):
    return email.split('@')[-1].lower()

def get_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📤 QR Secret", callback_data="show_secret"),
            InlineKeyboardButton("📲 OTP", callback_data="show_otp")
        ],
        [
            InlineKeyboardButton("📩 Mail OTP", callback_data="mail_otp")
        ]
    ])

def detect_service(label):
    l = label.lower()
    if 'facebook' in l: return "Facebook 2FA"
    if 'gmail' in l or 'google' in l: return "Gmail 2FA"
    if 'yandex' in l: return "Yandex 2FA"
    if 'zoho' in l: return "Zoho 2FA"
    return "Other 2FA"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Welcome! Send your alias email (e.g. cambo.ads+123@gmail.com) or QR/Secret Key.")

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if '@' in text:
        user_aliases[update.effective_user.id] = text
        await update.message.reply_text("✅ Alias saved.", reply_markup=get_keyboard())
    elif re.fullmatch(r'[A-Z2-7]{16,}', text.upper()):
        user_secrets[update.effective_user.id] = text.upper()
        context.user_data['label'] = "Manual Entry"
        context.user_data['service'] = "Manual 2FA"
        await update.message.reply_text("✅ Secret Key saved.", reply_markup=get_keyboard())
    else:
        await update.message.reply_text("⚠️ Invalid input.")

async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
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
                user_secrets[update.effective_user.id] = secret
                context.user_data['label'] = label
                context.user_data['service'] = service
                await update.message.reply_text(f"✅ {service} for *{label}*
🔐 Secret: `{secret}`", parse_mode="Markdown", reply_markup=get_keyboard())
            else:
                await update.message.reply_text("❌ No valid Secret in QR.")
        else:
            await update.message.reply_text("❌ QR unreadable.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error reading QR: {str(e)}")

async def handle_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = q.from_user.id
    if q.data == "show_secret":
        secret = user_secrets.get(uid)
        if secret:
            label = context.user_data.get("label", "Unknown")
            service = context.user_data.get("service", "2FA")
            await q.message.reply_text(f"✅ {service} for *{label}*
🔐 Secret: `{secret}`", parse_mode="Markdown")
        else:
            await q.message.reply_text("⚠️ No Secret found.")
    elif q.data == "show_otp":
        secret = user_secrets.get(uid)
        if secret:
            otp = pyotp.TOTP(secret).now()
            await q.message.reply_text(f"🔐 OTP: `{otp}`", parse_mode="Markdown")
        else:
            await q.message.reply_text("⚠️ No Secret found.")
    elif q.data == "mail_otp":
        alias = user_aliases.get(uid)
        if not alias:
            await q.message.reply_text("⚠️ Alias email not set.")
            return
        domain = get_domain(alias)
        accounts = EMAIL_ACCOUNTS.get(domain)
        if not accounts:
            await q.message.reply_text("❌ Domain not supported.")
            return
        for acc in accounts:
            try:
                mail = imaplib.IMAP4_SSL(acc['imap'])
                mail.login(acc['email'], acc['password'])
                mail.select("inbox")
                result, data = mail.search(None, f'TO "{alias}"')
                ids = data[0].split()
                if not ids: continue
                result, msg_data = mail.fetch(ids[-1], "(RFC822)")
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode()
                            break
                else:
                    body = msg.get_payload(decode=True).decode()
                otp_match = re.search(r'\b(\d{6})\b', body)
                if otp_match:
                    otp = otp_match.group(1)
                    await q.message.reply_text(f"✉️ Mail OTP: `{otp}`", parse_mode="Markdown")
                    return
            except:
                continue
        await q.message.reply_text("❌ No OTP found for alias.")

# ✅ Replace with your token
BOT_TOKEN = "8042421392:AAHMz2z5EJxenhDryF3rAVmMwWN58BbSljs"
app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
app.add_handler(CallbackQueryHandler(handle_button))
app.run_polling()
