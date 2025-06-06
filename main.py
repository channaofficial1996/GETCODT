import re
import imaplib
import email
import pyotp
import requests
import urllib.parse
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

# --------- EDIT EMAIL ACCOUNTS HERE ---------
EMAIL_ACCOUNTS = {
    "yandex.com": [
        {"email": "cambo.ads@yandex.com", "password": "jgexgxxedmqheewx", "imap": "imap.yandex.com"},
        {"email": "n4.ra@yandex.com", "password": "xiipvzmwomunjvnl", "imap": "imap.yandex.com"},
    ],
    "gmail.com": [
        {"email": "your.email@gmail.com", "password": "your_app_pwd", "imap": "imap.gmail.com"},
    ],
    "zoho.com": [
        {"email": "cambo.ads@zohomail.com", "password": "zoho_app_1", "imap": "imap.zoho.com"},
        {"email": "cambo.ads2@zohomail.com", "password": "zoho_app_2", "imap": "imap.zoho.com"},
    ],
    "hotmail.com": [
        {"email": "your.hotmail@hotmail.com", "password": "your_hotmail_pwd", "imap": "imap-mail.outlook.com"},
    ],
    "outlook.com": [
        {"email": "your.outlook@outlook.com", "password": "your_outlook_pwd", "imap": "imap-mail.outlook.com"},
    ],
}

user_aliases = {}
user_secrets = {}
user_context = {}

def get_domain(email):
    return email.split('@')[-1].lower()

def get_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📤 QR Secret", callback_data="show_secret"),
         InlineKeyboardButton("📲 OTP", callback_data="show_otp")],
        [InlineKeyboardButton("📩 Mail OTP", callback_data="mail_otp")]
    ])

def detect_service(label):
    l = label.lower()
    if 'facebook' in l: return "Facebook 2FA"
    if 'gmail' in l or 'google' in l: return "Gmail 2FA"
    if 'yandex' in l: return "Yandex 2FA"
    if 'zoho' in l: return "Zoho 2FA"
    return "Other 2FA"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Welcome! \n\n"
        "• ផ្ញើ alias email (ឧ. cambo.ads+123456@yandex.com)\n"
        "• ឬផ្ញើ QR / Secret Key (manual)\n",
        reply_markup=ReplyKeyboardMarkup([["Get OTP"]], resize_keyboard=True)
    )

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()

    if "+" in text and any(text.endswith(f"@{d}") for d in EMAIL_ACCOUNTS):
        user_aliases[user_id] = text
        await update.message.reply_text(f"✅ Alias `{text}` ត្រូវបានកំណត់។", parse_mode="Markdown", reply_markup=get_keyboard())
        return

    elif re.fullmatch(r'[A-Z2-7]{16,}', text.upper()):
        secret = text.upper()
        user_secrets[user_id] = secret
        user_context[user_id] = {"label": "Manual Entry", "service": "Manual 2FA"}
        await update.message.reply_text("✅ Secret Key saved.", reply_markup=get_keyboard())
        return

    elif text.lower() == "get otp":
        alias = user_aliases.get(user_id)
        if not alias:
            await update.message.reply_text("❌ សូមផ្ញើ alias email មុនសិន!")
            return
        domain = get_domain(alias)
        result = await fetch_mail_otp(alias, domain, debug_update=update)
        if result:
            await update.message.reply_text(f"🔐 OTP សម្រាប់ `{alias}` គឺ: `{result}`", parse_mode="Markdown")
        else:
            await update.message.reply_text("❌ មិនមាន OTP សម្រាប់ alias នេះ")
        return

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
                    f"✅ {service} for *{label}*\n🔐 Secret: `{secret}`", parse_mode="Markdown", reply_markup=get_keyboard())
            else:
                await update.message.reply_text("❌ No valid Secret in QR.")
        else:
            await update.message.reply_text("❌ QR unreadable.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error reading QR: {str(e)}")

async def handle_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    user_id = q.from_user.id

    if q.data == "show_secret":
        secret = user_secrets.get(user_id)
        c = user_context.get(user_id, {})
        if secret:
            await q.message.reply_text(
                f"✅ {c.get('service','2FA')} for *{c.get('label','Unknown')}*\n🔐 Secret: `{secret}`", parse_mode="Markdown")
        else:
            await q.message.reply_text("⚠️ No Secret found.")

    elif q.data == "show_otp":
        secret = user_secrets.get(user_id)
        if secret:
            otp = pyotp.TOTP(secret).now()
            await q.message.reply_text(f"🔐 OTP: `{otp}`", parse_mode="Markdown")
        else:
            await q.message.reply_text("⚠️ No Secret found.")

    elif q.data == "mail_otp":
        alias = user_aliases.get(user_id)
        if not alias:
            await q.message.reply_text("⚠️ Alias email not set.")
            return
        domain = get_domain(alias)
        result = await fetch_mail_otp(alias, domain, debug_update=q)
        if result:
            await q.message.reply_text(f"✉️ Mail OTP: `{result}`", parse_mode="Markdown")
        else:
            await q.message.reply_text("❌ No OTP found for alias.")

# --------- OTP Extraction Logic ---------
def extract_otp(text):
    # Accept patterns like 123456 or 123-456
    match = re.search(r'\b(\d{3}[-\s]?\d{3,5})\b', text)
    return match.group(1).replace('-', '').replace(' ', '') if match else None

# --------- Mail OTP Core ---------
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
                if any(k in folder_name.lower() for k in ["inbox", "social", "facebook", "network"]):
                    try:
                        mail.select(f'"{folder_name}"')
                        result, data = mail.search(None, "ALL")
                        ids = data[0].split()
                        latest_ids = ids[-20:] if len(ids) > 20 else ids
                        for num in reversed(latest_ids):
                            result, msg_data = mail.fetch(num, "(RFC822)")
                            raw_email = msg_data[0][1]
                            msg = email.message_from_bytes(raw_email)
                            headers = [(h, msg.get(h, "")) for h in ["To", "Delivered-To", "Envelope-To", "X-Yandex-Forward", "Cc", "Bcc", "Subject"]]
                            header_str = " ".join([h[1].lower().replace(" ", "").strip() for h in headers if h[1]])
                            alias_check = alias_email.lower().replace(" ", "").strip()

                            body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    if part.get_content_type() == "text/plain":
                                        body = part.get_payload(decode=True).decode(errors="ignore")
                                        break
                            else:
                                body = msg.get_payload(decode=True).decode(errors="ignore")

                            # Force debug preview every time for clarity
                            otp = extract_otp(msg.get("Subject", "")) or extract_otp(body)
                            if otp:
                                mail.logout()
                                return otp

                            if debug_update:
                                debug_msg = "\n".join([f"{h[0]}: {h[1]}" for h in headers])
                                preview = (body[:300] + "...") if len(body) > 300 else body
                                target = debug_update.message if hasattr(debug_update, "message") else debug_update
                                await target.reply_text(f"🔎 [DEBUG] No OTP found.\n\n{debug_msg}\n\n📝 Body:\n{preview}")
                    except Exception:
                        continue
            mail.logout()
        except Exception:
            continue
    return None

# --------- BOT ENTRY POINT ---------
BOT_TOKEN = "7845423216:AAHE0QIJy9nJ4jhz-xcQURUCQEvnIAgjEdE"
app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
app.add_handler(CallbackQueryHandler(handle_button))

print("🤖 Bot is running with QR/Secret + Alias Email OTP (Yandex, Zoho, Gmail, Hotmail, Outlook) Support...")
app.run_polling()
