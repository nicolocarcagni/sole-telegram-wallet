import logging
import json
import os
import hashlib
import ecdsa
import requests
import struct
import qrcode
from io import BytesIO
from decimal import Decimal
from decimal import Decimal
from datetime import datetime

# Image Processing
from PIL import Image
from pyzbar.pyzbar import decode as qr_decode

# Environment & Crypto
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# Telegram
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters
)

# --- CONFIGURATION (ENV) ---
load_dotenv() 

TOKEN = os.getenv("TELEGRAM_TOKEN")
NODE_URL = os.getenv("NODE_API_URL")
SECRET_KEY = os.getenv("BOT_SECRET_KEY")

USERS_FILE = "bot_users.json"
COIN = 100_000_000
VERSION = b'\x00'

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Check Configuration
if not TOKEN or not SECRET_KEY or not NODE_URL:
    logger.error("❌ MISSING CONFIGURATION! Please check .env file.")
    exit(1)

cipher_suite = Fernet(SECRET_KEY.encode() if isinstance(SECRET_KEY, str) else SECRET_KEY)

# --- HELPER: CLEAN CHAT PROTOCOL ---
async def safe_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Deletes the last bot message to ensure clean chat history."""
    last_id = context.user_data.get('last_msg_id')
    chat_id = update.effective_chat.id
    
    if last_id:
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=last_id)
        except Exception as e:
            pass # Message likely already deleted or too old
    
    # Also delete the user's triggering message if it was a text command/input
    if update.message:
        try:
            await update.message.delete()
        except:
            pass

async def send_new_screen(update: Update, context: ContextTypes.DEFAULT_TYPE, text=None, photo=None, keyboard=None, parse_mode='HTML'):
    """Deletes previous message and sends a new one, tracking its ID."""
    await safe_delete(update, context)
    
    chat_id = update.effective_chat.id
    markup = InlineKeyboardMarkup(keyboard) if keyboard else None
    
    msg = None
    if photo:
        msg = await context.bot.send_photo(chat_id=chat_id, photo=photo, caption=text, parse_mode=parse_mode, reply_markup=markup)
    else:
        msg = await context.bot.send_message(chat_id=chat_id, text=text, parse_mode=parse_mode, reply_markup=markup)
        
    context.user_data['last_msg_id'] = msg.message_id
    return msg

# --- CRYPTO PRIMITIVES ---
def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def base58_encode(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    encode = ''
    while num > 0:
        num, mod = divmod(num, 58)
        encode = alphabet[mod] + encode
    n_pad = len(data) - len(data.lstrip(b'\x00'))
    return alphabet[0] * n_pad + encode

def base58_check_encode(payload):
    first_sha = hashlib.sha256(payload).digest()
    sec_sha = hashlib.sha256(first_sha).digest()
    checksum = sec_sha[:4]
    return base58_encode(payload + checksum)

def base58_check_decode(s):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = 0
    for char in s:
        num = num * 58 + alphabet.index(char)
    combined = num.to_bytes(25, 'big')
    # strip checksum
    return combined[:-4]

def is_valid_address(address):
    if not address or len(address) < 25 or len(address) > 35:
        return False
    try:
        base58_check_decode(address)
        if not address.startswith('1'):
            return False
        return True
    except:
        return False

# --- SERIALIZATION ---
def serialize_for_hash(inputs, outputs):
    buffer = bytearray()
    for vin in inputs:
        buffer += bytes.fromhex(vin['txid'])
        buffer += struct.pack(">q", vin['vout'])
        pub = vin.get('pubkey', b'')
        if isinstance(pub, str): pub = bytes.fromhex(pub)
        buffer += pub
        sig = vin.get('signature', b'')
        if isinstance(sig, str): sig = bytes.fromhex(sig)
        buffer += sig
    for vout in outputs:
        buffer += struct.pack(">q", vout['value'])
        pkh = vout['pubkeyhash']
        buffer += pkh
    return buffer

def serialize_for_api(inputs, outputs):
    buffer = bytearray()
    buffer += struct.pack(">q", len(inputs))
    for vin in inputs:
        txid = bytes.fromhex(vin['txid'])
        buffer += struct.pack(">q", len(txid)); buffer += txid
        buffer += struct.pack(">q", vin['vout'])
        sig = vin.get('signature', b'')
        buffer += struct.pack(">q", len(sig)); buffer += sig
        pub = vin.get('pubkey', b'')
        buffer += struct.pack(">q", len(pub)); buffer += pub
    buffer += struct.pack(">q", len(outputs))
    for vout in outputs:
        buffer += struct.pack(">q", vout['value'])
        pkh = vout['pubkeyhash']
        buffer += struct.pack(">q", len(pkh)); buffer += pkh
    return buffer

# --- SECURE WALLET CLASS ---
class SecureWallet:
    def __init__(self, private_key_bytes):
        self.sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.NIST256p)
        self.vk = self.sk.verifying_key
        self.pub_key_bytes = self.vk.to_string()

    def get_address(self):
        sha_pub = hashlib.sha256(self.pub_key_bytes).digest()
        ripe_pub = ripemd160(sha_pub)
        payload = VERSION + ripe_pub
        return base58_check_encode(payload)

    def sign(self, message_hash):
        return self.sk.sign_digest(message_hash, sigencode=ecdsa.util.sigencode_string)

# --- USER MANAGER (ENCRYPTED) ---

def load_db():
    if not os.path.exists(USERS_FILE): return {}
    try:
        with open(USERS_FILE, 'r') as f: return json.load(f)
    except: return {}

def save_db(db):
    with open(USERS_FILE, 'w') as f: json.dump(db, f, indent=4)

def auth_user(user_id):
    db = load_db()
    return str(user_id) in db

def create_wallet(user_id):
    sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    sk_bytes = sk.to_string()
    encrypted_key = cipher_suite.encrypt(sk_bytes).decode('utf-8')
    w = SecureWallet(sk_bytes)
    address = w.get_address()
    
    db = load_db()
    db[str(user_id)] = {
        "enc_priv_key": encrypted_key,
        "address": address,
        "created_at": str(datetime.now())
    }
    save_db(db)
    return address

def get_wallet(user_id):
    db = load_db()
    if str(user_id) not in db: return None
    record = db[str(user_id)]
    try:
        sk_bytes = cipher_suite.decrypt(record["enc_priv_key"].encode('utf-8'))
        return SecureWallet(sk_bytes)
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None

# --- BOT HANDLERS ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if auth_user(user_id):
        await dashboard(update, context)
    else:
        text = (
            "🌞 <b>Welcome to SOLE Wallet</b>\n\n"
            "An educational, privacy-focused blockchain implementation written in Go.\n"
            "GitHub: <a href='https://github.com/nicolocarcagni/sole'>nicolocarcagni/sole</a>\n\n"
            "You don't have a wallet yet. Click below to generate one securely."
        )
        keyboard = [[InlineKeyboardButton("✨ Create new wallet", callback_data='create_wallet')]]
        await send_new_screen(update, context, text, keyboard=keyboard)

async def create_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer()
    addr = create_wallet(update.effective_user.id)
    # Redirect to Dashboard
    await dashboard(update, context)

async def dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not auth_user(user_id):
        return await start(update, context)
        
    db = load_db()
    addr = db[str(user_id)]['address']
    
    # Fetch Balance
    bal_text = "Checking..."
    try:
        r = requests.get(f"{NODE_URL}/balance/{addr}", timeout=3)
        if r.status_code == 200:
             bal_float = Decimal(r.json().get('balance', 0)) / Decimal(COIN)
             bal_text = f"{bal_float:.8f} SOLE"
        else:
            bal_text = "Node Error"
    except:
        bal_text = "Node Offline"
        
    text = (
        f"📊 <b>Dashboard</b>\n\n"
        f"💳 <b>Address:</b> <code>{addr}</code>\n"
        f"💰 <b>Balance:</b> {bal_text}"
    )
    
    keyboard = [
        [InlineKeyboardButton("💰 Refresh Balance", callback_data='refresh')],
        [InlineKeyboardButton("📥 Receive", callback_data='receive'), InlineKeyboardButton("📤 Send", callback_data='send_start')]
    ]
    
    # Use clean chat protocol
    await send_new_screen(update, context, text, keyboard=keyboard)

async def refresh_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer("Refreshing...")
    await dashboard(update, context)

async def receive_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer()
    user_id = update.effective_user.id
    db = load_db()
    addr = db[str(user_id)]['address']
    
    # QR
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(addr)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    bio = BytesIO()
    img.save(bio, 'PNG')
    bio.seek(0)
    
    keyboard = [[InlineKeyboardButton("🔙 Back to Dashboard", callback_data='back_dashboard')]]
    
    # Send Photo utilizing Clean Chat Protocol
    await send_new_screen(
        update, context, 
        text=f"<code>{addr}</code>", 
        photo=bio,
        keyboard=keyboard
    )

async def back_dashboard_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer()
    await dashboard(update, context)

# --- SEND WIZARD ---
ASK_ADDR, ASK_AMOUNT, CONFIRM = range(3)

async def send_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer()
    keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data='cancel_wizard')]]
    await send_new_screen(
        update, context,
        text="📤 <b>Send SOLE</b>\n\n1️⃣ Please paste the recipient's address:",
        keyboard=keyboard
    )
    return ASK_ADDR

async def ask_addr(update: Update, context: ContextTypes.DEFAULT_TYPE):
    addr = None
    keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data='cancel_wizard')]]
    
    # CASE A: Photo (QR Code)
    if update.message.photo:
        try:
            # Download photo
            photo_file = await update.message.photo[-1].get_file()
            img_bytes = await photo_file.download_as_bytearray()
            
            # Decode using PIL and pyzbar
            img = Image.open(BytesIO(img_bytes))
            decoded_objects = qr_decode(img)
            
            if not decoded_objects:
               await send_new_screen(
                    update, context,
                    text="⚠️ <b>No QR Code Found</b>\n\nThe image does not appear to contain a readable QR code. Try again or type the address:",
                    keyboard=keyboard
                )
               return ASK_ADDR
            
            # Extract data
            addr = decoded_objects[0].data.decode("utf-8")
            # Remove optional prefix like "sole:"
            if ":" in addr:
                addr = addr.split(":")[-1]
            
        except Exception as e:
            logger.error(f"QR Error: {e}")
            await send_new_screen(
                update, context,
                text="⚠️ <b>Error Processing Image</b>\n\nPlease try again or type manually:",
                keyboard=keyboard
            )
            return ASK_ADDR

    # CASE B: Text
    elif update.message.text:
        addr = update.message.text.strip()
    
    else:
        # Fallback
        await send_new_screen(update, context, text="⚠️ <b>Invalid Input</b>\n\nPlease send text or a QR code image.", keyboard=keyboard)
        return ASK_ADDR
    
    # VALIDATION
    if is_valid_address(addr):
        context.user_data['to_addr'] = addr
        
        # Feedback for QR
        extra_text = ""
        if update.message.photo:
            extra_text = f"✅ <b>QR Code Detected!</b>\nAddress: <code>{addr}</code>\n\n"
            
        await send_new_screen(
            update, context,
            text=f"{extra_text}✅ Address valid.\n\n2️⃣ Enter the amount to send (e.g. 10.5):",
            keyboard=keyboard
        )
        return ASK_AMOUNT
    else:
        # Invalid: Cleanup user input and show error state
        await send_new_screen(
            update, context,
            text=f"⚠️ <b>Invalid Address Format</b>\nInput: <code>{addr[:20]}...</code>\n\nPlease enter a valid Base58 address starting with '1'. Try again:",
            keyboard=keyboard
        )
        return ASK_ADDR

async def ask_amount(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = update.message.text.strip().replace(',', '.')
    keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data='cancel_wizard')]]
    
    try:
        amount_sole = Decimal(txt)
        if amount_sole <= 0: raise ValueError
        context.user_data['amount_sole'] = amount_sole
        context.user_data['amount_photons'] = int(amount_sole * Decimal(COIN))
        
        msg = (
            f"📝 <b>Transaction Summary</b>\n\n"
            f"➡️ <b>To:</b> <code>{context.user_data['to_addr']}</code>\n"
            f"💰 <b>Amount:</b> {amount_sole} SOLE\n\n"
            "Confirm sending?"
        )
        kb_confirm = [
            [InlineKeyboardButton("✅ Confirm", callback_data='confirm_yes'), InlineKeyboardButton("❌ Cancel", callback_data='cancel_wizard')]
        ]
        await send_new_screen(update, context, text=msg, keyboard=kb_confirm)
        return CONFIRM
        
    except:
        await send_new_screen(
            update, context,
            text="⚠️ <b>Invalid Amount</b>\n\nPlease enter a positive number (e.g. 5.5). Try again:",
            keyboard=keyboard
        )
        return ASK_AMOUNT

async def confirm_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer()
    
    # Show loading
    await send_new_screen(update, context, text="🔄 <b>Processing Transaction...</b>\n\nSigning and Broadcasting...")
    
    user_id = update.effective_user.id
    w = get_wallet(user_id)
    
    if not w:
        await send_new_screen(update, context, text="❌ <b>Critical Error</b>\nCould not decrypt wallet.")
        return ConversationHandler.END
        
    to_addr = context.user_data['to_addr']
    amount_photons = context.user_data['amount_photons']
    
    # 1. UTXOs
    try:
        r = requests.get(f"{NODE_URL}/utxos/{w.get_address()}")
        utxos = r.json()
    except:
        await send_new_screen(update, context, text="❌ <b>Node Offline</b>\nUnable to fetch UTXOs.")
        # Return to dash after delay/click? Or leave error? Better leave error with Back button.
        await dashboard(update, context) # Or just go back to dash
        return ConversationHandler.END

    # 2. Select
    acc = 0
    inputs = []
    for u in utxos:
        acc += u['amount']
        inputs.append({'txid': u['txid'], 'vout': u['vout'], 'amount': u['amount'], 'pubkey': w.pub_key_bytes, 'signature': b''})
        if acc >= amount_photons: break
        
    if acc < amount_photons:
        kb = [[InlineKeyboardButton("🔙 Back to Dashboard", callback_data='back_dashboard')]]
        await send_new_screen(update, context, text=f"❌ <b>Insufficient Funds</b>\n\nYou have {Decimal(acc)/Decimal(COIN)} SOLE.", keyboard=kb)
        return ConversationHandler.END
        
    # 3. Outputs
    outputs = []
    decoded = base58_check_decode(to_addr)
    outputs.append({'value': amount_photons, 'pubkeyhash': decoded[1:]})
    
    if acc > amount_photons:
        my_decoded = base58_check_decode(w.get_address())
        outputs.append({'value': acc - amount_photons, 'pubkeyhash': my_decoded[1:]})
        
    # 4. Sign
    try:
        for i, vin in enumerate(inputs):
            sign_inputs = []
            for j, v in enumerate(inputs):
                row = {'txid': v['txid'], 'vout': v['vout'], 'signature': b''}
                if i == j:
                    sha_pub = hashlib.sha256(w.pub_key_bytes).digest()
                    ripe_pub = ripemd160(sha_pub)
                    row['pubkey'] = ripe_pub
                else:
                    row['pubkey'] = b''
                sign_inputs.append(row)
            blob = serialize_for_hash(sign_inputs, outputs)
            tx_hash = hashlib.sha256(blob).digest()
            vin['signature'] = w.sign(tx_hash)
            
        # 5. Broadcast
        final_hex = serialize_for_api(inputs, outputs).hex()
        r = requests.post(f"{NODE_URL}/tx/send", json={"hex": final_hex})
        
        if r.status_code == 200:
            txid = r.json().get('txid', '???')
            kb = [[InlineKeyboardButton("🔙 Back to Dashboard", callback_data='back_dashboard')]]
            await send_new_screen(update, context, text=f"✅ <b>Transaction Sent!</b>\n\nTXID: <code>{txid}</code>", keyboard=kb)
        else:
             kb = [[InlineKeyboardButton("🔙 Back to Dashboard", callback_data='back_dashboard')]]
             await send_new_screen(update, context, text=f"❌ <b>Node Error</b>\n{r.text}", keyboard=kb)

    except Exception as e:
         kb = [[InlineKeyboardButton("🔙 Back to Dashboard", callback_data='back_dashboard')]]
         await send_new_screen(update, context, text=f"❌ <b>Error</b>\n{e}", keyboard=kb)
         
    return ConversationHandler.END

async def cancel_wizard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cancels the wizard and returns to Dashboard."""
    await update.callback_query.answer("Cancelled")
    await dashboard(update, context) # Dashboard will clean up
    return ConversationHandler.END

# --- MAIN ---
def main():
    app = ApplicationBuilder().token(TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(create_cb, pattern='^create_wallet$'))
    app.add_handler(CallbackQueryHandler(refresh_cb, pattern='^refresh$'))
    app.add_handler(CallbackQueryHandler(receive_cb, pattern='^receive$'))
    app.add_handler(CallbackQueryHandler(back_dashboard_cb, pattern='^back_dashboard$'))
    
    conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(send_start, pattern='^send_start$')],
        states={
            ASK_ADDR: [MessageHandler((filters.TEXT | filters.PHOTO) & ~filters.COMMAND, ask_addr), CallbackQueryHandler(cancel_wizard, pattern='^cancel_wizard$')],
            ASK_AMOUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, ask_amount), CallbackQueryHandler(cancel_wizard, pattern='^cancel_wizard$')],
            CONFIRM: [CallbackQueryHandler(confirm_send, pattern='^confirm_yes$'), CallbackQueryHandler(cancel_wizard, pattern='^cancel_wizard$')]
        },
        fallbacks=[CommandHandler('cancel', cancel_wizard), CallbackQueryHandler(cancel_wizard, pattern='^cancel_wizard$')]
    )
    app.add_handler(conv_handler)
    
    print("🤖 Bot is running (Clean Chat & English)...")
    app.run_polling()

if __name__ == "__main__":
    main()