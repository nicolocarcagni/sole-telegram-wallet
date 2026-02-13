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
import time

# Image Processing
from PIL import Image
from pyzbar.pyzbar import decode as qr_decode, ZBarSymbol

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
FAUCET_PRIVATE_KEY = os.getenv("FAUCET_PRIVATE_KEY")

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

if not FAUCET_PRIVATE_KEY:
    logger.warning("⚠️ FAUCET_PRIVATE_KEY missing! Faucet feature will be disabled.")

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

# --- UI HELPERS ---
def time_since(ts):
    now = int(time.time())
    diff = now - ts
    if diff < 60: return "Just now"
    if diff < 3600: return f"{diff//60}m ago"
    if diff < 86400: return f"{diff//3600}h ago"
    return f"{diff//86400}d ago"

def render_progressbar(current, total, length=10):
    percent = min(1.0, current / total)
    filled_len = int(length * percent)
    bar = "▓" * filled_len + "░" * (length - filled_len)
    return bar

# --- SERIALIZATION ---
def serialize_for_hash(inputs, outputs, timestamp):
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
    # Timestamp (int64, Big Endian)
    buffer += struct.pack(">q", timestamp)
    return buffer

def serialize_for_api(inputs, outputs, timestamp):
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
    # Timestamp (int64, Big Endian)
    buffer += struct.pack(">q", timestamp)
    return buffer

# --- SECURE WALLET CLASS ---
class SecureWallet:
    def __init__(self, private_key_bytes):
        self.sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.NIST256p)
        self.vk = self.sk.verifying_key
        # ANSI X9.62 Uncompressed: 0x04 + X + Y (65 bytes total for P-256)
        self.pub_key_bytes = b'\x04' + self.vk.to_string()

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

# --- FAUCET LOGIC ---
import random

async def faucet_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if not FAUCET_PRIVATE_KEY:
        await query.answer("⚠️ Faucet is disabled by admin.", show_alert=True)
        return

    user_id = update.effective_user.id
    db = load_db()

    # 1. User check
    if str(user_id) not in db:
        await query.answer("⚠️ Create a wallet first!", show_alert=True)
        return
        
    user_record = db[str(user_id)]
    user_addr = user_record['address']

    # 2. Rate Limit (24h)
    last_claim = user_record.get('last_claim', 0)
    current_time = int(time.time())
    
    # 24 hours = 86400 seconds
    elapsed = current_time - last_claim
    if elapsed < 86400:
        remaining = 86400 - elapsed
        hours = remaining // 3600
        mins = (remaining % 3600) // 60
        
        # Progress (Time Waited vs 24h)
        # We want bar to show how much we WAITED (filled)
        bar = render_progressbar(elapsed, 86400, length=12)
        
        await send_new_screen(
            update, context,
            text=(
                f"⏳ <b>Faucet Cooldown</b>\n\n"
                f"<code>[{bar}]</code>\n"
                f"Wait <b>{hours}h {mins}m</b> more.\n\n"
                f"<i>Give everyone a chance! 🌞</i>"
            ),
            keyboard=[[InlineKeyboardButton("🔙 Back", callback_data='back_dashboard')]]
        )
        return

    # 3. Amount (1.0 to 25.0 SOLE)
    amount_sole = round(random.uniform(1.0, 25.0), 2)
    amount_photons = int(amount_sole * COIN)

    # 4. Faucet Wallet Setup
    try:
        faucet_sk_bytes =  bytes.fromhex(FAUCET_PRIVATE_KEY) if len(FAUCET_PRIVATE_KEY) == 64 else FAUCET_PRIVATE_KEY.encode()
        # If raw bytes were passed as string? attempting hex decode is safest for keys usually
        # The provided user context says "hex or raw string". Let's assume hex if 64 chars.
        # Actually, let's try to handle potential formats more robustly if needed, 
        # but standardized hex is best.
        if len(FAUCET_PRIVATE_KEY) == 64:
             try: faucet_sk_bytes = bytes.fromhex(FAUCET_PRIVATE_KEY)
             except: faucet_sk_bytes = FAUCET_PRIVATE_KEY.encode() # Fallback
        else:
             faucet_sk_bytes = FAUCET_PRIVATE_KEY.encode() # Raw?

        # Fix: ecdsa expects bytes.
        
        # Initializing wallet
        # Note: If the key format is weird, SecureWallet might throw. 
        # But we assume standard 32-byte hex or bytes.
        
        faucet_w = SecureWallet(faucet_sk_bytes)
        faucet_addr = faucet_w.get_address()

    except Exception as e:
        logger.error(f"Faucet Key Error: {e}")
        await send_new_screen(update, context, text="❌ <b>System Error</b>\nFaucet configuration invalid.")
        return

    # 5. Build Transaction (Admin -> User)
    await send_new_screen(update, context, text="🔄 <b>Processing Faucet Claim...</b>\n\nFetching UTXOs and signing...")
    
    try:
        # A. Fetch UTXOs
        r = requests.get(f"{NODE_URL}/utxos/{faucet_addr}", timeout=5)
        if r.status_code != 200:
             raise Exception("Node offline or API error")
        
        utxos = r.json()
        
        # B. Select Inputs
        acc = 0
        inputs = []
        for u in utxos:
            acc += u['amount']
            inputs.append({'txid': u['txid'], 'vout': u['vout'], 'amount': u['amount'], 'pubkey': faucet_w.pub_key_bytes, 'signature': b''})
            if acc >= amount_photons: break
            
        if acc < amount_photons:
            await send_new_screen(
                update, context, 
                text="❌ <b>Faucet Empty</b>\n\nThe faucet wallet is dry! Please contact admin.",
                keyboard=[[InlineKeyboardButton("🔙 Back to Dashboard", callback_data='back_dashboard')]]
            )
            return

        # C. Outputs
        outputs = []
        # Target
        decoded_dest = base58_check_decode(user_addr)
        outputs.append({'value': amount_photons, 'pubkeyhash': decoded_dest[1:]})
        
        # Change
        if acc > amount_photons:
            decoded_change = base58_check_decode(faucet_addr)
            outputs.append({'value': acc - amount_photons, 'pubkeyhash': decoded_change[1:]})

        # D. Sign
        # Reuse logic from confirm_send mostly
        now_ts = int(time.time())
        for i, vin in enumerate(inputs):
            sign_inputs = []
            for j, v in enumerate(inputs):
                row = {'txid': v['txid'], 'vout': v['vout'], 'signature': b''}
                if i == j:
                    sha_pub = hashlib.sha256(faucet_w.pub_key_bytes).digest()
                    ripe_pub = ripemd160(sha_pub)
                    row['pubkey'] = ripe_pub
                else:
                    row['pubkey'] = b''
                sign_inputs.append(row)
            
            blob = serialize_for_hash(sign_inputs, outputs, now_ts)
            tx_hash = hashlib.sha256(blob).digest()
            vin['signature'] = faucet_w.sign(tx_hash)

        # E. Broadcast
        final_hex = serialize_for_api(inputs, outputs, now_ts).hex()
        r = requests.post(f"{NODE_URL}/tx/send", json={"hex": final_hex})
        
        if r.status_code == 200:
            txid = r.json().get('txid', '???')
            
            # Update DB check
            db[str(user_id)]['last_claim'] = now_ts
            save_db(db)
            
            msg = (
                f"✅ <b>Faucet Claim Successful!</b>\n\n"
                f"💰 <b>Received:</b> {amount_sole} SOLE\n"
                f"🆔 <b>TXID:</b> <code>{txid}</code>\n\n"
                f"<i>Come back in 24 hours for more!</i>"
            )
            kb = [[InlineKeyboardButton("🔙 Back to Dashboard", callback_data='back_dashboard')]]
            await send_new_screen(update, context, text=msg, keyboard=kb)
        else:
            raise Exception(f"Node rejected: {r.text}")

    except Exception as e:
        logger.error(f"Faucet TX Failed: {e}")
        await send_new_screen(
            update, context, 
            text=f"❌ <b>Claim Failed</b>\n\nError: {str(e)}",
            keyboard=[[InlineKeyboardButton("🔙 Back to Dashboard", callback_data='back_dashboard')]]
        )

# --- BOT HANDLERS ---

# --- INFO ---
async def info_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer()
    
    # Defaults
    height = "Unknown"
    peers = 0
    version = "v2.0 (Sole Core)"
    
    # 1. Get Tip
    try:
        r = requests.get(f"{NODE_URL}/blocks/tip", timeout=2)
        if r.status_code == 200:
            d = r.json()
            height = d.get('height', 'Unknown')
    except: pass
    
    # 2. Get Peers
    try:
        r = requests.get(f"{NODE_URL}/network/peers", timeout=2)
        if r.status_code == 200:
            d = r.json()
            peers = d.get('total_peers', 0)
    except: pass
    
    text = (
        f"ℹ️ <b>Network Info</b>\n\n"
        f"📏 <b>Block Height:</b> {height}\n"
        f"🔗 <b>Peers Connected:</b> {peers}\n"
        f"🛠 <b>Node Version:</b> {version}\n\n"
        f"<i>Sole Blockchain is live since Jan 2026.</i>"
    )
    
    keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='back_dashboard')]]
    await send_new_screen(update, context, text, keyboard=keyboard)


# --- HISTORY ---
def get_history(address):
    try:
        r = requests.get(f"{NODE_URL}/transactions/{address}", timeout=5)
        if r.status_code != 200: return []
        data = r.json()
        # Sort by timestamp desc
        data.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        
        parsed = []
        for tx in data:
            # Inputs/Outputs
            inputs = tx.get('inputs', [])
            outputs = tx.get('outputs', [])
            
            # 1. Determine Direction
            is_sent = False
            first_sender = inputs[0].get('sender_address', 'Unknown') if inputs else 'Unknown'
            
            if first_sender == address:
                is_sent = True
            
            # 2. Determine Amount & Display Address
            amount_val = Decimal(0)
            other_addr = "?"
            
            if is_sent:
                # Standard logic: Sum of everything NOT going back to me.
                recipients = []
                for o in outputs:
                    if o.get('receiver_address') != address:
                        amount_val += Decimal(o.get('value', 0))
                        recipients.append(o.get('receiver_address', '?'))
                
                # If multiple recipients, show the first one or "Multiple"
                if recipients:
                    other_addr = recipients[0]
                else:
                    # Special case: Self-send or Change-only? Show myself.
                    other_addr = address
            else:
                # IN: Sum of outputs where receiver == address
                for o in outputs:
                    if o.get('receiver_address') == address:
                        amount_val += Decimal(o.get('value', 0))
                # From: Sender
                other_addr = first_sender

            # 3. Format Date
            ts = tx.get('timestamp', 0)
            date_str = "Genesis"
            if ts > 0:
                dt = datetime.fromtimestamp(ts)
                date_str = dt.strftime('%Y-%m-%d %H:%M')
            
            parsed.append({
                'direction': 'OUT' if is_sent else 'IN',
                'amount': amount_val / Decimal(COIN),
                'other': other_addr,
                'amount': amount_val / Decimal(COIN),
                'other': other_addr,
                'date': date_str,
                'ts': ts # Keep raw timestamp for relative time
            })
            
        return parsed
    except Exception as e:
        logger.error(f"History parse error: {e}")
        return []

async def history_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    # Parse page
    page = 0
    try:
        parts = query.data.split('_')
        if len(parts) > 2:
           page = int(parts[-1])
    except: pass
    
    user_id = update.effective_user.id
    db = load_db()
    if str(user_id) not in db: return
    addr = db[str(user_id)]['address']
    
    history = get_history(addr)
    
    if not history:
        # Use send_new_screen to ensure clean state if history is empty
        await send_new_screen(
             update, context, 
             text="📜 <b>Transaction History</b>\n\nNo transactions found.", 
             keyboard=[[InlineKeyboardButton("🔙 Back to Dashboard", callback_data='back_dashboard')]]
        )
        return

    # Pagination
    ITEMS_PER_PAGE = 5
    total_pages = (len(history) + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE
    # Clamp page
    if page < 0: page = 0
    if page >= total_pages: page = total_pages - 1
    
    start_idx = page * ITEMS_PER_PAGE
    end_idx = start_idx + ITEMS_PER_PAGE
    page_items = history[start_idx:end_idx]
    
    msg_lines = [f"📜 <b>Transaction History</b> (Page {page+1}/{total_pages})\n"]
    
    for item in page_items:
        icon = "📤" if item['direction'] == 'OUT' else "📥"
        sign = "-" if item['direction'] == 'OUT' else "+"
        amt_fmt = f"{item['amount']:.2f}"
        
        # Relative time
        ago = time_since(item['ts'])
        
        # Format:
        # 📤 -5.00 SOLE | 🕒 20m ago
        # To: abc...
        
        msg_lines.append(
            f"{icon} <b>{sign}{amt_fmt} SOLE</b> | 🕒 {ago}\n"
            f"<code>{item['other']}</code>\n"
        )
        
    text = "\n".join(msg_lines)
    
    # Nav Buttons
    nav_row = []
    if page > 0:
        nav_row.append(InlineKeyboardButton("⬅️", callback_data=f'tx_page_{page-1}'))
    
    nav_row.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data=f'noop'))
    
    if page < total_pages - 1:
        nav_row.append(InlineKeyboardButton("➡️", callback_data=f'tx_page_{page+1}'))
        
    keyboard = [
        nav_row,
        [InlineKeyboardButton("🔙 Back", callback_data='back_dashboard')]
    ]
    
    # Try to edit the message to avoid spam
    try:
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=query.message.message_id,
            text=text,
            parse_mode='HTML',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    except Exception as e:
        # Fallback: Send new screen
        await send_new_screen(update, context, text, keyboard=keyboard)

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
             bal_text = f"{bal_float:,.8f} SOLE"
        else:
            bal_text = "⚠️ Node Error"
    except:
        bal_text = "🔌 Node Offline"
        
    text = (
        f"🌞 <b>SOLE Wallet</b>\n\n"
        f"💳 <b>Your Address:</b>\n<code>{addr}</code>\n\n"
        f"💰 <b>Balance:</b> {bal_text}"
    )
    
    keyboard = [
        [InlineKeyboardButton("📥 Receive", callback_data='receive'), InlineKeyboardButton("📤 Send", callback_data='send_start')],
        [InlineKeyboardButton("💰 Balance", callback_data='refresh'), InlineKeyboardButton("🚰 Faucet", callback_data='faucet')],
        [InlineKeyboardButton("📜 History", callback_data='tx_page_0'), InlineKeyboardButton("ℹ️ Network", callback_data='info')],
        [InlineKeyboardButton("🔄 Refresh", callback_data='refresh')]
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
    
    # QR with Styling
    qr = qrcode.QRCode(box_size=10, border=2)
    qr.add_data(addr)
    qr.make(fit=True)
    
    qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
    
    # Add Padding/Border for Dark Mode
    border_size = 20
    w, h = qr_img.size
    new_w = w + (border_size * 2)
    new_h = h + (border_size * 2)
    
    final_img = Image.new('RGB', (new_w, new_h), 'white')
    final_img.paste(qr_img, (border_size, border_size))
    
    bio = BytesIO()
    final_img.save(bio, 'PNG')
    bio.seek(0)
    
    keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='back_dashboard')]]
    
    await send_new_screen(
        update, context, 
        text=f"📥 <b>Receive SOLE</b>\n\nAddress:\n<code>{addr}</code>", 
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
        text=(
            "📤 <b>Send SOLE</b>\n\n"
            "1️⃣ <b>Recipient Address</b>\n"
            "Please paste the address or send a QR code image."
        ),
        keyboard=keyboard
    )
    return ASK_ADDR

async def ask_addr(update: Update, context: ContextTypes.DEFAULT_TYPE):
    addr = None
    keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data='cancel_wizard')]]
    
    # CASE A: Photo (QR Code)
    if update.message.photo:
        try:
            # Download photo (highest resolution)
            photo_file = await update.message.photo[-1].get_file()
            img_bytes = await photo_file.download_as_bytearray()
            
            # Base Image
            original_img = Image.open(BytesIO(img_bytes))
            decoded_objects = []
            
            # ATTEMPT 1: High Quality (Original)
            # Try to decode without modification to preserve details
            try:
                decoded_objects = qr_decode(original_img, symbols=[ZBarSymbol.QRCODE])
            except: pass
            
            # ATTEMPT 2: Grayscale (Convert 'L')
            # If failed, convert to grayscale (helps with contrast/artifacts)
            if not decoded_objects:
                try:
                    gray_img = original_img.convert('L')
                    decoded_objects = qr_decode(gray_img, symbols=[ZBarSymbol.QRCODE])
                except: pass
                
            # ATTEMPT 3: Downscale (Resize)
            # Only if huge > 2000px, resize to remove noise
            if not decoded_objects and (original_img.width > 2000 or original_img.height > 2000):
                try:
                    resized_img = original_img.copy()
                    resized_img.thumbnail((1024, 1024))
                    # Try on resized (maybe add grayscale here too? Let's just resize original)
                    decoded_objects = qr_decode(resized_img, symbols=[ZBarSymbol.QRCODE])
                except: pass

            if not decoded_objects:
               logger.info(f"QR Decode failed after 3 attempts. Size: {original_img.size}")
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
            text=f"{extra_text}✅ Address accepted.\n\n2️⃣ <b>Amount</b>\nEnter the amount to send (e.g. 5.5):",
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
            "3️⃣ <b>Confirm?</b>"
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
        kb = [[InlineKeyboardButton("🔙 Back", callback_data='back_dashboard')]]
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
        current_time = int(time.time())
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
            blob = serialize_for_hash(sign_inputs, outputs, current_time)
            tx_hash = hashlib.sha256(blob).digest()
            vin['signature'] = w.sign(tx_hash)
            
        # 5. Broadcast
        final_hex = serialize_for_api(inputs, outputs, current_time).hex()
        r = requests.post(f"{NODE_URL}/tx/send", json={"hex": final_hex})
        
        if r.status_code == 200:
            txid = r.json().get('txid', '???')
            kb = [[InlineKeyboardButton("🔙 Back", callback_data='back_dashboard')]]
            await send_new_screen(update, context, text=f"✅ <b>Transaction Sent!</b>\n\nTXID: <code>{txid}</code>", keyboard=kb)
        else:
             kb = [[InlineKeyboardButton("🔙 Back", callback_data='back_dashboard')]]
             await send_new_screen(update, context, text=f"❌ <b>Node Rejected</b>\n{r.text}", keyboard=kb)

    except Exception as e:
         logger.error(f"Send TX Failed: {e}")
         kb = [[InlineKeyboardButton("🔙 Back", callback_data='back_dashboard')]]
         await send_new_screen(update, context, text=f"❌ <b>Transaction Failed</b>\n\nAn error occurred while processing your transaction. Please try again.", keyboard=kb)
         
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
    app.add_handler(CallbackQueryHandler(history_cb, pattern='^tx_page_'))
    app.add_handler(CallbackQueryHandler(faucet_cb, pattern='^faucet$'))
    app.add_handler(CallbackQueryHandler(info_cb, pattern='^info$'))
    app.add_handler(CallbackQueryHandler(lambda u,c: u.callback_query.answer(), pattern='^noop$'))
    
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
    
    print("🤖 Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()