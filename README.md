# SOLE Telegram Wallet

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Telegram API](https://img.shields.io/badge/Telegram-API-2CA5E0?logo=telegram&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Stable-success)

## About
**SOLE Telegram Wallet** is a secure, high-speed custodial interface for interacting with the **SOLE Blockchain**. Designed for simplicity and performance, it allows users to manage funds, execute transactions, and monitor their history directly from their favorite messaging app. Whether you're a developer or a crypto enthusiast, this bot puts the power of the SOLE network in your pocket.

## Key Features

*   **🔐 Security First**
    Private keys are encrypted **at-rest** using **AES-256** encryption with a `BOT_SECRET_KEY`. No sensitive data is ever stored in plain text, ensuring maximum security for user funds.

*   **📸 Computer Vision Integration**
    Native support for **QR Code scanning**. Simply send a photo of a QR code, and the bot intelligently extracts the wallet address using `zbar` technology, streamlining the transaction process.

*   **✨ Clean UI Protocol**
    A polished interactions model that actively manages chat history. Old messages and menus are automatically cleaned up to prevent spam, keeping the interface focused and clutter-free.

*   **📜 Smart History**
    Real-time transaction tracking with visual indicators. Incoming (🟢) and outgoing (🔴) transactions are automatically parsed and presented in a clear, readable format.

## Prerequisites

Before getting started, ensure you have the following installed:

*   **Python 3.10+**
*   **System Libraries for QR Code Scanning (zbar)**
    This is **CRUCIAL** for the Computer Vision features to work.

    *   **Linux (Debian/Ubuntu):**
        ```bash
        sudo apt-get install libzbar0
        ```
    *   **macOS:**
        ```bash
        brew install zbar
        ```

## Installation & Setup

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/nicolocarcagni/sole-telegram-wallet.git
    cd sole-telegram-wallet
    ```

2.  **Set Up Virtual Environment**
    It's recommended to run the bot in an isolated environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

Create a `.env` file in the root directory completely to configure your bot instance. You can start by copying the example:

```bash
cp .env.example .env
```

### Environment Variables

| Variable | Description |
| :--- | :--- |
| `TELEGRAM_TOKEN` | Your unique Bot Token obtained from [@BotFather](https://t.me/BotFather). |
| `NODE_API_URL` | The URL of the SOLE Core Node |
| `BOT_SECRET_KEY` | A strong key used for AES-256 encryption of user wallets. |

**Example `.env` file:**

```ini
# Configurazione Bot Telegram
TELEGRAM_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
NODE_API_URL=http://127.0.0.1:8080

# Chiave segreta per cifratura AES
BOT_SECRET_KEY=your-super-secret-key-at-least-32-chars
```

## Usage

Start the bot with:

```bash
python bot.py
```

Once running, find your bot on Telegram and send the command:

*   **/start** - Initializes the wallet and opens the interactive main menu.

From there, you can:
*   View your **Balance**
*   **Send Transactions** (via Address or QR Code)
*   Check your **Transaction History**
*   **Receive** Funds (Show QR)

## Architecture

The SOLE Telegram Wallet operates as a lightweight client bridging the gap between Telegram users and the **SOLE Blockchain Core**.

*   **Backend:** Written in Python using `asyncio` for high-concurrency handling.
*   **network:** Communicates via HTTP REST API with the [SOLE Core Node](https://github.com/nicolocarcagni/sole).
*   **Encryption:** Uses `cryptography` library for client-side AES encryption handling.

---
