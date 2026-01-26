# SOLE Telegram Wallet

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Telegram API](https://img.shields.io/badge/Telegram-API-2CA5E0?logo=telegram&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Stable-success)

## About
**SOLE Telegram Wallet** is a custodial interface for the **SOLE Blockchain**, developed as a proof-of-concept for a university thesis project.

Designed to demonstrate practical blockchain integration, it allows users to manage test funds, execute transactions, and monitor history via a Telegram bot. This project is strictly for **educational and research purposes**.

> **Disclaimer:** This is an independent student project and is **NOT** officially affiliated with or endorsed by the University of Salento (Unisalento).

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
*   **network:** Communicates via HTTP REST API with the [SOLE Core](https://github.com/nicolocarcagni/sole).
*   **Encryption:** Uses `cryptography` library for client-side AES encryption handling.

---
