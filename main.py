# main.py (Single File Version)

import os
import logging
import json
import csv
import io
import asyncio
from typing import Dict, List, Tuple

import aiohttp
from aiohttp_socks import ProxyConnector
from telegram import Update, InputFile
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# --- Constants and Configuration ---
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

TARGET_URL = 'http://httpbin.org/ip'
TIMEOUT = 10  # စက္ကန့်

# --- Core Proxy Checking Logic ---

async def check_single_proxy(proxy_address: str, proxy_type: str) -> bool:
    """Proxy တစ်ခုကို သတ်မှတ်ထားသော protocol ဖြင့် အလုပ်လုပ်မလုပ် စစ်ဆေးပေးသည်။"""
    connector = ProxyConnector.from_url(f'{proxy_type}://{proxy_address}')
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(TARGET_URL, timeout=TIMEOUT) as response:
                return response.status == 200
    except Exception:
        return False

async def auto_check_proxy_detailed(proxy_address: str) -> Dict:
    """Proxy တစ်ခုကို protocol သုံးမျိုးလုံးဖြင့် စစ်ဆေးပြီး ရလဒ်ကို dictionary အနေဖြင့် ပြန်ပေးသည်။"""
    protocols_to_check = ['http', 'socks4', 'socks5']
    results = {'proxy': proxy_address}
    tasks = {
        protocol: asyncio.create_task(check_single_proxy(proxy_address, protocol))
        for protocol in protocols_to_check
    }
    for protocol, task in tasks.items():
        results[protocol] = await task
    return results

async def run_batch_check_detailed(proxies: List[str]) -> List[Dict]:
    """Proxy list တစ်ခုလုံးကို တစ်ပြိုင်နက်တည်း စစ်ဆေးပြီး ရလဒ် dictionary list ကို ပြန်ပေးသည်။"""
    tasks = [auto_check_proxy_detailed(proxy) for proxy in proxies]
    detailed_results = await asyncio.gather(*tasks)
    return detailed_results

# --- Telegram Bot Command Handlers ---

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_html(
        "👋 **Proxy Checker Bot မှ ကြိုဆိုပါသည်။**\n\n"
        "**အသုံးပြုနည်းများ:**\n"
        "1️⃣ **Auto Check:** `ip:port` format ဖြင့် proxy တစ်ခုပို့ပါ။ Bot မှ (http, socks4, socks5) တို့ဖြင့် အလိုအလျောက် စစ်ဆေးပေးပါမည်။\n"
        "2️⃣ **Manual Check:** `type ip:port` format ဖြင့် ပို့ပါ။ (ဥပမာ: `socks5 1.2.3.4:8080`)\n"
        "3️⃣ **File Check:** `.txt`, `.json`, `.csv` file တစ်ခုကို upload တင်ပြီး၊ ထို file ကို reply ပြုလုပ်၍ `/checkfile` ဟု ရိုက်ထည့်ပါ။"
    )

async def check_file_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message.reply_to_message or not update.message.reply_to_message.document:
        await update.message.reply_text("ကျေးဇူးပြု၍ စစ်ဆေးလိုသော file ကို reply ပြုလုပ်ပြီး `/checkfile` command ကို အသုံးပြုပါ။")
        return

    document = update.message.reply_to_message.document
    file_name = document.file_name.lower()
    
    if not (file_name.endswith('.txt') or file_name.endswith('.json') or file_name.endswith('.csv')):
        await update.message.reply_text("လက်ခံနိုင်သော file အမျိုးအစားများမှာ .txt, .json, .csv เท่านั้นဖြစ်ပါသည်။")
        return

    status_msg = await update.message.reply_text("📥 File ကို Download လုပ်နေပါသည်။ ...")
    
    try:
        file_bytes = await (await context.bot.get_file(document.file_id)).download_as_bytearray()
        file_content = file_bytes.decode('utf-8')
        
        proxies = []
        if file_name.endswith('.txt'):
            proxies = [line.strip() for line in file_content.splitlines() if line.strip()]
        elif file_name.endswith('.json'):
            data = json.loads(file_content)
            proxies = [p.strip() for p in data if isinstance(p, str)]
        elif file_name.endswith('.csv'):
            csvfile = io.StringIO(file_content)
            reader = csv.reader(csvfile)
            proxies = [row[0].strip() for row in reader if row]
        
        if not proxies:
            await status_msg.edit_text("❌ File ထဲတွင် စစ်ဆေးရန် proxy များ မတွေ့ပါ။")
            return

        await status_msg.edit_text(f"⏳ Proxy {len(proxies)} ခုကို စစ်ဆေးနေပါသည်။ အချိန်အနည်းငယ် ကြာမြင့်နိုင်ပါသည်။")
        
        detailed_results = await run_batch_check_detailed(proxies)
        
        http_working, socks4_working, socks5_working = [], [], []
        for result in detailed_results:
            proxy_address = result['proxy']
            if result.get('http'): http_working.append(proxy_address)
            if result.get('socks4'): socks4_working.append(proxy_address)
            if result.get('socks5'): socks5_working.append(proxy_address)
        
        output_lines = []
        if http_working:
            output_lines.extend(["[HTTP]"] + http_working + [""])
        if socks4_working:
            output_lines.extend(["[SOCKS4]"] + socks4_working + [""])
        if socks5_working:
            output_lines.extend(["[SOCKS5]"] + socks5_working)
        
        if not output_lines:
             await status_msg.edit_text("❌ စစ်ဆေးမှုပြီးဆုံးပါသည်။ အလုပ်လုပ်သော proxy တစ်ခုမှ မတွေ့ပါ။")
             return

        result_content = "\n".join(output_lines)
        result_bio = io.BytesIO(result_content.encode('utf-8'))
        result_bio.name = 'results.txt'
        
        await update.message.reply_document(document=InputFile(result_bio, filename='results.txt'), caption="✅ စစ်ဆေးမှုပြီးဆုံးပါပြီ။")
        await status_msg.delete()

    except Exception as e:
        await status_msg.edit_text(f"❗️ Error ဖြစ်ပွားပါသည်: {e}")
        logger.error(f"File processing error: {e}", exc_info=True)

# --- Message Handler ---
async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_input = update.message.text.strip()
    parts = user_input.split()

    status_msg = await update.message.reply_text(f"⏳ `{user_input}` ကို စစ်ဆေးနေပါသည်...")
    result_message = ""

    if len(parts) == 1 and ':' in parts[0]: # Auto Check (ip:port)
        proxy_address = parts[0]
        detailed_result = await auto_check_proxy_detailed(proxy_address)
        working_protocols = [p for p, is_working in detailed_result.items() if p != 'proxy' and is_working]
        
        if working_protocols:
            result_message = f"✅ `{proxy_address}`\n<b>အလုပ်လုပ်သော Protocol များ:</b> {', '.join(p.upper() for p in working_protocols)}"
        else:
            result_message = f"❌ `{proxy_address}`\nProtocol အားလုံးဖြင့် အလုပ်မလုပ်ပါ။"

    elif len(parts) == 2 and ':' in parts[1]: # Manual Check (type ip:port)
        proxy_type = parts[0].lower()
        proxy_address = parts[1]
        
        if proxy_type not in ['http', 'socks4', 'socks5']:
            await status_msg.edit_text("❌ Protocol အမျိုးအစားမှားနေပါသည်။ http, socks4, socks5 ကိုသာ လက်ခံပါသည်။")
            return
            
        is_working = await check_single_proxy(proxy_address, proxy_type)
        if is_working:
            result_message = f"✅ `{proxy_type}://{proxy_address}`\nအလုပ်လုပ်ပါသည်။"
        else:
            result_message = f"❌ `{proxy_type}://{proxy_address}`\nအလုပ်မလုပ်ပါ။"
    else:
        await status_msg.edit_text("Format မှားနေပါသည်။ `/start` ကိုနှိပ်ပြီး အသုံးပြုနည်းကို ပြန်ကြည့်ပါ။")
        return

    await status_msg.edit_text(result_message, parse_mode='HTML')

# --- Main Function to Start the Bot ---
def main() -> None:
    BOT_TOKEN = os.getenv("BOT_TOKEN")
    if not BOT_TOKEN:
        print("Error: BOT_TOKEN ကို Replit Secrets တွင် ရှာမတွေ့ပါ။")
        return

    application = Application.builder().token(BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("checkfile", check_file_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message))

    print("Bot is running...")
    application.run_polling()

if __name__ == "__main__":
    main()
    
