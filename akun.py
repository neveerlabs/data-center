import sys
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
except ImportError:
    print("Install pycryptodome: pip install pycryptodome")
    sys.exit(1)

import os
import json
import hashlib
import base64
import curses
import termios
import tty
import time
import traceback

HOME = os.path.expanduser("~")
DATA_CENTER_DIR = os.path.join(HOME, ".data-center")
PASS_FILE = os.path.join(DATA_CENTER_DIR, ".password")
SALT_FILE = os.path.join(DATA_CENTER_DIR, ".salt")
DATA_FILE = os.path.join(DATA_CENTER_DIR, ".data.enc")

SESSION_TIMEOUT = 300 # 5 minute
last_activity = time.time()

def ensure_dir():
    if not os.path.exists(DATA_CENTER_DIR):
        try:
            os.makedirs(DATA_CENTER_DIR)
        except Exception:
            pass

def get_password(prompt):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        password = ""
        while True:
            ch = sys.stdin.read(1)
            if ch == '\r' or ch == '\n':
                sys.stdout.write('\n')
                break
            elif ch == '\x7f' or ch == '\x08':
                if len(password) > 0:
                    password = password[:-1]
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif ch == '\x03':
                raise KeyboardInterrupt
            else:
                password += ch
                sys.stdout.write('*')
                sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return password

def get_salt():
    if not os.path.exists(SALT_FILE):
        salt = get_random_bytes(16)
        with open(SALT_FILE, "wb") as f:
            f.write(base64.b64encode(salt))
    else:
        with open(SALT_FILE, "rb") as f:
            salt = base64.b64decode(f.read())
    return salt

def init_password(salt):
    if not os.path.exists(PASS_FILE):
        print("Create new password:")
        p1 = get_password("Password: ")
        p2 = get_password("Repeat password: ")
        if p1 != p2:
            print("Passwords do not match.")
            sys.exit(1)
        if len(p1) < 4:
            print("Password must be at least 4 characters.")
            sys.exit(1)
        h = hashlib.sha256((p1 + salt.hex()).encode()).hexdigest()
        with open(PASS_FILE, "w") as f:
            f.write(h)
        return p1
    else:
        p = get_password("Password: ")
        with open(PASS_FILE, "r") as f:
            stored = f.read().strip()
        h = hashlib.sha256((p + salt.hex()).encode()).hexdigest()
        if h != stored:
            print("Wrong password.")
            sys.exit(1)
        return p

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=100000)

def encrypt_data(data, key):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode())
    return nonce + tag + ciphertext

def decrypt_data(enc_data, key):
    nonce = enc_data[:12]
    tag = enc_data[12:28]
    ciphertext = enc_data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    dec = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(dec.decode())

def load_data(key):
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "rb") as f:
            enc = f.read()
        try:
            return decrypt_data(enc, key)
        except Exception:
            print("Failed to decrypt data. Wrong password or corrupted file.")
            sys.exit(1)
    return []

def save_data(data, key):
    try:
        enc = encrypt_data(data, key)
        with open(DATA_FILE, "wb") as f:
            f.write(enc)
    except Exception:
        pass

def reauthenticate(stdscr, salt):
    global last_activity
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    msg = "Session expired. Please enter your password: "
    y = h//2
    x = (w - len(msg))//2
    if x < 0:
        x = 0
    try:
        stdscr.addnstr(y, x, msg, w - x - 1)
    except:
        pass
    stdscr.refresh()
    
    curses.echo()
    curses.curs_set(1)
    p = ""
    input_x = x + len(msg)
    stdscr.move(y, input_x)
    stdscr.clrtoeol()
    
    try:
        while True:
            key_val = stdscr.getch()
            if key_val == 10 or key_val == 13:
                break
            elif key_val == 27:
                sys.exit(0)
            elif key_val == curses.KEY_BACKSPACE or key_val == 127:
                if len(p) > 0:
                    p = p[:-1]
                    stdscr.move(y, input_x + len(p))
                    stdscr.delch()
            else:
                if 32 <= key_val <= 126:
                    p += chr(key_val)
                    stdscr.move(y, input_x + len(p) - 1)
                    stdscr.addch('*')
    except Exception:
        sys.exit(1)
        
    curses.noecho()
    curses.curs_set(0)
    
    if not os.path.exists(PASS_FILE):
        stdscr.clear()
        stdscr.addstr(h//2, (w-15)//2, "No password set.")
        stdscr.refresh()
        time.sleep(1)
        sys.exit(1)
        
    try:
        with open(PASS_FILE, "r") as f:
            stored = f.read().strip()
    except Exception:
        sys.exit(1)

    h_hash = hashlib.sha256((p + salt.hex()).encode()).hexdigest()
    
    if h_hash != stored:
        stdscr.clear()
        try:
            stdscr.addnstr(h//2, (w - len("Wrong password."))//2, "Wrong password.", w - 1)
        except:
            pass
        stdscr.refresh()
        time.sleep(1)
        sys.exit(1)
    
    last_activity = time.time()
    curses.flushinp()
    return derive_key(p, salt)

def getch_with_activity(stdscr):
    global last_activity
    key = stdscr.getch()
    last_activity = time.time()
    return key

def input_field(stdscr, prompt, y, x, default=""):
    curses.noecho()
    curses.curs_set(1)
    stdscr.move(y, x)
    stdscr.clrtoeol()
    full_prompt = f"{prompt}: "
    stdscr.addstr(y, x, full_prompt)
    if default:
        stdscr.addstr(default)
    val = default if default else ""
    pos = len(val)
    cursor_x = x + len(full_prompt)
    
    def draw_input():
        stdscr.move(y, x)
        stdscr.clrtoeol()
        stdscr.addstr(y, x, full_prompt)
        if val:
            stdscr.addstr(val)
            stdscr.move(y, cursor_x + len(val))
        else:
            stdscr.move(y, cursor_x)
        stdscr.refresh()

    draw_input()
    
    while True:
        key = getch_with_activity(stdscr)
        if key == 10 or key == 13:
            break
        elif key == 27:
            return None
        elif key == curses.KEY_BACKSPACE or key == 127:
            if pos > 0:
                val = val[:pos-1] + val[pos:]
                pos -= 1
                draw_input()
        elif key == curses.KEY_DC:
            if pos < len(val):
                val = val[:pos] + val[pos+1:]
                draw_input()
        elif key == curses.KEY_LEFT:
            if pos > 0:
                pos -= 1
                stdscr.move(y, cursor_x + pos)
        elif key == curses.KEY_RIGHT:
            if pos < len(val):
                pos += 1
                stdscr.move(y, cursor_x + pos)
        elif key == curses.KEY_HOME:
            pos = 0
            stdscr.move(y, cursor_x)
        elif key == curses.KEY_END:
            pos = len(val)
            stdscr.move(y, cursor_x + pos)
        elif key in (curses.KEY_UP, curses.KEY_DOWN):
            pass
        else:
            if 32 <= key <= 126:
                val = val[:pos] + chr(key) + val[pos:]
                pos += 1
                draw_input()
    
    curses.curs_set(0)
    return val

def input_placeholder(stdscr, prompt, y, x, placeholder_text):
    curses.noecho()
    curses.curs_set(1)
    stdscr.move(y, x)
    stdscr.clrtoeol()
    full_prompt = f"{prompt}: "
    stdscr.addstr(y, x, full_prompt)
    
    val = ""
    pos = 0
    cursor_x = x + len(full_prompt)
    
    def draw_input():
        stdscr.move(y, x)
        stdscr.clrtoeol()
        stdscr.addstr(y, x, full_prompt)
        if val:
            stdscr.addstr(val)
            stdscr.move(y, cursor_x + len(val))
        else:
            stdscr.attron(curses.A_DIM)
            stdscr.addstr(placeholder_text)
            stdscr.attroff(curses.A_DIM)
            stdscr.move(y, cursor_x)
        stdscr.refresh()

    draw_input()
    
    while True:
        key = getch_with_activity(stdscr)
        if key == 10 or key == 13:
            break
        elif key == 27:
            return None
        elif key == curses.KEY_BACKSPACE or key == 127:
            if pos > 0:
                val = val[:pos-1] + val[pos:]
                pos -= 1
                draw_input()
        elif key == curses.KEY_DC:
            if pos < len(val):
                val = val[:pos] + val[pos+1:]
                draw_input()
        elif key == curses.KEY_LEFT:
            if pos > 0:
                pos -= 1
                stdscr.move(y, cursor_x + pos)
        elif key == curses.KEY_RIGHT:
            if pos < len(val):
                pos += 1
                stdscr.move(y, cursor_x + pos)
        elif key == curses.KEY_HOME:
            pos = 0
            stdscr.move(y, cursor_x)
        elif key == curses.KEY_END:
            pos = len(val)
            stdscr.move(y, cursor_x + pos)
        elif key in (curses.KEY_UP, curses.KEY_DOWN):
            pass
        else:
            if 32 <= key <= 126:
                val = val[:pos] + chr(key) + val[pos:]
                pos += 1
                draw_input()
    
    curses.curs_set(0)
    return val

def show_message(stdscr, msg, y=None, x=None):
    h, w = stdscr.getmaxyx()
    if y is None: y = h//2
    if x is None: x = (w - len(msg))//2
    if x < 0: x = 0
    if y < 0: y = 0
    try:
        stdscr.attron(curses.A_REVERSE)
        stdscr.addnstr(y, x, msg, w - x - 1)
        stdscr.attroff(curses.A_REVERSE)
    except:
        pass
    stdscr.refresh()
    getch_with_activity(stdscr)

def confirm_delete(stdscr, title):
    h, w = stdscr.getmaxyx()
    max_title_len = 30
    if len(title) > max_title_len:
        title = title[:max_title_len] + "..."
    msg = f"Delete '{title}'? (y/n)"
    y = h//2
    x = (w - len(msg))//2
    if x < 0: x = 0
    if y < 0: y = 0
    stdscr.clear()
    try:
        stdscr.attron(curses.A_REVERSE)
        stdscr.addnstr(y, x, msg, w - x - 1)
        stdscr.attroff(curses.A_REVERSE)
    except:
        pass
    stdscr.refresh()
    while True:
        ch = getch_with_activity(stdscr)
        if ch == ord('y') or ch == ord('Y'):
            return True
        elif ch == ord('n') or ch == ord('N') or ch == 27:
            return False

def select_category(stdscr):
    categories = ["Account", "API"]
    current = 0
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        y = h//2 - 1
        x = w//2 - 10
        stdscr.addstr(y-1, x, "Select category:")
        for i, cat in enumerate(categories):
            if i == current:
                stdscr.attron(curses.A_REVERSE)
                stdscr.addstr(y+i, x, f"  {cat}  ")
                stdscr.attroff(curses.A_REVERSE)
            else:
                stdscr.addstr(y+i, x, f"  {cat}  ")
        stdscr.refresh()
        key = getch_with_activity(stdscr)
        if key == curses.KEY_UP:
            current = (current - 1) % len(categories)
        elif key == curses.KEY_DOWN:
            current = (current + 1) % len(categories)
        elif key == 10:
            return categories[current].lower()
        elif key == 27:
            return None

def edit_form_account(stdscr, data=None, is_edit=False):
    fields = ["title", "name", "note", "username", "password"]
    if data is None:
        data = {f: "" for f in fields}
    y0 = 4
    x0 = 4
    stdscr.clear()
    stdscr.addstr(2, x0, "===> ENTER ACCOUNT DATA <===" if not is_edit else "===> EDIT ACCOUNT DATA <===")
    new_data = {}
    for idx, f in enumerate(fields):
        default = data.get(f, "")
        prompt = f.capitalize()
        val = input_field(stdscr, prompt, y0 + idx, x0, default)
        if val is None:
            return None
        new_data[f] = val
    new_data["type"] = "account"
    return new_data

def edit_form_api(stdscr, data=None, is_edit=False):
    fields = ["title", "category", "name", "note", "api_key"]
    if data is None:
        data = {f: "" for f in fields}
    y0 = 4
    x0 = 4
    stdscr.clear()
    stdscr.addstr(2, x0, "===> ENTER API DATA <===" if not is_edit else "===> EDIT API DATA <===")
    new_data = {}
    if not is_edit:
        cat = None
        while cat is None:
            stdscr.clear()
            stdscr.addstr(2, x0, "===> ENTER API DATA <===")
            stdscr.addstr(4, x0, "Category: ")
            choices = ["ai", "platform"]
            current = 0
            while True:
                stdscr.move(4, x0 + 10)
                stdscr.clrtoeol()
                for i, ch in enumerate(choices):
                    if i == current:
                        stdscr.attron(curses.A_REVERSE)
                        stdscr.addstr(4, x0 + 10 + i*10, f" {ch} ")
                        stdscr.attroff(curses.A_REVERSE)
                    else:
                        stdscr.addstr(4, x0 + 10 + i*10, f" {ch} ")
                stdscr.refresh()
                key = getch_with_activity(stdscr)
                if key == curses.KEY_LEFT:
                    current = (current - 1) % len(choices)
                elif key == curses.KEY_RIGHT:
                    current = (current + 1) % len(choices)
                elif key == 10:
                    cat = choices[current]
                    break
                elif key == 27:
                    return None
        new_data["category"] = cat
    else:
        new_data["category"] = data.get("category", "ai")
    for f in ["title", "name", "note", "api_key"]:
        default = data.get(f, "")
        prompt = f.capitalize()
        if f == "api_key":
            prompt = "API Key"
        val = input_field(stdscr, prompt, y0 + len(new_data), x0, default)
        if val is None:
            return None
        new_data[f] = val
    new_data["type"] = "api"
    return new_data

def edit_form(stdscr, data=None, is_edit=False):
    if data is None:
        cat = select_category(stdscr)
        if cat is None:
            return None
        if cat == "account":
            return edit_form_account(stdscr, None, False)
        else:
            return edit_form_api(stdscr, None, False)
    else:
        if data.get("type") == "account":
            return edit_form_account(stdscr, data, True)
        else:
            return edit_form_api(stdscr, data, True)

def check_duplicate(data, new_data, exclude_idx=None):
    fields = ["title", "name", "username", "password", "category", "api_key"]
    dup_indices = []
    for i, item in enumerate(data):
        if i == exclude_idx:
            continue
        match = True
        for f in fields:
            if f == "category" and new_data.get("type") != "api":
                continue
            if f == "api_key" and new_data.get("type") != "api":
                continue
            if f == "username" and new_data.get("type") != "account":
                continue
            if f == "password" and new_data.get("type") != "account":
                continue
            val1 = item.get(f, "")
            val2 = new_data.get(f, "")
            if val1 != val2:
                match = False
                break
        if match:
            dup_indices.append(i)
    return dup_indices

def confirm_duplicate(stdscr, dup_indices):
    choices = ["Add anyway", "Overwrite", "Cancel"]
    current = 0
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        y = h//2 - 2
        x = w//2 - 20
        msg = "Duplicate data exists. What do you want to do?"
        stdscr.addstr(y, x, msg)
        for i, choice in enumerate(choices):
            if i == current:
                stdscr.attron(curses.A_REVERSE)
                stdscr.addstr(y+2+i, x, f"  {choice}  ")
                stdscr.attroff(curses.A_REVERSE)
            else:
                stdscr.addstr(y+2+i, x, f"  {choice}  ")
        stdscr.refresh()
        key = getch_with_activity(stdscr)
        if key == curses.KEY_UP:
            current = (current - 1) % len(choices)
        elif key == curses.KEY_DOWN:
            current = (current + 1) % len(choices)
        elif key == 10:
            if current == 0:
                return "add"
            elif current == 1:
                return "overwrite"
            else:
                return "cancel"
        elif key == 27:
            return "cancel"

def select_item(stdscr, items, prompt="Select:", enable_filter=True):
    if not items:
        show_message(stdscr, "No data.")
        return None
    h, w = stdscr.getmaxyx()
    menu_y = 4
    menu_x = 4
    current = 0
    filter_text = ""
    filtered_items = items[:]
    
    while True:
        stdscr.clear()
        stdscr.addstr(2, menu_x, prompt)
        
        if enable_filter:
            filter_prompt = "Type to search" if not filter_text else f"Search: {filter_text}"
            stdscr.addstr(3, menu_x, filter_prompt)
            
        for i, (display, _) in enumerate(filtered_items):
            y = menu_y + i
            if y >= h - 2:
                break
            display_str = f"{i+1}. {display}"
            if i == current:
                stdscr.attron(curses.A_REVERSE)
                stdscr.addnstr(y, menu_x, display_str, w - menu_x - 1)
                stdscr.attroff(curses.A_REVERSE)
            else:
                stdscr.addnstr(y, menu_x, display_str, w - menu_x - 1)
        stdscr.refresh()
        
        key = getch_with_activity(stdscr)
        if key == curses.KEY_UP:
            if current > 0:
                current -= 1
        elif key == curses.KEY_DOWN:
            if current < len(filtered_items) - 1:
                current += 1
        elif key == 10:
            if filtered_items:
                return filtered_items[current][1]
            else:
                continue
        elif key == 27:
            return None
        elif enable_filter and (32 <= key <= 126):
            filter_text += chr(key)
            filtered_items = [item for item in items if filter_text.lower() in item[0].lower()]
            current = 0
            if not filtered_items:
                current = 0
        elif enable_filter and (key == curses.KEY_BACKSPACE or key == 127):
            if filter_text:
                filter_text = filter_text[:-1]
                filtered_items = [item for item in items if filter_text.lower() in item[0].lower()]
                current = 0
                if not filtered_items:
                    current = 0

def view_details(stdscr, item):
    global last_activity
    h, w = stdscr.getmaxyx()
    x = 2
    lines = []
    if item.get("type") == "account":
        lines.append(f"Type     : Account")
        lines.append(f"Title    : {item.get('title', '')}")
        lines.append(f"Name     : {item.get('name', '')}")
        lines.append(f"Note     : {item.get('note', '')}")
        lines.append(f"Username : {item.get('username', '')}")
        lines.append(f"Password : {item.get('password', '')}")
    else:
        lines.append(f"Type     : API")
        lines.append(f"Title    : {item.get('title', '')}")
        lines.append(f"Category : {item.get('category', '')}")
        lines.append(f"Name     : {item.get('name', '')}")
        lines.append(f"Note     : {item.get('note', '')}")
        lines.append(f"API Key  : {item.get('api_key', '')}")
    msg = "Press any key to continue..."

    def draw():
        stdscr.clear()
        yy = 2
        for line in lines:
            if yy >= h - 2:
                break
            stdscr.addnstr(yy, x, line, w - x - 1)
            yy += 1
        try:
            stdscr.addnstr(yy, x, msg, w - x - 1)
        except:
            pass
        stdscr.refresh()

    draw()
    curses.flushinp()
    while True:
        key = stdscr.getch()
        if key != -1:
            last_activity = time.time()
            break
        if time.time() - last_activity > SESSION_TIMEOUT:
            # Re-authenticate needs salt, which we don't have here directly unless passed
            # For simplicity in this specific function, we assume main loop handles global timeout
            # But if triggered here, we need a way to get salt. 
            # Since this function is called from main_menu, we can't easily access salt here without changing signature.
            # Workaround: Let the main loop handle the timeout check primarily.
            # If we must handle here, we need to pass salt. 
            # For now, let's just break and let main loop catch it next iteration or rely on global check.
            # Actually, better to just return and let main loop handle it to avoid complexity.
            return

def settings_menu(stdscr, salt, current_key):
    global last_activity
    options = ["Set password", "Change password", "Delete password", "Back"]
    current = 0
    
    while True:
        if time.time() - last_activity > SESSION_TIMEOUT:
            new_key = reauthenticate(stdscr, salt)
            last_activity = time.time()
            current_key = new_key 
        
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        y = h//2 - 2
        x = w//2 - 15
        
        stdscr.addstr(y-2, x, "===> SETTINGS <===")
        
        for i, opt in enumerate(options):
            if i == current:
                stdscr.attron(curses.A_REVERSE)
                stdscr.addstr(y+i, x, f"  {opt}  ")
                stdscr.attroff(curses.A_REVERSE)
            else:
                stdscr.addstr(y+i, x, f"  {opt}  ")
        
        stdscr.refresh()
        key = getch_with_activity(stdscr)
        
        if key == curses.KEY_UP:
            current = (current - 1) % len(options)
        elif key == curses.KEY_DOWN:
            current = (current + 1) % len(options)
        elif key == 10:
            if current == 0:
                handle_set_password(stdscr, salt)
            elif current == 1:
                handle_change_password(stdscr, salt, current_key)
            elif current == 2:
                handle_delete_password(stdscr)
            elif current == 3:
                return
        elif key == 27:
            return

def handle_set_password(stdscr, salt):
    global last_activity
    if os.path.exists(PASS_FILE):
        h, w = stdscr.getmaxyx()
        y = h//2
        x = w//2 - 25
        
        stdscr.clear()
        stdscr.addstr(y-1, x, "===> CONFIRM ACTION <===")
        
        confirm_val = input_placeholder(stdscr, "Are you sure you want to set a new password", y, x, "y or n")
        
        if confirm_val is None:
            return
        
        if confirm_val.lower() != 'y':
            return
    
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    y = h//2 - 1
    x = w//2 - 20
    
    stdscr.addstr(y-1, x, "===> SET NEW PASSWORD <===")
    
    p1 = input_placeholder(stdscr, "New Password", y, x, "y or n")
    if p1 is None:
        return
    
    if p1.lower() == 'n':
        return

    p2 = input_placeholder(stdscr, "Repeat Password", y+1, x, "y or n")
    if p2 is None:
        return
    
    if p1 != p2:
        show_message(stdscr, "Passwords do not match.")
        return
    
    if len(p1) < 4:
        show_message(stdscr, "Password must be at least 4 characters.")
        return
    
    h_hash = hashlib.sha256((p1 + salt.hex()).encode()).hexdigest()
    with open(PASS_FILE, "w") as f:
        f.write(h_hash)
    
    show_message(stdscr, "Password updated successfully.")

def handle_change_password(stdscr, salt, old_key):
    global last_activity
    if not os.path.exists(PASS_FILE):
        show_message(stdscr, "No password set yet. Use 'Set password' first.")
        return
    
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    y = h//2 - 1
    x = w//2 - 20
    
    stdscr.addstr(y-1, x, "===> CHANGE PASSWORD <===")
    
    old_p = input_placeholder(stdscr, "Current Password", y, x, "y or n")
    if old_p is None:
        return
    
    h_old = hashlib.sha256((old_p + salt.hex()).encode()).hexdigest()
    with open(PASS_FILE, "r") as f:
        stored = f.read().strip()
    
    if h_old != stored:
        show_message(stdscr, "Current password is wrong.")
        return
    
    new_p1 = input_placeholder(stdscr, "New Password", y+1, x, "y or n")
    if new_p1 is None:
        return
    
    new_p2 = input_placeholder(stdscr, "Repeat New Password", y+2, x, "y or n")
    if new_p2 is None:
        return
    
    if new_p1 != new_p2:
        show_message(stdscr, "Passwords do not match.")
        return
    
    if len(new_p1) < 4:
        show_message(stdscr, "Password must be at least 4 characters.")
        return
    
    h_new = hashlib.sha256((new_p1 + salt.hex()).encode()).hexdigest()
    with open(PASS_FILE, "w") as f:
        f.write(h_new)
    
    show_message(stdscr, "Password changed successfully.")

def handle_delete_password(stdscr):
    global last_activity
    if not os.path.exists(PASS_FILE):
        show_message(stdscr, "No password to delete.")
        return
    
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    y = h//2
    x = w//2 - 25
    
    stdscr.addstr(y-1, x, "===> CONFIRM ACTION <===")
    
    confirm_val = input_placeholder(stdscr, "Are you sure you want to delete the password", y, x, "y or n")
    
    if confirm_val is None:
        return
    
    if confirm_val.lower() != 'y':
        return
    
    try:
        os.remove(PASS_FILE)
        show_message(stdscr, "Password deleted successfully.")
    except Exception as e:
        show_message(stdscr, f"Error deleting password: {str(e)}")

def main_menu(stdscr, data, key, salt):
    global last_activity
    stdscr.keypad(True)
    curses.curs_set(0)
    if curses.has_colors():
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLUE)
    
    menu_items = ["Add", "Edit", "Delete", "View", "Setting", "Exit"]
    current_menu = 0
    stdscr.timeout(1000)
    
    while True:
        if time.time() - last_activity > SESSION_TIMEOUT:
            key = reauthenticate(stdscr, salt)
            last_activity = time.time()
            try:
                data = load_data(key)
            except Exception:
                stdscr.clear()
                stdscr.addstr(0,0, "Data load failed after reauth.")
                stdscr.refresh()
                time.sleep(2)
                break
        
        try:
            stdscr.clear()
            h, w = stdscr.getmaxyx()
            if h < 10 or w < 30:
                stdscr.addstr(0, 0, "Screen too small. Minimum 30x10.")
                stdscr.refresh()
                key_input = stdscr.getch()
                if key_input != -1:
                    last_activity = time.time()
                continue

            headers = ["No", "Title", "Name", "Note", "Username", "Password"]
            max_cols = len(headers)
            base_width = w - 2
            fixed = 4
            remaining = base_width - fixed - (max_cols - 1)
            if remaining < 10:
                col_widths = [4, 4, 4, 4, 4, 4]
            else:
                each = remaining // (max_cols - 1)
                col_widths = [fixed] + [each] * (max_cols - 1)
                col_widths = [min(c, 30) for c in col_widths]
                total = sum(col_widths) + (max_cols - 1)
                if total > w - 2:
                    ratio = (w - 2 - (max_cols - 1)) / sum(col_widths)
                    col_widths = [max(2, int(c * ratio)) for c in col_widths]

            y = 2
            x = 1
            for i, hdr in enumerate(headers):
                try:
                    if curses.has_colors():
                        stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
                    stdscr.addnstr(y, x, hdr[:col_widths[i]].ljust(col_widths[i]), col_widths[i])
                    if curses.has_colors():
                        stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
                except:
                    pass
                x += col_widths[i] + 1
            y += 1
            x = 1
            sep = "-" * (sum(col_widths) + (max_cols - 1))
            try:
                stdscr.addnstr(y, x, sep, w - 2)
            except:
                pass
            y += 1

            for idx, item in enumerate(data):
                if y >= h - 5:
                    break
                x = 1
                if item.get("type") == "account":
                    row = [
                        str(idx+1),
                        item.get("title", "")[:col_widths[1]],
                        item.get("name", "")[:col_widths[2]],
                        "***" if item.get("note") else "",
                        "***" if item.get("username") else "",
                        "***" if item.get("password") else ""
                    ]
                else:
                    row = [
                        str(idx+1),
                        item.get("title", "")[:col_widths[1]],
                        item.get("name", "")[:col_widths[2]],
                        "***" if item.get("note") else "",
                        "***" if item.get("api_key") else "",
                        ""
                    ]
                for i, col in enumerate(row):
                    try:
                        stdscr.addnstr(y, x, col.ljust(col_widths[i])[:col_widths[i]], col_widths[i])
                    except:
                        pass
                    x += col_widths[i] + 1
                y += 1

            menu_y = h - 3
            total_width = sum(col_widths) + (max_cols - 1)
            if total_width > w - 2:
                total_width = w - 2
            menu_x = (w - total_width) // 2
            if menu_x < 0:
                menu_x = 1
            try:
                stdscr.addnstr(menu_y, menu_x, "-" * total_width, total_width)
            except:
                pass
            menu_y += 1
            menu_items_display = []
            for i, item in enumerate(menu_items):
                if i == current_menu:
                    menu_items_display.append(f"[{item}]")
                else:
                    menu_items_display.append(f" {item} ")
            sep = "  "
            menu_str = sep.join(menu_items_display)
            menu_x = (w - len(menu_str)) // 2
            if menu_x < 0:
                menu_x = 1
            try:
                stdscr.addstr(menu_y, menu_x, menu_str)
            except:
                pass
            stdscr.refresh()

            key_input = stdscr.getch()
            if key_input == -1:
                continue
            last_activity = time.time()

            if key_input == curses.KEY_LEFT:
                current_menu = (current_menu - 1) % len(menu_items)
            elif key_input == curses.KEY_RIGHT:
                current_menu = (current_menu + 1) % len(menu_items)
            elif key_input == 10:
                if current_menu == 0:
                    try:
                        new = edit_form(stdscr)
                        if new is not None:
                            dup = check_duplicate(data, new)
                            if dup:
                                action = confirm_duplicate(stdscr, dup)
                                if action == "cancel":
                                    continue
                                elif action == "overwrite":
                                    for idx in sorted(dup, reverse=True):
                                        del data[idx]
                            data.append(new)
                            save_data(data, key)
                    except Exception as e:
                        show_message(stdscr, f"Add error: {str(e)}")
                elif current_menu == 1:
                    try:
                        items = [(f"{d.get('title','')} - {d.get('name','')}", i) for i, d in enumerate(data)]
                        sel = select_item(stdscr, items, "Select item to edit or type to search:", enable_filter=True)
                        if sel is not None:
                            old = data[sel]
                            new = edit_form(stdscr, old, is_edit=True)
                            if new is not None:
                                dup = check_duplicate(data, new, exclude_idx=sel)
                                if dup:
                                    action = confirm_duplicate(stdscr, dup)
                                    if action == "cancel":
                                        continue
                                    elif action == "overwrite":
                                        for idx in sorted(dup, reverse=True):
                                            del data[idx]
                                        if sel > len(data):
                                            sel = len(data) - 1
                                data[sel] = new
                                save_data(data, key)
                    except Exception as e:
                        show_message(stdscr, f"Edit error: {str(e)}")
                elif current_menu == 2:
                    try:
                        items = [(f"{d.get('title','')} - {d.get('name','')}", i) for i, d in enumerate(data)]
                        sel = select_item(stdscr, items, "Select item to delete or type to search:", enable_filter=True)
                        if sel is not None:
                            if confirm_delete(stdscr, data[sel].get('title', '')):
                                del data[sel]
                                save_data(data, key)
                    except Exception as e:
                        show_message(stdscr, f"Delete error: {str(e)}")
                elif current_menu == 3:
                    try:
                        items = [(f"{d.get('title','')} - {d.get('name','')}", i) for i, d in enumerate(data)]
                        sel = select_item(stdscr, items, "Select item to view or type to search:", enable_filter=True)
                        if sel is not None:
                            view_details(stdscr, data[sel])
                    except Exception as e:
                        show_message(stdscr, f"View error: {str(e)}")
                elif current_menu == 4:
                    settings_menu(stdscr, salt, key)
                    try:
                        data = load_data(key)
                    except Exception:
                        key = reauthenticate(stdscr, salt)
                        last_activity = time.time()
                        data = load_data(key)
                elif current_menu == 5:
                    save_data(data, key)
                    break
            elif key_input == 27:
                save_data(data, key)
                break
        except curses.error:
            pass
        except KeyboardInterrupt:
            save_data(data, key)
            break
    stdscr.timeout(-1)

def main():
    ensure_dir()
    salt = get_salt()
    password = init_password(salt)
    key = derive_key(password, salt)
    data = load_data(key)
    try:
        curses.wrapper(main_menu, data, key, salt)
    except KeyboardInterrupt:
        save_data(data, key)
        print("\nExited.")
    except Exception as e:
        save_data(data, key)
        print(f"Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
