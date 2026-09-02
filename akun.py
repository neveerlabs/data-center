import sys
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
except ImportError:
    print("Instal pycryptodome: pip install pycryptodome")
    sys.exit(1)

import os
import json
import hashlib
import base64
import curses
import getpass

HOME = os.path.expanduser("~")
DATA_CENTER_DIR = os.path.join(HOME, ".data-center")
PASS_FILE = os.path.join(DATA_CENTER_DIR, ".password")
SALT_FILE = os.path.join(DATA_CENTER_DIR, ".salt")
DATA_FILE = os.path.join(DATA_CENTER_DIR, ".data.enc")

def ensure_dir():
    if not os.path.exists(DATA_CENTER_DIR):
        os.makedirs(DATA_CENTER_DIR)

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
        p1 = getpass.getpass("Password: ")
        p2 = getpass.getpass("Repeat password: ")
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
        p = getpass.getpass("Password: ")
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
        except:
            print("Failed to decrypt data. Wrong password or corrupted file.")
            sys.exit(1)
    return []

def save_data(data, key):
    enc = encrypt_data(data, key)
    with open(DATA_FILE, "wb") as f:
        f.write(enc)

def input_field(stdscr, prompt, y, x, default=""):
    curses.noecho()
    curses.curs_set(1)
    stdscr.move(y, x)
    stdscr.clrtoeol()
    stdscr.addstr(y, x, prompt + ": ")
    if default:
        stdscr.addstr(default)
    val = default if default else ""
    pos = len(val)
    stdscr.move(y, x + len(prompt) + 2 + pos)
    while True:
        key = stdscr.getch()
        if key == 10 or key == 13:
            break
        elif key == 27:
            return None
        elif key == curses.KEY_BACKSPACE or key == 127:
            if pos > 0:
                val = val[:pos-1] + val[pos:]
                pos -= 1
                stdscr.move(y, x + len(prompt) + 2 + pos)
                stdscr.delch()
        elif key == curses.KEY_DC:
            if pos < len(val):
                val = val[:pos] + val[pos+1:]
                stdscr.move(y, x + len(prompt) + 2 + pos)
                stdscr.delch()
        elif key == curses.KEY_LEFT:
            if pos > 0:
                pos -= 1
                stdscr.move(y, x + len(prompt) + 2 + pos)
        elif key == curses.KEY_RIGHT:
            if pos < len(val):
                pos += 1
                stdscr.move(y, x + len(prompt) + 2 + pos)
        elif key == curses.KEY_HOME:
            pos = 0
            stdscr.move(y, x + len(prompt) + 2 + pos)
        elif key == curses.KEY_END:
            pos = len(val)
            stdscr.move(y, x + len(prompt) + 2 + pos)
        elif key in (curses.KEY_UP, curses.KEY_DOWN):
            pass
        else:
            if 32 <= key <= 126:
                val = val[:pos] + chr(key) + val[pos:]
                pos += 1
                stdscr.move(y, x + len(prompt) + 2 + pos - 1)
                stdscr.addch(key)
                if pos < len(val):
                    stdscr.addstr(val[pos:])
                    stdscr.move(y, x + len(prompt) + 2 + pos)
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
    stdscr.getch()

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
        key = stdscr.getch()
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
    stdscr.addstr(2, x0, "--- ENTER ACCOUNT DATA ---" if not is_edit else "--- EDIT ACCOUNT DATA ---")
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
    fields = ["title", "category", "name", "note", "data_api"]
    if data is None:
        data = {f: "" for f in fields}
    y0 = 4
    x0 = 4
    stdscr.clear()
    stdscr.addstr(2, x0, "--- ENTER API DATA ---" if not is_edit else "--- EDIT API DATA ---")
    new_data = {}
    if not is_edit:
        cat = None
        while cat is None:
            stdscr.clear()
            stdscr.addstr(2, x0, "--- ENTER API DATA ---")
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
                key = stdscr.getch()
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
    for f in ["title", "name", "note", "data_api"]:
        default = data.get(f, "")
        prompt = f.capitalize()
        if f == "data_api":
            prompt = "Data API"
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

def select_item(stdscr, items, prompt="Select:"):
    if not items:
        show_message(stdscr, "No data.")
        return None
    h, w = stdscr.getmaxyx()
    menu_y = 4
    menu_x = 4
    current = 0
    while True:
        stdscr.clear()
        stdscr.addstr(2, menu_x, prompt)
        for i, item in enumerate(items):
            y = menu_y + i
            if y >= h - 2:
                break
            display = f"{i+1}. {item}"
            if i == current:
                stdscr.attron(curses.A_REVERSE)
                stdscr.addnstr(y, menu_x, display, w - menu_x - 1)
                stdscr.attroff(curses.A_REVERSE)
            else:
                stdscr.addnstr(y, menu_x, display, w - menu_x - 1)
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            current = (current - 1) % len(items)
        elif key == curses.KEY_DOWN:
            current = (current + 1) % len(items)
        elif key == 10:
            return current
        elif key == 27:
            return None

def view_details(stdscr, item):
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    y = 2
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
        lines.append(f"Data API : {item.get('data_api', '')}")
    for line in lines:
        if y >= h - 2:
            break
        stdscr.addnstr(y, x, line, w - x - 1)
        y += 1
    stdscr.addstr(y, x, "Press any key to continue...")
    stdscr.refresh()
    stdscr.getch()

def main_menu(stdscr, data, key):
    stdscr.keypad(True)
    curses.curs_set(0)
    if curses.has_colors():
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLUE)
    menu_items = ["Add", "Edit", "Delete", "View", "Exit"]
    current_menu = 0
    while True:
        try:
            stdscr.clear()
            h, w = stdscr.getmaxyx()
            if h < 10 or w < 30:
                stdscr.addstr(0, 0, "Screen too small. Minimum 30x10.")
                stdscr.refresh()
                stdscr.getch()
                continue

            headers = ["No", "Title", "Name", "Note", "Username/Data", "Password"]
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
                        "***" if item.get("data_api") else "",
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
            if key_input == curses.KEY_LEFT:
                current_menu = (current_menu - 1) % len(menu_items)
            elif key_input == curses.KEY_RIGHT:
                current_menu = (current_menu + 1) % len(menu_items)
            elif key_input == 10:
                if current_menu == 0:
                    new = edit_form(stdscr)
                    if new is not None:
                        data.append(new)
                        save_data(data, key)
                elif current_menu == 1:
                    items = [f"{d.get('title','')} - {d.get('name','')}" for d in data]
                    sel = select_item(stdscr, items, "Select account to edit:")
                    if sel is not None:
                        old = data[sel]
                        new = edit_form(stdscr, old, is_edit=True)
                        if new is not None:
                            data[sel] = new
                            save_data(data, key)
                elif current_menu == 2:
                    items = [f"{d.get('title','')} - {d.get('name','')}" for d in data]
                    sel = select_item(stdscr, items, "Select account to delete:")
                    if sel is not None:
                        try:
                            stdscr.addstr(menu_y+2, 1, f"Delete '{data[sel].get('title','')}'? (y/n)")
                            stdscr.refresh()
                            ch = stdscr.getch()
                            if ch == ord('y') or ch == ord('Y'):
                                del data[sel]
                                save_data(data, key)
                        except:
                            pass
                elif current_menu == 3:
                    items = [f"{d.get('title','')} - {d.get('name','')}" for d in data]
                    sel = select_item(stdscr, items, "Select account to view:")
                    if sel is not None:
                        view_details(stdscr, data[sel])
                elif current_menu == 4:
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

def main():
    ensure_dir()
    salt = get_salt()
    password = init_password(salt)
    key = derive_key(password, salt)
    data = load_data(key)
    try:
        curses.wrapper(main_menu, data, key)
    except KeyboardInterrupt:
        save_data(data, key)
        print("\nExited.")
    except Exception as e:
        save_data(data, key)
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()