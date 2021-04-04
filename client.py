import socket
import os
import json
import hashlib
import threading
import sys
from datetime import datetime
from tkinter import *
from signal import SIGTERM
from re import match as re_match
from tkinter import messagebox, font
from argparse import ArgumentParser
from random import randint as random_int
from time import sleep
from beepy import beep


class Argparser(ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.stderr.write(f"\nError: {message}\n")
        sys.exit(2)


def parse_args():
    argparser = Argparser()
    argparser.add_argument('-i', '--ip', help="Server IP", required=True, action="store")
    argparser.add_argument('-p', '--port', help="Server Port", type=int, required=True, action="store")
    argparser.add_argument('-k', '--key', help="Chat key file", action="store")
    return argparser.parse_args()


def get_message_hash(message_bytes, bytes_len):
    res = bytearray(bytes_len)
    for i in range(len(message_bytes)):
        res[i % bytes_len] = res[i % bytes_len] ^ message_bytes[i]
    return res


def get_encode(message_bytes, key):
    if len(message_bytes) > 248:
        return
    key_pos = random_int(0, len(key))
    res = bytearray(256)
    res[0] = key_pos & 255
    res[1] = (key_pos >> 8) & 255
    res[2] = (key_pos >> 16) & 255
    res[3] = len(message_bytes)
    curpos = 4
    trash_size = (248 - len(message_bytes)) // 2
    for i in range(curpos, curpos + trash_size - 1 + ((248 - len(message_bytes)) % 2) + 1):
        res[i] = random_int(0, 255)
    curpos += trash_size + ((248 - len(message_bytes)) % 2)
    res[curpos:curpos + len(message_bytes)] = message_bytes[:]
    curpos += len(message_bytes)
    for i in range(curpos, curpos + trash_size):
        res[i] = random_int(0, 255)
    curpos += trash_size
    msg_hash = get_message_hash(res, 4)
    res[curpos:curpos + len(msg_hash)] = msg_hash[:]
    for i in range(3, len(res)):
        res[i] = res[i] ^ key[(key_pos + i) % len(key)]
    return res


def get_decode(message_bytes, key):
    if len(message_bytes) != 256:
        return
    decode_msg = bytearray(256)
    key_pos = message_bytes[0] | (message_bytes[1] << 8) | (message_bytes[2] << 16)
    decode_msg[:] = message_bytes[:]
    for i in range(3, len(decode_msg)):
        decode_msg[i] = decode_msg[i] ^ key[(key_pos + i) % len(key)]
    res = bytearray(decode_msg[3])
    res[:] = decode_msg[4 + ((248 - len(res)) // 2) + ((248 - len(res)) % 2):4 + ((248 - len(res)) // 2) + ((248 - len(res)) % 2) + len(res)]
    decode_hash = bytearray(4)
    decode_hash[:4] = decode_msg[-4:]
    decode_msg[-4:] = bytearray(4)[:]
    msg_hash = get_message_hash(decode_msg, 4)
    if msg_hash != decode_hash:
        return
    return res


def genkey(bytes_size, file_path):
    key = bytearray([random_int(0, 255) for _ in range(bytes_size)])
    with open(file_path, 'wb') as f:
        f.write(key)
    messagebox.showinfo(title="Generated key", message=f"New key file: ({file_path})" )


def getkey(file_path):
    with open(file_path, 'rb') as f:
        key = f.read()
    return key


args = parse_args()
ipv4, port = args.ip, args.port
chat_key = ''
try:
    chat_key = getkey(args.key)
except:
    pass

if not re_match(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", ipv4):
    exit("Given IP is invalid")


def rcv_cmd(connection):
    data1 = bytearray()
    while True:
        try:
            data = connection.recv(1)
            if not data:
                messagebox.showwarning(title="No connection", message="Connection has been dropped by server")
                os.kill(os.getpid(), SIGTERM)
            if data == b'\n':
                return data1.decode('utf-8')
            data1 += data
            if len(data1) > 1536:
                return
        except:
            messagebox.showwarning(title="No connection", message="Connection has been dropped by server")
            os.kill(os.getpid(), SIGTERM)


def wait_rcv_cmd(connection):
    while True:
        data = rcv_cmd(connection)
        if not data:
            continue
        return data


def snd_cmd(connection, cmd):
    connection.send((cmd + '\n').encode('utf-8'))


def jsonfy_request(call_func, args):
    res = {
        "call_func": call_func,
        "args": args
    }
    return json.dumps(res)


def hash_md5(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()


def key_hash():
    return '0' if not chat_key else hashlib.md5(chat_key).hexdigest()


def tkinter_elements(window):
    _list = window.winfo_children()
    for item in _list :
        if item.winfo_children() :
            _list.extend(item.winfo_children())
    return _list


def clear_tk(window):
    widget_list = tkinter_elements(window)
    for item in widget_list:
        item.place_forget()


def fpublicity_button(title, cmd):
    btn = Button(root,
                  text=title,
                  command=cmd, 
                  bg='black', 
                  fg='#0f0',
                  activebackground='#777')
    return btn


def fpublicity_label(title):
    return Label(root, text=title, bg='black', fg='#0f0')


def fpublicity_entry(symb=None, textvar=None):
    return Entry(root, show=symb, bg='#333', fg='#0f0', textvariable=textvar)


def window_create_room():
    def create_room(room_name, username, password):
        snd_cmd(sock, jsonfy_request('create_room', (str(room_name), str(username), str(hash_md5(password)))))
        messagebox.showinfo(title="Room id", message="Your Room id: " + str(wait_rcv_cmd(sock)))
        os.kill(os.getpid(), SIGTERM)
    clear_tk(root)
    canvas.place(x=310, y=(600 - logo_size) // 4)
    fpublicity_label("Room name:").place(x=20, y=20, width=200, height=25)
    fpublicity_label("Password:").place(x=20, y=140, width=200, height=25)
    fpublicity_label("Username:").place(x=20, y=80, width=200, height=25)
    username = fpublicity_entry()
    password = fpublicity_entry('*')
    room_name = fpublicity_entry()
    room_name.place(x=20, y=50, width=200, height=25)
    username.place(x=20, y=110, width=200, height=25)
    password.place(x=20, y=170, width=200, height=25)
    fpublicity_button("Create Room", lambda: create_room(room_name.get(), username.get(), password.get())).place(x=20, y=210, width=200, height=35)


def window_register_room():
    def registrate_room(room_id, username, password):
        snd_cmd(sock, jsonfy_request('registrate_room', (str(room_id), key_hash(), str(username), str(hash_md5(password)))))
        messagebox.showinfo(title="Wait", message="Wait until admin will accept you")
        messagebox.showinfo(title="Info", message= str(wait_rcv_cmd(sock)))
        os.kill(os.getpid(), SIGTERM)
    clear_tk(root)
    canvas.place(x=310, y=(600 - logo_size) // 4)
    fpublicity_label("Room id:").place(x=20, y=20, width=200, height=25)
    fpublicity_label("Password:").place(x=20, y=140, width=200, height=25)
    fpublicity_label("Username:").place(x=20, y=80, width=200, height=25)
    username = fpublicity_entry()
    password = fpublicity_entry("*")
    room_id = fpublicity_entry()
    room_id.place(x=20, y=50, width=200, height=25)
    username.place(x=20, y=110, width=200, height=25)
    password.place(x=20, y=170, width=200, height=25)
    fpublicity_button("Register Room", lambda: registrate_room(room_id.get(), username.get(), password.get())).place(x=20, y=210, width=200, height=35)


def window_chat(room_id):
    def save_chat():
        with open('room_' + str(room_id) + '_' + str(int(datetime.now().timestamp())) + '.txt', 'w') as f: 
            f.write('\n'.join([i for i in chat_history.get(0, END)]))
        messagebox.showinfo(title="Saved", message="Successfully saved chat!")


    def entry_callback(label, entry_string):
        font_height = font.Font().metrics('linespace')
        commands = [
            "/change_room_key <path_to_key_file> (Admin)",
            "/kick <username> (Admin)",
            "/delete_room (Admin)",
            "/info",
            "/sound",
            "/change_password <password>",
        ]
        lines_count = 0
        label_text = ''
        if entry_string.get() and entry_string.get().find(' ') == -1:
            for command in commands:
                if command.startswith(entry_string.get()):
                    label_text += command + '\n'
                    lines_count += 1
        height = font_height*lines_count
        label.config(text=label_text)
        label.place(x=20, y=340-height, width=500, height=height)


    def send_input(event):
        global notifications
        message = user_input.get()
        if not message.strip():
            return
        if message[0] == '/':
            message = message.split(' ')
            if message[0] == '/change_room_key':
                file_path = message[1]
                try:
                    new_hash = hashlib.md5(getkey(file_path)).hexdigest()
                    snd_cmd(sock, jsonfy_request('set_room_key', (new_hash,)))
                    messagebox.showinfo(title="Room key updated", message="Room key has been updated successfully!")
                    os.kill(os.getpid(), SIGTERM)
                except FileNotFoundError:
                    messagebox.showwarning(title="File not found", message="File " + file_path + " is not found!")
                os.kill(os.getpid(), SIGTERM)
            if message[0] == '/kick':
                try:
                    snd_cmd(sock, jsonfy_request('kick_user', (message[1],)))
                except:
                    messagebox.showwarning(title="", message="User is not found!")
            if message[0] == '/delete_room':
                snd_cmd(sock, jsonfy_request('delete_room', ("",)))
                messagebox.showinfo(title="", message="Room has been deleted")
            if message[0] == '/info':
                snd_cmd(sock, jsonfy_request('room_info', ("", )))
            if message[0] == '/change_password':
                snd_cmd(sock, jsonfy_request('change_password', (hash_md5(message[1]),)))
                messagebox.showinfo(title="", message="Password has been changed!")
            if message[0] == '/sound':
                notifications = not notifications
                messagebox.showinfo(title="", message="Sound: " + ('on' if notifications else 'off'))
        else:
            if key_hash() == '0':
                user_input.delete(0, END)
                messagebox.showinfo(title="", message="You need to set room key first. Use /change_room_key <file name>")
                return
            encoded_msg = get_encode(bytearray(message.encode('cp1251')), chat_key)
            encoded_msg = ''.join([format(x, '02x') for x in encoded_msg])
            snd_cmd(sock, jsonfy_request('broadcast', (encoded_msg,)))
        user_input.delete(0, END)
    threading.Thread(target=chat_listener).start()
    clear_tk(root)
    chat_history.place(x=20, y=20, width=560, height=300)
    cmd_label = Label(text="", fg="#0f0", bg="#222", anchor="nw", justify=LEFT)
    entry_string = StringVar()
    entry_string.trace("w", lambda name, index, mode, text=entry_string: entry_callback(cmd_label, entry_string))
    user_input = fpublicity_entry(textvar=entry_string)
    user_input.place(x=20, y=340, width=500, height=40)
    user_input.bind('<Return>', send_input)
    fpublicity_button("Save", lambda: save_chat()).place(x=530, y=340, width=50, height=40)


def window_enter_room():
    def login_room(room_id, username, password):
        snd_cmd(sock, jsonfy_request('login_room', (room_id, username,)))
        salt = wait_rcv_cmd(sock)
        snd_cmd(sock, hash_md5(key_hash() + salt + hash_md5(password)))
        login_response = str(wait_rcv_cmd(sock))
        if login_response != 'Logged in':
            messagebox.showwarning(title="Error", message=login_response)
            os.kill(os.getpid(), SIGTERM)
        window_chat(room_id)
    clear_tk(root)
    canvas.place(x=310, y=(600 - logo_size) // 4)
    fpublicity_label("Room id:").place(x=20, y=20, width=200, height=25)
    fpublicity_label("Password:").place(x=20, y=140, width=200, height=25)
    fpublicity_label("Username:").place(x=20, y=80, width=200, height=25)
    username = fpublicity_entry()
    password = fpublicity_entry("*")
    room_id = fpublicity_entry()
    room_id.place(x=20, y=50, width=200, height=25)
    username.place(x=20, y=110, width=200, height=25)
    password.place(x=20, y=170, width=200, height=25)
    fpublicity_button("Enter room", lambda: login_room(room_id.get(), username.get(), password.get())).place(x=20, y=210, width=200, height=35)


def window_help():
    clear_tk(root)
    scrollbar = Scrollbar(root)
    scrollbar.pack(side=RIGHT, fill=Y)
    help_listbox = Listbox(root, bg="black", fg="#0f0", font=font.Font(size=13))
    help_listbox.place(x=0, y=0, width=585, height=400)
    help_text = '''Fpublicity dev. start date: 29.11.2020
Generate Key:
    Generates a megabyte key file that you have to keep.
    Please, share this key privately only with room members.

Create Room:
    To create the private room you have to enter Room name,
    Admin username and password. When the room is created
    you will get the room id that you need to save it.

Enter Room:
    You have to be a member of the room if you want to enter.
    You will get "Invalid credentials" error if you have right
    username and password, but wrong room key.

Register Room:
    To join the room first you need to have the same room key.
    Then enter room id of the room you want to join. Choose
    username and password and wait until admin accepts you.


Example:
    Imagine, Alice and Bob want to chat privately:
    *Alice and Bob needs fpublicity server ip and port*
    *They need to start program with --ip <ip> --port <port>*

    Alice: Create Room
        Room name => Bob_and_Alice
        Username => a1is3
        Password => ********
    Server Response: room id = 123123
    *Alice needs to save this room id*    
    Alice: Generate Key
        Key file name: key5711053.bin
    Alice: Enter Room
        Room id => 123123
        Username => a1is3
        Password => ********
    Alice: /change_room_key key5711053.bin
    *Alice restarts the program with --key key5711053.bin argument*
    *Alice shares the key and room id to Bob*
    Alice: Enter room
    *Bob starts the program with --key key5711053.bin argument*
    Bob: Registrate room
        Room id => 123123
        Username => b0b
        Password => **********
    *Alice accepts Bob*
    Bob: Enter Room
        Room id => 123123
        Username => b0b
        Password => **********
    *Alice and Bob start to chat privately*
    *Other users also can join the room just as Bob did*

WARNING:
    If you are entering the room you just created you need to
    start the program with no --key argument. Then update the room
    key.

Developers:
    N0n3-github, x64BitWorm'''
    for help_item in help_text.split('\n'):
        help_listbox.insert(END, help_item)
    help_listbox.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=help_listbox.yview)

root = Tk()
root.configure(background='black')
root.title("fpublicity")
root.geometry("600x400")
root.resizable(False, False)
logo = [0, 18158513697557968896, 18446735277616530431, 36028796482093057, 35184372056064, 18437736908814548988, 18446742974214701055, 18446744073575342079,
       36028797018947587, 567462316929442302, 18302661875210518512, 17302690099242696711, 2413789694644502577, 17871303651252240316, 4611545289527980287,
       4611624273979637663, 540713362012373308, 16141587224142604295, 71776630169657358, 14876484648961052390, 18441381755496824057, 14123288015358917695,
       18229515760231317503, 18338631053721108423, 18338631286798581735, 4107252058802078671, 13944147184284073500, 15789195264061455, 4311859204, 4096, 0, 0,
       0, 9223372037123211264, 4469378955280385, 18302629980850364384, 35993612914786307, 18374704063267766208, 36024433330094087, 13835066851375184896,
       18445618174876450815, 18446743523953999871, 144115187807420479, 17592185978880, 18158513699705323488, 18446462598733103103, 72057456598974495,
       8796025913344, 1073725440, 18374686479671754744, 15, 0, 52]
logo_size = 300
logos = []
canvas = Canvas(root, width=logo_size, height=logo_size, bg="black", bd=0, highlightthickness=0)
canvas.place(x=310, y=(600 - logo_size) // 4)
chat_history = Listbox(root, bg="black", fg="#0f0")
notifications = False


def redraw_logo():
    canvas.delete("all")
    img = logos[random_int(0, len(logos) - 1)]
    canvas.create_image((logo_size // 2, logo_size // 2), image=img, state="normal")
    canvas.after(200, redraw_logo)


def prepare_logo():
    for f in range(10):
        img = PhotoImage(width=logo_size, height=logo_size)
        img.blank()
        for y in range((124) // 2):
            for x in range(logo[-1]):
                if isbitset(logo, x, y):
                    img.put("green" if random_int(0, 2) else "lime", (x << 2, y << 2))
        logos.append(img)


def isbitset(a, x, y):
    px = (y * a[len(a) - 1] + x)
    return ((a[px >> 6] & (1 << (px & 63)))) > 0


def chat_listener():
    main_font = font.Font()
    while True:
        try:
            data = rcv_cmd(sock)
            if not data:
                sleep(.1)
                continue
            data = json.loads(data)
            if data['cmd'] == 'join_request':
                snd_cmd(sock, messagebox.askquestion('Confirmation', 'User <' + data['args'][0] + '> wants to join. Accept?'))
            elif data['cmd'] == 'inbox':
                message = bytearray.fromhex(data['args'][1])
                message = get_decode(message, chat_key).decode('cp1251')
                msg_text = datetime.now().strftime("%H:%M") + ' <' + data['args'][0] + '>: ' + message
                msg_buf = ''
                counter = chat_history.size()
                for i in msg_text:
                    while main_font.measure(msg_buf + i) > 540:
                        if ' ' in msg_buf:
                            pos = msg_buf.rindex(' ')
                            if pos == 0:
                                chat_history.insert(END, (' '*10 if chat_history.size() != counter else '') + msg_buf)
                                msg_buf = ''
                            else:
                                chat_history.insert(END, (' '*10 if chat_history.size() != counter else '') + msg_buf[:pos])
                                msg_buf = msg_buf[pos:]
                        else:
                            chat_history.insert(END, (' '*10 if chat_history.size() != counter else '') + msg_buf)
                            msg_buf = ''
                    msg_buf += i
                chat_history.insert(END, (' '*10 if chat_history.size() != counter else '') + msg_buf)
                chat_history.see(END)
                if notifications:
                    beep(sound=1)
            elif data['cmd'] == 'popup':
                messagebox.showinfo(title="Info", message=data['args'])
            else:
                chat_history.insert(END, datetime.now().strftime("%H:%M") + ' <' + data['args'][0] + '>: ' + data['args'][1])
                chat_history.see(END)
        except:
            sleep(.1)


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((ipv4, port))
except ConnectionRefusedError:
    root.withdraw()
    messagebox.showwarning(title="Warning", message="Could not connect to Server " + str(ipv4) + ':' + str(port))
    os.kill(os.getpid(), SIGTERM)
try:
    fpublicity_button("Create Room", window_create_room).place(x=5, y=5, width=200, height=70)
    fpublicity_button("Enter Room", window_enter_room).place(x=5, y=85, width=200, height=70)
    fpublicity_button("Register Room", window_register_room).place(x=5, y=165, width=200, height=70)
    fpublicity_button("Generate Key", lambda: genkey(1024**2, 'key' + str(random_int(1000000, 9999999)) + '.bin')).place(x=5, y=245, width=200, height=70)
    fpublicity_button("Help", window_help).place(x=5, y=325, width=200, height=70)
except:
    os.kill(os.getpid(), SIGTERM)
root.protocol("WM_DELETE_WINDOW", lambda: os.kill(os.getpid(), SIGTERM))
canvas.after(100, redraw_logo)
prepare_logo()
root.mainloop()
