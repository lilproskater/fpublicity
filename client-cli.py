#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import os
import json
import hashlib
import threading
import curses
import sys
from datetime import datetime
from signal import SIGTERM
from re import match as re_match
from argparse import ArgumentParser
from getpass import getpass
from random import randint as random_int
from time import sleep


class Argparser(ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.stderr.write(f"\nError: {message}\n")
        sys.exit(2)


class Layout:
    TITLE_ROWS = 1
    PROMPT_ROWS = 1

    def __init__(self):
        self.rows, self.cols = Layout.terminal_size()
        # Calculate dimensions of each window
        self.title_rows = Layout.TITLE_ROWS
        self.title_cols = self.cols
        self.title_start_row = 0
        self.title_start_col = 0

        self.history_rows = self.rows - Layout.TITLE_ROWS - Layout.PROMPT_ROWS
        self.history_cols = self.cols
        self.history_start_row = 1
        self.history_start_col = 0

        self.prompt_rows = Layout.PROMPT_ROWS
        self.prompt_cols = self.cols
        self.prompt_start_row = self.rows - 1
        self.prompt_start_col = 0

    @staticmethod
    def terminal_size():
        rows, cols = os.popen('stty size', 'r').read().split()
        return int(rows), int(cols)


class Title:
    def __init__(self, layout, title, screen):
        self.window = curses.newwin(layout.title_rows, layout.title_cols,
            layout.title_start_row, layout.title_start_col)
        start_col = (layout.title_cols - len(title)) // 2
        self.window.addstr(0, start_col, title, curses.A_BOLD)

    def redraw(self):
        self.window.refresh()


class History:
    def __init__(self, layout, screen):
        self.messages = []
        self.layout = layout
        self.screen = screen
        self.window = curses.newwin(layout.history_rows, layout.history_cols,
            layout.history_start_row, layout.history_start_col)
        # Because of border, the number of visible rows/cols is fewer
        self.visible_rows = self.layout.history_rows - 2
        self.visible_cols = self.layout.history_cols - 2

    def append(self, msg):
        self.messages.append(msg)

    def redraw(self):
        self.window.clear()
        self.window.border(0)
        # Draw the last messages, count - number of visible rows
        row = 1
        for msg in self.messages[-self.visible_rows:]:
            self.window.move(row, 1)
            self.window.addstr(msg)
            row += 1
        self.window.refresh()


class Prompt:
    def __init__(self, layout, screen):
        self.layout = layout
        self.screen = screen
        self.window = curses.newwin(layout.prompt_rows, layout.prompt_cols,
            layout.prompt_start_row, layout.prompt_start_col)
        self.window.keypad(True)
        self.window.addstr('> ')

    def getchar(self):
        return self.window.getch()

    def getstr(self):
        return self.window.getstr()

    def redraw(self):
        self.window.refresh()

    def reset(self, text='> '):
        self.window.clear()
        self.window.addstr(text)
        self.redraw()


class FpublicityCLI:
    running = False
    def __init__(self):
        self.layout = Layout()
        self.screen = None
        self.confirm_pop_up = False


    def _start_curses(self):
        if FpublicityCLI.running:
            raise Exception("Curses is already running")
        self.screen = curses.initscr()
        curses.cbreak()
        self.screen.keypad(True)
        FpublicityCLI.running = True

    def _stop_curses(self):
        if not FpublicityCLI.running:
            raise Exception("Curses is not running")
        curses.nocbreak()
        self.screen.keypad(False)
        self.screen = None
        curses.endwin()
        FpublicityCLI.running = False

    def redraw(self):
        self.screen.refresh()
        self.history.redraw()
        self.title.redraw()
        self.prompt.redraw()

    # def save_chat():
    #     with open('room_' + str(room_id) + '_' + str(int(datetime.now().timestamp())) + '.txt', 'w') as f:
    #         f.write('\n'.join([i for i in chat_history.get(0, END)]))  # self.history
    #     messagebox.showinfo(title="Saved", message="Successfully saved chat!")

    def chat_listener(self):
        while True:
            try:
                data = rcv_cmd(sock)
                if not data:
                    sleep(.1)
                    continue
                data = json.loads(data)
                if data['cmd'] == 'join_request':
                    self.confirm_pop_up = True
                    self.prompt.reset('User <' + data['args'][0] + '> wants to join. Accept (y/yes)? ')
                elif data['cmd'] == 'inbox':
                    message = bytearray.fromhex(data['args'][1])
                    message = get_decode(message, chat_key).decode('cp1251')
                    msg_text = datetime.now().strftime("%H:%M") + ' <' + data['args'][0] + '>: ' + message
                    self.history.append(msg_text)
                elif data['cmd'] == 'popup':
                    self.history.append('Info from server: ' + data['args'])
                else:
                    self.history.append(datetime.now().strftime("%H:%M") + ' <' + data['args'][0] + '>: ' + data['args'][1])
                self.redraw()
            except:
                sleep(.1)


    def start(self):
        try:
            # Start curses and initialize all curses-based objects
            self._start_curses()
            self.title = Title(self.layout, "fpublicity cli v0.1.0", self.screen)
            self.history = History(self.layout, self.screen)
            self.prompt = Prompt(self.layout, self.screen)
            self.redraw()
            threading.Thread(target=self.chat_listener).start()
            # Run the main loop
            while True:
                message = self.prompt.getstr().decode('cp1251')
                if self.confirm_pop_up:
                    snd_cmd(sock, message)
                    self.confirm_pop_up = False
                    self.prompt.reset()
                    continue
                clear_input = False
                if not message.strip():
                    continue
                if message[0] == '/':
                    first_space = message.find(' ')
                    message = [message[:first_space], message[first_space + 1:]] if first_space != -1 else [message, '']
                    commands = ('/change_room_key', '/kick', '/delete_room', '/info', '/change_password', '/sound')
                    if message[0] in commands:
                        clear_input = True
                    if message[0] == '/change_room_key':
                        file_path = message[1]
                        try:
                            new_hash = hashlib.md5(getkey(file_path)).hexdigest()
                            snd_cmd(sock, jsonfy_request('set_room_key', (new_hash,)))
                        except FileNotFoundError:
                            self.history.append("Error: File " + file_path + " is not found!")
                            self.redraw()
                    if message[0] == '/exit':
                        self.stop()
                        os.kill(os.getpid(), SIGTERM)
                    if message[0] == '/kick':
                        snd_cmd(sock, jsonfy_request('kick_user', (message[1],)))
                    if message[0] == '/delete_room':
                        snd_cmd(sock, jsonfy_request('delete_room', ("",)))
                    if message[0] == '/info':
                        snd_cmd(sock, jsonfy_request('room_info', ("",)))
                    if message[0] == '/change_password':
                        if not message[1]:
                            self.history.append("Password cannot be empty!")
                            self.redraw()
                        else:
                            snd_cmd(sock, jsonfy_request('change_password', (hash_md5(message[1]),)))
                else:
                    if key_hash() == '0':
                        self.prompt.reset()
                        self.history.append("You need to set room key first. Use /change_room_key <file name>")
                        self.redraw()
                        continue
                    message = message.replace('\n', ' ')
                    try:
                        message = bytearray(message.encode('cp1251'))
                    except:
                        self.history.append("Cannot encode some characters. Use cp1251 only")
                        self.redraw()
                    else:
                        encoded_msg = get_encode(message, chat_key)
                        if not encoded_msg:
                            self.history.append("Message is too long. Type something shorter")
                            self.redraw()
                        else:
                            encoded_msg = ''.join([format(x, '02x') for x in encoded_msg])
                            snd_cmd(sock, jsonfy_request('broadcast', (encoded_msg,)))
                            clear_input = True
                if clear_input:
                    self.prompt.reset()
        # Ignore keyboard interrupts and exit cleanly
        except:
            self.stop()
            os.kill(os.getpid(), SIGTERM)


    def stop(self):
        self._stop_curses()


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
    print(f"Info: Generated key. New key file: ({file_path})")


def getkey(file_path):
    with open(file_path, 'rb') as f:
        key = f.read()
    return key


args = parse_args()
ipv4, port = args.ip, args.port
chat_key = ''
if args.key:
    try:
        chat_key = getkey(args.key)
    except FileNotFoundError:
        exit('KeyFile "' + args.key + '" was not found')
if not re_match(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", ipv4):
    exit("Given IP is invalid")
if not port in range(1, 65354):
    exit("Given port is invalid")


def rcv_cmd(connection):
    data = bytearray()
    while True:
        try:
            chunk = connection.recv(1)
            if chunk == b'\n':
                if data in (b"Password has been changed successfully!", ):
                    print('Info: ' + data.decode('utf-8'))
                else:
                    return data.decode('utf-8')
            if not chunk:
                print("No connection: Connection has been dropped by server")
                os.kill(os.getpid(), SIGTERM)
            data += chunk
            if len(data) > 1536:
                return
        except:
            print("No connection: Connection has been dropped by server")
            os.kill(os.getpid(), SIGTERM)


def wait_rcv_cmd(connection):
    while True:
        data = rcv_cmd(connection)
        if not data:
            continue
        return data


def snd_cmd(connection, cmd):
    try:
        connection.send((cmd + '\n').encode('utf-8'))
    except:
        print("No connection: Connection has been dropped by server")
        os.kill(os.getpid(), SIGTERM)


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


def create_room_window():
    def create_room(room_name, username, password):
        snd_cmd(sock, jsonfy_request('create_room', (str(room_name), str(username), str(hash_md5(password)))))
        print("Your Room id: " + str(wait_rcv_cmd(sock)))
        os.kill(os.getpid(), SIGTERM)
    username = input('Username: ')
    password = getpass('Password: ')
    room_name = input('Room name: ')
    create_room(room_name, username, password)


def window_chat(room_id):
    # 950605819 lilproskater 123
    fpublicity_cli = FpublicityCLI()
    fpublicity_cli.start()


def enter_room_window():
    def login_room(room_id, username, password):
        snd_cmd(sock, jsonfy_request('login_room', (room_id, username,)))
        salt = wait_rcv_cmd(sock)
        snd_cmd(sock, hash_md5(key_hash() + salt + hash_md5(password)))
        login_response = str(wait_rcv_cmd(sock))
        if login_response != 'Logged in':
            print("Error: " + login_response)
            os.kill(os.getpid(), SIGTERM)
        window_chat(room_id)
    room_id = input('Room id: ')
    username = input('Username: ')
    password = getpass('Password: ')
    login_room(room_id, username, password)


def register_room_window():
    def registrate_room(room_id, username, password):
        snd_cmd(sock,
                jsonfy_request('registrate_room', (str(room_id), key_hash(), str(username), str(hash_md5(password)))))
        reg_response = str(wait_rcv_cmd(sock))
        print("Info: " + reg_response)
        if reg_response == "Wait until admin will accept you":
            print("Info: " + str(wait_rcv_cmd(sock)))
        os.kill(os.getpid(), SIGTERM)
    room_id = input('Room id: ')
    username = input('Username: ')
    password = getpass('Password: ')
    registrate_room(room_id, username, password)


def generate_key_window():
    genkey(1024 ** 2, 'key' + str(random_int(1000000, 9999999)) + '.bin')


def help_window():
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
    print(help_text)


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10.0)
try:
    sock.connect((ipv4, port))
except (ConnectionRefusedError, socket.timeout):
    print("Error: Could not connect to Server " + str(ipv4) + ':' + str(port))
    os.kill(os.getpid(), SIGTERM)
sock.settimeout(None)
print('Actions:\n1. Create Room\n2. Enter Room\n3. Register Room\n4. Generate Key\n5. Help')
try:
    choice = int(input('Choose action: '))
    if choice not in range(1, 6):
        print('Error: Invalid action chosen')
    function = [create_room_window, enter_room_window, register_room_window, generate_key_window, help_window]
    function[choice-1]()
except:
    os.kill(os.getpid(), SIGTERM)
