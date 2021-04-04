import socket
import threading
import sqlite3
import sys
import json
import hashlib
from argparse import ArgumentParser
from errno import EADDRNOTAVAIL, EADDRINUSE
from re import match as re_match
from random import randint as random_int, choice as random_choice
from time import time, sleep


def sql_exec(sql):
    db_connection = sqlite3.connect('data.sqlite')
    db_cursor = db_connection.cursor()
    db_cursor.execute(sql)
    db_connection.commit()
    fetched_cursor = db_cursor.fetchall()
    db_cursor.close()
    db_connection.close()
    return fetched_cursor


def rcv_cmd(connection):
    data1 = bytearray()
    while True:
        try:
            data = connection.recv(1)
            if data == b'\n':
                return data1.decode('utf-8')
            if not len(data):
                return
            data1 += data
            if len(data1) > 1536:
                return
        except socket.timeout:
            if connection.fileno() == -1:
                return "Closed"
            continue
        except:
            return "Closed"


def wait_rcv_cmd(connection):
    while True:
        data = rcv_cmd(connection)
        if not data:
            continue
        return data


def hash_md5(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()


def snd_cmd(connection, cmd):
    connection.send((str(cmd) + '\n').encode('utf-8'))


def db_contoller():
    while True:
        sql_exec(f"""DELETE FROM rooms WHERE last_message < {int(time()) - 90 * 86400}""")  # 3 months inactive groups
        sleep(3600)


sql_exec("""CREATE TABLE IF NOT EXISTS rooms (
            room_id INTEGER PRIMARY KEY,
            room_name VARCHAR(30),
            admin_username VARCHAR(16),
            user_keys TEXT,
            key_hash VARCHAR(32),
            last_message INTEGER
         );""")

connections_handler = []


def create_room(room_name, admin_username, pwd_hash):
    admin_username = admin_username.lower()
    if not re_match(r'^[A-z0-9._А-яЁё]{3,30}', admin_username):
        return "Invalid room name"
    if not re_match(r'^[A-z0-9._]{3,16}', admin_username):
        return "Invalid admin username"
    room_id = random_int(-2000000000, 2000000000)
    while sql_exec(f"""SELECT * FROM rooms WHERE room_id = {room_id}"""):
        room_id = random_int(-2000000000, 2000000000)
    sql_exec(f"""INSERT INTO rooms VALUES(
                {room_id},
                '{room_name}',
                '{admin_username}',
                '{admin_username};{pwd_hash}',
                '0',
                {int(time())}
            );""")
    return room_id


def set_room_key(room_id, key_hash):
    sql_exec(f"""
            UPDATE rooms
            SET key_hash = '{key_hash}'
            WHERE room_id = {room_id}
        """)


def login_room(room_id, username):
    username = username.lower()
    data = sql_exec(f"""
            SELECT key_hash, user_keys FROM rooms WHERE room_id={room_id}
        """)
    if not len(data):
        return None, None
    for user in data[0][1].split(','):
        if user.split(';')[0] == username:
            return data[0][0], user.split(';')[1]
    return None, None


def can_registrate(room_id, key_hash, username, pwd_hash):
    username = username.lower()
    data = sql_exec(f"""
            SELECT user_keys FROM rooms WHERE room_id={room_id} AND key_hash='{key_hash}'
        """)
    if not data:
        return "Invalid room credentials"
    for i in data[0][0].split(','):
        if i.split(';')[0] == username:
            return "Username already exists"
    return True


def registrate_user(room_id, username, pwd_hash):
    username = username.lower()
    data = sql_exec(f"""
            SELECT user_keys FROM rooms WHERE room_id={room_id}
        """)
    if not data:
        return "Invalid room credentials"
    sql_exec(f"""UPDATE rooms SET user_keys='{data[0][0] + ',' + username + ';' + pwd_hash}' WHERE room_id={room_id}""")


def room_delete(room_id):
    sql_exec(f"""DELELTE FROM rooms WHERE room_id={room_id}""")


def kick_user(room_id, username):
    username = username.lower()
    data = sql_exec(f"""
            SELECT user_keys FROM rooms WHERE room_id={room_id}
        """)
    if not data:
        return False
    data = data[0][0].split(',')
    for i in range(len(data)):
        if data[i].split(';')[0] == username:
            data.pop(i)
            sql_exec(f"""UPDATE rooms SET user_keys='{','.join(data)}'""")
            for connection_handler in connections_handler:
                if connection_handler.room_id == room_id and connection_handler.username == username:
                    connection_handler.connection.close()
            return True
    return False


def get_room_admin(room_id):
    for connection_handler in connections_handler:
        if connection_handler.room_id == room_id and connection_handler.is_admin:
            return connection_handler
    return


def change_password(room_id, username, new_pwd_hash):
    data = sql_exec(f"""SELECT user_keys FROM rooms WHERE room_id={room_id}""")[0][0].split(',')
    for i in range(len(data)):
        if data[i].split(';')[0] == username:
            data[i] = username + ';' + new_pwd_hash
    sql_exec(f"""UPDATE rooms SET user_keys='{",".join(data)}' WHERE room_id={room_id}""")


def broadcast(room_id, username, message):
    if not message.strip():
        return
    for connection_handler in connections_handler:
        try:
            if connection_handler.room_id == room_id:
                snd_cmd(connection_handler.connection, json.dumps({"cmd": "inbox", "args": [username, message]}))
        except:
            pass


def broadcast_info(room_id, username, message):
    if not message.strip():
        return
    for connection_handler in connections_handler:
        try:
            if connection_handler.room_id == room_id:
                snd_cmd(connection_handler.connection, json.dumps({"cmd": "info", "args": [username, message]}))
        except:
            pass


def is_user_online(room_id, username):
    for connection_handler in connections_handler:
        try:
            if connection_handler.room_id == room_id and connection_handler.username == username:
                return True
        except:
            pass
    return False


def get_room_info(room_id):
    data = sql_exec(f"""SELECT room_name, user_keys FROM rooms WHERE room_id={room_id}""")
    usernames = [user.split(';')[0] for user in data[0][1].split(',')]
    for i in range(len(usernames)):
        if is_user_online(room_id, usernames[i]):
            usernames[i] = '*' + usernames[i]
    return "room_name: " + data[0][0] + '; ' + "users: " + ", ".join(usernames)


def delete_room(room_id):
    sql_exec(f"""DELETE FROM rooms WHERE room_id={room_id}""")


class Argparser(ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.stderr.write(f"\nError: {message}\n")
        sys.exit(2)


def parse_args(socket_host):
    argparser = Argparser()
    argparser.add_argument('-i', '--ip', help="IP to listen [Default value - " + socket_host + "]", default=socket_host)
    argparser.add_argument('-p', '--port', help="Port to listen", type=int, required=True, action="store")
    return argparser.parse_args()


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
args = parse_args(socket.gethostbyname(socket.gethostname()))
ipv4, port = args.ip, args.port
if not re_match(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", ipv4):
    exit("Given IP is invalid")

try:
    server_socket.bind((ipv4, port))
except PermissionError:
    exit(f"Permission denied for port {port}")
except OverflowError:
    exit("Port must be in range of 0-65535")
except OSError as e:
    if e.errno == EADDRNOTAVAIL:
        exit(f"Could not listen on {ipv4}")
    elif e.errno == EADDRINUSE:
        exit(f"Port {port} is already in use")

server_socket.listen()
print('Listening at', str(ipv4) + ':' + str(port) + ' ...')


class ConnectionHandler:
    def __init__(self, connection, ip):
        self.ip = ip
        self.room_id = 0
        self.key_hash = '0'
        self.username = ''
        self.pwd_hash = ''
        self.is_admin = False
        self.admin_request = ''
        self.connection = connection

    def connection_handler(self):
        try:
            while True:
                sleep(.1)
                data = wait_rcv_cmd(self.connection)
                if data == "Closed":
                    break
                data = json.loads(data)
                if data['call_func'] == 'create_room':
                    snd_cmd(self.connection, create_room(*data['args']))
                    break
                if data['call_func'] == 'registrate_room':
                    if can_registrate(*data['args']) != True:
                        snd_cmd(self.connection, "You cannot join this room")
                        break
                    room_admin = get_room_admin(data['args'][0])
                    if not room_admin:
                        snd_cmd(self.connection, "Admin is not online")
                        break
                    if room_admin.admin_request == 'busy':
                        snd_cmd(self.connection, "Admin is already accepting another user")
                        break
                    room_admin.admin_request = 'busy'
                    snd_cmd(room_admin.connection, json.dumps({"cmd": "join_request", "args": [data['args'][2]]}))
                    while room_admin.admin_request == 'busy':
                        sleep(.1)
                    if room_admin.admin_request.lower() not in ('yes', 'y'):
                        snd_cmd(self.connection, "Admin has not accepted you")
                        break
                    room_admin.admin_request = ''
                    registrate_user(data['args'][0], data['args'][2], data['args'][3])
                    snd_cmd(self.connection, "Admin accepted you")
                    broadcast_info(room_admin.room_id, room_admin.username, f"Admin has accepted \"{data['args'][2]}\" to the room")
                    break
                if data['call_func'] == 'login_room':
                    room_key_hash, login_pwd_hash = login_room(data['args'][0], data['args'][1])
                    salt = "".join([random_choice("abcdefghigklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789") for _ in range(32)])
                    snd_cmd(self.connection, salt)
                    client_response = wait_rcv_cmd(self.connection)
                    if (not room_key_hash) or (hash_md5(room_key_hash + salt + login_pwd_hash) != client_response):
                        snd_cmd(self.connection, "Invalid credentials")
                        break
                    data['args'] = [data['args'][0], room_key_hash, data['args'][1], login_pwd_hash]
                    already_logged = False
                    for connection_handler in connections_handler:
                        if connection_handler.room_id == data['args'][0] and connection_handler.username == data['args'][2].lower():
                            already_logged = True
                            break
                    if already_logged:
                        snd_cmd(self.connection, "Username is already logged in")
                        break
                    self.room_id = data['args'][0]
                    self.key_hash = data['args'][1]
                    self.username = data['args'][2].lower()
                    self.pwd_hash = data['args'][3]
                    if self.username == sql_exec(f"""SELECT admin_username FROM rooms WHERE room_id={self.room_id}""")[0][0]:
                        self.is_admin = True
                    sql_exec(f"""
                            UPDATE rooms SET last_message={int(time())} WHERE room_id={self.room_id}
                        """)
                    snd_cmd(self.connection, "Logged in")
                    broadcast_info(self.room_id, self.username, f"User \"{self.username}\" has joined to the room")
                while True:  # chat Loop
                    data = rcv_cmd(self.connection)
                    if data == "Closed":
                        break
                    elif not data:
                        sleep(.1)
                        continue
                    if self.admin_request == 'busy':
                        data = 'no' if data == 'busy' else data
                        self.admin_request = data
                        continue
                    data = json.loads(data)
                    if data['call_func'] == 'broadcast':
                        broadcast(self.room_id, self.username, data['args'][0])
                    if data['call_func'] == 'kick_user' and self.is_admin:
                        if kick_user(self.room_id, data['args'][0]):
                            broadcast_info(self.room_id, self.username, f"User \"{data['args'][0]}\" has been kicked from room")
                        else:
                            snd_cmd(self.connection, "User has not been kicked")
                    if data['call_func'] == 'room_info':
                        snd_cmd(self.connection, json.dumps({'cmd': 'popup', 'args' : get_room_info(self.room_id)}))
                    if data['call_func'] == 'change_password':
                        change_password(self.room_id, self.username, data['args'][0])
                        snd_cmd(self.connection, "Password has been changed successfully!")
                        break
                    if data['call_func'] == 'delete_room' and self.is_admin:
                        delete_room(self.room_id)
                        broadcast_info(self.room_id, self.username, f"This room has been deleted!")
                    if data['call_func'] == 'set_room_key' and self.is_admin:
                        set_room_key(self.room_id, data['args'][0])
                        broadcast_info(self.room_id, self.username, f"Room key has been changed!")
                        for connection_handler in connections_handler:
                            if connection_handler.room_id == self.room_id:
                                try:
                                    connection_handler.connection.close()
                                    connections_handler.pop(connections_handler.index(connection_handler))
                                except:
                                    pass
                break
        except:
            pass
        try:
            if self.room_id:
                broadcast_info(self.room_id, self.username, f"User \"{self.username}\" has left the room")
        except:
            pass
        try:
            self.connection.close()
        except:
            pass
        try:
            connections_handler.pop(connections_handler.index(self))
        except:
            pass


threading.Thread(target=db_contoller).start()
while True:
    connection, address = server_socket.accept()
    address = address[0]
    connection.settimeout(5.0)
    connections_ip = [connection_handler.ip for connection_handler in connections_handler]
    if connections_ip.count(address) < 2:  # No more than 2 connections for 1 ip
        handler = ConnectionHandler(connection, address)
        connections_handler.append(handler)
        threading.Thread(target=handler.connection_handler).start()
    else:
        connection.close()
