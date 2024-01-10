
import datetime


def sanitize_outgoing_msg(msg):
    return msg.replace("\n", "\\n")

def sanitize_incoming_msg(msg):
    return msg.replace("\\n", "\n")

def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def recv_until_newline(client_socket):
    try:
        data = b""
        while not data.decode().endswith("\n\n"):
            chunk = client_socket.recv(1024)
            if chunk == b'':
                break
            data += chunk
        return data.decode().replace("\n\n", "")
    except:
        return None