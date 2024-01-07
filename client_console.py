#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import socket
import threading



class Message:
    def __init__(self,comunicate, sender, recipient, body):
        self.comunicate = comunicate
        self.sender = sender
        self.recipient = recipient
        self.body = body

class Chat:
    def __init__(self, user1, user2, messages):
        self.user1 = user1
        self.user2 = user2
        self.messages = []
    
    def add_message(self, message):
        self.messages.append(message)

    def __str__(self):
        print("Chat między {} a {}\n".format(self.user1, self.user2))
        for message in self.messages:
            print("Od {}: {}\n".format(message.sender, message.body))
            
def sanitize_message(msg):
    return msg.replace("\n", "")

def process_message(msg, current_user,chats):
    mess = msg.split("\n",1)
    if mess[0] == "MESSAGE":
        return message(mess[0], mess[1], current_user, sanitize_message(mess[2]))
    elif mess[0] == "DELIVERED":
        print("Wiadomość dostarczona do odbiorcy")
    elif mess[0] == "NOT_DELIVERED":
        print("Wiadomość nie dostarczona do odbiorcy")
    elif mess[0] == "ALL_MESSAGES":
        list_of_messages = mess[1].split("MSG_END")
        
        first_message = list_of_messages[0].split("/")
        chat = Chat(first_message[0], first_message[1], [])

        for i in range(0, len(list_of_messages)-1):
            message = list_of_messages[i].split("/")
            new_message = Message("MESSAGE", message[0], message[1], sanitize_message(message[2]))
            chat.add_message(new_message)

        chats.append(chat)



def recv_until_newline(client_socket):
    data = b""
    while not data.endswith("\n\n"):
        chunk = client_socket.recv(1024)
        if chunk == b'':
            break
        data += chunk
    return data

def send_func(socket, login):
    while True:
        print("1. Wyślij wiadomość\n 2. Wyświetl wiadomości\n 3. Wyjdź")
        choice = input("Wybierz opcję: ")
        if choice == "1":
            recipient = input("Podaj odbiorcę: ")
            message = input("Podaj wiadomość: ")
            message = "SEND_MESSAGE\n{}\n{}\n{}\n\n".format(login,recipient, message)
            socket.sendall(message.encode())
            print("Wysłano wiadomość do serwera")
            response = recv_until_newline(socket)
            print(response)
        elif choice == "2":
            recipient = input("Podaj od kogo wiadomości chcesz wyświetlić: ")
            message = "GET_ALL_MESSAGES\n{}\n{}\n\n".format(login, recipient)
            socket.sendall(message.encode())
            print("Wysłano wiadomość do serwera")
        elif choice == "3":
            socket.sendall("LOGOUT\n\n".encode())
            break
        else:
            print("Nieprawidłowy wybór")

def recv_func(socket, login, chats):
    while True:
        response = recv_until_newline(socket)
        process_message(response, login, chats)
        
        # if message.comunicate is not None:
        #     if message.comunicate == "LOGOUT_OK":
        #         print("Wylogowano")
        #         break
        #     else:
        #         print("Otrzymano wiadomość od {}: {}".format(message.sender, message.body))
        

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('0.0.0.0', 1234)
    client_socket.connect(server_address)

    response = recv_until_newline(client_socket)
    while response != "LOGIN_OK":
        login = input("Wpisz login: ")
        password = input("Wpisz hasło: ")
        login_msg = "LOGIN\n{}\n{}\n\n".format(login, password)
        client_socket.sendall(login_msg.encode())
        print("Wysłano wiadomość do serwera")
        response = recv_until_newline(client_socket).strip()

    chat_list = []

    try:
        send_thread = threading.Thread(target=send_func, args=(client_socket, login))
        recv_thread = threading.Thread(target=recv_func, args=(client_socket, login, chat_list))
        send_thread.start()
        recv_thread.start()
        send_thread.join()
        recv_thread.join()
    except KeyboardInterrupt:
        print("Zamykanie klienta...")
    finally:
        client_socket.close()

if __name__ == '__main__':
    main()