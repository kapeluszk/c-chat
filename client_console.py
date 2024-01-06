#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import socket
import threading
import json

class message:
    def __init__(self,comunicate, sender, recipient, body):
        self.comunicate = comunicate
        self.sender = sender
        self.recipient = recipient
        self.body = body

def process_message(msg, current_user):
    mess = msg.split("\n")
    if mess[0] == "MESSAGE":
        return message(mess[0], mess[1], current_user, mess[2])
    return mess
    

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
            message = "GET_ALL_MESSAGES\n{}\n\n".format(login)
            socket.sendall(message.encode())
            print("Wysłano wiadomość do serwera")
        elif choice == "3":
            socket.sendall("LOGOUT\n\n".encode())
            break
        else:
            print("Nieprawidłowy wybór")

def recv_func(socket, login):
    while True:
        response = recv_until_newline(socket)
        message = process_message(response, login)
        print("Otrzymano wiadomość od {}: {}".format(message.sender, message.body))
        

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('0.0.0.0', 1234)
    client_socket.connect(server_address)

    response = recv_until_newline(client_socket)
    while response != "LOGIN_OK":
        print(response)
        login = input("Wpisz login: ")
        password = input("Wpisz hasło: ")
        login_msg = "LOGIN\n{}\n{}\n\n".format(login, password)
        client_socket.sendall(login_msg.encode())
        print("Wysłano wiadomość do serwera")
        response = recv_until_newline(client_socket).strip()


    try:
        send_thread = threading.Thread(target=send_func, args=(client_socket, login))
        recv_thread = threading.Thread(target=recv_func, args=(client_socket, login))
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