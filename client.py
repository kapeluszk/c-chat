#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import socket

def recv_until_newline(client_socket):
    data = b""
    while not data.endswith("\n\n"):
        chunk = client_socket.recv(1024)
        if chunk == b'':
            break
        data += chunk
    return data

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('0.0.0.0', 1234)
    client_socket.connect(server_address)

    try:
        while True:
            sender = input("Wpisz nadawcę: ")

            message = "GET_ALL_MESSAGES\n{}\n\n".format(sender)
            client_socket.sendall(message.encode())
            print("Wysłano wiadomość do serwera")

            
            print("Oczekiwanie na odpowiedź serwera...")
            response = recv_until_newline(client_socket)
            if len(response) == 0:
                print("Nie otrzymano odpowiedzi od serwera")
            else:
                print("Odpowiedź serwera:", response)

    except KeyboardInterrupt:
        print("Zamykanie klienta...")

    finally:

        client_socket.close()

if __name__ == '__main__':
    main()