#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import socket


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('0.0.0.0', 1234)
    client_socket.connect(server_address)

    try:
        while True:
            sender = input("Wpisz nadawcę: ")
            recipient = input("Wpisz odbiorcę: ")
            text = input("Wpisz treść wiadomości: ")

            message = "SEND_MESSAGE\n{}\n{}\n{}\n\n".format(sender, recipient, text)
            client_socket.sendall(message.encode())
            print("Wysłano wiadomość do serwera")

            
            print("Oczekiwanie na odpowiedź serwera...")
            response = client_socket.recv(13)
            if len(response) == 0:
                print("Nie otrzymano odpowiedzi od serwera")
            else:
                print("Odpowiedź serwera:", response.decode())

    except KeyboardInterrupt:
        print("Zamykanie klienta...")

    finally:

        client_socket.close()

if __name__ == '__main__':
    main()