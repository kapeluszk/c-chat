import sys
import tkinter as tk
import ttkbootstrap as ttk
import tkinter.simpledialog
import threading
import socket
import ipaddress
import queue
import time
from utils import sanitize_outgoing_msg, sanitize_incoming_msg, timestamp, recv_until_newline

# Kody komunikatów
SEND_MESSAGE = " 1"
GET_USER_LIST = " 2"
GET_ALL_MESSAGES = " 3"
CHECK_USER_STATUS = " 4"
CHECK_IF_USER_EXISTS = " 5"
EXISTS = " 6"
NOT_EXISTS = " 7"
LOGIN = " 8"
LOGIN_OK = " 9"
LOGIN_NOT_OK = "10"
LOGOUT = "11"
LOGOUT_OK = "12"
LOGOUT_NOT_OK = "13"


chat_lock = threading.Lock()
contacts_lock = threading.Lock()

######### DEFINICJE WIADOMOŚCI I CZATU #########

class Message:
    def __init__(self, communicate, sender, recipient, body, timestamp):
        self.communicate = communicate
        self.sender = sender
        self.recipient = recipient
        self.body = body
        self.timestamp = timestamp 

class Chat:
    def __init__(self, user1, user2, messages):
        self.user1 = user1
        self.user2 = user2
        self.messages = []
        self.status = 0 # 0 - offline, 1 - online
    
    def add_message(self, message):
        self.messages.append(message)

    def __str__(self):
        print("Chat między {} a {}\n".format(self.user1, self.user2))
        for message in self.messages:
            print("Od {}: {}\n".format(message.sender, message.body))
    
# Funkcja do wyszukiwania czatu - najpierw sprawdza, czy istnieje czat między user1 i user2, a jeśli nie, to sprawdza, czy istnieje czat między user2 i user1    
def find_chat(user1, user2, chats):
    for chat in chats:
        if chat.user1 == user1 and chat.user2 == user2:
            return chat
        elif chat.user1 == user2 and chat.user2 == user1:
            return chat
    return None
            
######### KONIEC DEFINICJI WIADOMOŚCI I CZATU #########


######### LOGOWANIE I WYLOGOWANIE #########

def logout(socket, current_user, system_info_queue):
    logout_packet = "{}\n{}\n\n".format(LOGOUT, current_user)
    socket.sendall(logout_packet.encode())
    response = system_info_queue.get(timeout=1)
    if response.communicate == LOGOUT_OK:
        return True
    else:
        return False
    
def close_app(working_flag, socket):
    print("Zamykanie klienta...")
    print("Zamykanie gniazda...")
    socket.close()
    working_flag.set()
    print("Zamykanie wątków...")
    for thread in threading.enumerate():
        if thread is not threading.main_thread():
            thread.join()
    
    sys.exit(0)

def on_close(socket,working_flag, current_user, system_info_queue):
    counter = 0
    while True:
        try:
            if logout(socket, current_user, system_info_queue):
                break
        except:
            if counter == 5:
                print("wylogowanie nie powiodło się po 5 próbach, zamykanie aplikacji awaryjnie")
                close_app(working_flag, socket)
            print("wylogowanie nie powiodło się, ponawiam próbę")
            counter += 1

    print("wylogowanie powiodło się")
    close_app(working_flag, socket)


def login(client_socket):
        response = recv_until_newline(client_socket)
        while True:
            login = tk.simpledialog.askstring("Logowanie", "Podaj login:")
            password = tk.simpledialog.askstring("Logowanie", "Podaj hasło:", show="*")
            login = sanitize_outgoing_msg(login)
            password = sanitize_outgoing_msg(password)
            
            if response == LOGIN or response == LOGIN_NOT_OK:
                login_msg = "{}\n{}\n{:02d}\n{}\n\n".format(LOGIN, login, len(password), password)
                client_socket.sendall(login_msg.encode())
            
            response = recv_until_newline(client_socket)

            if response == LOGIN_OK:
                break
            else:
                tk.messagebox.showerror("Błąd", "Niepoprawny login lub hasło")
        
        return login

def show_server_ip_popup():
    while True:
        server_ip = tk.simpledialog.askstring("Wybierz IP serwera", "Podaj IP serwera:")
        if server_ip:
            try:
                ipaddress.ip_address(server_ip)
                return server_ip
            except ValueError:
                tk.messagebox.showerror("Błąd", "Niepoprawny adres IP. Spróbuj ponownie.")
        else:
            tk.messagebox.showerror("Błąd", "Niepoprawny adres IP. Spróbuj ponownie.")


def start_connection():
    while True:
        try:
            server_ip = show_server_ip_popup()
            
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = (server_ip, 1234)

            client_socket.connect(server_address)
            break
        except ConnectionRefusedError:
            tk.messagebox.showerror("Błąd", "Nie można połączyć się z serwerem, spróbuj ponownie.")

    return client_socket

######### KONIEC LOGOWANIA I WYLOGOWANIA #########

######### PRZETWARZANIE WIADOMOŚCI #########

# funkcja przetwarzająca wiadomości - sprawdza kod komunikatu i wykonuje odpowiednie akcje
def process_message(message, current_user, chats, contacts, system_info_queue, system_info_queue2, messages_queue):
    
    mess = message.split("\n",1)
    if mess[0] == SEND_MESSAGE:
        message = mess[1].split("\n")
        msg = Message(SEND_MESSAGE, message[0], current_user, sanitize_incoming_msg(message[1]), timestamp())
        messages_queue.put(msg)
    elif mess[0] == GET_USER_LIST:
        list_of_users = mess[1].split("/USER_END")
        list_of_users.remove("\n\n")
        for user in list_of_users:
            with chat_lock:
                contacts.append(user)
                chat = Chat(current_user, user, [])
                chats.append(chat)
    elif mess[0] == GET_ALL_MESSAGES:
        list_of_messages = mess[1].split("/MSG_END")
        
        list_of_messages[0] = sanitize_incoming_msg(list_of_messages[0])
        first_message = list_of_messages[0].split("\n")
        if find_chat(first_message[0], first_message[1], chats) is None:
            chat = Chat(first_message[0], first_message[1], [])
            with chat_lock:
                chats.append(chat)
        else:
            chat = find_chat(first_message[0], first_message[1], chats)

        for i in range(0, len(list_of_messages)-1):
            list_of_messages[i] = sanitize_incoming_msg(list_of_messages[i])
            message = list_of_messages[i].split("\n")
            new_message = Message(SEND_MESSAGE, message[0], message[1], message[2], message[3])
            with chat_lock:
                chat.add_message(new_message)
    elif mess[0] == EXISTS:
        system_info_queue2.put(Message(EXISTS, "SERVER", current_user, "", timestamp()))
    elif mess[0] == NOT_EXISTS:
        system_info_queue2.put(Message(NOT_EXISTS, "SERVER", current_user, "", timestamp()))
    elif mess[0] == LOGOUT_OK:
        system_info_queue.put(Message(LOGOUT_OK, "SERVER", current_user, "", timestamp()))
    elif mess[0] == LOGOUT_NOT_OK:
        system_info_queue.put(Message(LOGOUT_NOT_OK, "SERVER", current_user, "", timestamp()))
    elif mess[0] == CHECK_USER_STATUS:
        messages = mess[1].split("\n")
        status = int(messages[1])
        with chat_lock:
            chat = find_chat(messages[0], current_user, chats)
            chat.status = status
        system_info_queue.put(Message(CHECK_USER_STATUS, message[0], current_user, status, timestamp()))
    else:
        pass

# funkcja odbierająca wiadomości od serwera uruchamiana w osobnym wątku
def recv_func(working_flag, socket, login, chats, contacts, system_info_queue, system_info_queue2, messages_queue):
    while not working_flag.is_set():
        response = recv_until_newline(socket)
        if response:
            process_message(response, login, chats, contacts, system_info_queue, system_info_queue2, messages_queue)

# funkcja odbierająca listę wszystkich użytkowników, z którymi wcześniej prowadzono rozmowy
def fetch_contacts(client_socket, login, contacts, chats, current_user):
    fetch_msg = "{}\n{}\n\n".format(GET_USER_LIST, login)
    client_socket.sendall(fetch_msg.encode())
    response = recv_until_newline(client_socket)
    msg = response.split("\n",1)
    if msg[0] == GET_USER_LIST:
        msg = response.split("\n",1)
        list_of_users = msg[1].split("/USER_END")
        list_of_users.pop()
        for user in list_of_users:

            contacts.append(user)
            with chat_lock:
                chat = Chat(current_user, user, [])
                chats.append(chat)
        
        return True
    else:
        tk.messagebox.showerror("Błąd", "Nie można pobrać listy kontaktów")
        return False

# funkcja pobierająca wszystkie wiadomości z serwera od użytkowników, z którymi wcześniej prowadzono rozmowy
def fetch_messages(client_socket, login, chats, contacts):
    for contact in contacts:
        fetch_msg = "{}\n{}\n{}\n\n".format(GET_ALL_MESSAGES, login, contact)
        client_socket.sendall(fetch_msg.encode())
        response = recv_until_newline(client_socket)
        
        msg = response.split("\n",1)
        if msg[0] == GET_ALL_MESSAGES:
            list_of_messages = msg[1].split("/MSG_END")
            
            list_of_messages[0] = sanitize_incoming_msg(list_of_messages[0])
            first_message = list_of_messages[0].split("\n")

            if find_chat(first_message[0], first_message[1], chats) is None:
                chat = Chat(first_message[0], first_message[1], [])
                chats.append(chat)
            else:
                chat = find_chat(first_message[0], first_message[1], chats)

            for i in range(0, len(list_of_messages)-1):

                list_of_messages[i] = sanitize_incoming_msg(list_of_messages[i])
                message = list_of_messages[i].split("\n")

                new_message = Message(SEND_MESSAGE, message[0], message[1], message[2], message[3])
                chat.add_message(new_message)
    return True

# funkcja sprawdzająca kolejkę wiadomości i dodająca je do odpowiednich czatów
def queue_checker(working_flag, messages_queue, chats, contacts_listbox, contacts):
    while not working_flag.is_set():
        if not messages_queue.empty():
            msg = messages_queue.get()
            with chat_lock:
                chat = find_chat(msg.sender, msg.recipient, chats)
            if chat is None:
                chat = Chat(msg.sender, msg.recipient, [])
                with chat_lock:
                    chats.append(chat)
                with contacts_lock:
                    contacts.append(msg.sender)
                contacts_listbox.insert(tk.END, msg.sender)
            with chat_lock:
                chat.add_message(msg)
        time.sleep(1)
        
######### KONIEC PRZETWARZANIA WIADOMOŚCI #########
        
######### OKNA CZATU #########

# funkcja sprawdzająca, czy użytkownik istnieje i jeśli tak, to czy istnieje już czat z nim
def start_chat(current_user, contact, chats, socket, system_info_queue2):
    check_packet = "{}\n{}\n\n".format(CHECK_IF_USER_EXISTS,contact)
    socket.sendall(check_packet.encode())
    try:
        response = system_info_queue2.get(timeout=1)
        print(response.communicate)
        if response.communicate == EXISTS:
            if find_chat(current_user, contact, chats) is None:
                with chat_lock:
                    chat = Chat(current_user, contact, [])
                    chats.append(chat)
            return True
        else:
            tk.messagebox.showerror("Błąd", "Użytkownik nie istnieje")
            return False
    except queue.Empty:
        tk.messagebox.showerror("Błąd", "Użytkownik nie istnieje")
        return False
    

def open_chat_window(current_user, contact, chats, socket):
    chat_window = ttk.Window()
    chat_window.title("Czat z {}".format(contact))
    chat_window.geometry("400x500")
    chat_window.resizable(False, False)
    

    chat = find_chat(current_user, contact, chats)
    messages = chat.messages

    messages_text = tk.Text(chat_window)
    messages_text.grid(row=0, column=0, columnspan=2, sticky='nsew')

    chat_window.grid_rowconfigure(0, weight=4)  # 80% wysokości dla messages_text
    chat_window.grid_columnconfigure(0, weight=1)  # 100% szerokości dla messages_text

    # sprawdza czy wiadomość nie jest dłuższa niż 250 znaków
    def validate_length(P):
        return len(P) <= 250

    vcmd = (chat_window.register(validate_length), '%P')

    message_entry = ttk.Entry(chat_window, validate='key', validatecommand=vcmd)
    message_entry.grid(row=1, column=0, sticky='nsew')
    message_entry.bind('<Return>', lambda event: on_send_button_click())

    # Funkcja do wysyłania wiadomości
    def on_send_button_click():
        message = message_entry.get()
        if message != "":
            message = sanitize_outgoing_msg(message)
            message_packet = "{}\n{}\n{}\n{}\n\n".format(SEND_MESSAGE, current_user, contact, message)
            socket.sendall(message_packet.encode())
            new_message = Message(SEND_MESSAGE, current_user, contact, message, timestamp())
            with chat_lock:
                chat.add_message(new_message)
            messages_text.insert(tk.END, "{} {}: {}\n".format(new_message.timestamp,current_user, message))
            message_entry.delete(0, tk.END)

    send_button = ttk.Button(chat_window, text="Wyślij", command=on_send_button_click)
    send_button.grid(row=1, column=1, sticky='nsew')

    chat_window.grid_rowconfigure(1, weight=1)  # 20% wysokości dla message_entry i send_button
    chat_window.grid_columnconfigure(0, weight=4)  # 80% szerokości dla message_entry
    chat_window.grid_columnconfigure(1, weight=1)  # 20% szerokości dla send_button

    status_label = ttk.Label(chat_window)
    status_label.grid(row=2, column=0, columnspan=2, sticky='nsew')

    # Funkcja do aktualizowania okna czatu
    def update_chat_window():
        if chat_window.winfo_exists():
            messages_text.delete(1.0, tk.END)

            for message in messages:
                messages_text.insert(tk.END, "{} {}: {}\n".format(message.timestamp,message.sender, message.body))
            
            contact_check_packet = "{}\n{}\n\n".format(CHECK_USER_STATUS, contact)
            socket.sendall(contact_check_packet.encode())
            if chat.status == 0:
                status_label.config(text="Użytkownik jest offline, może nie odczytać twojej wiadomości", foreground="red")
            else:
                status_label.config(text="Użytkownik jest online", foreground="green")

            update_id = chat_window.after(1000, update_chat_window)
            return update_id

    update_id = chat_window.after(1000, update_chat_window)
    

    def close_chat_window():
        chat_window.after_cancel(update_id)
        chat_window.destroy()

    chat_window.protocol("WM_DELETE_WINDOW", close_chat_window)


    chat_window.mainloop()


def main():
    
    root = ttk.Window( themename="darkly")
    root.protocol("WM_DELETE_WINDOW", lambda: on_close(client_socket,working_flag, current_user, system_info_queue))
    root.title("Komunikator")
    root.geometry("200x300")
    root.resizable(False, False)
    root.withdraw()
    
    client_socket = start_connection()
    working_flag = threading.Event() 
    current_user = login(client_socket)
    
    
    chat_list = []
    contacts = []
    messages_queue = queue.Queue()
    system_info_queue = queue.Queue()
    system_info_queue2 = queue.Queue()

    fetch_contacts(client_socket, current_user, contacts, chat_list, current_user)
    fetch_messages(client_socket, current_user, chat_list, contacts)

    recv_thread = threading.Thread(target=recv_func, args=(working_flag, client_socket, current_user, chat_list, contacts, system_info_queue, system_info_queue2, messages_queue))
    recv_thread.start()


    # przywrócenie wyświetlania okna głównego
    root.deiconify()

    greeting_label = tk.Label(master=root, text=f"Witaj, {current_user}!")
    greeting_label.pack(pady=10)

    # Przycisk do rozpoczęcia czatu z kimś spoza kontaktów
    start_chat_button = ttk.Button(root, text="Rozpocznij czat", bootstyle="primary" )
    start_chat_button.pack(padx=10, pady=10)

    # Lista kontaktów
    contacts_listbox = tk.Listbox(root)
    for contact in contacts:
        contacts_listbox.insert(tk.END, contact)
    contacts_listbox.pack()

    q_checker_thread = threading.Thread(target=queue_checker, args=(working_flag, messages_queue, chat_list, contacts_listbox, contacts))
    q_checker_thread.start()

    # Funkcja do otwierania okna czatu po kliknięciu na kontakt
    def on_contact_select(event):
        selected_contact = contacts_listbox.get(contacts_listbox.curselection())
        open_chat_window(current_user,selected_contact, chat_list, client_socket)
    
    # Funkcja do rozpoczęcia czatu z kimś spoza kontaktów
    def on_start_chat_button_click():
        while True:
            user_to_chat = tk.simpledialog.askstring("Rozpocznij czat", "Podaj nazwę użytkownika:")
            if user_to_chat == current_user:
                tk.messagebox.showerror("Błąd", "Nie możesz rozpocząć czatu ze sobą")
            else:
                if start_chat(current_user, user_to_chat, chat_list, client_socket, system_info_queue2):
                    if user_to_chat not in contacts:
                        with contacts_lock:
                            contacts.append(user_to_chat)
                        contacts_listbox.insert(tk.END, user_to_chat)
                    open_chat_window(current_user, user_to_chat, chat_list, client_socket)
                    break
                else:
                    break

    start_chat_button.config(command=on_start_chat_button_click)

    # "bindujemy" funkcję on_contact_select do zdarzenia kliknięcia na kontakt
    contacts_listbox.bind('<<ListboxSelect>>', on_contact_select)

    
    
    root.mainloop()
    
    # chyba niepotrzebne, bo wychodzi z pętli mainloop, ale na wszelki wypadek
    recv_thread.join()
    q_checker_thread.join()
    client_socket.close()
    print("Zamykanie klienta...")


if __name__ == "__main__":
    main()