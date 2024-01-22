#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/wait.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sqlite3.h>

// ---------------sekcja z deklaracją kodów komunikatów-----------------

const char* SEND_MESSAGE = " 1";
const char* GET_USER_LIST = " 2";
const char* GET_ALL_MESSAGES = " 3";
const char* CHECK_USER_STATUS = " 4";
const char* CHECK_IF_USER_EXISTS = " 5";
const char* EXISTS = " 6";
const char* NOT_EXISTS = " 7";
const char* LOGIN = " 8";
const char* LOGIN_OK = " 9";
const char* LOGIN_NOT_OK = "10";
const char* LOGOUT = "11";
const char* LOGOUT_OK = "12";
const char* LOGOUT_NOT_OK = "13";

// ---------------sekcja z deklaracją listy uzytkownikow i funkcji do jej obslugi-----------------

//struktura przechowujaca informacje o polaczeniu z klientem
struct cln {
    int cfd;
    struct sockaddr_in caddr;
};

//lista uzytkownikow aktualnie zalogowanych
typedef struct user{
    int fd;
    char id[10];
    struct user *next;
} User;

User *users = NULL;



//funkcja zwraca fd uzytkownika o podanym id lub -1 jesli nie ma takiego uzytkownika
int find_user(char* id){
    User *current = users;
    while(current != NULL){
        // printf("im checking user: %s\n", current->id);
        // printf("result: %d\n", strcmp(current->id, id));
        if(strcmp(current->id, id) == 0){
            return current->fd;
        }
        current = current->next;
    }
    return -1;
}

void add_user(int fd, char* id){
    User *new_user = malloc(sizeof(User));
    new_user->fd = fd;
    strncpy(new_user->id, id, 10);
    new_user->next = users;
    users = new_user;
}

void delete_user(int fd){
    User *current = users;
    User *prev = NULL;
    while(current != NULL){
        if(current->fd == fd){
            if(prev == NULL){
                users = current->next;
            }else{
                prev->next = current->next;
            }
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

void list_users(){
    User *current = users;
    while(current != NULL){
        printf("%s\n", current->id);
        current = current->next;
    }
}

void delete_list(){
    User *current = users;
    while(current != NULL){
        User *next = current->next;
        free(current);
        current = next;
    }
}

// ---------------koniec sekcji listy-----------------

// ---------------sekcja z deklaracją funkcji zastepujacych read i write-----------------

//funkcja zastepujaca read - czyta dane az do napotkania znakow konca komunikatu
int _read(int cfd, char* buf, int buf_size){
    int x = 0;
    while(x < 2 || strncmp(buf+x-2, "\n\n", 2) != 0){
        int j = read(cfd, buf + x, buf_size-x);
        if (j == 0) {
            break;
        }
        x = x + j;
    }
    return x;
}

//funkcja zastepujaca write - sprawdza czy wszystkie dane zostaly wyslane
int _write(int cfd, char* buf, int len){
    while(len > 0){
        int i = write(cfd,buf,len);
        if (i < 1) {
            perror("error writing to socket");
            return i;
        }
        len -=i;
        buf += i;
    }
    return len;
}

void send_msg(int cfd, char* msg){
    ssize_t bytes_written = _write(cfd, msg, strlen(msg));
    if (bytes_written < 0) {
        perror("error writing to socket");
    }
}


// ---------------koniec sekcji z funkcjami zastepujacymi read i write-----------------



// ---------------sekcja z deklaracją funkcji do obslugi bazy danych-----------------

//uchwyt do bazy danych
sqlite3 *db;


//funkcja wywoluje zapytanie sql i sprawdza czy nie wystapil blad
int exec_sql_query(const char* query){
    char* err = 0;
    int rc = sqlite3_exec(db, query, 0, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        return rc;
    }
    return rc;
}

//funkcja inicjalizuje baze danych - tworzy tabele jesli nie istnieja i dodaje uzytkownikow testowych
void init_db(){
    int rc = sqlite3_open("test.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }else{
        fprintf(stderr, "Opened database successfully\n");
    }
    const char* msg_table_query = "CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender INTEGER REFERENCES Users(id), receiver INTEGER REFERENCES Users(id), content TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, status INTEGER);";
    rc = exec_sql_query(msg_table_query);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    const char* users_table_query = "CREATE TABLE IF NOT EXISTS Users (id INTEGER PRIMARY KEY, password TEXT, status INTEGER);";
    rc = exec_sql_query(users_table_query);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    const char* users_insert_query = "INSERT OR REPLACE INTO Users (id, password, status) VALUES (123456789, 'admin', 1);";
    rc = exec_sql_query(users_insert_query);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    users_insert_query = "INSERT OR REPLACE INTO Users (id, password, status) VALUES (987654321, 'user1', 1);";
    rc = exec_sql_query(users_insert_query);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    users_insert_query = "INSERT OR REPLACE INTO Users (id, password, status) VALUES (123123123, 'user2', 1);";
    rc = exec_sql_query(users_insert_query);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    }





//funkcja dodaje wiadomosc do bazy danych
void add_msg_to_db(const char* sender, const char* receiver, const char* content, int status){
    char* err = 0;
    char query[2048];
    sprintf(query, "INSERT INTO Messages (sender, receiver, content, status) VALUES ('%s', '%s', '%s', '%d');", sender, receiver, content, status);
    int rc = sqlite3_exec(db, query, 0, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        exit(EXIT_FAILURE);
    }
}

//funkcja aktualizuje status wiadomosci na 1 (dostarczona) na podstawie listy id wiadomosci
void update_msg_status(int msgList[], int size){
    char query[256];
    //przygotowujemy zapytanie UPDATE Messages SET status=1 WHERE id IN (1,2,3,4,5...);
    sprintf(query, "UPDATE Messages SET status=1 WHERE id IN (");
    for(int i = 0; i < size; i++){
        char id[10];
        sprintf(id, "%d,", msgList[i]);
        strcat(query, id);
    }
    query[strlen(query) - 1] = ')';  // zamieniamy ostatni przecinek na nawias zamykajacy
    strcat(query, ";");
    char* err = 0;
    int rc = sqlite3_exec(db, query, 0, 0, &err);
    if (rc != SQLITE_OK) {
        printf("%s\n", query);
        fprintf(stderr, "SQL error: %s\n", err);
        exit(EXIT_FAILURE);
    }
}

//funkcja na podstawie podanych uzytkownikow zwraca wszystkie wiadomosci miedzy nimi
void read_msg_from_db(int cfd, const char* user1, const char* user2) {
    char query[256];
    sprintf(query, "SELECT * FROM Messages WHERE (sender='%s' AND receiver='%s') OR (sender='%s' AND receiver='%s');", user1, user2, user2, user1);
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("%s\n", query);
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    //tablica przechowujaca id wiadomosci do aktualizacji - wysylamy wiadomosci do klienta i zmieniamy status na 1 (dostarczona)
    char packet[30];
    sprintf(packet, "%s\n", GET_ALL_MESSAGES);
    send_msg(cfd, packet);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        char msg[2048];
        //jesli status wiadomosci jest 0 to dodajemy id do listy wiadomosci do aktualizacji
        // if (sqlite3_column_int(stmt, 5) == 0){
        //     toUpdate[i] = sqlite3_column_int(stmt, 0);
        //     i++;
        // }
        snprintf(msg, sizeof(msg), 
                 "%s\n%s\n%s\n%s\n%d/MSG_END",
                 //sqlite column zaczyna sie od 0 nie 1 bo 0 to identyfikatory wiadomosci
                 sqlite3_column_text(stmt, 1),
                 sqlite3_column_text(stmt, 2),
                 sqlite3_column_text(stmt, 3),
                 sqlite3_column_text(stmt, 4),
                 sqlite3_column_int(stmt, 5));
        _write(cfd, msg, strlen(msg));
        
    }
    _write(cfd,"\n\n",2);
    // int* toUpdateArr = malloc(i * sizeof(int));
    // memcpy(toUpdateArr, toUpdate, i * sizeof(int));
    // update_msg_status(toUpdateArr, sizeof(toUpdateArr)/sizeof(int));
    sqlite3_finalize(stmt);
}



//funkcja na podstawie podanego id zwraca liste użytkowników, z którymi wysyłał wiadomości
void get_user_list(int cfd, const char* user){
    char query[256];
    sprintf(query, "SELECT DISTINCT CASE WHEN sender = '%s' THEN receiver WHEN receiver = '%s' THEN sender END AS user FROM Messages WHERE sender = '%s' OR receiver = '%s';", user, user, user, user);
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    //wysylamy komunikat GET_USER_LIST
    char packet[30];
    sprintf(packet, "%s\n", GET_USER_LIST);
    send_msg(cfd, packet);
    //wysylamy liste uzytkownikow w petli
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        char msg[512];
        snprintf(msg, sizeof(msg), 
                 "%s/USER_END",
                 sqlite3_column_text(stmt, 0));
        send_msg(cfd, msg);
        printf("%s\n", msg);
    }
    //wysylamy znaki konca komunikatu
    _write(cfd,"\n\n",2);
    sqlite3_finalize(stmt);
}

//funkcja na podstawie podanego id zwraca status użytkownika
void check_user_status(int cfd, char* user){
    int rc = find_user(user);
    char msg[50];
    //jesli uzytkownik jest zalogowany to status = 1
    if(rc != -1){
        sprintf(msg, "%s\n%s\n%s\n\n", CHECK_USER_STATUS, user, "1");
        send_msg(cfd, msg);
    }else{
        sprintf(msg, "%s\n%s\n%s\n\n", CHECK_USER_STATUS, user,"0");
        send_msg(cfd, msg);
    }
}

//funkcja sprawdza czy podane dane logowania są poprawne
int check_credentials(const char* username, const char* password){
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE id='%s' AND password='%s';", username, password);
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    //jesli zapytanie zwroci wiersz to znaczy ze dane logowania sa poprawne
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        return 1;
    }
    return 0;
}

int check_if_user_exists(const char* username, int cfd){
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE id='%s';", username);
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    char msg[256];

    //jesli zapytanie zwroci wiersz to znaczy ze uzytkownik istnieje
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sprintf(msg, "%s\n%s\n\n",EXISTS, username);
        send_msg(cfd, msg);
    }else{
        sprintf(msg, "%s\n%s\n\n", NOT_EXISTS, username);
        send_msg(cfd, msg);

    }
    return 0;
}

// ---------------koniec sekcji z funkcjami do obslugi bazy danych-----------------

// ---------------sekcja z deklaracją funkcji obslugujacych polaczenie z klientem-----------------

//funkcja obslugujaca polaczenie z klientem w osobnym watku
void* cthread(void* arg){
    struct cln* c = (struct cln*)arg;
    printf("new connection from: %s:%d\n",
            inet_ntoa((struct in_addr)c->caddr.sin_addr), //inet network to address
            ntohs(c->caddr.sin_port));

    //wysylamy komunikat login - na niego klient odpowie swoim loginem i haslem 
    char login_msg[30];
    sprintf(login_msg, "%s\n\n", LOGIN);
    send_msg(c->cfd, login_msg);
    
    char buf[2048];   
    while (1) {
        int rc = _read(c->cfd, buf, sizeof(buf));
        //jesli read zwroci 0 to znaczy ze klient sie rozlaczyl
        if (rc == 0) {
            printf("connection closed\n");
            delete_user(c->cfd);
            close(c->cfd);
            free(c);
            return NULL;
        //jesli read zwroci mniej niz 0 to znaczy ze wystapil blad
        }else if (rc < 0) {
            perror("error reading from socket");
            delete_user(c->cfd);
            close(c->cfd);
            free(c);
            return NULL;
        //ponizej sprawdzamy jaki komunikat przyslal klient i wykonujemy odpowiednie akcje
        }else {
            char* packet_code = memcpy(malloc(3), buf, 2);
            packet_code[2] = '\0';
            if (strncmp(packet_code, LOGIN,2) == 0){
                //wyciagamy z bufora login i haslo
                char* username = memcpy(malloc(10), buf+3, 9);
                char* password_len = memcpy(malloc(3), buf+13, 2);
                password_len[2] = '\0';
                int len = atoi(password_len);
                char* password = memcpy(malloc(6), buf+16, len);
                //dodajemy znak konca stringa
                username[9] = '\0';
                password[len] = '\0';
                //sprawdzamy czy dane logowania sa poprawne
                if (check_credentials(username, password)){
                    add_user(c->cfd, username);
                    char msg[50];
                    sprintf(msg, "%s\n\n", LOGIN_OK);
                    send_msg(c->cfd, msg);
                    list_users();
                }else{
                    printf("%s\n", username);
                    printf("%s\n", password);
                    char msg[50];
                    sprintf(msg, "%s\n\n", LOGIN_NOT_OK);
                    send_msg(c->cfd, msg);
                }

                memset(buf, 0, sizeof(buf));
                free(username);
                free(password);
            }else if(strncmp(packet_code, SEND_MESSAGE, 2) == 0){
                char* sender = memcpy(malloc(10), buf+3, 10);
                char* receiver = memcpy(malloc(10), buf+13, 10);
                char* content = memcpy(malloc(256), buf+23, 256);
                sender[9] = '\0';
                receiver[9] = '\0';
                content[256] = '\0';
                printf("%s wysyła wiadomość do %s\n", sender, receiver);
                //sprawdzamy czy odbiorca jest zalogowany
                int receiver_fd = find_user(receiver);
                //jesli jest to wysylamy mu wiadomosc i dodajemy ja do bazy danych
                if(receiver_fd != -1){
                    char msg[512];
                    sprintf(msg, "%s\n%s\n%s\n\n", SEND_MESSAGE, sender, content);
                    send_msg(receiver_fd, msg);
                    add_msg_to_db(sender, receiver, content, 1);
                //jesli nie to dodajemy wiadomosc do bazy danych i wysylamy komunikat o niepowodzeniu
                }else{
                    add_msg_to_db(sender, receiver, content, 0);
                }

                memset(buf, 0, sizeof(buf));
                free(sender);
                free(receiver);
                free(content);
            }else if(strncmp(packet_code, GET_USER_LIST, 2) == 0){
                char* user = memcpy(malloc(10), buf+3, 10);
                user[9] = '\0';
                //wysylamy liste uzytkownikow z ktorymi komunikowal sie klient
                get_user_list(c->cfd, user);

                memset(buf, 0, sizeof(buf));
                free(user);
            }
            else if(strncmp(packet_code, GET_ALL_MESSAGES, 2) == 0){
                char* user1 = memcpy(malloc(10), buf+3, 10);
                user1[9] = '\0';
                char* user2 = memcpy(malloc(10), buf+13, 10);
                user2[9] = '\0';
                //wysylamy wszystkie wiadomosci miedzy podanymi uzytkownikami
                read_msg_from_db(c->cfd, user1, user2);
                
                memset(buf, 0, sizeof(buf));
                free(user1);
                free(user2);
            }else if(strncmp(packet_code, LOGOUT, 2) == 0){
                //usuwamy uzytkownika z listy zalogowanych, wysylamy komunikat o poprawnym wylogowaniu i zamykamy polaczenie
                delete_user(c->cfd);
                char msg[50];
                sprintf(msg, "%s\n\n", LOGOUT_OK);
                _write(c->cfd, msg, strlen(msg));
                close(c->cfd);
                printf("connection closed: user logged off\n");
                free(c);
                return NULL;
            }else if(strncmp(packet_code, CHECK_USER_STATUS, 2) == 0){
                char* user = memcpy(malloc(10), buf+3, 10);
                user[9] = '\0';
                //wysylamy status uzytkownika
                check_user_status(c->cfd, user);
                
                memset(buf, 0, sizeof(buf));
                free(user);
            }else if(strncmp(packet_code, CHECK_IF_USER_EXISTS, 2) == 0){
                char* user = memcpy(malloc(10), buf+3, 10);
                user[9] = '\0';
                //wysylamy status uzytkownika
                check_if_user_exists(user, c->cfd);
                
                memset(buf, 0, sizeof(buf));
                free(user);
            }
        }
    }
}

//serwer
int main(int argc, char**argv) {
    
    init_db();
    
    
    socklen_t sl;
    pthread_t tid;
    int sfd, on = 1;
    struct sockaddr_in saddr, caddr;
    

    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY; //dowolny adres ip ktory mamy skonfigurowany
    saddr.sin_port = htons(1234);

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    //trzeba uwazac na odpalanie serwera kilka razy - port moze byc zajety, bo zwalnia sie po dopiero okolo 4 minutach - dlatego przydaje sie ponizsza linia:
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));
    bind(sfd, (struct sockaddr*)&saddr, sizeof(saddr));
    listen(sfd, 10);

    printf("Server address: %s\n", inet_ntoa(saddr.sin_addr));

    while (1){
        struct cln* c = malloc(sizeof(struct cln));
        sl = sizeof(caddr);

        c->cfd = accept(sfd, (struct sockaddr*)&c->caddr, &sl);

        pthread_create(&tid, NULL, cthread, c);
        pthread_detach(tid);
    }
    delete_list();
    close(sfd);
    sqlite3_close(db);
    
    return EXIT_SUCCESS;
}
