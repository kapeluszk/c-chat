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

struct cln {
    int cfd;
    struct sockaddr_in caddr;
};

typedef struct user{
    int fd;
    char id[10];
    struct user *next;
} User;

User *users = NULL;

void add_user(int fd, char* id){
    User *new_user = malloc(sizeof(User));
    new_user->fd = fd;
    strncpy(new_user->id, id, 10);
    new_user->next = users;
    users = new_user;
}

//funkcja zwraca fd uzytkownika o podanym id lub -1 jesli nie ma takiego uzytkownika
int find_user(char* id){
    User *current = users;
    while(current != NULL){
        if(strcmp(current->id, id) == 0){
            return current->fd;
        }
        current = current->next;
    }
    return -1;
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

void childend(int signo)
{
    wait(NULL);
    printf("##connection closed##\n");
}

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

int _write(int cfd, char* buf, int len){
    while(len > 0){
        int i = write(cfd,buf,len);
        len -=i;
        buf += i;
    }
}

sqlite3 *db;


//funkcja wywolywana przy kazdym wierszu zapytania
int exec_sql_query(const char* query){
    char* err = 0;
    int rc = sqlite3_exec(db, query, 0, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        exit(EXIT_FAILURE);
    }
}

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
    }

void close_db(){
    sqlite3_close(db);
}

void send_msg(int cfd, const char* msg){
    ssize_t bytes_written = write(cfd, msg, strlen(msg));
    if (bytes_written < 0) {
        perror("error writing to socket");
    }
}

void add_msg_to_db(const char* sender, const char* receiver, const char* content, int status){
    char* err = 0;
    char query[256];
    sprintf(query, "INSERT INTO Messages (sender, receiver, content, status) VALUES ('%s', '%s', '%s', '%d');", sender, receiver, content, status);
    int rc = sqlite3_exec(db, query, 0, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        exit(EXIT_FAILURE);
    }
}

//funkcja przyjmuje zapytanie sql i wysyla wynik do klienta w postaci pliku json
void read_msg_from_db(int cfd, const char* query) {
    char* err = 0;
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        char json_row[1024];
        snprintf(json_row, sizeof(json_row), 
                 "{\"sender\": \"%s\", \"recipient\": \"%s\", \"message\": \"%s\", \"timestamp\": \"%s\", \"status\": %d}",
                 //sqlite column zaczyna sie od 0 nie 1 bo 0 to identyfikatory wiersza
                 sqlite3_column_text(stmt, 1),
                 sqlite3_column_text(stmt, 2),
                 sqlite3_column_text(stmt, 3),
                 sqlite3_column_text(stmt, 4),
                 sqlite3_column_int(stmt, 5));
        _write(cfd, json_row, strlen(json_row));
        
    }
    _write(cfd,"\n\n",2);
    sqlite3_finalize(stmt);
}

void check_user_status(int cfd, const char* user){
    char query[256];
    sprintf(query, "SELECT status FROM users WHERE username='%s';", user);
    char* err = 0;
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        char json_row[512];
        snprintf(json_row, sizeof(json_row), 
                 "{\"status\": %d}\n",
                 sqlite3_column_int(stmt, 0));
        _write(cfd, json_row, strlen(json_row));
    }
}

int check_credentials(const char* username, const char* password){
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE id='%s' AND password='%s';", username, password);
    char* err = 0;
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        return 1;
    }
    return 0;
}

void* cthread(void* arg){
    struct cln* c = (struct cln*)arg;
    printf("new connection from: %s:%d\n",
            inet_ntoa((struct in_addr)c->caddr.sin_addr), //inet network to address
            ntohs(c->caddr.sin_port));

    //wysylamy komunikat login - na niego klient odpowie swoim loginem i haslem 
    const char* login_msg = "LOGIN\n\n";
    send_msg(c->cfd, login_msg);
    
    char buf[512];
    while (1) {
        int rc = _read(c->cfd, buf, sizeof(buf));
        if (rc == 0) {
            printf("connection closed\n");
            delete_user(c->cfd);
            close(c->cfd);
            free(c);
            return NULL;
        }else if (rc < 0) {
            perror("error reading from socket");
            close(c->cfd);
            free(c);
            return NULL;
        }else if (strncmp(buf, "LOGIN",5) == 0){
            char* username = memcpy(malloc(10), buf+6, 10);
            char* password = memcpy(malloc(6), buf+16, 6);
            username[9] = '\0';
            password[5] = '\0';
            if (check_credentials(username, password)){
                add_user(c->cfd, username);
                send_msg(c->cfd, "LOGIN_OK\n\n");
                list_users();
            }else{
                send_msg(c->cfd, "LOGIN_NOT_OK\n\n");
                printf("%s\n%s", username, password);
            }
            free(username);
            free(password);
        }else if(strncmp(buf, "SEND_MESSAGE", 12) == 0){
            char* sender = memcpy(malloc(10), buf+13, 10);
            char* receiver = memcpy(malloc(10), buf+24, 10);
            char* content = memcpy(malloc(256), buf+35, 256);
            sender[10] = '\0';
            receiver[10] = '\0';
            content[256] = '\0';
            int receiver_fd = find_user(receiver);
            if(receiver_fd != -1){
                char msg[512];
                sprintf(msg, "MESSAGE\n\n{\"sender\": \"%s\", \"message\": \"%s\"}\n\n", sender, content);
                send_msg(receiver_fd, msg);
                add_msg_to_db(sender, receiver, content, 1);
                char* msg_sent = "MESSAGE_SENT\n\n";
                send_msg(c->cfd, msg_sent);
            }else{
                add_msg_to_db(sender, receiver, content, 0);
                char* msg_not_delivered = "MESSAGE_NOT_DELIVERED\n\n";
                send_msg(c->cfd, msg_not_delivered);
            }
            free(sender);
            free(receiver);
            free(content);
        }else if(strncmp(buf, "GET_ALL_MESSAGES", 16) == 0){
            char* user = memcpy(malloc(10), buf+17, 10);
            user[10] = '\0';
            char query[256];
            sprintf(query, "SELECT * FROM Messages WHERE receiver='%s' OR sender='%s';", user, user);
            read_msg_from_db(c->cfd, query);
            free(user);
        }else if(strncmp(buf, "LOGOUT", 6) == 0){
            delete_user(c->cfd);
            close(c->cfd);
            free(c);
            return NULL;
        }
    }
}

//serwer
int main(int argc, char**argv) {
    
    init_db();
    
    
    socklen_t sl;
    pthread_t tid;
    int sfd, cfd, on = 1;
    struct sockaddr_in saddr, caddr;
    char buf[256];
    
    signal(SIGCHLD, childend);
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
    close_db();
    
    return EXIT_SUCCESS;
}
