#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sqlite3.h>

void childend(int signo)
{
    wait(NULL);
    printf("##############\n");
}

int _read(int cfd, char* buf){
    int x = 0;
    while(strncmp(buf+x, "\n", 2) != 0){
        int j = read(cfd, buf + x, sizeof(buf)-x);
        x = x + j;
        printf("%d\n",j);
    }
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
    const char* table_query = "CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY, sender TEXT, receiver TEXT, content TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);";
    rc = exec_sql_query(table_query);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
}

void close_db(){
    sqlite3_close(db);
}

void add_msg_to_db(const char* sender, const char* receiver, const char* content){
    char* err = 0;
    char query[256];
    sprintf(query, "INSERT INTO Messages (sender, receiver, content) VALUES ('%s', '%s', '%s');", sender, receiver, content);
    int rc = sqlite3_exec(db, query, 0, 0, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err);
        exit(EXIT_FAILURE);
    }
}

void send_msg(int cfd, const char* msg){
    _write(cfd, msg, strlen(msg));
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
        char json_row[512];
        snprintf(json_row, sizeof(json_row), 
                 "{\"sender\": \"%s\", \"recipient\": \"%s\", \"message\": \"%s\", \"timestamp\": \"%s\", \"status\": %d}\n",
                 sqlite3_column_text(stmt, 0),
                 sqlite3_column_text(stmt, 1),
                 sqlite3_column_text(stmt, 2),
                 sqlite3_column_text(stmt, 3),
                 sqlite3_column_int(stmt, 4));
        _write(cfd, json_row, strlen(json_row));
    }
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




//serwer
int main(int argc, char**argv) {
    init_db();
    
    socklen_t sl;
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

    while (1)
    {
        sl = sizeof(caddr);
        cfd = accept(sfd, (struct sockaddr*)&caddr, &sl);

        if(!fork())
        {
            close(sfd);
            printf("new connection from: %s:%d\n",
                   inet_ntoa((struct in_addr)caddr.sin_addr), //inet network to address
                   ntohs(caddr.sin_port));

            int rc=_read(cfd, buf);
            if (strncmp(buf, "SEND_MESSAGE", 12) == 0)
            {
                char sender[64], receiver[64], content[256];
                _read(cfd, sender);
                _read(cfd, receiver);
                _read(cfd, content);

                add_msg_to_db(sender, receiver, content);
                send_msg(cfd, "Message sent\n");
                memset(buf, 0, sizeof(buf));
            }
            else if (strncmp(buf, "GET_MESSAGES", 12) == 0)
            {
                const char* user = buf + 13;
                char query[256];
                sprintf(query, "SELECT * FROM Messages WHERE receiver='%s';", user);
                read_msg_from_db(cfd, query);
            }
            else if (strncmp(buf, "GET_ALL_MESSAGES", 16) == 0)
            {
                const char* user = buf + 17;
                char query[256];
                sprintf(query, "SELECT * FROM Messages WHERE receiver='%s' OR sender='%s';", user, user);
                read_msg_from_db(cfd, query);
            }
            else if (strncmp(buf, "GET_NEW_MESSAGES", 16) == 0)
            {
                const char* user = buf + 17;
                char query[256];
                sprintf(query, "SELECT * FROM Messages WHERE receiver='%s' AND status=0;", user);
                read_msg_from_db(cfd, query);
            }
            else if (strncmp(buf, "SET_MESSAGE_STATUS", 18) == 0)
            {
                char* id = buf + 19;
                char query[256];
                sprintf(query, "UPDATE Messages SET status=1 WHERE id=%s;", id);
                exec_sql_query(query);
                send_msg(cfd, "Message status updated\n");
            }
            else if (strncmp(buf, "GET_USER_STATUS", 15) == 0)
            {
                const char* user = buf + 16;
                check_user_status(cfd, user);
            }
            else {
                strcpy(buf,"\0\0\0\0\0\0\0\0\n");
                _write(cfd, "Nieprawidlowy indeks\n", 22);
            }

            return EXIT_SUCCESS;
        }

        close(cfd);
    }
    close(sfd);
    close_db();
    return EXIT_SUCCESS;
    //konsola komenda strace "nazwa_serwera" - wypisuje w konsoli wszystkie wywolane funkcje serwera
}
/*
write() to funkcja memcopy z pola procesu do bufora jądra systemu, z którego moduł tco tworzy pakiet
i dalej leci do karty sieciowej. W buforze jądra jest zamek (problem producenta - procesu i konsumenta - jądra)
write zwraca liczbę bajtów, które udało się skopiować z buforu procesu do bufora jądra.

write musimy wywoływać tak długo aż suma i będzie równa N:
i = write(fd, buf, N)

po wysłaniu przez tcp pakietów jądro drugiego systemu przekazuje do bufora odbiorczego.
funkcja read to rowniez memcopy z zamkiem - jedyna roznica, dziala w druga strone. kopiuje z bufora odbiorczego do bufora jadra

read i write zwracają ilość bajtów, które udało się skopiować
odczytujemy tak długo dopoki j = N
j = read(fd, buf, M)

read i write są funkcjami blokującymi
gdy proces wysyłający skończy wysyłanie a odczytujący spróbuje odczytać jeszcze raz to będzie wisieć na blokadzie (będzie czekał na odpowiedź, której nie ma)

Rozwiązania:
1) komunikat z rozmiarem N - jak to zrobić skoro musimy odebrać go funkcją read()? musimy znac z gory wielkosc komunikatu i kolejne wiadomosci musza sie trzymac tego przesłanego ozmiaru
2) stały rozmiar danych  - jeżeli wiadomość jest mniejsza niż stały rozmiar to uzupełniamy zerami - gdy większy niż stały rozmiar to nie wysyłamy wszystkich/wcale
3) znak końca danych - odczytujemy tak długo aż napotkamy znak końca danych - musimy miec gwarancje ze znaku nie bedzie w danych (np pliki binarne moga zawierac znak konca danych)
to są wszystkie rozwiązania

http - 1) i 3)
przesyłany jest nagłówek
3) dla nagłówka to podwójny znak nowej linii \n\n
1) jest przesyłane w nagłówku - moze być dowolne bo przekazywane jest w nagłówku kończącym się znakiem końca danych

/proc/sys/net/ipv4/tcp_rmem lub tcp_wmem pliki z wielkością bufora. po lewej minimalna wielkosć, po srodku domyslna, po prawej maksymalnas
*/