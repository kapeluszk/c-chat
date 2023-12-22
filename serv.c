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


//serwer
int main(int argc, char**argv) {
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
            if (strncmp(buf, "154030", 6) == 0)
            {
                strcpy(buf,"\0\0\0\0\0\0\0\0\n");
                _write(cfd, "Czesc Bartek\n", 14);
            }
            else if (strncmp(buf, "154042", 6) == 0)
            {
                strcpy(buf,"\0\0\0\0\0\0\0\0\n");
                _write(cfd, "Czesc Kacper\n", 14);
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