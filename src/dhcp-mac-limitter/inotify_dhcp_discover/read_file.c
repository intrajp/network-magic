/* Written by Shintaro Fujiwara
 * shintaro.fujiwara@gmail.com
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h> /* for date related functions */
#include <unistd.h> /* for execl */

int i_mac = 0;
char start_time [50];
char check_time [50];
int start_int = 0;
int check_int = 0;

int get_word_line ( char **line )
{
    const char s [ 2 ] = ","; /* this is the delimiter */
    char *token = ""; /* line would be set into this variable in while loop */
    char token_pre [4096];
    token = strtok ( *line, s );
    //printf ("line\n");
    int i = 0;
    //int i_mac = 0;
    while ( token != NULL )
    {
        //first column
        if ( i == 0 )
        {
            if ( i_mac == 1 )
            {
                strncpy ( start_time, token, strlen ( token ) );
                /* converting char[] to const *char */
                start_int = atoi(start_time); 
                printf("start_time:%d\n",start_int);
            }
            if ( i_mac == 10 )
            {
                strncpy ( check_time, token, strlen ( token ) );
                /* converting char[] to const *char */
                check_int = atoi(check_time); 
                //printf("check_time:%d\n",check_int);
                //printf("####start_int:%d\n",start_int);
                //printf("####check_int:%d\n",check_int);
            }
        }
        //second column
        if ( i == 1 )
        {
            /* if same as former mac address, count up i_mac
            this means, reading /tmp/dhcp-discover.log, if containing same address as former line */
            if ( strcmp ( token_pre, token ) == 0 )
            {
                i_mac++;
                // if i_mac exceeds some number, compare time 
                if ( ( i_mac > 5 ) && ( ( check_int - start_int ) < 300 ) )
                {
                    //puts("--------ALERT!!--------");
                    //printf("token:%s\n",token);
                    char *const str[] = { "/usr/local/bin/dhcpdiscover-mac-limitter.sh", token, NULL };
                    execv ("/usr/local/bin/dhcpdiscover-mac-limitter.sh", str );
                }
            }   
            else   
            {
                i_mac = 0;
            }
            printf("i_mac:%d\n",i_mac);
            strncpy ( token_pre, token, strlen ( token ) );
        }
        printf ("token_pre:%s\n", token_pre);
        printf ("token-%d:%s\n", i,token);
        token = strtok ( NULL, s );
        i++;
    }
    return ( 0 );
}

void read_file (const char *filename)
{
    i_mac = 0;
    FILE *fp;
    char linebuf [4096];
    char *line;
    /* open /tmp/dhcp-discover.log */
    if ( ( fp = fopen ( filename, "r" ) ) == NULL )
    {
        printf("Cannot open file (%s): %s\n",filename,strerror(errno));
        exit ( EXIT_FAILURE );
    }
    else
    {
        //read line and do the job
        while ( fgets ( linebuf, sizeof ( linebuf ), fp) != NULL )
        {
            line = linebuf;
            if ( get_word_line ( &line ) != 0 )
                continue;
        }
        fclose ( fp );
    }
}
