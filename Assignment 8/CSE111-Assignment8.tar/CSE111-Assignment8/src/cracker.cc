/*
 * Copyright (C) 2018-2022 David C. Harrison. All right reserved.
 *
 * You may not use, distribute, publish, or modify this code without 
 * the express written permission of the copyright holder.
 */

#include <iostream>
#include <strings.h>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <vector>
#include <thread>
#include <crypt.h>
#include <atomic>

#include "cracker.h"

std::atomic<bool> found = false;

//the meat and potatoes of the program, sort of like homebase.
void crackr(Message &m);

//first part of a multithreaded cracking function, passes 
//multiple threads to threadguess() for the rest of the work.
void customCrack(const char *alphabet, const char *hash, char *passwd);
//the heavy lifting of the cracking algorithm, run on multiple
//threads.
void threadguess(const char *alphabet, const char *hash, const char *salt, crypt_data data, char *res, char *pass, char *passwd);

//UDP recieve function.
void recieve(Message &m);

//TCP send function.
void send(Message &m);

//TCP server for multi-server talk.
void recievePasswords(std::vector<Message> &passwords);
//TCP client for multi-server talk.
void sendPasswords(Message &m);


/**
 * @brief main function of your cracker
 * 
 * No command line arguments are passed
 * 
 * @return int not checked by test harness
 */ 
int main() {
    Message m;
    recieve(m);
    crackr(m);
    send(m);
}

// FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////

void crackr(Message &m){
    //get number of passwords.
    unsigned int npass = ntohl(m.num_passwds);

    //retrieve the current server hostname to check what portion
    //of work it crackr will be doing.
    char hostname[64];
    gethostname(hostname, sizeof(hostname));
    char noggin[] = "noggin";
    char nogbad[] = "nogbad";
    char olaf[] = "olaf";
    char thor[] = "thor";

    //depending on the host, these if statements will dispatch the work.
    if (strcmp(hostname, noggin) == 0){
        //create a vector of messages to store passwords from the other servers
        //and send it off to listen for the other servers in a different thread.
        std::vector<Message> passwords(4);
        std::thread passThread{recievePasswords, std::ref(passwords)};

        unsigned int n = 0;
        while (n <= (npass - 1)){            
            //crack passwords 0, 4, 8, etc.
            char cracked[14];
            customCrack(m.alphabet, m.passwds[n], cracked);
            strcpy(m.passwds[n], cracked);
            n += 4;
        }
        
        //join back from the server thread.
        passThread.join();
        //for every message we recieve back...
        for (Message p : passwords){
            unsigned int w = 0;
            //go through their password lists...
            for (char *ps : p.passwds){
                //if we find a completed password, snatch it.
                if (strlen(ps) == 4){
                    strcpy(m.passwds[w], ps);
                }
                w++;
            }
        }
        return;
    }
    
    //SEE ABOVE COMMENTS.
    if (strcmp(hostname, nogbad) == 0){
        unsigned int g = 1;
        while (g <= (npass - 1)){            
            char cracked[14];
            customCrack(m.alphabet, m.passwds[g], cracked);
            strcpy(m.passwds[g], cracked);
            g += 4;
        }
        sendPasswords(m);
        exit(0);
    }

    //SEE ABOVE COMMENTS.
    if (strcmp(hostname, olaf) == 0){
        unsigned int f = 2;
        while (f <= (npass - 1)){            
            char cracked[14];
            customCrack(m.alphabet, m.passwds[f], cracked);
            strcpy(m.passwds[f], cracked);
            f += 4;
        }
        sendPasswords(m);
        exit(0);
    }

    //SEE ABOVE COMMENTS.
    if (strcmp(hostname, thor) == 0){
        unsigned int r = 3;
        while (r <= (npass - 1)){            
            char cracked[14];
            customCrack(m.alphabet, m.passwds[r], cracked);
            strcpy(m.passwds[r], cracked);
            r += 4;
        }
        sendPasswords(m);
        exit(0);
    }
    return;
}

void customCrack(const char *alphabet, const char *hash, char *passwd){
    //create necessary variables...
    struct crypt_data data;

    char pass[] = "aaaa";

    char salt[] = "aa";
    salt[0] = hash[0];
    salt[1] = hash[1];

    char *res;

    std::vector<std::thread> threads(24);
    unsigned int x = 0;

    //create an array of char *s to hold each threads guesses.
    char *passTemp[24];
    char temp[5] = "aaaa";
    for (int i = 0; i < 24; i++){
        passTemp[i] = new char[5];
        strcpy(passTemp[i], temp);
    }

    //for all beginning letters...
    for (size_t a = 0; a < strlen(alphabet); a++){
        for (int i = 0; i < 24; i++){
            if ((a + x) < strlen(alphabet)){
                //send a thread to try everything beginning with that letter.
                passTemp[i][0] = alphabet[a + x];
                threads.push_back( std::thread(threadguess, alphabet, hash, salt, data, res, passTemp[i], passwd) );
                x++;
            }
        }
        //make sure to offset 'a' with all the threads we sent out.
        a += x;
        
        //join all the threads back.
        for (int i = 0; i < 24; i++){
            for (std::thread &t : threads){
                if (t.joinable()){
                    t.join();
                    x--;
                }
            }
        }
        //if we found the pass, reset.
        if (found == true){
            found = false;
            return;
        }
    }

    //default exit.
    strcpy(passwd, pass);
    return;
}

void threadguess(const char *alphabet, const char *hash, const char *salt, crypt_data data, char *res, char *pass, char *passwd){
    //nested for loops to check each possible combination...
    for (size_t b = 0; b < strlen(alphabet); b++){
        pass[1] = alphabet[b];
        for (size_t c = 0; c < strlen(alphabet); c++){
            pass[1] = alphabet[b];
            pass[2] = alphabet[c];
            for (size_t d = 0; d < strlen(alphabet); d++){
                pass[1] = alphabet[b];
                pass[2] = alphabet[c];
                pass[3] = alphabet[d];
                //if we call crypt_r() on a passwd and it matches the one
                //we are looking for, bring it on back and notify the found
                //atomic bool (all threads can see).
                res = crypt_r(pass, salt, &data);
                if (strcmp(res, hash) == 0){
                    strcpy(passwd, pass);
                    found = true;
                    return;
                }
            }
        }
    }
    return;
}

// SEND AND RECIEVE /////////////////////////////////////////////////////////////////////////////////////////

//followed lecture specs.
void recieve(Message &m){
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) exit (-1);

    struct sockaddr_in server_addr;
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(get_multicast_port());

    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
        exit(-1);

    struct ip_mreq multicastRequest;
    multicastRequest.imr_multiaddr.s_addr = get_multicast_address();
    multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *) &multicastRequest, sizeof(multicastRequest)) < 0)
        exit(-1);
    
    struct sockaddr_in remote_addr;
    socklen_t len = sizeof(remote_addr);

    int n = recvfrom(sockfd, &m, sizeof(m), 0, (struct sockaddr *)&remote_addr, &len);
    if (n < 0) exit(-1);

    close(sockfd);
}

//followed lecture specs.
void send(Message &m){
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) exit(-1);

    struct hostent *server = gethostbyname(m.hostname);
    if (server == NULL) exit(-1);

    struct sockaddr_in serv_addr;
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);

    serv_addr.sin_port = m.port;

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) exit(-1);

    int n = write(sockfd, &m, sizeof(m));
    if (n < 0){
        exit(-1);
    }   

    close(sockfd);
}

//followed lecture specs.
void recievePasswords(std::vector<Message> &passwords){
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
        std::cout << "Err0: BadSock\n";
        exit(-1);
    }

    struct sockaddr_in server_addr;
    bzero((char *) &server_addr, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(get_unicast_port());

    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0){
        std::cout << "Err1: BadBind\n";
        exit(-1);
    }

    listen(sockfd, 4);
    
    unsigned int index = 0;

    for (;;){
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);

        int newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &len);
        if (newsockfd < 0) exit (-1);

        int n = recv(newsockfd, &passwords[index], sizeof(passwords[index]), 0);
        if (n < 0){
            std::cout << "Err2: BadRecv\n";
            exit(-1);
        }
        index++;

        close(newsockfd);
        if (index == 3){
            close(sockfd);
            return;
        }
    }

    return;
}

//followed lecture specs.
void sendPasswords(Message &m){
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) exit(-1);

    char hostname[] = "noggin";
    struct hostent *server = gethostbyname(hostname);
    if (server == NULL){
        std::cout << "Err3: BadFind\n";
        exit(-1);
    }

    struct sockaddr_in serv_addr;
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);

    serv_addr.sin_port = htons(get_unicast_port());

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
        std::cout << "Err1: BadConnect\n";
        exit(-1);
    }

    int n = write(sockfd, &m, sizeof(m));
    if (n < 0){
        std::cout << "Err5: BadWrite\n";
        exit(-1);
    }   

    close(sockfd);
}
