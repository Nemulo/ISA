/*
    AUTHOR: Marek Nemeth
    MAIL:   xnemet05@stud.fit.vutbr.cz
    FILE:   socket.cpp
    Project:popcl
    Subject:ISA
    Last Date modified: 30.10.2021
*/



#ifndef SOCK
#define SOCK

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <string>

class Socket
{
    /*  class variables required for communication and socket initialization
        address -> represents hostname
        port -> stores port number
        cert_file -> stores path to certfile
        cert_addr -> stores path to directory with certificates
        user -> stores username for authentication
        pass -> stores password for authentication
        dl_de -> true if option for reading/downloading data is chosen, false if deleting
        dir_out -> stores path to output directory
        T,S -> options from arg parsing
        err -> if error occured in any time, this is set to true
        count -> stores number of saved mails
    */
    std::string address;
    std::string port;
    std::string cert_file;
    std::string cert_addr;
    std::string user;
    std::string pass;
    bool dl_de;
    std::string dir_out;
    bool T,S;
    bool err;
    int count = 0;

    public:
        Socket(std::string ,std::string ,bool,bool,std::string ,std::string ,std::string,bool,std::string);

    private:
        void login(BIO*);
        BIO* secure(BIO*);
        void open(bool);
        void open_s(bool);
        void close(BIO *);
        bool receive(BIO*);
        int receive_num(BIO*);
        std::string Get_msg_id(BIO*);
        bool get_mail(BIO*,std::string);
        void download(BIO*);
        void delete_m(BIO*);
        void send_m(BIO*,std::string);
        void resolve_auth(std::string);
};

#endif