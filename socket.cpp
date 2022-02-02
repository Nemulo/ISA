/*
    AUTHOR: Marek Nemeth
    MAIL:   xnemet05@stud.fit.vutbr.cz
    FILE:   socket.cpp
    Project:popcl
    Subject:ISA
    Last Date modified: 30.10.2021
*/


#include "socket.hpp"
#include <string>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <regex>
#include <iterator>
#include <fstream>
#include <filesystem>

/* Constructor, saves given values to class variables, see usage in main.cpp    */

Socket::Socket(std::string addr,std::string p,bool t,bool s,std::string c_file,std::string c_addr,std::string a_file,bool del,std::string od)
{

    //  User and pass data are resolved from authfile
    resolve_auth(a_file);

    address = addr;
    cert_file = c_file;
    cert_addr = c_addr;
    port = p;
    dl_de = del;
    dir_out = od;
    T = t;
    S = s;
    err = false;
    if (t)
    {   
        //  open in secured communication
        open_s(s);
    }
    else
    {   
        //  open in unsecured communication
        open(s);
    }
}

/*
    Function
        when this function is called, it requests to open TLS communication with server via STLS command
        and then upgrades the communication to Secured state

        bio -> pointer to BIO object

        returns pointer to BIO object with Secured communication
*/

BIO* Socket::secure(BIO *bio)
{
    //  sends STLS request
    send_m(bio,"STLS\r\n");
    if (err)
    {
        return bio;
    }
    //  reads data from server
    if (!receive(bio))
    {
        err = true;
        return bio;
    }

    //  Create secured communication and push it to original BIO object
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (cert_addr.size()== 0 && cert_addr.size() == 0)
    {
        SSL_CTX_set_default_verify_paths(ctx);
    }
    else
    {
        if (! SSL_CTX_load_verify_locations(ctx, ((cert_file.size()==0)?NULL:cert_file.c_str()), ((cert_addr.size()==0)?NULL:cert_addr.c_str())))
        {
            //TODO handle error
            std::cerr<<"Error unable to verify"<<std::endl;
            err = true;
            return bio;
        }
    }
    BIO *ssl;
    if ((ssl = BIO_new_ssl(ctx, 1)) == NULL)
    {
        std::cerr<<"unable to create ssl bio"<<std::endl;
        err = true;
        return bio;
    }
    if ((bio = BIO_push(ssl, bio)) == NULL)
    {
        std::cerr<<"unable to push"<<std::endl;
        err = true;
        return bio;
    }
    return bio;
}

/*
    Function
        similiar to function Socket::receive, this funcion is used when data(e.g. message amount) are required to be retrieved from server response
        see bool Socket::socket for details
*/
int Socket::receive_num(BIO *bio)
{
    bool ok = false;
    char resp[4096] = {};
    std::smatch match_obj;
    std::string str_rsp;
    int x = BIO_read(bio,resp,4095);
    int amount = -1;
    if (x==0)
    {
        std::cerr<<"Error : Unable to read from server"<<std::endl;
        return -1;
    }
    else if (x<0)
    {
        if (!BIO_should_retry(bio))
        {
            std::cerr<<"Error : Server closed connection"<<std::endl;
            return -1;
        }
    }
    str_rsp = resp;
    if (!ok)
    {
        if (!(std::regex_search(str_rsp,match_obj,std::regex("^\\+OK\\s*(\\d+).*"))))
        {
            // TODO server response not ok
            return -1;
        }
        ok = true;
        std::stringstream num;
        num<<match_obj.format("$1");
        num>>amount;
    }

    return amount;
    

}
/*
    Funcion
        handles delete request from arguments

        bio -> pointer to BIO object
*/
void Socket::delete_m(BIO *bio)
{
    //  Requests number of messages from server
    send_m(bio,"STAT\r\n");
    if (err)
    {
        return;
    }

    //  save the number
    int msgs = receive_num(bio);
    if (msgs ==-1)
    {
        return;
    }

    //  iterate over all messages and delete them
    for (int i=1;i<=msgs;i++)
    {
        std::stringstream conv;
        conv<<i;
        std::string num_str;
        conv>>num_str;
        std::string del_comm = "DELE "+num_str+"\r\n";
        send_m(bio,del_comm);
        if (err)
        {
            return;
        }
        receive(bio);
    }

    //  end communication to save changes
    send_m(bio,"QUIT\r\n");
    if(!receive(bio))
    {
        return;
    }
}

/*
    Function
        handles download request from arguments
        bio -> pointer to BIO object

*/
void Socket::download(BIO *bio)
{
    //  Requests number of messages from server
    send_m(bio,"STAT\r\n");
    if (err)
    {
        return;
    }
    //  save the number
    int msgs = receive_num(bio);
    if (msgs ==-1)
    {
        return;
    }
    //  iterate over all messages and handle them
    for (int i=1;i<=msgs;i++)
    {
        std::stringstream conv;
        conv<<i;
        std::string num_str;
        conv>>num_str;

        //  retrieve message
        std::string retr_comm = "RETR "+num_str+"\r\n";
        send_m(bio,retr_comm);
        if (err)
        {
            return;
        }
        //  resolve message id from current message
        std::string fn = Get_msg_id(bio);
        if (err)
        {
            return;
        }
        //  check whether this message exists(see get_mail)
        struct stat info;
        if (stat(dir_out.c_str(),&info)!=0)
        {
            mkdir(dir_out.c_str(),0);
        }

        if (stat((dir_out+fn+".eml").c_str(),&info)!=0)
        {
            //  message is not saved locally in outdir, request again to save
            send_m(bio,retr_comm);
            get_mail(bio,(dir_out+"/"+fn+".eml"));
            count++;
        }
        
    }
    std::cout<<"Downloaded "<<count<<" messages\n";
    send_m(bio,"QUIT\r\n");
    if(!receive(bio))
    {
        return;
    }
    return;
}

/*
    Function
        saves email locally

        bio-> pointer to BIO object
        file_n -> filename

        returns true if succesfully saved, false otherwise

        for detail, see Socket::receive
*/
bool Socket::get_mail(BIO *bio,std::string file_n)
{
    std::ofstream file;

    //  create file with name of Message-ID
    file.open(file_n.c_str(),std::ios_base::app);
    while(1)
    {
        char resp[4096] = {};
        std::string str_rsp;
        std::smatch match_obj;
        int x = BIO_read(bio,resp,4095);
        if (x==0)
        {
            std::cerr<<"Error : Unable to read from server"<<std::endl;
            return false;
        }
        else if (x<0)
        {
            if (!BIO_should_retry(bio))
            {
                std::cerr<<"Error : Server closed connection"<<std::endl;
                return false;
            }
        }
        str_rsp = resp;
        str_rsp = std::regex_replace(str_rsp,std::regex("(\\+OK.*\\r\\n)"),"");

        if (std::regex_search(str_rsp,match_obj,std::regex("\\r\\n\\.\\r\\n")))
        {
            str_rsp = std::regex_replace(str_rsp,std::regex("\\r\\n\\.\\r\\n"),"");
            file<<str_rsp;
            break;
        }
        file<<str_rsp;
    }
    file.close();
    return true;
}

/*
    Function
        resolves authentication data for loggin in on server

        filename -> file with auth. data
*/
void Socket::resolve_auth(std::string filename)
{
    std::string line;

    //  Open file for reading
    std::ifstream auth(filename.c_str());

    while (std::getline (auth,line))
    {
        std::smatch match_obj;

        //  Find username
        if(std::regex_search(line,match_obj,std::regex("^username\\s*=\\s(.*)")))
        {
            user = match_obj.format("$1");
        }

        //  Find password
        if(std::regex_search(line,match_obj,std::regex("^password\\s*=\\s*(.*)")))
        {
            pass = match_obj.format("$1");
        }
    }
}

/*
    Function
        Locates and returns message-Id

        bio -> pointer to BIO object

        returns string with message-ID

        see Socket::receive for more detail
*/
std::string Socket::Get_msg_id(BIO* bio)
{
    std::string filename;
    while (1)
    {
        char resp[4096] = {};
        std::smatch match_obj;
        std::string str_rsp;
        int x = BIO_read(bio,resp,4095);
        if (x==0)
        {
            std::cerr<<"Error : Unable to read from server"<<std::endl;
            err = true;
            return filename;
        }
        else if (x<0)
        {
            if (!BIO_should_retry(bio))
            {
                std::cerr<<"Error : Server closed connection"<<std::endl;
                err = true;
                return filename;
            }
        }
        str_rsp = resp;
        
        //  Finds message-Id in response
        if (std::regex_search(str_rsp,match_obj,std::regex("Message-ID:\\s*<(.*)@.*",std::regex_constants::icase)))
        {
            filename = match_obj.format("$1");
        }
        
        if (std::regex_search(str_rsp,match_obj,std::regex("\\r\\n\\.\\r\\n")))
        {   
            break;
        }
    }
    return filename;

}

/* 
    Function
        reads response from server

        bio-> pointer to BIO object

        returns true if succesfuly read, false otherwise
*/
bool Socket::receive(BIO *bio)
{
    //  buffer for response
    char resp[4096] = {};

    std::smatch match_obj;
    std::string str_rsp;

    //  Reading from server
    int x = BIO_read(bio,resp,4095);

    //  Read 0 bytes
    if (x==0)
    {
        std::cerr<<"Error : Unable to read from server"<<std::endl;
        return false;
    }

    //  Error while reading
    else if (x<0)
    {
        if (!BIO_should_retry(bio))
        {
            std::cerr<<"Error : Server closed connection"<<std::endl;
            return false;
        }
    }

    //  assign response to string type for better handling
    str_rsp = resp;

    //  Response was -Err 
    if (std::regex_search(str_rsp,match_obj,std::regex("^-ERR.*\r\n")))
    {
        std::cerr<<resp<<std::endl;
        return false;
    }
    else
    {
        //  Response was 
        if (std::regex_search(str_rsp,match_obj,std::regex("^\\+OK.*\r\n")))
        {
            // TODO server response ok, do not continue reading
            return true;
        }
    }
    // Unexpected response from server
    std::cerr<<"Error : unexpected response"<<std::endl;
    return false;
    
    
}

/*
    Function
        sends requests(commands) to server

        bio -> pointer to BIO object
        message -> request to server

*/
void Socket::send_m(BIO* bio, std::string message)
{
    if(BIO_write(bio,message.c_str(),message.size())<=0)
        {
            if(! BIO_should_retry(bio))
            {
                //  TODO handle err
                std::cerr<<"Error: unable to send"<<std::endl;
                err = true;
                return;
            }
        }
}

/*
    Function
        logs user into server using auth data
*/
void Socket::login(BIO* bio)
{
    send_m(bio,"USER "+user+"\r\n");
    if (err)
    {
        return;
    }
    if(!receive(bio))
    {
        err = true;
        return;
    }
    send_m(bio,"PASS "+pass+"\r\n");
    if (err)
    {
        return;
    }
    if(!receive(bio))
    {
        err = true;
        return;
    }

}

/*
    Function
        opens unsecured communication
*/
void Socket::open(bool S)
{

    //  create BIO object
    BIO *bio;
    std::string hostname = address+':'+port;
    
    //  connect to host
    bio = BIO_new_connect(hostname.c_str());
    if (bio == NULL)
    {
        //TODO err handler
        std::cerr<<"Error, unable to create bio method"<<std::endl;
        return;
    }
    if(BIO_do_connect(bio) <= 0)
    {
        //TODO err handler
        std::cerr<<"Error connecting to server"<<std::endl;
        return;
    }

    //  Receive response from connecting to server
    if(!receive(bio))
    {
        close(bio);
        return;
    }
    //  Handle securing according to options
    if (S)
    {
        bio = secure(bio);
        if (err)
        {
            close(bio);
            return;
        }
        
    }
    login(bio);
    if (err)
        {
            close(bio);
            return;
        }
    if (dl_de)
    {
        download(bio);
    }
    else
    {
        delete_m(bio);
    }
    // reason to oppen
    close(bio);
    

}

/*
    Function
        opens secured Connection to server
    see https://developer.ibm.com/tutorials/l-openssl/ for details
*/
void Socket::open_s(bool S)
{
    BIO *bio;

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *ssl;
    if (cert_addr.size()== 0 && cert_addr.size() == 0)
    {
        SSL_CTX_set_default_verify_paths(ctx);
    }
    else
    {
        if (! SSL_CTX_load_verify_locations(ctx, ((cert_file.size()==0)?NULL:cert_file.c_str()), ((cert_addr.size()==0)?NULL:cert_addr.c_str())))
        {
            //TODO handle error
            std::cerr<<"Error unable to verify certificates"<<std::endl;
            return;
        }
    }
    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    std::string hostname = address+':'+port;
    BIO_set_conn_hostname(bio, hostname.c_str());

    if(BIO_do_connect(bio) <= 0)
    {
        //  TODO handle failed conn
        std::cerr<<"Error connecting to server"<<std::endl;
        SSL_CTX_free(ctx);
        close(bio);
        return;
    }

    if(SSL_get_verify_result(ssl) != X509_V_OK)
    {
        // Handle the failed verification /
        std::cerr<<"Error while veryfing ssl"<<std::endl;
        SSL_CTX_free(ctx);
        close(bio);
        return;
    }
    receive(bio);
    login(bio);
    if (dl_de)
    {
        download(bio);
    }
    else
    {
        delete_m(bio);
    }
    SSL_CTX_free(ctx);
    close(bio);



}

/*
    Function
        closes communication
*/

void Socket::close(BIO *bio)
{
    BIO_free_all(bio);
}

