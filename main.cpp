/*
    AUTHOR: Marek Nemeth
    MAIL:   xnemet05@stud.fit.vutbr.cz
    FILE:   socket.cpp
    Project:popcl
    Subject:ISA
    Last Date modified: 30.10.2021
*/

#include <iostream> 
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "socket.hpp"

/* Function
  ipaddr - address of host

  returns - true, if address is valid
            false otherwise
  */
bool validateIpAddress(std::string ipaddr)
{
  if (gethostbyname(ipaddr.c_str())!=nullptr)
  {
    return 1;
  }
  return 0;
}

/*=========================
          Main
*/ 
int main(int argc, char *argv[])
{
  int opt;

  //  options

  std::string ip;
  std::string port;
  std::string certfile;
  std::string certaddr;
  std::string authfile;
  std::string outdir;
  
  // arg validation variables 
  bool T = false;
  bool S = false;
  bool ok = true;
  bool d = false;
  bool n = false;

  //------------------------------------------
  //            Arg Parsing
  //------------------------------------------

  while ((opt = getopt(argc,argv,"-dnp:TSc:C:a:o:")) !=-1)
  {
    switch (opt)
    {
      case 'p':
        if (optarg!=nullptr)
        {
          port = optarg;
        }
        else
        {
          std::cerr<<"port is missing"<<std::endl;
          ok = false;
        }
        break;
      case 'T':
        T=true;
        break;
      case 'S':
        S = true;
        break;
      case 'c':
        if ((!T&&!S) || (T&&S) )
        {
          std::cerr<<"invalid argument combination"<<std::endl;
          ok = false;
        }
        else
        {
          if (optarg==nullptr)
          {
            std::cerr<<"Certificate file is missing"<<std::endl;
            ok=false;
          }
          else
          {
            certfile = optarg;
          }
        }
        break;
      case 'C':
        if (optarg == nullptr)
        {
          std::cerr<<"Certificate address is missing"<<std::endl;
          ok = false;
        }
        else
        {
          certaddr = optarg;
        }
        break;
      case 'd':
        d = true;
        break;
      case 'n':
        n = true;
        break; 
      case 'a':
        if (optarg == nullptr)
        {
          std::cerr<<"Auth file is missing"<<std::endl;
          ok = false;
        }
        else
        {
          authfile = optarg;
        }
        break;
      case 'o': 
        if(optarg == nullptr)
        {
          std::cerr<<"Outdir is missing"<<std::endl;
          ok = false;
        }
        else
        {
          outdir = optarg;
        }
        break;
      default:

      /* the only unknown option might be server address */
        ip = optarg;
        // check if the server name/address is valid

        if (!validateIpAddress(ip))
        {
          std::cerr<<"Unable to validate hostname"<<std::endl;
          ok = false;
        }
        break;
    }
  }
  if ((d&&n)||!d&&!n)
  {
    ok = false;
  }
  if (outdir.size() == 0 || authfile.size() == 0 || ip.size() == 0)
  {
    ok = false;
  }
  //  Arg parsing ended with errors
  if (!ok || argc<7)
  {
    std::cerr<<"An error occured while parsing arguments, please use following format\npopcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>\n"<<std::endl;
    return 1;   
  }

  //-----------------------------------------------------------
  //          Creating connection
  //-----------------------------------------------------------


  OpenSSL_add_all_algorithms();
  OpenSSL_add_ssl_algorithms();
  ERR_load_BIO_strings();
  SSL_load_error_strings();

  //  port was not provided, substituing default ports for communication

  if (port.size()==0)
  {
    if (T)
    {
      /*  Communication is secured, opening on port 995 
          Creating socket with parameters from args
          ip -> hostname
          995 ->  port
          T -> option T (true of false)
          S -> option S (true or false)
          certfile -> certificate file
          certaddr -> certificate address
          authfile -> file with authentication data
          n -> variable represents options -d/-n, if true, option for reading is selected, otherwise for deleting
          outdir -> directory for writing output
      */

      Socket s1 = Socket(ip,"995",T,S,certfile,certaddr,authfile,n,outdir);
    }
    else 
    { 
      /*  Communication is opened unsecured, port 110 */

      Socket s1 = Socket(ip,"110",T,S,certfile,certaddr,authfile,n,outdir);
    }
  }
  else
  {
    Socket s1 = Socket(ip,port,T,S,certfile,certaddr,authfile,n,outdir);
  }
  return 0;
}