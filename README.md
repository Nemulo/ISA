# POP3 client system

Author: Marek Nemeth

## Contents

1. Usage
2. Libraries
3. Classes and Implementation
4. Files Included
5. Known problems

## Usage

To build the system use command `make`.
To run the system use following :

```bash
./popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>
```

### Options

1. Mandatory

    ```<server>```:      specifies the hostname or ip address to remote pop3 server

    ```-a <authfile>```:  specifies name of authentication file to log in and download messages from server

    ```-o <outdir>```:    specifies directory/path in which messages should be saved

    ```-d/-n``` :         option that defines operation that should be executed

      ```-d```: delete all messages

      ```-n```: retrieve all new messages

2. Optional

    ```-p <port>```:      specifies which port should be used, if omitted, default ports are used: 110 for unsecured commm. and 995 for TLS secured comm.

      ```-T``` : opening and using secured communication

       or

      ```-S``` : opening unsecured communication, which is after connecting to server upgraded to TLS

        If omitted, unsecured communication is estabilished and used.

    ```-c <certfile>```:  specifies the name of file containing certificates for connection

    ```-C <certaddr>```:  specifies the path/directory in which file/s with certificates can be found

## Libraries

Interesting and most used library in this system was ```<openssl/bio.h>``` and ```<openssl/ssl.h>```
since they contain functions as ```BIO_connect()```, for connecting to server and ```BIO_read()```,```BIO_write()``` for communication with server.

## Classes and implementation

Project uses one vital class ```Socket``` which contains multiple private functions, variables and one public function - object constructor. All functions neccesary for program to run as required are used within constructor which means that upon construction of ```Socket``` object, the purpose of the program is executed.
Object is constructed with parameters given from launching the system, from which object itself will operate as user requires.
Example of program execution:
user executes command ```./popcl address.com -T -d -a auth.txt -o outdir```

1. hostname is resolved
2. Object is created
3. In object constructor, depending on option -T/-S connection is opened via ```Socket::open()``` or ```Socket::open_s()```
4. Option d specifies data to be downloaded, system reads number of mails from server response
5. System downloads all new mails

## Files included

#### Header files :   ```socket.hpp```

#### Program files :    ```main.cpp socket.cpp```

#### other :    ```Makefile maunal.pdf README.md```

## Known problems

Client might have following problems :

1. If the server does not send responses imidiately or separately - e.g.
```
CLI: STAT
SER: +OK 10 4564
CLI: RETR 3
SER: +OK x octets follow
```
System is implemented to expect x octets to follow imidiately after response, not in 2 separate responses from server. This occurance may lead to infinite waiting for server to respond although Client did not send any request.

2. Downloading large number of messages - client might download less messages than expected and end in softlock, problem seems to be same as in #1
