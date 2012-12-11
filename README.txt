Asa Merrigan
CS 165: Project

   For this project, the goal was to implement a client/server application
using the Open SSL library.   The program written for this project was meant
to have the client retrieve a document from the server using its RSA public
key.  First, the client establishes an SSL connection to the server.  Then,
the client sends the server an encrypted random challenge.  The server then
decrypts, hashes, signs, and returns this challenge. The client requests a
file from the server and the server returns the file over the SSL connection. 
Finally the client displays the file.
   
    The initial connection between the server and client is setup in
section 1 of both ssl_server.cpp and ssl_client.cpp.  This was included in the
code and not altered.

Client.2 uses SSL_write() to write a random number to the server.

Server.2 recieves the challenge using SSL_read().

Server.3 generates teh SHA1 hash of the challenge by pushing a hash BIO * on
to a BIO * which contains the challenge.

Server.4 signs the key using he RSA private key specified in the file
"rsaprivatekey.pem".  This encryption is taken from the simple.cpp file created
in lab 7.

Server.5 sends the signature to the client using the SSL_write()

Client.3.a recieves the signed key from the server using SSL_read()

Client.3.b authenticates the signed key by decrypting it.  This decryption is
taken from the simple.cpp file created in lab 7.

Client.4 sends teh server a file request using SSL_write()

Server.6 receives a filename request from th client using SSL_read()

Server.7 sends the requested file back to the client, assuming it exists
using BIO_read() and SSL_write()

Client.5 receives and dislpays the content of the file requested

Server.8 closes the connection using SSL_shutdown() and BIO_reset

Client.6 closes the connection using SSL_shutdown()

NOTE: For the 2.1 Client-Side Steps, I did not number the execution of steps
      4 or 6 because I was not sure where to implement them.  I don't believe
      they were neccessary.

NOTE: The content of the file, given to client from the server, does not have
      the correct content.  The file gives most of the proper information.  
      However there are extra characters at the end of the file.