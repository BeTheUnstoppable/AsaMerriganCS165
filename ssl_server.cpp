//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
#include <fstream>
#include <iostream>

using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	printf("SERVER STEP 1 \n");
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("SERVER STEP 2 \n");
	printf("2. Waiting for client to connect and send challenge...");
    
    //SSL_read
    char challenge[BUFFER_SIZE];
    memset(challenge,0,BUFFER_SIZE);
    int chalen = SSL_read(ssl,challenge,BUFFER_SIZE);

	if (chalen <= 0)
	{
		printf("Error recieving challenge from client");
        print_errors();
		exit(EXIT_FAILURE);
	}
    
	printf("DONE.\n");
	printf("    (Challenge: \"%s\")\n", 
	       buff2hex((const unsigned char*)(challenge),chalen).c_str());

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("SERVER STEP 3 \n");
	printf("3. Generating SHA1 hash...");
	
	BIO *hash, *bbuf;
	char mdbuf[20];
	memset(mdbuf,0,sizeof(mdbuf));

	//BIO_new(BIO_s_mem());
	bbuf = BIO_new(BIO_s_mem());
	//BIO_write
	BIO_write(bbuf, challenge, chalen);
	//BIO_new(BIO_f_md());
	hash = BIO_new(BIO_f_md());
	//BIO_set_md;
	BIO_set_md(hash, EVP_sha1());
	//BIO_push;
	BIO_push(hash, bbuf);
	//BIO_gets;
	//int mdlen=BIO_gets(hash, mdbuf,sizeof(mdbuf));
	int mdlen=BIO_read(hash, mdbuf,sizeof(mdbuf));
	string hash_string = buff2hex((const unsigned char*)(mdbuf), mdlen);

	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", hash_string.c_str(), mdlen);

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("SERVER STEP 4 \n");
	printf("4. Signing the key...");

	unsigned char signature[EVP_MAX_MD_SIZE];
	BIO *rsaprikey = BIO_new_file("rsaprivatekey.pem", "r");

	//PEM_read_bio_RSAPrivateKey
	RSA * rsa_pri = PEM_read_bio_RSAPrivateKey(rsaprikey,NULL,0,NULL);
	//RSA_private_encrypt
	int siglen = RSA_private_encrypt(mdlen,(const unsigned char*)(mdbuf),
					 signature, rsa_pri, RSA_PKCS1_PADDING);

    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", siglen);
    printf("    (Signature: \"%s\" (%d bytes))\n", 
	   buff2hex((const unsigned char*)signature, siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("SERVER STEP 5 \n");
	printf("5. Sending signature to client for authentication...");

	//BIO_flush
	BIO_flush(server);
	//SSL_write
	SSL_write(ssl,signature,siglen);


	//char signature[BUFFER_SIZE];
	//memset(signature,0,BUFFER_SIZE);
	//int siglen = SSL_read(ssl, signature, BUFFER_SIZE);
	
    printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("SERVER STEP 6 \n");
	printf("6. Receiving file request from client...");

    //SSL_read
    char filename[50];
    memset(filename,0,sizeof(filename));
    
    int flen = SSL_read(ssl,filename,BUFFER_SIZE);
	
    if (flen <= 0)
      {
		printf("Error recieving filename from client");
        print_errors();
		exit(EXIT_FAILURE);
	}
    

    printf("RECEIVED.\n"); 
    printf("    (File requested: \"%s\"\n", filename);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("SERVER STEP 7 \n");
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
      //BIO_flush
	BIO_flush(server);
      //BIO_new_file
	BIO *bfile = BIO_new_file(filename,"r");
      //BIO_puts(server, "fnf");
	//BIO_puts(server, "fnf");
      //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
	char buffer[100];
	int bytesSent=0;
	int bytesRead=1;
	ifstream file;
	file.open(filename);
	if(!file.is_open())
	{
	  printf("Error, no file read, no file sent\n");
	  print_errors();
	  exit(EXIT_FAILURE);
	}  
	
	while(bytesRead>0){
	  int count=0;
	  //SSL_write(ssl, buffer, bytesRead);
	  for(int i=0;i<100;i++){
	    if(!file.is_open())
	      break;
	    file.get(buffer[i]);
	    count++;
	  }
	  bytesRead= BIO_read(bfile, buffer,count);
	  bytesSent+=SSL_write(ssl,buffer,bytesRead);
	}
	
	file.close();

    printf("SENT.\n");
    printf("    (Bytes sent: %d)\n", bytesSent);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("SERVER STEP 8 \n");
	printf("8. Closing connection...");

	//SSL_shutdown
	SSL_shutdown(ssl);
	//BIO_reset

    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}
