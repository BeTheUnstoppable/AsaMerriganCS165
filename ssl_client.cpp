//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
#include <fstream>
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("CLIENT STEP 1 \n");
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("CLIENT STEP 2 \n");
	printf("2.  Sending challenge to the server...");
    
    string randomNumber = "31338";
	//SSL_write

	printf("\nCLIENT STEP 3 \n");
    int num_bytes = SSL_write(ssl, randomNumber.c_str(), BUFFER_SIZE);
    
    
    printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", randomNumber.c_str());

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server

	printf("CLIENT STEP 5 \n");
	printf("3a. Receiving signed key from server...");


	//SSL_read;
	char buff[BUFFER_SIZE];
	memset(buff,0,BUFFER_SIZE);
	int len = SSL_read(ssl, buff, BUFFER_SIZE);

	if (len <= 0)
	{
		printf("Error recieving signed hash from server");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", 
	       buff2hex((const unsigned char*)(buff), len).c_str(), len);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");
	
	BIO *bbuf, *rsapubkey;
	char dkey[20];

	//BIO_new(BIO_s_mem())
	bbuf = BIO_new(BIO_s_mem());
	//BIO_write
	BIO_write(bbuf,buff, len);
	//BIO_new_file
	rsapubkey = BIO_new_file("rsapublickey.pem", "r");
	//PEM_read_bio_RSA_PUBKEY
	RSA *rsa_pub = PEM_read_bio_RSA_PUBKEY(rsapubkey,NULL,0,NULL);
	//RSA_public_decrypt
	int r_p_d = RSA_public_decrypt(len, (const unsigned char *)(buff),(unsigned char*)(dkey), rsa_pub, RSA_PKCS1_PADDING);

	//BIO_free
	string generated_key= buff2hex((const unsigned char*)(buff),len);
	string decrypted_key= buff2hex((const unsigned char*)(dkey),20);

	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("CLIENT STEP 7 \n");
	printf("4.  Sending file request to server...");

	PAUSE(2);
	//BIO_flush
	BIO_flush(client);
	//BIO_puts
	BIO_puts(bbuf,filename);
	
	//SSL_write
	SSL_write(ssl,filename,40);//sizeof(filename));

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("CLIENT STEP 8 \n");
	printf("5.  Receiving response from server...");

    //BIO_new_file
	//bbuf = BIO_new_file("outfile.txt","w");
	ofstream file;
	file.open("outfile.txt");
	int filelength=0;
	int temp_fl=0;
	char intofile[BUFFER_SIZE];
    //SSL_read
	do{
	  //temp_fl=SSL_read(ssl,(void *)(bbuf),BUFFER_SIZE);
	  //BIO_write(bbuf,intofile,temp_fl);
	  temp_fl=SSL_read(ssl,intofile,BUFFER_SIZE);
	  print_errors();
	  printf("string:%s  \n-----------\n",intofile,temp_fl);
	  //BIO_write(bbuf,intofile,temp_fl);
	  file<<intofile;
	  filelength+=temp_fl;
	}while(temp_fl>0);
	file.close();
	//BIO_write
	//BIO_free

	printf("FILE RECEIVED.\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("CLIENT STEP 9 \n");
	printf("6.  Closing the connection...");

// 	//SSL_shutdown
// 	SSL_shutdown(ssl);
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

	//SSL_shutdown
	SSL_shutdown(ssl);
    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
