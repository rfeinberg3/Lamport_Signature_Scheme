/*
  Program Summary

:compile: gcc Sign.c -ltomcrypt -lzmq -o Alice
:run: ./Alice Message1.txt SK.txt
*/

//Header Files
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <tomcrypt.h>
#include <zmq.h>

#define BITS_PER_MESSAGE 256
#define BYTES_PER_MESSAGE 32

// Function prototypes
unsigned char *Read_File (char fileName[], int *fileLen);
void Read_Multiple_Lines_from_File (char fileName[], unsigned char message[2 * BITS_PER_MESSAGE][2*BYTES_PER_MESSAGE+1]);
void Write_File(char fileName[], unsigned char input[], unsigned char type[2]);
void Write_Multiple_Lines_to_File(char fileName[], unsigned char input[BITS_PER_MESSAGE][2*32+1]);
unsigned char *PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
void Convert_to_Hex(unsigned char output[], unsigned char input[], int inputlength);
unsigned char *Hash_SHA256(unsigned char* input, unsigned long inputlen);
void Send_via_ZMQ(unsigned char send[], int sendlen);
unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit);

void reverse(unsigned char str[], int length);
unsigned char* citoa(int num, unsigned char* str, int base);


int main(int argc, char *argv[]) {
	if(argc != 3) {
		printf("Error: Exactly two arguments are required.\n");
		return 1;
	}
	// Read in Message
	int message_length;
	unsigned char *message = Read_File(argv[1], &message_length);
  	printf("The size of the message (in bytes) is: %d\n", message_length);
  	
  	// Read in the SK
	unsigned char SK[2*BITS_PER_MESSAGE][2*BYTES_PER_MESSAGE+1];
  	Read_Multiple_Lines_from_File(argv[2], SK);
  	
  	// Hash the Message
  	unsigned char hash[32];
  	memcpy(hash, Hash_SHA256(message, message_length), 32);
  	
  	// Get Hash Bits
  	unsigned char hash_bits[8*32+1];
  	for(int i = 0; i < 32; i++) {
  		unsigned char ch = hash[i];
  		int int_from_char = hash[i];
  		unsigned char temp[9];
  		citoa(int_from_char, temp, 2);
  		memcpy(hash_bits+8*i, temp, 8); // Append 8-bits to Signature 
  		//printf("It:%d The binary of character '%c' (decimal = %d) is: %s\n", i, ch, ch, temp);
  	}
  	hash_bits[8*32+1] = '\0';
  	
  	// Make Signature and Write to Signature.txt
  	unsigned char Signature[BITS_PER_MESSAGE][2*BYTES_PER_MESSAGE+1];
  	for(int i = 0; i < 2*BITS_PER_MESSAGE; i=i+2) {
  		unsigned char sig_i[2*32+1];
  		if (hash_bits[i/2] == '0') memcpy(sig_i, SK[i], 2*32+1); // SK[i][0]
  		else memcpy(sig_i, SK[i+1], 2*32+1); //SK[i][1]
		memcpy(Signature+(i/2), sig_i, (2*32+1)); // Append to Message
		Signature[i/2][2*BYTES_PER_MESSAGE] = '\0'; // Truncate newline character
		//printf("It:%d: Signature = %s", i/2, Signature[i/2]);
  	}
  	Write_Multiple_Lines_to_File("Signature.txt", Signature);
  	
  	// Sending Message and Signature to Bob
	unsigned char sendingMess[message_length + BITS_PER_MESSAGE * (2*BYTES_PER_MESSAGE+1)];
	memcpy(sendingMess, message, message_length);
	for(int i = 0; i < BITS_PER_MESSAGE; i++) 
		memcpy(
		  sendingMess + message_length + i*(2*BYTES_PER_MESSAGE+1),
		  Signature[i],
		  2*BYTES_PER_MESSAGE+1
		);		
	Send_via_ZMQ(sendingMess, message_length + (2*BYTES_PER_MESSAGE+1) * BITS_PER_MESSAGE);
	
  	return 0;
}

// A utility function to reverse a string
void reverse(unsigned char str[], int length)
{
    int start = 0;
    int end = length - 1;
    while (start < end) {
        unsigned char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        end--;
        start++;
    }
}
// Implementation of citoa()
unsigned char* citoa(int num, unsigned char* str, int base)
{
    int i = 0;
    bool isNegative = false;
 
    /* Handle 0 explicitly, otherwise empty string is
     * printed for 0 */
    if (num == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }
 
    // In standard itoa(), negative numbers are handled
    // only with base 10. Otherwise numbers are
    // considered unsigned.
   // if (num < 0 && base == 10) {
    //    isNegative = true;
   //     num = -num;
    //}
 
    // Process individual digits
    while (num != 0) {
        int rem = num % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num = num / base;
    }
    
    // Pad to 8 bits if needed
    while(i < 8)
    	str[i++] = '0';
    
    // If number is negative, append '-'
    //if (isNegative)
    //    str[i++] = '-';
 
    str[i] = '\0'; // Append string terminator
 
    // Reverse the string
    reverse(str, i);
 
    return str;
}

// Read from File
unsigned char *Read_File (char fileName[], int *fileLen)
{
	FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
	fseek(pFile, 0L, SEEK_END);
	int temp_size = ftell(pFile)+1;
  	fseek(pFile, 0L, SEEK_SET);
    	unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    	*fileLen = temp_size-1;
	return output;
}
//Read Multiple Lines from File
void Read_Multiple_Lines_from_File(char fileName[], unsigned char message[2 * BITS_PER_MESSAGE][2*BYTES_PER_MESSAGE+1])
{
  char *line_buf = NULL;
  size_t line_buf_size = 0;
  int line_count = 0;
  ssize_t line_size;
  FILE *fp = fopen(fileName, "r");
  if (!fp)
  {
    fprintf(stderr, "Error opening file '%s'\n", fileName);
  }
  int j=0;
  line_size = getline(&line_buf, &line_buf_size, fp);
  while (line_size >= 0)
  {
    for(int i=0; i<2*BYTES_PER_MESSAGE+1; i++){
      message[j][i] = line_buf[i];
    }
    message[j][2*BYTES_PER_MESSAGE+1] ='\0';
    //printf("Message%d == %s\n", j+1, message[j]);
    j++;
    line_size = getline(&line_buf, &line_buf_size, fp);
  }
  free(line_buf);
  line_buf = NULL;
  fclose(fp);
}
// Write multiple lines to file
void Write_Multiple_Lines_to_File(char fileName[], unsigned char input[BITS_PER_MESSAGE][2*BYTES_PER_MESSAGE+1])
 { 
	FILE *pFile;
	pFile = fopen(fileName,"w");
	if (pFile == NULL){
		printf("Error opening file. \n");
		exit(0);
	}
	for(int i=0; i<BITS_PER_MESSAGE; i++) {
		unsigned char temp[2*BYTES_PER_MESSAGE+1];
		memcpy(temp, input[i], 2*BYTES_PER_MESSAGE+1);
		temp[2*BYTES_PER_MESSAGE+1] = '\0';
		fputs(temp, pFile);
		if (i < (BITS_PER_MESSAGE-1)) fputs("\n", pFile);
	}
	fclose(pFile);
}

//Write to File
void Write_File(char fileName[], unsigned char input[], unsigned char type[2]) {
	FILE *pFile;
	pFile = fopen(fileName, type);
	if (pFile == NULL){
		printf("Error opening file. \n");
		exit(0);
	}
	fputs(input, pFile);
	fclose(pFile);
}

//Showing in Hex
void Show_in_Hex(char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

//Convert to Hex
void Convert_to_Hex(unsigned char output[], unsigned char input[], int inputlength)
{
	for (int i=0; i<inputlength; i++){
		sprintf(&output[2*i], "%02x", input[i]);
	}
	output[2*inputlength] = '\0';
	//printf("Hex format: %s\n", output);  //remove later
}

//SHA-256 Fucntion
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
	unsigned char *hash_result = (unsigned char*) malloc(inputlen);
	//LibTomCrypt structure for hash
	hash_state md;
	//Initializing the hash set up
	sha256_init(&md);
	//Hashing the data given as input with specified length
	sha256_process(&md, (const unsigned char*)input, inputlen);
	//Produces the hash (message digest)
	sha256_done(&md, hash_result);

	return hash_result;
}

//Sending via ZeroMQ
void Send_via_ZMQ(unsigned char send[], int sendlen)
{
	void *context = zmq_ctx_new ();	//creates a socket to talk to Bob
    	void *requester = zmq_socket (context, ZMQ_REQ); //creates requester that sends the messages
   	printf("Connecting to Bob and sending the message...\n");
    	zmq_connect (requester, "tcp://localhost:5555");//make outgoing connection from socket
    	zmq_send (requester, send, sendlen, 0);	//send msg to Bob
    	zmq_close (requester); //closes the requester socket
    	zmq_ctx_destroy (context); //destroys the context & terminates all 0MQ processes
}

//Receiving via ZeroMQ
unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit) 
{
	void *context = zmq_ctx_new ();	//creates a socket to talk to Alice
	void *responder = zmq_socket (context, ZMQ_REP); //creates responder that receives the messages
   	int rc = zmq_bind (responder, "tcp://*:5555"); //make outgoing connection from socket
    	int received_length = zmq_recv (responder, receive, limit, 0); //receive message from Alice
    	unsigned char *temp = (unsigned char*) malloc(received_length);
    	for(int i=0; i<received_length; i++){
        	temp[i] = receive[i];
    	}
    	*receivelen = received_length;
    	printf("Received Message: %s\n", receive);
    	printf("Size is %d\n", received_length);
    	return temp;
}
