//Header Files
#include <stdlib.h>
#include <stdio.h>
#include <tomcrypt.h>

#define BITS_PER_MESSAGE 256
#define BYTES_PER_MESSAGE 32
#define SEED_SIZE 30

/*
  Program Summary
:compile: gcc KeyGen.c -ltomcrypt -o CertificateAuthority
:run: ./CertificateAuthority Seed1.txt
*/


// Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], unsigned char input[], unsigned char type[2]);
void Write_Multiple_Lines_to_File_K(char fileName[], unsigned char input[2*BITS_PER_MESSAGE][2*BYTES_PER_MESSAGE+1]);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
void Convert_to_Hex(unsigned char output[], unsigned char input[], int inputlength);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void generate_private_keys(unsigned char secret_keys[BYTES_PER_MESSAGE][BYTES_PER_MESSAGE], const unsigned char* seed);
void generate_public_keys(unsigned char public_keys[BYTES_PER_MESSAGE][BYTES_PER_MESSAGE], unsigned char secret_keys[BYTES_PER_MESSAGE][BYTES_PER_MESSAGE]);


// Main Program
int main(int argc, char* argv[]) {
	if(argc != 2) {
		printf("Error: Exactly one argument is required.\n");
		return 1;
	}
	
	// Read in seed
	int seed_length;
	unsigned char* seed = Read_File(argv[1], &seed_length);
	printf("The size of the seed (in bytes) is: %d\n", seed_length);
	
	// Generate Secret Keys
	unsigned char secret_keys[2*BITS_PER_MESSAGE][BYTES_PER_MESSAGE];
	generate_private_keys(secret_keys, seed);
	// Write Secret Keys to .txt File
	unsigned char hex_secret_keys[2*BITS_PER_MESSAGE][2*BYTES_PER_MESSAGE+1];
	for (int i = 0; i < 2; ++i) {
        	for (int j = 0; j < BITS_PER_MESSAGE; ++j) { 
			Convert_to_Hex (
				hex_secret_keys[i*BITS_PER_MESSAGE+j],
				secret_keys[i*BITS_PER_MESSAGE+j],
				BYTES_PER_MESSAGE
			);
		}
	}
	Write_Multiple_Lines_to_File_K("SK.txt", hex_secret_keys);
	
	// Generate Public Keys
	unsigned char public_keys[2 * BITS_PER_MESSAGE][BYTES_PER_MESSAGE];
	generate_public_keys(public_keys, secret_keys);
	// Write Public Keys to .txt File
	unsigned char hex_public_keys[2*BITS_PER_MESSAGE][2*BYTES_PER_MESSAGE+1];
	for (int i = 0; i < 2; ++i) {
        	for (int j = 0; j < BITS_PER_MESSAGE; ++j) { 
			Convert_to_Hex (
				hex_public_keys[i*BITS_PER_MESSAGE+j],
				public_keys[i*BITS_PER_MESSAGE+j],
				BYTES_PER_MESSAGE
			);
		}
	}
	Write_Multiple_Lines_to_File_K("PK.txt", hex_public_keys);
	
	return 0;
}

// Read from File
unsigned char* Read_File (char fileName[], int *fileLen)
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

// Write multiple lines to file
void Write_Multiple_Lines_to_File_K(char fileName[], unsigned char input[2*BITS_PER_MESSAGE][2*BYTES_PER_MESSAGE+1]) { 
	FILE *pFile;
	pFile = fopen(fileName,"w");
	if (pFile == NULL){
		printf("Error opening file. \n");
		exit(0);
	}
	for(int j=0; j<BITS_PER_MESSAGE; j++) {
		for(int i=0; i<2; i++) {
			unsigned char temp[2*BYTES_PER_MESSAGE+1];
			temp[2*BYTES_PER_MESSAGE+1] = '\0';
			memcpy(temp, input[i*BITS_PER_MESSAGE+j], 2*BYTES_PER_MESSAGE+1);
			fputs(temp, pFile);
	    
			if (j != (BITS_PER_MESSAGE-1) || i == 0) fputs("\n", pFile);
		}
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

// Generate Private Keys Function
void generate_private_keys(unsigned char secret_keys[BYTES_PER_MESSAGE][BYTES_PER_MESSAGE], const unsigned char* seed) {
    unsigned char position_seed[SEED_SIZE + 2]; // make room for row and column characters
    memcpy(position_seed, seed, SEED_SIZE);
    
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < BITS_PER_MESSAGE; ++j) {
            position_seed[SEED_SIZE] = (unsigned char) i;
            position_seed[SEED_SIZE + 1] = (unsigned char) j;
            // use the first 256 columns for i = 0 and the remaining 256 columns for i = 1 to store secret keys
            memcpy
            (
            	secret_keys[i * BITS_PER_MESSAGE + j],
            	PRNG(position_seed, BYTES_PER_MESSAGE, BYTES_PER_MESSAGE),
            	BYTES_PER_MESSAGE
            );
        }
    }
}

// Generate Public Keys Function
void generate_public_keys(unsigned char public_keys[BYTES_PER_MESSAGE][BYTES_PER_MESSAGE], unsigned char secret_keys[BYTES_PER_MESSAGE][BYTES_PER_MESSAGE]) {
	for (int i = 0; i < 2; ++i) {
        	for (int j = 0; j < BITS_PER_MESSAGE; ++j) {
        		memcpy(
        			public_keys[i*BITS_PER_MESSAGE+j], // output of hash
        			Hash_SHA256(secret_keys[i*BITS_PER_MESSAGE+j], BYTES_PER_MESSAGE), // hash private key
        			BYTES_PER_MESSAGE // size of private key
        		);
        	}
	}
}

//PRNG Function
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen)
{
	int err;
	unsigned char *pseudoRandomNumber = (unsigned char*) malloc(prnlen);

	prng_state prng;                                                             //LibTomCrypt structure for PRNG
	if ((err = chacha20_prng_start(&prng)) != CRYPT_OK){                        //Sets up the PRNG state without a seed
		printf("Start error: %s\n", error_to_string(err));
	}					                
	if ((err = chacha20_prng_add_entropy(seed, 32, &prng)) != CRYPT_OK) {  //Uses a seed to add entropy to the PRNG
		printf("Add_entropy error: %s\n", error_to_string(err));
	}	            
	if ((err = chacha20_prng_ready(&prng)) != CRYPT_OK) {                       //Puts the entropy into action
		printf("Ready error: %s\n", error_to_string(err));
	}
	chacha20_prng_read(pseudoRandomNumber, prnlen, &prng);                     //Writes the result into pseudoRandomNumber[]

	if ((err = chacha20_prng_done(&prng)) != CRYPT_OK) {                        //Finishes the PRNG state
		printf("Done error: %s\n", error_to_string(err));
	}

	return (unsigned char*)pseudoRandomNumber;
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
