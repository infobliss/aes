/*============================================================================
 Name        : aes.cpp
 Author      : Infobliss
 Version     : 1.0
 License   : MIT
 Description : Implementation of the Advanced Encryption Standard(AES) block cipher in C++.
 Implementation Details :
 This C++ program implements the AES block cipher which is a modern symmetric block cipher, i.e., the same key
 is used for encryption and decryption.
 Input : A 128-bit plaintext
 Key size : 128-bit
 Round key size : 128-bit
 No. of rounds : 10 + 1
 The property of AES is such that the output of the 1st and 9th encryption round is identical to the output of
 the corresponding decryption rounds.
 This fact is verified in the code.
============================================================================*/

#include <iostream>
#include <cstdlib>
#include <string>
#include <stdio.h>
#include <math.h>

using namespace std;
//The expanded key is 176 bytes of which 16 bytes will be used in each round
uint8_t expandedKey2[176];
//The key is 128-bit or 16 bytes
uint8_t key[16] = { 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98};
//The plaintext
uint8_t plainText2[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
//The substitution bytes table
uint8_t sbox[256] =
{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
//The inverse substitution bytes table
uint8_t rsbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

/*Function to return the substitute Byte
 @param input: the byte to be substituted
 @param mode: the mode is 0 for encryption phase and 1 for decryption phase
 Returns the substitution byte for the input byte by looking up the appropriate substitution table
*/
uint8_t SubstituteBytes(uint8_t input, int mode){
	if (mode==0){
	return sbox[input];
	}
	else if(mode==1){
		return rsbox[input];
	}
	return 0;
}
/*Function to convert from binary to decimal
 @param byte: an 8-digit binary number
 Returns the corresponding decimal value
*/
uint8_t binToDec(uint8_t* byte)
{
	uint8_t dec=0;
	for(int i=0; i<8; i++)
	{
		dec += byte[i]*pow(2, 7-i);
	}
	return dec;
}
/*Function to convert from binary to decimal
 @param word: a set of 4 bytes, i.e., B0 B1 B2 B3
 Returns the corresponding rotated word, i.e., B1 B2 B3 B0
*/
void RotWord(uint8_t* word)
{
	int i;
	uint8_t temp;

	temp = word[0];		//copy the first byte of word into temp

	for(i=1; i<4; i++)		//shift left bytes
	{
		word[i-1] = word[i];
	}

	word[3] = temp;

}
/*Function to calculate the round constant to be used in the key expansion module
 @param i: index at which round constant is sought
 Returns index i of an array of constants
*/
uint8_t RoundConst(int i)
{
	if (i==1)
		return 1;
	else if(i<9)
		return 2*RoundConst(i-1);
	else if(i == 9) //Since multiplication is defined over the field GF(2^8)
		return 0x1b;    //2^9 = (2^8)*2 = 80*2 = 1B
	else if(i == 10)
		return 0x36;    //2^10 = (2^9)*2 = 1B*2 = 36
	return 0;
}
/*Function to calculate the EXPANDED key
 @param key: 128-bit key
 @param expandedKey: computed expanded key
*/
void keyExpander(uint8_t* key, uint8_t* expandedKey)
{
	int i, j, k;
	uint8_t tempWord[4], byte, roundCon;

	//copy the given key into word0 to word3
	for(i=0; i<4; i++)
	{
		for(j=0; j<4; j++)
		{
			expandedKey[i*4 + j] = key[i*4 + j];
		}
	}

	//find the words from 4 to 43
	for(i=4; i<44; i++)
	{
		//temp = w[i-1]
		for(j=0; j<4; j++)
		{
			tempWord[j] = expandedKey[(i-1)*4 + j];
		}
		//if(i(mod4) == 0)   temp = SubWord(RotWord(temp)) XOR Rcon[i/4];
		//processing on tempWord which is 4 bytes at any time
		if(i%4 == 0)
		{
			RotWord(tempWord);
			//Substitute the SubstituteBytes(byte input) from Sunny
			for(k=0; k<4; k++)
			{
				byte = SubstituteBytes(tempWord[k],0);
				tempWord[k] = byte;
			}
			roundCon = RoundConst(i/4);
			tempWord[0] = tempWord[0] xor roundCon;
		}
		//w[i]=w[i-4] xor tempWord
		for(j=0; j<4; j++)
		{
			expandedKey[i*4 + j] = expandedKey[(i-4)*4 + j] xor tempWord[j];
		}
		//Making Column major
	}

}
/*Function to do the Add Round Key Transformation
 @param plainText: 128-bit plainText
 @param expandedKey: the computed expanded key
 @param roundNo : the current round number
 Returns XORed result
*/
void AddRoundKey(uint8_t* plainText, uint8_t* expandedKey, int roundNo)
{
	for(int i=0; i<16; i++)
	{
			plainText[i] = plainText[i] xor expandedKey[roundNo*16 + i];
	}
}
/*Function to calculate the EXPANDED key
 @param inputState: 4*4 input state matrix conssiting of 16 bytes
 @param mode: 0 for encryption, 1 for decryption
*/
void ShiftBytes(uint8_t *inputState,int mode){
	if (mode==0)// for encryption
			{
				/*Have to leave the 1st 4 bytes as it is
				Shifting the next 4 bytes by 1 position left*/
				uint8_t temp=inputState[4];
				inputState[4]=inputState[5];
				inputState[5]=inputState[6];
				inputState[6]=inputState[7];
				inputState[7]=temp;
				//Shifting the next 4 bytes by 2 position*/
				temp=inputState[8];
				inputState[8]=inputState[10];
				inputState[10]=temp;
				temp=inputState[9];
				inputState[9]=inputState[11];
				inputState[11]=temp;
				//Shifting the next 4 bytes by 3 position*/
				uint8_t temp2;
				temp=inputState[12];
				inputState[12]=inputState[15];
				inputState[15]=inputState[14];
				temp2=inputState[13];
				inputState[13]=temp;
				inputState[14]=temp2;
			}
	if (mode==1)// for decryption
				{
					/*Have to leave the 1st 4 bytes as it is
					Shifting the next 4 bytes by 1 position right*/
					uint8_t temp=inputState[7];
					inputState[7]=inputState[6];
					inputState[6]=inputState[5];
					inputState[5]=inputState[4];
					inputState[4]=temp;
					//Shifting the next 4 bytes by 2 position*/
					temp=inputState[10];
					inputState[10]=inputState[8];
					inputState[8]=temp;
					temp=inputState[11];
					inputState[11]=inputState[9];
					inputState[9]=temp;
					//Shifting the next 4 bytes by 3 position*/
					uint8_t temp2;
					temp=inputState[15];
					inputState[15]=inputState[12];
					inputState[12]=inputState[13];
					temp2=inputState[14];
					inputState[14]=temp;
					inputState[13]=temp2;
				}

}
/*Function to multiply over the field GF(2^8)
 @param f, g : two numbers
 Reurns the product f*g
*/
uint8_t GF2raisedTo8Multiply(uint8_t f, uint8_t g)
{
	int i;
	uint8_t irreducible = 0x1b;
	uint8_t lookup[8], product = 0x00;
	lookup[0] = f;
	for(i=0; i<7; i++)
	{
		//if the given numbers MSB is not set just left shift
		if(lookup[i] < 0x80)
		{
			lookup[i+1] = lookup[i]<<1;
		}
		else
		{
			lookup[i+1] = lookup[i]<<1;
			lookup[i+1] = lookup[i+1] xor irreducible;
		}
	}
	//Now do the multiplication of f with g
	uint8_t powersOf2[8] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
	for(i=0; i<8; i++)
	{
		if((g & powersOf2[i]) != 0)
			product = product xor lookup[i];
	}
	return product;
}
/*Function to multiply the state with pre-decided 4*4 matrix
 @param multMatrix : pre-decided matrix to multiply the state with
 @param plainText : the state matrix
*/
void mixColumns(uint8_t* multMatrix, uint8_t* plainText)
{
	uint8_t byte;
	int i, j, k;
	for(i=0; i<4; i++)
	{
		for(j=0; j<4; j++)
		{
			byte=0x00;
			//cout<<"index ("<<i<<","<<j<<"):";
			for(k=0; k<4; k++)
			{
				//printf("\nMulti %0x and %0x", multMatrix[i*4 + k], plainText[k*4 + j]);
				byte = byte xor GF2raisedTo8Multiply(multMatrix[i*4 + k], plainText[k*4 + j]);
			}
			plainText2[i*4 + j] = byte;
		}
	}
	for(i=0; i<16; i++)
	{
		plainText[i] = plainText2[i];
	}
}
/*Function to convert the keys for each round into column major form
 @param expandedKey2 : expanded key to be converted into column major form
 @param expandedKey : the converted key in column major form
*/
void convertToColMajor(uint8_t* expandedKey2, uint8_t* expandedKey)
{
	int l,m,offset=0;
	for(l=0; l<11; l++)
	{
		offset = l*16;
		for(int i=0; i<4; i++)
			{
				for(int j=0; j<4; j++)
				{
					expandedKey[i*4 + j + offset] = expandedKey2[i + 4*j + offset];
				}
			}
	}
}
/*
The main function
*/
int main() {
	cout << "!!!Hello World!!!" << endl;

	uint8_t pt[16], ct[16], plainText[16];

	cout<<"Key is \n";
			for(int i=0; i<16; i++)
			{	printf("%0x ",key[i]);
			}

	cout<<"\nplainText is \n";
		for(int i=0; i<16; i++)
		{	printf("%0x ",plainText2[i]);
			pt[i] = plainText2[i];
		}

	//Make the plainText column major
	for(int i=0; i<4; i++)
	{
		for(int j=0; j<4; j++)
		{
			plainText[i*4 + j] = plainText2[i + 4*j];
		}
	}

	//Pass this key to the keyExpander module
	uint8_t expandedKey[44*4] = {0}, byte;		//44 words expanded key
	keyExpander(key, expandedKey2);

	convertToColMajor(expandedKey2, expandedKey);

	cout<<"\n\nExpanded key is :\n";
	for(int i=0; i<4*44; i++)
		printf("%0x ",expandedKey[i]);

	cout<<endl;
	int roundNo=0;
	//Round 0: Add Round Key
	AddRoundKey(plainText, expandedKey, roundNo);


	//First 9 rounds
	for(roundNo=1; roundNo<10; roundNo++)
	{
	//Each Round: Sub Bytes, Shift Rows, Mix Columns, Add Round Key
	//1.1: Sub Bytes
	for(int k=0; k<16; k++)
	{
		byte = SubstituteBytes(plainText[k],0);
		plainText[k] = byte;
	}
	//1.2: Shift Rows
	ShiftBytes(plainText, 0);

	//1.3: Mix Columns
	uint8_t multMatrix[16] = { 0x02, 0x03, 0x01, 0x01, 0x01, 0x02, 0x03, 0x01, 0x01, 0x01, 0x02, 0x03, 0x03, 0x01, 0x01, 0x02};
	mixColumns(multMatrix, plainText);

	//1.4: Add Round Key
	AddRoundKey(plainText, expandedKey, roundNo);
	if(roundNo == 1)
    {
        cout<<"\nTransformed plaintext after round 1\n";
        for(int q=0; q<16; q++)
		{	printf("%0x ",plainText[q]);
		}
    }

	}
	//Round 10
	roundNo=10;
	//1.1: Sub Bytes
		for(int k=0; k<16; k++)
		{
			byte = SubstituteBytes(plainText[k],0);
			plainText[k] = byte;
		}
	//1.2: Shift Rows
		ShiftBytes(plainText, 0);
	//1.4: Add Round Key
		AddRoundKey(plainText, expandedKey, roundNo);
	cout<<"\n\nCipherText is \n";
	for(int i=0; i<16; i++)
	{	printf("%0x ",plainText[i]);
		ct[i] = plainText[i];
	}

	//-------------------ENCRYPTION FINISHED------------------//
		//plainText means input.
		roundNo=0;
		//Round 0: Add Round Key
		AddRoundKey(plainText, expandedKey, 10 - roundNo);
		//First 9 rounds
		for(roundNo=1; roundNo<10; roundNo++)
		{
			//Each Round: Shift Rows, Sub Bytes, Add Round Key, Mix Columns
		//1.1: Shift Rows
		ShiftBytes(plainText, 1);

		//1.2: Sub Bytes
		for(int k=0; k<16; k++)
		{
			byte = SubstituteBytes(plainText[k],1);
			plainText[k] = byte;
		}

        if(roundNo == 9)    //printing the transformed ciphertext after round 9
        {
            printf("\n\nTransformed ciphertext after round %d\n", roundNo);

            for(int q=0; q<16; q++)
            {	printf("%0x ",plainText[q]);
            }
        }   //This should match the Transformed plaintext after round 1

		//1.3: Add Round Key
		AddRoundKey(plainText, expandedKey, 10 - roundNo);

		//1.4: Mix Columns
		uint8_t multMatrix[16] = { 0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e, 0x0b, 0x0d, 0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09, 0x0e};
		mixColumns(multMatrix, plainText);


        }
		//Round 10
		roundNo = 10;
		//1.1: Shift Rows
		ShiftBytes(plainText, 1);
		//1.2: Sub Bytes
			for(int k=0; k<16; k++)
			{
				byte = SubstituteBytes(plainText[k],1);
				plainText[k] = byte;
			}
		//1.3: Add Round Key
		AddRoundKey(plainText, expandedKey, 10 - roundNo);
		uint8_t recoveredPlainText[16];		//To store the recovered plaintext
		//Make the plainText row major
		for(int i=0; i<4; i++)
		{
			for(int j=0; j<4; j++)
			{
				recoveredPlainText[i*4 + j] = plainText[i + 4*j];
			}
		}
		cout<<"\n\nRecovered plainText is \n";
		for(int i=0; i<16; i++)
		{	printf("%0x ", recoveredPlainText[i]);
		}
	return 0;
}
