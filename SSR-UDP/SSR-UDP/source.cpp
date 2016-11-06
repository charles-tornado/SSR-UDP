#include "windows.h"

#include <algorithm>  // for std::copy
#include <fstream>
#include <iostream>
#include <iterator>  // for std::istreambuf_iterator
#include <string>
#include <sstream>
#include <time.h>
#include "invert_GF_matrix.h"


#define MX (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (k[p&3^e]^z);

using namespace std;

int table[256];
int arc_table[256];
int inverse_table[256];

namespace {
	const std::string original_file("1.rmvb");
	const std::string encrypted_file("22.rmvb");
	const std::string decrypted_file("33.rmvb");

	const int k = 3;
	const int n = 4;
	const int bytes = 16;
    long ID = 0x01000001;//IP��ַΪ1.0.0.1
	int i, j, l, g;//ѭ��ϵ��	
	int groups;//�ܵ�����
	long groups_seqence = 0;//groups��
	int groups_bytes = bytes*k;
	long h;//�������


	unsigned char *a_ij = (unsigned char*)malloc(sizeof(unsigned char)*n*k);//ϵ������
	unsigned char *xi = (unsigned char*)malloc(sizeof(unsigned char)*bytes);
	double *a_ij_invert = (double*)malloc(sizeof(double)*k*k);
	long *decrypt = (long*)malloc(sizeof(long)*n*k);
	unsigned char *c = (unsigned char *)malloc(sizeof(unsigned char)* k*k);
	unsigned char *recover_data = (unsigned char*)malloc(sizeof(unsigned char)*bytes*k);

}

int mul(int x, int y)
{
	if (!x || !y)
		return 0;

	return table[(arc_table[x] + arc_table[y]) % 255];
}



//XXTEA-128�㷨��Ϊ���ܺ���G�����ܺ���������Ϊ128λ�Ķ����ƴ�����bytes�ֽڵ�����
long btea(long *v, long n, long *k)
{
	unsigned long z = v[n - 1], y = v[0], sum = 0, e, DELTA = 0x9e3779b9;
	long p, q;

	if (n > 1)
	{				/* ���ܹ��� */
		q = 6 + 52 / n;
		while (q-- > 0)
		{
			sum += DELTA;
			e = (sum >> 2) & 3;

			for (p = 0; p < n - 1; p++)
				y = v[p + 1], z = v[p] += MX;

			y = v[0];
			z = v[n - 1] += MX;
		}
		return 0;
	}
	else if (n < -1)
	{				/* ���ܹ��� */
		n = -n;
		q = 6 + 52 / n;
		sum = q * DELTA;

		while (sum != 0)
		{
			e = (sum >> 2) & 3;

			for (p = n - 1; p > 0; p--)
				z = v[p - 1], y = v[p] -= MX;

			z = v[n - 1];
			y = v[0] -= MX;
			sum -= DELTA;
		}
		return 0;
	}
	return 1;
}


void copy(){
	//1st method
	//std::ifstream infile(original_file.c_str(), std::ios::binary);
	//const std::string plaintext((std::istreambuf_iterator<char>(infile)),
	//std::istreambuf_iterator<char>());
	//infile.close();



	//2nd method
	//std::ifstream t(original_file.c_str(), std::ios::binary);
	//std::stringstream buffer;
	//buffer << t.rdbuf();
	//std::string plaintext(buffer.str());
	//t.close();

	//3rd method
	std::ifstream t;
	int length;
	t.open(original_file.c_str(), std::ios::binary);      // open input file  
	t.seekg(0, std::ios::end);    // go to the end  
	length = t.tellg();           // report location (this is the length)  
	t.seekg(0, std::ios::beg);    // go back to the beginning  
	char * buffer = new char[length];    // allocate memory for a buffer of appropriate dimension  
	t.read(buffer, length);       // read the whole file into the buffer  
	t.close();                    // close file handle  

//	std::ofstream outfile(encrypted_file.c_str(), std::ios::binary);
	std::ofstream outfile;
	outfile.open(encrypted_file.c_str(), ofstream::app|ofstream::binary);
	//outfile.write(plaintext.c_str(), plaintext.size());
	outfile.write(buffer, length);
	outfile.close();

}


unsigned char * padding(unsigned char * buffer, int length){

	groups = ceil( (float)length / groups_bytes );
	int remainder_bytes = length % groups_bytes;
	if (remainder_bytes != 0)
	{
		unsigned char * str = new unsigned char[groups*groups_bytes];
		memcpy(str, buffer, length);
		memset(str + length, 0, groups_bytes - remainder_bytes);
		return str;
	}
	return buffer;

}


unsigned char * coefficient_matrix(long *keys, long k,long n, long groups_seqence){
	long *G_parameters = (long*)malloc(sizeof(long)*n*k);
	long *encrypt = (long*)malloc(sizeof(long)*n*k);
	for (i = 0; i<n; i++)
	{
		for (j = 0; j<k; j++)
		{
			*(G_parameters + (i*k + j)) = ((double)(i*n+j))/groups_seqence*100000;//ʹi, j, seqence �����������������ɢ
		}

	}

	for (i = 0; i < n*k; i++){
		encrypt[i] = G_parameters[i];
	}
	btea(encrypt, n*k, keys);

	for (i = 0; i < n*k; i++){
		a_ij[i] = abs(encrypt[i])%256;//ϵ������ȡ8λ  0-255
	}
	free(G_parameters);
	free(encrypt);
	return a_ij;
}

void Enrypted(long * keys){
	std::ifstream t;
	int length;
	t.open(original_file.c_str(), std::ios::binary);      // open input file  
	t.seekg(0, std::ios::end);    // go to the end  
	length = t.tellg();           // report location (this is the length)  
	t.seekg(0, std::ios::beg);    // go back to the beginning  
	unsigned char * buffer = new unsigned char[length];    // allocate memory for a buffer of appropriate dimension  
	t.read((char *)buffer, length);       // read the whole file into the buffer  
	t.close();                    // close file handle  

	std::ofstream outfile;
	outfile.open(encrypted_file.c_str(), ofstream::app | ofstream::out | ofstream::binary);//create output file

	//unsigned char buffer[] = "A safe and reliable coding method!             A safe and reliable coding method!";
	//int length = strlen((char *)buffer);

	unsigned char* str = padding(buffer, length);
	memset(xi, 0, sizeof(unsigned char)*bytes);
	for (g = 0; g < groups; g++){

		a_ij = coefficient_matrix(keys, k, n, g);
		for ( l = 0; l < n; l++)
		{
			for ( j = 0; j < bytes; j++)
			{
				for ( i = 0; i < k; i++)
				{
					xi[j] ^= mul(a_ij[i + l*k], str[g*groups_bytes + (i*bytes + j)]);// str 0-255
				}							
			}
			outfile.write((const char *)xi, bytes);
			memset(xi, 0, sizeof(unsigned char)*bytes);
						
		}			
	}	
	outfile.close();
}


void Decrypt(long * keys){
	std::ifstream t;
	int length;
	t.open(encrypted_file.c_str(), std::ios::binary);      // open input file  
	t.seekg(0, std::ios::end);    // go to the end  
	length = t.tellg();           // report location (this is the length)  
	t.seekg(0, std::ios::beg);    // go back to the beginning  
	unsigned char * buffer = new unsigned char[length];    // allocate memory for a buffer of appropriate dimension  
	t.read((char*)buffer, length);       // read the whole file into the buffer  
	t.close();                    // close file handle  

	std::ofstream outfile;
	outfile.open(decrypted_file.c_str(), ofstream::app | ofstream::out | ofstream::binary);//create output file


	groups = ceil((float)length / (n*bytes));
	
	for (g = 0; g < groups; g++){

		a_ij = coefficient_matrix(keys, k, n, g);

		int *receive_id = (int*)malloc(sizeof(int)*k);
		memset(receive_id, 0, sizeof(int)*k);
		memset(recover_data, 0, sizeof(unsigned char)*bytes*k);
		int count = 0;
		do
		{
			for (i = 0; i < k; i++)
			{
				//��ʼ�����յ���Ϊn�����е�ǰk����
				receive_id[i] = (i+count)%n+1;

			}
			for (i = 0; i<k; i++)
			{
				for (j = 0; j<k; j++)
				{
					c[i*k + j] = a_ij[(receive_id[i] - 1)*k + j];
				}

			}
			count++;
			if (count>100)
			{	
				printf("this matrix can't be invert!");
				system("pause");
			}
		} while (!inv(c, k));


		for (l = 0; l<k; l++)
		{
			for (j = 0; j<bytes; j++)
			{
				for (i = 0; i<k; i++)
				{
					recover_data[l*bytes + j] ^= mul(c[l*k + i], buffer[g*n*bytes + (receive_id[i] - 1)*bytes + j]);

				}
				recover_data[l*bytes + j] = recover_data[l*bytes + j];
			}

		}


		outfile.write((char *)recover_data, bytes*k);	
		free(receive_id);
	}
	outfile.close();
}

void table_initialize(){
	table[0] = 1;//g^0
	for (i = 1; i < 255; ++i)//����ԪΪx + 1
	{
		//������m_table[i] = m_table[i-1] * (x + 1)�ļ�д��ʽ
		table[i] = (table[i - 1] << 1) ^ table[i - 1];

		//���ָ���Ѿ�����8����Ҫģ��m(x)
		if (table[i] & 0x100)
		{
			table[i] ^= 0x11B;//�õ���ǰ��˵���ĳ˷�����
		}
	}



	for (i = 0; i < 255; ++i)
		arc_table[table[i]] = i;



	for (i = 1; i < 256; ++i)//0û����Ԫ�����Դ�1��ʼ
	{
		int k = arc_table[i];
		k = 255 - k;
		k %= 255;//m_table��ȡֵ��ΧΪ [0, 254]
		inverse_table[i] = table[k];
	}

}




int main() {
	long keys[] = { 0x5f4dcc3b, 0x5aa765d6, 0x1d8327de, 0xb882cf99 };

	table_initialize();

	
	clock_t start, end;
	double totaltime;
	start = clock();

//	copy();
//	Enrypted(keys);
	Decrypt(keys);
	
	end = clock();
	totaltime = (double)(end - start) / CLOCKS_PER_SEC;
	cout << "�˳�������ʱ��Ϊ" << totaltime << "�룡" << endl;
	
	cin.get();

	free(a_ij);
	free(xi);
	free(a_ij_invert);
	free(decrypt);
	free(c);
	free(recover_data);
	return 0;
}