/*******************************************************************************
*                     Criptografia em Software e Hardware                      *
*                                                                              *
* Algoritmo DES                                                                *
*                                                                              *
* Edward David Moreno Ordonez                                                  *
* Fábio Dacêncio Pereira                                                       *
* Rodolfo Barros Chiaramonte                                                   *
*******************************************************************************/
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

// ------------------------------------------------
// --- Protótipos das funções utilizadas no DES ---
// ------------------------------------------------

typedef enum {false, true} bool;

void rotacionar(bool C[28], bool D[48]);
void gerar_sub_chaves(bool chave[64], bool subchave[16][48]);
void sbox(bool aux48[48], bool aux32[]);
void bin (char val, bool sb[8][4], int num_sb);

// ------------------------------------------------
// ---          Constantes Globais              ---
// ------------------------------------------------

const unsigned char ML[2][2] =
{
  0,1,2,3
};

const unsigned char ROT[16] =
{
  1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};
const unsigned char MC[2][2][2][2] = 
{
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
};

// Permutação Inicial
const unsigned char PI[64]=
{  
 58,50,42, 34, 26,18, 10, 2,
60,52,44, 36, 28,20, 12, 4,
62,54,46, 38, 30,22, 14, 6,
64,56,48, 40, 32,24, 16, 8,
57,49,41, 33, 25,17,  9, 1,
59,51,43, 35, 27,19, 11, 3,
61,53,45, 37, 29,21, 13, 5,
63,55,47, 39, 31,23, 15, 7

};

const unsigned char PF[64]=
{
40,     8,   48,    16,    56,   24,    64,   32,
39,     7,   47,    15,    55,   23,    63,   31,
38,     6,   46,    14,    54,   22,    62,   30,
37,     5,   45,    13,    53,   21,    61,   29,
36,     4,   44,    12,    52,   20,    60,   28,
35,     3,   43,    11,    51,   19,    59,   27,
34,     2,   42,    10,    50,   18,    58,   26,
33,     1,   41,     9,    49,   17,    57,   25
};
// Permutação de Expansão
const unsigned char PE[48] = 
{
 32,1,2,3,4,5,4,5,6,7,8,9,
 8,9,10,11,12,13,12,13,14,15,16,17,
 16,17,18,19,20,21,20,21,22,23,24,25,	
 24,25,26,27,28,29,28,29,30,31,32,1
};

// P-BOX
const unsigned char PBOX[32] = 
{
 16,7,20,21,29,12,28,17,
 1,15,23,26,5,18,31,10,
 2,8,24,14,32,27,3,9,
 19,13,30,6,22,11,4,25
};

//Permutação de Compressão inicial
const unsigned char PCI[56] = 
{
 57,49,41,33,25,17,9,1,58,50,42,34,26,18,
 10,2,59,51,43,35,27,19,11,3,60,52,44,36,
 63,55,47,39,31,23,15,7,62,54,46,38,30,22,
 14,6,61,53,45,37,29,21,13,5,28,20,12,4
};

//Permutação de Compressão
const unsigned char PC[48] = 
{
 14,17,11,24,1,5,3,28,
 15,6,21,10,23,19,12,4,
 26,8,16,7,27,20,13,2,
 41,52,31,37,47,55,30,40,	
 51,45,33,48,44,49,39,56,	
 34,53,46,42,50,36,29,32	
};

//S-BOXES
const unsigned char SBOX[8][4][16] = 
{
14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,

15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,

10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,


7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,


2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,


12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,


4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,

13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11


};

// ------------------------------------------------
// ---           Funções de Conversão           ---
// ------------------------------------------------

void bloco2bits(unsigned int bloco[], bool b[])
{
    unsigned int aux;
    int i=0;

	for (aux = 0x80000000; aux > 0; aux >>= 1)
         b[i++] = ((bloco[1] & aux) != 0);

   	for (aux = 0x80000000; aux > 0; aux >>= 1)
         b[i++] = ((bloco[0] & aux) != 0);
}

void bits2bloco(bool b[], unsigned int bloco[])
{
    int i;
    bloco[0] = 0;
    bloco[1] = 0;

    for(i=0;i<32;i++)
        bloco[0] += b[63-i] << i;
    for(i=32;i<64;i++)
        bloco[1] += b[63-i] << i-32;

}


// ------------------------------------------------
// ---              Funções do DES              ---
// ------------------------------------------------

// rotaciona 1 ou 2 bits
void rotacionar(bool C[28], bool D[48])
{
 int i;
 bool auxC[28];
 bool auxD[28];

 //rotaciona C
 for (i=0;i<=26;i++){
     auxC[i]=C[i+1];
     auxD[i]=D[i+1];
 }
 auxC[27]=C[0];
 auxD[27]=D[0];
 for (i=0;i<=27;i++){C[i]=auxC[i];D[i]=auxD[i];}
}

void gerar_sub_chaves(bool chave[64], bool subchave[16][48])
{
 int i,j,k=0;
 bool aux[56];
 bool C[28];  // parte mais significativa da chave
 bool D[28];  // parte menos significativa da chave
 bool CD[56]; // união de C e D

 for (i=0;i<=55;i++){aux[i]= chave[PCI[i]-1];}
 // ****** Gerar C e D *********
 for (i=0;i<=55;i++){
     if (i<=27){C[i]= aux[i];}
     else {D[k]= aux[i];k++;}
 }
 
 // a partir deste ponto pode-se gerar as subchaves
 for (j=0;j<=15;j++){
     // rotaciona C e D
     if (ROT[j]==1) rotacionar(C,D);      
     else {rotacionar(C,D);rotacionar(C,D);}
     
     //concatena C e D
     for (i=0;i<=27;i++){CD[i]=C[i];}
     for (i=0;i<=27;i++){CD[i+28]=D[i];}
     
     // Permutação de Compressão
     for (i=0;i<=47;i++){subchave[j][i]=CD[PC[i]-1];}
 }
} 

// S-BOXES
void sbox(bool aux48[48], bool aux32[])
{
 int i,j,k;
 int lin,col;
 bool sb[8][4];

 for (i=0;i<=7;i++){
 lin = ML[aux48[(i*6)]] [aux48[(i*6)+5]];
 col = MC[aux48[(i*6)+1]][aux48[(i*6)+2]][aux48[(i*6)+3]][aux48[(i*6)+4]];
 bin (SBOX[i][lin][col],sb,i);
 }

 //concatena SBs
 k=0;
 for (i=0;i<=7;i++){
     for (j=0;j<=3;j++){
          aux32[k]=sb[i][j];k++;
     }
 }
}

// converte para binario (4 bits)
void bin (char val, bool sb[8][4], int num_sb)
{
 sb[num_sb][3] = ((val & 0x1) != 0);
 sb[num_sb][2] = ((val & 0x2) != 0);
 sb[num_sb][1] = ((val & 0x4) != 0);
 sb[num_sb][0] = ((val & 0x8) != 0);
}

// ------------------------------------------------
// ---           Programa Principal             ---
// ------------------------------------------------

void cifrar(bool texto[], bool chave[])
{
  int i,k=0; // indices
  bool subchaves[16][48]; // todas subchaves
  bool L[64];              // parte mais significativa (texto plano)
  bool R[64];              // parte menos significativa (texto plano)
  bool RL[64];             // união de R e L
  bool PB[64];             // resultado da P-BOX
  bool aux64[64];          // vetor auxiliar
  bool aux48[48];          // vetor auxiliar
  bool aux32[32];          // vetor auxiliar
  int itera;              // indice de ietrações

  // *** gerando subchaves ****

  gerar_sub_chaves(chave,subchaves);

  // ----------------------------
  // --- inicio da cifragem   ---
  // ----------------------------
  
  // permutação inicial
  for (i=0;i<=63;i++){aux64[i]= texto[PI[i]-1];}


  // gera L e R
  for (i=0;i<=63;i++){
       if (i<=31) {L[i]= aux64[i];}
       else       {R[k]= aux64[i];k++;}
  }k=0;

  itera=0;
  // iterações do DES
  while (itera<=15) {
     //permutação de expansão
     for (i=0;i<=47;i++){aux48[i]= R[PE[i]-1];}

     // ou exclusivo (XOR)
     for (i=0;i<=47;i++){aux48[i]= aux48[i] ^ subchaves[itera][i];}    // cifra
     // Sbox

     sbox(aux48,aux32);

    // Pbox
    for (i=0;i<=31;i++){PB[i]= aux32[PBOX[i]-1];}
    //ou exclusivo
    for (i=0;i<=31;i++){PB[i]= PB[i] ^ L[i];}  
    // L recebe R anterior
    for (i=0;i<=31;i++){L[i]= R[i];}  
    // R recebe resultado da Xor
    for (i=0;i<=31;i++){R[i]= PB[i];}

    itera++;
  }
  itera=0; //fim das iterações
  
 //concatena R e L
 for (i=0;i<=31;i++){RL[i]=R[i];}
 for (i=0;i<=31;i++){RL[i+32]=L[i];}

 //permutação final
 for (i=0;i<=63;i++){texto[i]=RL[PF[i]-1];}

}

void decifrar(bool texto[], bool chave[])
{
  int i,k=0; // indices
  bool subchaves[16][48]; // todas subchaves
  bool L[64];              // parte mais significativa (texto plano)
  bool R[64];              // parte menos significativa (texto plano)
  bool RL[64];             // união de R e L
  bool PB[64];             // resultado da P-BOX
  bool aux64[64];          // vetor auxiliar
  bool aux48[48];          // vetor auxiliar
  bool aux32[32];          // vetor auxiliar
  int itera;              // indice de ietrações

  // *** gerando subchaves ****

  gerar_sub_chaves(chave,subchaves);

  // ----------------------------
  // --- inicio da cifragem   ---
  // ----------------------------
  
  // permutação inicial
  for (i=0;i<=63;i++){aux64[i]= texto[PI[i]-1];}

  // gera L e R
  for (i=0;i<=63;i++){
       if (i<=31) {L[i]= aux64[i];}
       else       {R[k]= aux64[i];k++;}
  }k=0;

  itera=0;
  // iterações do DES
  while (itera<=15) {
     //permutação de expansão
     for (i=0;i<=47;i++){aux48[i]= R[PE[i]-1];}

     // ou exclusivo (XOR)
     for (i=0;i<=47;i++){aux48[i]= aux48[i] ^ subchaves[15-itera][i];} //decifra

     // Sbox
     sbox(aux48,aux32);

    // Pbox
    for (i=0;i<=31;i++){PB[i]= aux32[PBOX[i]-1];}
    //ou exclusivo
    for (i=0;i<=31;i++){PB[i]= PB[i] ^ L[i];}  
    // L recebe R anterior
    for (i=0;i<=31;i++){L[i]= R[i];}  
    // R recebe resultado da Xor
    for (i=0;i<=31;i++){R[i]= PB[i];}

    itera++;
  }
  itera=0; //fim das iterações
  
 //concatena R e L
 for (i=0;i<=31;i++){RL[i]=R[i];}
 for (i=0;i<=31;i++){RL[i+32]=L[i];}

 //permutação final
 for (i=0;i<=63;i++){texto[i]=RL[PF[i]-1];}

}

void cifrafile()
{
	FILE *arq;
	FILE *cifrado;
	char filename[128];
	char newfile[128];
	int i,j;
	unsigned char aux[8];
	unsigned char chave[8];
    bool auxb[64];
    bool chaveb[64];
	long inicio, fim;

	printf("Nome do arquivo a ser cifrado: ");
	scanf("%s",&filename);
	printf("Nome do arquivo cifrado: ");
	scanf("%s", &newfile);

	arq = fopen(filename, "rb");
	if (arq==NULL)
	{
		printf("nao foi possivel abrir o arquivo para leitura\n");
        return;
	}
	cifrado = fopen(newfile, "wb");
	if (cifrado==NULL)
	{
		printf("nao foi possivel abrir o arquivo para escrita\n");
        return;
	}

	printf ("Chave: ");
	scanf("%s", &chave);

    bloco2bits((unsigned int *)chave, chaveb);

	inicio = clock();
	while (!feof(arq))
	{
		i = fread(&aux,sizeof(char),8,arq);
		if (i == 8)
		{
            bloco2bits((unsigned int *)aux, auxb);
			cifrar(auxb,chaveb);
            bits2bloco(auxb, (unsigned int *)aux);
			fwrite(&aux,sizeof(char),8,cifrado);
		}
        else if (i != 0)
        {
            for (j=i;j<8;j++)
               aux[j] = 0;
            bloco2bits((unsigned int *)aux, auxb);
            cifrar(auxb,chaveb);
            bits2bloco(auxb, (unsigned int *)aux);
			fwrite(&aux,sizeof(char),8,cifrado);
        }
	}
	fim = clock();
	printf("Tempo: %.3f segundos", (fim-inicio)/CLOCKS_PER_SEC);
	fclose(arq);
	fclose(cifrado);

}

void decifrafile()
{
	FILE *arq;
	FILE *decifrado;
	char filename[128];
	char newfile[128];
	int i,j;
	unsigned char aux[8];
	unsigned char chave[8];
    bool auxb[64];
    bool chaveb[64];
	long inicio, fim;

	printf("Nome do arquivo a ser decifrado: ");
	scanf("%s",&filename);
	printf("Nome do arquivo decifrado: ");
	scanf("%s", &newfile);

	arq = fopen(filename, "rb");
	if (arq==NULL)
	{
		printf("nao foi possivel abrir o arquivo para leitura\n");
        return;
	}
	decifrado = fopen(newfile, "wb");
	if (decifrado==NULL)
	{
		printf("nao foi possivel abrir o arquivo para escrita\n");
        return;
	}

	printf ("Chave: ");
	scanf("%s", &chave);

    bloco2bits((unsigned int *)chave, chaveb);

	inicio = clock();
	while (!feof(arq))
	{
		i = fread(&aux,sizeof(char),8,arq);
		if (i == 8)
		{
            bloco2bits((unsigned int *)aux, auxb);
			decifrar(auxb,chaveb);
            bits2bloco(auxb, (unsigned int *)aux);
			fwrite(&aux,sizeof(char),8,decifrado);
		}
        else if (i != 0)
        {
            for (j=i;j<8;j++)
               aux[j] = 0;
            bloco2bits((unsigned int *)aux, auxb);
            decifrar(auxb,chaveb);
            bits2bloco(auxb, (unsigned int *)aux);
			fwrite(&aux,sizeof(char),8,decifrado);
        }
	}
	fim = clock();
	printf("Tempo: %.3f segundos", (fim-inicio)/CLOCKS_PER_SEC);
	fclose(arq);
	fclose(decifrado);

}


int main()
{
	int i,j,k;
    char texto[128];
    char novo[128];
	unsigned char aux[8];
	unsigned char chave[8];
    bool auxb[64];
    bool chaveb[64];

    int op;

    do
    {
          for(i=0;i<128;i++)
          {
              texto[i] = 0; novo[i] = 0; // limpar os valores antigos
          }
          for (i=0;i<8;i++)
          {
              chave[i] = 0; // limpar a chave antiga
          }
          printf("1 - Cifrar Arquivo\n");
          printf("2 - Decifrar Arquivo\n");
          printf("3 - Cifrar Texto\n");
          printf("4 - Sair\n");
          printf("Opcao: ");
          scanf("%d", &op);
          switch(op)
          {
               case 1:
                    cifrafile();
                    break;
               case 2:
                    decifrafile();
                    break;
               case 3:
                    {
	                    printf("Texto: ");
                     	scanf("%s", &texto);

                     	printf("Chave para cifrar: ");
                     	scanf("%s", &chave);

                        bloco2bits((unsigned int *)chave, chaveb);

                        i=0; j=0;
                        while(texto[i]!=0)
                        {
                             aux[j] = texto[i]; j++; i++;
                             if (j == 8)
                             {
                                 bloco2bits((unsigned int *)aux, auxb);
                                 cifrar(auxb,chaveb);
                                 bits2bloco(auxb, (unsigned int *)aux);
                                 j=0;
                                 for(k=i-8;k<i;k++)
                                      novo[k] = aux[j++];
                                 j=0;
                             }
                        }
                        if (j > 0)
                        {
                           for (k=j;k<8;k++)
                           {
                               aux[k] = 0; i++;
                           }

                           bloco2bits((unsigned int *)aux, auxb);
                           cifrar(auxb,chaveb);
                           bits2bloco(auxb, (unsigned int *)aux);
                           j=0;
                           for(k=i-8;k<i;k++)
                               novo[k] = aux[j++];
                        }
                        novo[i]=0;

                        printf("Cifrado: %s", novo);

                        printf("\nChave para decifrar: ");
                       	scanf("%s", &chave);

                        bloco2bits((unsigned int *)chave, chaveb);

                        i=0; j=0;
                        while(novo[i]!=0)
                        {
                             aux[j] = novo[i]; j++; i++;
                             if (j == 8)
                             {
                                 bloco2bits((unsigned int *)aux, auxb);
                                 decifrar(auxb,chaveb);
                                 bits2bloco(auxb, (unsigned int *)aux);
                                 j=0;
                                 for(k=i-8;k<i;k++)
                                      texto[k] = aux[j++];
                                 j=0;
                             }
                        }
                        if (j > 0)
                        {
                           for (k=j;k<8;k++)
                           {
                               aux[k] = 0; i++;
                           }

                           bloco2bits((unsigned int *)aux, auxb);
                           decifrar(auxb,chaveb);
                           bits2bloco(auxb, (unsigned int *)aux);
                           j=0;
                           for(k=i-8;k<i;k++)
                               texto[k] = aux[j++];
                        }
                        texto[i] = 0;

                        printf("Decifrado: %s", texto);
                    }
                    break;
               default:
                    continue;
          }
          printf("\n");

    }while(op != 4);
    return 0;
}
