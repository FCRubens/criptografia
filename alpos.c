/*******************************************************************************
*                     Criptografia em Software e Hardware                      *
*                                                                              *
* Algoritmo ALPOS                                                              *
*                                                                              *
* Edward David Moreno Ordonez                                                  *
* Fábio Dacêncio Pereira                                                       *
* Rodolfo Barros Chiaramonte                                                   *
*******************************************************************************/

#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

void ler(char texto[],int max);
void cifra(char tcifrado[], char texto[], int valores[], int gchave);
void decifra(char tcifrado[], char texto[], int valores[], int gchave);
int grauchave(char chave[]);
void valorchave(char chave[], int valores[]);
int cifrachar (char pcifrar, int pos, int valores[], int gchave);
int decifrachar (char pdecifrar, int pos, int valores[], int gchave);
void cifrafile();
void decifrafile();

/**************************************************
* Função para realizar a criptografia de arquivos *
**************************************************/
void cifrafile()
{
	FILE *arq;
	FILE *cifrado;
	char aux;
	char filename[128];
	char newfile[128];
	int i;
	char chave[128];
	int pos=1;
	int gchave;
	long inicio, fim;
	int valores[20];

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
	gchave = grauchave(chave);

	valorchave(chave,valores);

	inicio = clock();
	while (!feof(arq))
	{
		i = fread(&aux,sizeof(char),1,arq);
		if (i > 0)
		{
			aux = cifrachar(aux,pos,valores,gchave);
			fwrite(&aux,sizeof(char),1,cifrado);
			pos++;
		}
	}
	fim = clock();
	printf("Tempo: %.3f segundos", (fim-inicio)/CLOCKS_PER_SEC);
	fclose(arq);
	fclose(cifrado);

}

/****************************************************
* Função para realizar a decriptografia de arquivos *
****************************************************/
void decifrafile()
{
	FILE *cifrado;
	FILE *decifrado;
	char aux;
	char filename[128];
	char newfile[128];
	int i;
	char chave[128];
	int gchave;
	int pos=1;
	int valores[20];
	long inicio, fim;

	printf("Nome do arquivo a ser decifrado: ");
	scanf("%s", &filename);
	printf("Nome do arquivo decifrado: ");
	scanf("%s", &newfile);

	printf ("Chave: ");
	scanf("%s", &chave);
	gchave = grauchave(chave);

	valorchave(chave,valores);
	cifrado = fopen(filename, "rb");
	if (cifrado==NULL)
	{
		printf("nao foi possivel abrir o arquivo para leitura");
        return;
	}
	decifrado = fopen(newfile, "wb");
	if (decifrado==NULL)
	{
		printf("nao foi possivel abrir o arquivo para escrita");
        return;
	}

	inicio = clock();
	while (!feof(cifrado))
	{
		i = fread(&aux,sizeof(char),1,cifrado);
		if (i > 0)
		{
			aux = decifrachar(aux,pos,valores,gchave);
			fwrite(&aux,sizeof(char),1,decifrado);
			pos++;
		}
	}
	fim = clock();
	printf("Tempo: %.3f segundos", (fim-inicio)/CLOCKS_PER_SEC);
	fclose(cifrado);
	fclose(decifrado);
}
/************************************************
* Função para realizar a criptografia de textos *
************************************************/
void decifra(char tcifrado[], char texto[], int valores[], int gchave)
{
    int i=0;
    while (tcifrado[i] != '\0')
    {
		if (tcifrado[i] != '\0')
			texto[i] = decifrachar(tcifrado[i], i+1, valores, gchave);
		i++;
    }
    texto[i] = '\0';
}

/**************************************************
* Função para realizar a decriptografia de textos *
**************************************************/
void cifra(char tcifrado[], char texto[], int valores[], int gchave)
{
    int i = 0;
    while (texto[i] != '\0')
    {
		if (texto[i] != '\0')
        	tcifrado[i] = cifrachar(texto[i], i+1, valores, gchave);
        i++;
    }
    tcifrado[i] = '\0';
}

/************************************************************
* Função para realizar a criptografia de um único caracter. *
* É utilizada nas funções anteriores.                       *
************************************************************/
int cifrachar (char pcifrar, int pos,  int valores[], int gchave)
{
    int vchave;
    int i;
	unsigned long int soma = 0;
    int aux;
    aux = pcifrar;

	for (i = 1; i <= gchave; i++) // calcula o resultado da expressão:
    {                             // a1 * x^n + a2 * x^n-1 + ... + an * x^1
		vchave = valores[i];
        soma += vchave * pow(pos,gchave-i+1);
    }
    aux = (aux + soma) % 256; // soma o resultado da espressão com o valor
                              // original e calcula o modulo
    return aux;
}

/**************************************************************
* Função para realizar a decriptografia de um único caracter. *
* É utilizada nas funções anteriores.                         *
**************************************************************/
int decifrachar (char pdecifrar, int pos, int valores[], int gchave)
{
    int vchave;
    int i;
	unsigned long int subt = 0;
    int aux;
    aux = pdecifrar;

	for (i = 1; i <= gchave; i++)  // calcula o resultado da expressão:
    {                              // a1 * x^n + a2 * x^n-1 + ... + an * x^1
		vchave = valores[i];
        subt += vchave * pow(pos,gchave-i+1);
    }
    aux = (aux - subt) % 256; // subtrai o resultado da espressão do valor
    return aux;               // que estava criptografado (processo inverso
                              // ao da função anterior)
}

/******************************************************************
* Função para converter o valor entrado no formato "a,b,c,..." em *
* um vetor de inteiros. Este vetor contem a chave na forma em que *
* será utilizada pelo algoritmo (duas funções anteriores)         *
******************************************************************/
void valorchave(char chave[], int valores[])
{
	char aux[128];
    int valor = 0;
    int i = 0; //posição char chave
    int j = 0; //posição char aux
	int t = 0; //tamanho do string chave
    int n = 1; //nº q indica qual o grau atual
	int ai;    //contadores

	while (chave[t] != '\0')
		t++;
	
	for(i=0;i<=t;i++)
	{
    	if (chave[i] == ',' || chave[i] == '\0')
		{
			aux[j] = '\0';
			ai = 0;
		    j--;
			while (aux[ai] != '\0')
		    {
				valor += (aux[ai] - 48) * (pow(10 , j));
		        j--;
    			ai++;
			}
			j = 0;
			valores[n] = valor;
			valor = 0;
       		n++;
		}
		else
		{
        	aux[j] = chave[i];
            j++;
		}
	}
}

/*****************************************************
* Função para determinar o grau da chave, ou seja, o *
* número de elementos na chave                       *
*****************************************************/
int grauchave(char chave[])
{
	int i = 0;
    int j = 1;
    while (chave[i] != '\0')
	{
       	if (chave[i] == ',')
        	j++;
        i++;
     }
    return j;
}

int main()
{

	char texto[128];
	char chave[128];
	char novo[128];
	int valores[15];
	int grau_chave;
    int op;

    do
    {
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
                        grau_chave = grauchave(chave);
                        valorchave(chave,valores);
                        cifra(novo,texto,valores,grau_chave);
                        printf("Cifrado: %s", novo);

                        printf("\nChave para decifrar: ");
                       	scanf("%s", &chave);
                      	grau_chave = grauchave(chave);
                      	valorchave(chave,valores);
                      	decifra(novo,texto,valores,grau_chave);
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
