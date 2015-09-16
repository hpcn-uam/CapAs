#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/time.h>
#include <fcntl.h>
#include "NDleeTrazas.h"

#define FLAG_DISPLAY 0
/**ETHERNET*/
#define ETH_ALEN      6      /* Tamano de direccion ethernet             */
#define ETH_HLEN      14     /* Tamano de cabecera ethernet              */
#define ETH_TLEN      2      /* Tamano del campo tipo ethernet           */
#define ETH_FRAME_MAX 1514   /* Tamano maximo trama ethernet (sin CRC)   */
#define ETH_FRAME_MIN 60     /* Tamano minimo trama ethernet (sin CRC)   */

/****** ASCII FILTER **********/
#define MIN_LEGIBLE_ASCII 32
#define MAX_LEGIBLE_ASCII 125
#define ASCII_FILTER //ASCIIs filter active
#define COEF_MIN_LEGIBLE 60
#define N_BYTES_ANALYSIS 1514
#define N_BYTES_ANALYSIS2 1514
#define COEF_LEN_RACHA 12
#define COEF_MIN_DESVIACION_RACHA 7
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define MEMBUF_SIZE 4000000000 //Buffer para guardar la traza
#define TRACE_NUMPAQS 50000001 //Numero de paquetes de la traza +1 (Para guardar el -1 de fin de traza)

NDLTdataEscritura_t *tr_escritura=NULL;
NDLTdata_t *tr_lectura=NULL;
long long maxTime=0;
long long iniTime=-1;
long iniIntervalo=0;
long longIntervalo=0;
long maxSize=0;
long currentSize=0;
long currentSize2=0;

void ayuda(){
	printf("Cambia los timestamp de los paquetes de la traza para ajustarlos al intervalo introducido, manteniendo el orden y la proporción del tiempo entre paquetes.\n");
	printf("4/5 Parametros de entrada:\n");
	printf("\t-Path Traza lectura\n");
	printf("\t-Path Traza escritura\n");
	printf("\t-timestamp del primer paquete\n");
	printf("\t-longitud del intervalo de timestamps\n");
	printf("\t-(Opcional) Tamaño maximo de la traza (Bytes)\n");
}
int numPaqs2=0;
void callback_ini(u_char *user_data, const struct NDLTpkthdr *h, const u_char *bytes){
	numPaqs2++;
	long long currentTime=h->ts.tv_sec*1000000000+h->ts.tv_nsec;
	if(maxTime < currentTime)maxTime=currentTime;
	if(iniTime<0)iniTime=h->ts.tv_sec*1000000000+h->ts.tv_nsec;
	//printf("iniTime: %lld  |  maxTime: %lld\n",iniTime,maxTime);
	currentSize2+=h->caplen+sizeof(struct NDLTpkthdr);
	if(currentSize2>maxSize && maxSize>0)NDLTbreakloop(tr_lectura);
	//if(numPaqs2>=10)NDLTbreakloop(tr_lectura);
}

int numPaqs=0;
void callback_p(u_char *user_data, const struct NDLTpkthdr *h, const u_char *bytes){
	struct NDLTpkthdr hh;
	long long timestmp=h->ts.tv_sec*1000000000+h->ts.tv_nsec;
	numPaqs++;
	//printf("time: %lld | %lld\n",timestmp,maxTime);
	long long newTimestmp=( (timestmp-iniTime)*1.0/((maxTime-iniTime)*1.0)*longIntervalo ) + iniIntervalo;
	//printf("%lld | newTime: %lld | %lld\n",iniTime,newTimestmp,maxTime);

	hh.ts.tv_sec=newTimestmp/1000000000;
	hh.ts.tv_nsec=newTimestmp%1000000000;
	hh.caplen=h->caplen;
	hh.len=h->len;

	
	NDLTdump(tr_escritura, &hh, bytes);
	currentSize+=hh.caplen+sizeof(struct NDLTpkthdr);
	if(currentSize>maxSize && maxSize>0)NDLTbreakloop(tr_lectura);
	//if(numPaqs>=10)NDLTbreakloop(tr_lectura);

}

int main(int argc, char **argv){
	int i;
	char *filter="";
	char errbuf[PCAP_ERRBUF_SIZE];
	char errbuf_escritura[PCAP_ERRBUF_SIZE];
	
	if(argc < 5 || argc >6){
		ayuda();
		return -1;
	}
	if(argc==6)maxSize=atol(argv[5]);
	iniIntervalo=atol(argv[3]);
	longIntervalo=atol(argv[4]);


	tr_lectura=NDLTabrirTraza(argv[1],NDLTFORMAT_PCAP_STR, filter, 0, errbuf);
	if(!tr_lectura){
		printf("Error al abrir la traza a analizar\n");
		return -1;
	}
	
	tr_escritura=NDLTabrirTrazaEscritura(argv[2], NDLTFORMAT_PCAP_STR, FLAG_DISPLAY, ETH_FRAME_MAX, errbuf_escritura);
	if(!tr_escritura){
		printf("Error al crear la traza salida\n");
		NDLTclose(tr_lectura);
		return -1;
	}

	if(NDLTloop(tr_lectura, callback_ini, (u_char *)tr_escritura)!=1)
		printf("Error NDLTloop\n");

	NDLTclose(tr_lectura);
	tr_lectura=NDLTabrirTraza(argv[1],NDLTFORMAT_PCAP_STR, filter, 0, errbuf);
	if(!tr_lectura){
		printf("Error al abrir la traza a analizar\n");
		return -1;
	}

	printf("\n\nTraza Analizada: TIEMPOS: %lld  |  %lld \n(%ld)\n",iniTime, maxTime,sizeof(struct NDLTpkthdr) );

	if(NDLTloop(tr_lectura, callback_p, (u_char *)tr_escritura)!=1)
		printf("Error NDLTloop\n");


	NDLTclose(tr_lectura);
	NDLTcloseEscritura(tr_escritura);

	printf("\n\nTraza Analizada: TIEMPOS: %lld  |  %lld \nSize: %ld (numpaqs: %ld)\n",iniTime, maxTime,currentSize,numPaqs );

	return 1;

}