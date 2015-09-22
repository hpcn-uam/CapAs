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

#define HDR_SIZE 34

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
//char membuf[MEMBUF_SIZE]; //Buffer para guardar la traza, no contiene cabeceras ETH,IP ni TCP(se ignoran los HDR_SIZE primeros bytes)
char* membuf;
char* membuf_ptr; //Puntero para moverse por membuf
int paqsize[TRACE_NUMPAQS]; //Array con los tamaños de los paquetes (-1 indica el final de la traza)
long currpaq=0; //Entero para moverse por paqsize.



long numPaqNoFiltrados=0;
long numPaqNoFiltrados2=0;

char *tabla_ascii;

int stop=0;
void capturaSenial(int nSenial)
{
	if(stop==1)
		return;
	stop=1;
	return;
}

char *ini_tabla_ascii(){
	char c='a';
	char *tabla=(char *)calloc(256,sizeof(char));
	if(!tabla)return NULL;
	for(c=MIN_LEGIBLE_ASCII;c<=MAX_LEGIBLE_ASCII;c++){
		tabla[c]=1;
	}
	tabla[9]=1; //Tab
	tabla[10]=1; //Enter
	tabla[13]=1; //\r
	return tabla;
}

long contBytesLeidoBasico=0;
long contBytesLeidoSaltos=0;
long contSaltosFalloPrediccion[13]={0};

int filtroRachas(u_int8_t* paq,int len){   
   int i,legiblesASCII=0;
    int r_ascii=0;
    //int deviation_ascii=0,deviation_ebcdic=0;
    if( len<=0 )return 0;

    for(i=0;i<len;i++){
        if(tabla_ascii[paq[i]]){//if( (MIN_LEGIBLE_ASCII<=paq[i]) && (paq[i]<=MAX_LEGIBLE_ASCII) ){
            legiblesASCII+=100;
            r_ascii++;
            if(r_ascii>=COEF_LEN_RACHA){
            	contBytesLeidoBasico+=i;
                return 0;
            }
        }else{
            r_ascii=0;
        }
       
    }
   
    if(legiblesASCII>=(COEF_MIN_LEGIBLE*len) ){// || (r_ebcdic_max>=COEF_LEN_RACHA && legiblesEBCDIC/$
        //printf("NumBytes: %d (ASCIIs %d)\n",len,legiblesASCII);
        contBytesLeidoBasico+=len;
        return 2;
    }
    //printf("NumBytes: %d (ASCIIs %d)\n",len,legiblesASCII);
    contBytesLeidoBasico+=len;
    return 1;

}


#ifdef FILTRO_1
int filtroN=1;
int filtroRachasSaltos(u_int8_t* paq,int len){  
	int i,legiblesASCII=0;
	    int r_ascii=0;
    //int deviation_ascii=0,deviation_ebcdic=0;
    if( len<=0 )return 0;

    for(i=0;i<len;i++){
        if(tabla_ascii[paq[i]]){//if( (MIN_LEGIBLE_ASCII<=paq[i]) && (paq[i]<=MAX_LEGIBLE_ASCII) ){
            legiblesASCII+=100;
            r_ascii++;
            if(r_ascii>=COEF_LEN_RACHA){
            	contBytesLeidoBasico+=i;
                return 0;
            }
        }else{
            r_ascii=0;
        }
       
    }
   
    if(legiblesASCII>=(COEF_MIN_LEGIBLE*len) ){// || (r_ebcdic_max>=COEF_LEN_RACHA && legiblesEBCDIC/$
        //printf("NumBytes: %d (ASCIIs %d)\n",len,legiblesASCII);
        contBytesLeidoBasico+=len;
        return 2;
    }
    //printf("NumBytes: %d (ASCIIs %d)\n",len,legiblesASCII);
    contBytesLeidoBasico+=len;
    return 1;

}

#elif FILTRO_4
int filtroN=4;
int filtroRachasSaltos(u_int8_t* paq,int len){   
   int i=0,j=0,legiblesASCII=0;
    int num_bytes_analizados=0;
    int contadorSaltos=0;
    if( len<=0 )return 0;
    if( len<=COEF_LEN_RACHA*3) return filtroRachas(paq,len);

    int len_ini_racha=COEF_LEN_RACHA;
busqContinua:
	if(j+len_ini_racha > len) goto fin;
    for(i=0; i<len_ini_racha ; i++){
    	contBytesLeidoSaltos++;
    	if( !tabla_ascii[paq[j+i]] )//Byte i-esimo NO ASCII
    		goto busqSaltos;
    	
    }

    return 0;

busqSaltos:
	contadorSaltos=0;
	for(j=j+i+4 ; j<len ; j+=4){
		num_bytes_analizados++;
		contBytesLeidoSaltos++;
		if( tabla_ascii[paq[j]] ){//Byte i-esimo ASCII
			contadorSaltos++;
			legiblesASCII+=100;	
			if(contadorSaltos==3){ //Posibilidad de haber detectado racha asci, los bytes 3,6,9 12 "ultimos" son ASCII
				//Vuelta atras buscando la racha asci
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-1]] ){ 
					contSaltosFalloPrediccion[1]++;
					j=j-1;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-2]] ){ 
					contSaltosFalloPrediccion[2]++;
					j=j-2;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-3]] ){ 
					contSaltosFalloPrediccion[3]++;
					j=j-3;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-5]] ){ 
					contSaltosFalloPrediccion[5]++;
					j=j-5;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-6]] ){ //Los bytes j-6:j son ASCII busco racha continua pero de 7 mas a partir de j+1
					contSaltosFalloPrediccion[6]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-6;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-7]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[7]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-7;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-9]] ){ //Los bytes j-9:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[9]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-9;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-10]] ){ //Los bytes j-10:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[10]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-10;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-11]] ){ //Los bytes j-11:j son ASCII busco racha continua pero de 4 mas a partir de j+1
					contSaltosFalloPrediccion[11]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-11;
					goto busqContinua;
				}
				//12 bytes anteriores a j son ASCII, racha encontrada
				return 0;
			}
		}else{
			contadorSaltos=0;
		}
	}
fin:
    if(legiblesASCII>=(COEF_MIN_LEGIBLE*num_bytes_analizados) ){
    	//printf("NumBytes: %d (ASCIIs %d)!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",num_bytes_analizados,legiblesASCII);
        return 2;
    }

    return 1;

}

#elif FILTRO_6
int filtroN=6;
int filtroRachasSaltos(u_int8_t* paq,int len){   
   int i=0,j=0,legiblesASCII=0;
    
    
    int num_bytes_analizados=0;
    int contadorSaltos=0;
    if( len<=0 )return 0;
    if( len<=COEF_LEN_RACHA*3) return filtroRachas(paq,len);    

    int len_ini_racha=COEF_LEN_RACHA;
busqContinua:
	if(j+len_ini_racha > len) goto fin;
    for(i=0; i<len_ini_racha ; i++){
    	contBytesLeidoSaltos++;
    	if( !tabla_ascii[paq[j+i]] )//Byte i-esimo NO ASCII
    		goto busqSaltos;
    	
    }

    return 0;

busqSaltos:
	contadorSaltos=0;
	for(j=j+i+6 ; j<len ; j+=6){
		num_bytes_analizados++;
		contBytesLeidoSaltos++;
		if( tabla_ascii[paq[j]] ){//Byte i-esimo ASCII
			contadorSaltos++;
			legiblesASCII+=100;	
			if(contadorSaltos==2){ //Posibilidad de haber detectado racha asci, los bytes 3,6,9 12 "ultimos" son ASCII
				//Vuelta atras buscando la racha asci
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-3]] ){ 
					contSaltosFalloPrediccion[3]++;
					j=j-3;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-1]] ){ 
					contSaltosFalloPrediccion[1]++;
					j=j-1;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-2]] ){ 
					contSaltosFalloPrediccion[2]++;
					j=j-2;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-4]] ){ 
					contSaltosFalloPrediccion[4]++;
					j=j-5;i=0;
					goto busqSaltos;
				}
				
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-5]] ){ 
					contSaltosFalloPrediccion[5]++;
					j=j-5;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-7]] ){ //Los bytes j-6:j son ASCII busco racha continua pero de 7 mas a partir de j+1
					contSaltosFalloPrediccion[7]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-7;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-8]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[8]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-8;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-9]] ){ //Los bytes j-9:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[9]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-9;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-10]] ){ //Los bytes j-10:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[10]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-10;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-11]] ){ //Los bytes j-11:j son ASCII busco racha continua pero de 4 mas a partir de j+1
					contSaltosFalloPrediccion[11]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-11;
					goto busqContinua;
				}
				//12 bytes anteriores a j son ASCII, racha encontrada
				return 0;
			}
		}else{
			contadorSaltos=0;
		}
	}
fin:
    if(legiblesASCII>=(COEF_MIN_LEGIBLE*num_bytes_analizados) ){
    	//printf("NumBytes: %d (ASCIIs %d)!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",num_bytes_analizados,legiblesASCII);
        return 2;
    }

    return 1;

}


#elif FILTRO_8
int filtroN=8;
int filtroRachasSaltos(u_int8_t* paq,int len){   
   int i=0,j=0,legiblesASCII=0;
    
    
    int num_bytes_analizados=0;
    int contadorSaltos=0;
    if( len<=0 )return 0;
    if( len<=COEF_LEN_RACHA*3) return filtroRachas(paq,len);

    int len_ini_racha=COEF_LEN_RACHA;
busqContinua:
	if(j+len_ini_racha > len) goto fin;
    for(i=0; i<len_ini_racha ; i++){
    	contBytesLeidoSaltos++;
    	if( !tabla_ascii[paq[j+i]] )//Byte i-esimo NO ASCII
    		goto busqSaltos;
    	
    }

    return 0;

busqSaltos:
	contadorSaltos=0;
	for(j=j+i+8 ; j<len ;){
		num_bytes_analizados++;
		contBytesLeidoSaltos++;
		if( tabla_ascii[paq[j]] ){//Byte i-esimo ASCII
			contadorSaltos++;
			legiblesASCII+=100;	
			if(contadorSaltos==2){ //Posibilidad de haber detectado racha asci, los bytes 3,6,9 12 "ultimos" son ASCII
				//Vuelta atras buscando la racha asci
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-6]] ){ 
					contSaltosFalloPrediccion[6]++;
					j=j-6;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-1]] ){ 
					contSaltosFalloPrediccion[1]++;
					j=j-1;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-2]] ){ 
					contSaltosFalloPrediccion[2]++;
					j=j-2;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-3]] ){ 
					contSaltosFalloPrediccion[3]++;
					j=j-3;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-5]] ){ 
					contSaltosFalloPrediccion[5]++;
					j=j-5;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-7]] ){ //Los bytes j-6:j son ASCII busco racha continua pero de 7 mas a partir de j+1
					contSaltosFalloPrediccion[7]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-7;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-8]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[8]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-8;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-9]] ){ //Los bytes j-9:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[9]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-9;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-10]] ){ //Los bytes j-10:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[10]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-10;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-11]] ){ //Los bytes j-11:j son ASCII busco racha continua pero de 4 mas a partir de j+1
					contSaltosFalloPrediccion[11]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-11;
					goto busqContinua;
				}
				//12 bytes anteriores a j son ASCII, racha encontrada
				return 0;
			}else{
				j+=4;
			}
		}else{
			contadorSaltos=0;
			j+=8;
		}
	}
fin:
    if(legiblesASCII>=(COEF_MIN_LEGIBLE*num_bytes_analizados) ){
    	//printf("NumBytes: %d (ASCIIs %d)!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",num_bytes_analizados,legiblesASCII);
        return 2;
    }

    return 1;

}


#elif FILTRO_9
int filtroN=9;
int filtroRachasSaltos(u_int8_t* paq,int len){   
   int i=0,j=0,legiblesASCII=0;
    
    
    int num_bytes_analizados=0;
    int contadorSaltos=0;
    if( len<=0 )return 0;
    if( len<=COEF_LEN_RACHA*3) return filtroRachas(paq,len);

    int len_ini_racha=COEF_LEN_RACHA;
busqContinua:
	if(j+len_ini_racha > len) goto fin;
    for(i=0; i<len_ini_racha ; i++){
    	contBytesLeidoSaltos++;
    	if( !tabla_ascii[paq[j+i]] )//Byte i-esimo NO ASCII
    		goto busqSaltos;
    	
    }

    return 0;

busqSaltos:
	contadorSaltos=0;
	for(j=j+i+9 ; j<len ;){
		num_bytes_analizados++;
		contBytesLeidoSaltos++;
		if( tabla_ascii[paq[j]] ){//Byte i-esimo ASCII
			contadorSaltos++;
			legiblesASCII+=100;	
			if(contadorSaltos==2){ //Posibilidad de haber detectado racha asci, los bytes 3,6,9 12 "ultimos" son ASCII
				//Vuelta atras buscando la racha asci
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-6]] ){ 
					contSaltosFalloPrediccion[6]++;
					j=j-6;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-1]] ){ 
					contSaltosFalloPrediccion[1]++;
					j=j-1;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-2]] ){ 
					contSaltosFalloPrediccion[2]++;
					j=j-2;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-4]] ){ 
					contSaltosFalloPrediccion[4]++;
					j=j-4;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-5]] ){ 
					contSaltosFalloPrediccion[5]++;
					j=j-5;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-7]] ){ //Los bytes j-6:j son ASCII busco racha continua pero de 7 mas a partir de j+1
					contSaltosFalloPrediccion[7]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-7;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-8]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[8]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-8;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-9]] ){ //Los bytes j-9:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[9]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-9;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-10]] ){ //Los bytes j-10:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[10]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-10;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-11]] ){ //Los bytes j-11:j son ASCII busco racha continua pero de 4 mas a partir de j+1
					contSaltosFalloPrediccion[11]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-11;
					goto busqContinua;
				}
				//12 bytes anteriores a j son ASCII, racha encontrada
				return 0;
			}else{
				j+=3;
			}
		}else{
			contadorSaltos=0;
			j+=9;
		}
	}
fin:
    if(legiblesASCII>=(COEF_MIN_LEGIBLE*num_bytes_analizados) ){
    	//printf("NumBytes: %d (ASCIIs %d)!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",num_bytes_analizados,legiblesASCII);
        return 2;
    }

    return 1;

}

#elif FILTRO_10
int filtroN=10;
int filtroRachasSaltos(u_int8_t* paq,int len){   
   int i=0,j=0,legiblesASCII=0;
    
    int num_bytes_analizados=0;
    if( len<=0 )return 0;

    if( len<=COEF_LEN_RACHA*3){
    	numPaqNoFiltrados++;
    	return filtroRachas(paq,len);
    } 

    int len_ini_racha=COEF_LEN_RACHA;
busqContinua:
	if(j+len_ini_racha > len) goto fin;
    for(i=0; i<len_ini_racha ; i++){
    	contBytesLeidoSaltos++;
    	if( !tabla_ascii[paq[j+i]] )//Byte i-esimo NO ASCII
    		goto busqSaltos;
    	
    }

    return 0;

busqSaltos:
	
	for(j=j+i+10 ; j<len ; j+=10){
		num_bytes_analizados++;
		contBytesLeidoSaltos++;
		if( tabla_ascii[paq[j]] ){//Byte i-esimo ASCII
			legiblesASCII+=100;
			j+=2;	
			num_bytes_analizados++;	
			contBytesLeidoSaltos++;
			if(tabla_ascii[paq[j]] && j<len  ){ //Posibilidad de haber detectado racha asci, los bytes 3,6,9 12 "ultimos" son ASCII
				//Vuelta atras buscando la racha asci
				legiblesASCII+=100;
				
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-1]] ){ 
					contSaltosFalloPrediccion[1]++;
					j=j-1;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-3]] ){ 
					contSaltosFalloPrediccion[3]++;
					j=j-3;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-4]] ){ 
					contSaltosFalloPrediccion[4]++;
					j=j-4;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-5]] ){ 
					contSaltosFalloPrediccion[5]++;
					j=j-5;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-6]] ){ 
					contSaltosFalloPrediccion[6]++;
					j=j-6;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-7]] ){ //Los bytes j-6:j son ASCII busco racha continua pero de 7 mas a partir de j+1
					contSaltosFalloPrediccion[7]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-7;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-8]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[8]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-8;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-9]] ){ //Los bytes j-9:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[9]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-9;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-10]] ){ //Los bytes j-10:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[10]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-10;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-11]] ){ //Los bytes j-11:j son ASCII busco racha continua pero de 4 mas a partir de j+1
					contSaltosFalloPrediccion[11]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-11;
					goto busqContinua;
				}
				//12 bytes anteriores a j son ASCII, racha encontrada
				return 0;
			}
		}
	}
fin:
    if(legiblesASCII>=(COEF_MIN_LEGIBLE*num_bytes_analizados) ){
    	//printf("NumBytes: %d (ASCIIs %d)!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",num_bytes_analizados,legiblesASCII);
        return 2;
    }

    return 1;

}


#elif FILTRO_12
int filtroN=12;
int filtroRachasSaltos(u_int8_t* paq,int len){   
   int i=0,j=0,legiblesASCII=0;
    int num_bytes_analizados=0;
    
    if( len<=0 )return 0;
    if( len<=COEF_LEN_RACHA*3) return filtroRachas(paq,len);

    int len_ini_racha=COEF_LEN_RACHA;
busqContinua:
	if(j+len_ini_racha > len) goto fin;
    for(i=0; i<len_ini_racha ; i++){
    	contBytesLeidoSaltos++;
    	if( !tabla_ascii[paq[j+i]] )//Byte i-esimo NO ASCII
    		goto busqSaltos;
    	
    }

    return 0;

busqSaltos:
	for(j=j+i+12 ; j<len ; j+=12){
		num_bytes_analizados++;
		contBytesLeidoSaltos++;
		if( tabla_ascii[paq[j]] ){//Byte i-esimo ASCII
			legiblesASCII+=100;	
				
				
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-1]] ){ 
					contSaltosFalloPrediccion[1]++;
					j=j-1;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-2]] ){ 
					contSaltosFalloPrediccion[2]++;
					j=j-2;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-3]] ){ 
					contSaltosFalloPrediccion[3]++;
					j=j-3;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-4]] ){ 
					contSaltosFalloPrediccion[4]++;
					j=j-4;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-5]] ){ 
					contSaltosFalloPrediccion[5]++;
					j=j-5;i=0;
					goto busqSaltos;
				}
				if( !tabla_ascii[paq[j-6]] ){ 
					contSaltosFalloPrediccion[6]++;
					j=j-6;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-7]] ){ //Los bytes j-6:j son ASCII busco racha continua pero de 7 mas a partir de j+1
					contSaltosFalloPrediccion[7]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-7;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-8]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[8]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-8;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-9]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[9]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-9;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-10]] ){ //Los bytes j-10:j son ASCII busco racha continua pero de 5 mas a partir de j+1
					contSaltosFalloPrediccion[10]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-10;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-11]] ){ //Los bytes j-11:j son ASCII busco racha continua pero de 4 mas a partir de j+1
					contSaltosFalloPrediccion[11]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-11;
					goto busqContinua;
				}
				//12 bytes anteriores a j son ASCII, racha encontrada
				return 0;
		}
	}
fin:
    if(legiblesASCII>=(COEF_MIN_LEGIBLE*num_bytes_analizados) ){
    	//printf("NumBytes: %d (ASCIIs %d)!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",num_bytes_analizados,legiblesASCII);
        return 2;
    }

    return 1;

}

#elif FILTRO_0
int filtroN=0;
int filtroRachasSaltos(u_int8_t* paq,int len){   
    return 1;
}

#else
int filtroN=3;
int filtroRachasSaltos(u_int8_t* paq,int len){   
   int i=0,j=0,legiblesASCII=0;
    
    int num_bytes_analizados=0;
    int contadorSaltos=0;
    if( len<=0 )return 0;
    if( len<=COEF_LEN_RACHA*3) return filtroRachas(paq,len);

    int len_ini_racha=COEF_LEN_RACHA;
busqContinua:
	if(j+len_ini_racha > len) goto fin;
    for(i=0; i<len_ini_racha ; i++){
    	contBytesLeidoSaltos++;
    	if( !tabla_ascii[paq[j+i]] )//Byte i-esimo NO ASCII
    		goto busqSaltos;
    	
    }

    return 0;

busqSaltos:
	contadorSaltos=0;
	for(j=j+i+3 ; j<len ; j+=3){
		num_bytes_analizados++;
		contBytesLeidoSaltos++;
		if( tabla_ascii[paq[j]] ){//Byte i-esimo ASCII
			contadorSaltos++;
			legiblesASCII+=100;	
			if(contadorSaltos==4){ //Posibilidad de haber detectado racha asci, los bytes 3,6,9 12 "ultimos" son ASCII
				//Vuelta atras buscando la racha asci
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-1]] ){ 
					contSaltosFalloPrediccion[1]++;
					j=j-1;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-2]] ){ 
					contSaltosFalloPrediccion[2]++;
					j=j-2;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-4]] ){ 
					contSaltosFalloPrediccion[4]++;
					j=j-4;i=0;
					goto busqSaltos;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-5]] ){ 
					contSaltosFalloPrediccion[5]++;
					j=j-5;i=0;
					goto busqSaltos;
					
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-7]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[7]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-7;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-8]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[8]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-8;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-10]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[10]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-10;
					goto busqContinua;
				}
				contBytesLeidoSaltos++;
				if( !tabla_ascii[paq[j-11]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					contSaltosFalloPrediccion[11]++;
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-11;
					goto busqContinua;
				}
				//12 bytes anteriores a j son ASCII, racha encontrada
				return 0;
			}
		}else{
			contadorSaltos=0;
		}
	}
fin:
    if(legiblesASCII>=(COEF_MIN_LEGIBLE*num_bytes_analizados) ){
    	//printf("NumBytes: %d (ASCIIs %d)!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",num_bytes_analizados,legiblesASCII);
        return 2;
    }

    return 1;

}

#endif

long numPaq=0;
long contadorDesigual=0;
long contadorDesigual2=0;
long desigual=0;
long noAscii1=0;
long noAscii2=0;
long numBytes=0;
long numBytesAscii=0;
long numBytesBasicoAscii=0;
long numBytesNoAscii=0;
long numBytesBasicoNoAscii=0;

long numBytesAscii2=0;
long numBytesAsciiLen=0;
long numBytesNoAsciiLen=0;
long numBytesLen=0;
long numBytesSaltoAscii=0;
long numBytesNoAscii2=0;
long numBytesSaltoNoAscii=0;
long numAsciiSaltoPC=0;
long numAsciiPC=0;

void callback_p(u_char *user_data, const struct NDLTpkthdr *h, const u_char *bytes){
	int ret2=-1;
	u_int8_t *paq=bytes+HDR_SIZE;
	numPaq++;
	long contLeidoS=contBytesLeidoSaltos;
	long contLeidoB=contBytesLeidoBasico;
	if(h->caplen<=HDR_SIZE){
		return;
	}
	numBytes+=h->caplen-HDR_SIZE;
	//printf("%ld: %ld (%ld) %lf\n",numPaq,h->caplen-HDR_SIZE,numBytes,numBytes*1.0/numPaq);
	FILE *ff=NULL;
	int ret=filtroRachas(paq,h->caplen-HDR_SIZE);
	if(ret==0 || ret==2){
		numBytesAscii+=h->caplen-HDR_SIZE;
		numBytesBasicoAscii+=(contBytesLeidoBasico-contLeidoB);
		if(ret==2)numAsciiPC++;
	}
	if(ret==1){
		numBytesNoAscii+=h->caplen-HDR_SIZE;
		numBytesBasicoNoAscii+=(contBytesLeidoBasico-contLeidoB);
	}
	
		ret2=filtroRachasSaltos(paq,MIN(h->caplen-HDR_SIZE, N_BYTES_ANALYSIS2));
		if(numPaq<50)printf("infoPaq%d: caplen:%d resultado:%d\n",numPaq,h->caplen,ret2);
		if(ret2==0 || ret2==2){
			numBytesAscii2+=h->caplen-HDR_SIZE;
			numBytesAsciiLen+=h->len;
			numBytesSaltoAscii+=(contBytesLeidoSaltos-contLeidoS);
			if(ret2==2)numAsciiSaltoPC++;
		}
		if(ret2==1){
			numBytesNoAscii2+=h->caplen-HDR_SIZE;
			numBytesNoAsciiLen+=h->len;
			numBytesSaltoNoAscii+=(contBytesLeidoSaltos-contLeidoS);
		}
	
	//printf("%d %d\n",ret,ret2);
	if(ret==1 && ret2==2){
		contadorDesigual++;
	}else if(ret==2 && ret2==1){
		contadorDesigual2++;
	}else if(ret!=ret2){
		desigual++;
		if(ret==1)contadorDesigual++;
		else contadorDesigual2++;
		// printf("%d-%d (%d)\n",ret,ret2,h->caplen-HDR_SIZE );
		// int k=0;
		// for(k=0;k<(h->caplen-HDR_SIZE);k++){
		// 	printf("%c",(char)paq[k]);
		// }
		// printf("$$$\n---------------\n");
	}
	if(ret==1) noAscii1++;
	if(ret2==1) noAscii2++;


	//Metemos el payload del paquete en el buffer de memoria (sin cabeceras hasta TCP)
	
		memcpy(membuf_ptr,paq,h->caplen-HDR_SIZE);
		membuf_ptr+=h->caplen-HDR_SIZE;
		paqsize[currpaq]=h->caplen-HDR_SIZE;
		currpaq++;
	
	if(membuf_ptr-membuf>MEMBUF_SIZE){
		printf("ERROR: se ha desbordado el buffer de memoria para guardar el paquete (membuf).\n");
		exit(-1);
	}if(currpaq>TRACE_NUMPAQS-1){ //Hay que dejar un hueco para el -1
		printf("ERROR: se ha desbordado el array con el numero de paquetes y sus tamaños (paqsize). currpaq=%ld \n",currpaq);
		exit(-1);
	}
}



int main(int argc, char **argv){
	int i;
	char *filter="";
	char errbuf[PCAP_ERRBUF_SIZE];
	char errbuf_escritura[PCAP_ERRBUF_SIZE];
	NDLTdataEscritura_t *tr_escritura=NULL;
	NDLTdata_t *tr_lectura=NULL;
	FILE *ff=NULL;
	tabla_ascii=ini_tabla_ascii();
	if((membuf=(char*) malloc(MEMBUF_SIZE))==NULL){
		printf("Error en malloc al reservar el buffer. Tamanio solicitado=%ld\n",MEMBUF_SIZE);
	}
	membuf_ptr=membuf;
	tr_lectura=NDLTabrirTraza(argv[1],NDLTFORMAT_PCAP_STR, filter, 0, errbuf);
	if(!tr_lectura){
		printf("Error al abrir la traza a analizar\n");
		return -1;
	}
	if(argc>2){
		tr_escritura=NDLTabrirTrazaEscritura(argv[2], NDLTFORMAT_PCAP_STR, FLAG_DISPLAY, ETH_FRAME_MAX, errbuf_escritura);
		if(!tr_escritura){
			printf("Error al crear la traza salida\n");
			NDLTclose(tr_lectura);
			return -1;
		}
	}

	printf("\nCalculando estadisticas de la traza y cargandola en memoria.\n");
	currpaq=0;
	if(NDLTloop(tr_lectura, callback_p, (u_char *)tr_escritura)!=1)
		printf("Error NDLTloop\n");
	paqsize[currpaq]=-1;

	printf("Traza cargada en memoria.\n\n");
	float media=numBytes*1.0/numPaq*1.0;
	printf("Tamanio medio de payload: %lf. (Es el tamanio medio que analizamos, no el real, no se incluyen cabeceras)\n",media );
	
	double desviacion=0;
	for(desviacion=0,currpaq=0;paqsize[currpaq]!=-1; ){
			desviacion+=(paqsize[currpaq]-media)*(paqsize[currpaq]-media);
			membuf_ptr+=paqsize[currpaq];
			currpaq++;
		}
	double desv=desviacion/(currpaq-1);
	double ratioFiltroPaq=1-(noAscii1*1.0/(numPaq*1.0));
	double falsoPos=contadorDesigual*1.0/numPaq;
	double falsoNeg=contadorDesigual2*1.0/numPaq;
	double tasaBytesAnalizados=(contBytesLeidoBasico*1.0)/(contBytesLeidoSaltos*1.0);
	double tasaBytesAnalizadosAscii=(numBytesSaltoAscii*1.0)/(numBytesAscii2*1.0);
	double tasaBytesAnalizadosNoAscii=(numBytesSaltoNoAscii*1.0)/(numBytesNoAscii2*1.0);
	double tasaFiltroSBytes=(numBytesAscii2*1.0)/(numBytes*1.0);
	double tasaBytesAsciiLen=(numBytesAsciiLen*1.0)/(numBytesAsciiLen+numBytesNoAsciiLen)*1.0;
	double tasaAsciiPC=(numAsciiPC*1.0)/(numPaq-noAscii1)*1.0;
	double tasaAsciiSaltoPC=(numAsciiSaltoPC*1.0)/(numPaq-noAscii2)*1.0;

	printf("Desviacion del tamano de payload: %lf en %ld paquetes\n",desviacion/(currpaq-1),currpaq);
	printf("Filtro a Saltos VS Basico:\n");
	printf("\tfalsos positivos= %ld / %ld (%lf)\n",contadorDesigual,numPaq, contadorDesigual*1.0/numPaq);
	printf("\tfalsos negativos= %ld / %ld (%lf)\n",contadorDesigual2,numPaq, contadorDesigual2*1.0/numPaq);
	printf("\tErrores= %ld / %ld (%lf)\n",desigual,numPaq, (desigual*1.0)/(numPaq*1.0));
	printf("\t\tFallos Cometidos Totales: %ld (%lf)\n",contadorDesigual+contadorDesigual2, (contadorDesigual2+contadorDesigual)*1.0/numPaq);
	printf("\tRendimiento: BytesAnalizados %ld VS %ld (%lf)\n",contBytesLeidoBasico,contBytesLeidoSaltos,(contBytesLeidoBasico*1.0)/(contBytesLeidoSaltos*1.0));
	printf("\nFallos de prediccion de rachas saltando:\n");
	long sum=0;
	for(i=0;i<=12;i++){
		printf("\t%d- %ld\n",i,contSaltosFalloPrediccion[i]);
		sum+=contSaltosFalloPrediccion[i];
	}
	printf("\tsum=%ld\n\n\n",sum);
	printf("Filtro:\n");
	printf("\tBasico: NoAscii=%ld (%lf)\n",noAscii1,noAscii1*1.0/(numPaq*1.0));
	printf("\tSaltos: NoAscii=%ld (%lf)\n",noAscii2,noAscii2*1.0/(numPaq*1.0));
	printf("FBasico ASCII (%lf):\n", (numBytesAscii*1.0)/(numBytes*1.0));
	printf("\tBytes analizados en paq Ascii: %ld / %ld (%lf)\n",numBytesBasicoAscii,numBytesAscii, (numBytesBasicoAscii*1.0)/(numBytesAscii*1.0) );
	printf("\tBytes analizados en paq NoAscii: %ld / %ld (%lf)\n",numBytesBasicoNoAscii,numBytesNoAscii, (numBytesBasicoNoAscii*1.0)/(numBytesNoAscii*1.0) );
	printf("\tTasa de paquetes Ascii por Porcentaje: %lf (%ld / %ld)\n",tasaAsciiPC,numAsciiPC,numPaq-noAscii1);
	printf("FSalto ASCII (%lf):\n", (numBytesAscii2*1.0)/(numBytes*1.0));
	printf("\tBytes analizados en paq Ascii: %ld / %ld (%lf)\n",numBytesSaltoAscii,numBytesAscii2, (numBytesSaltoAscii*1.0)/(numBytesAscii2*1.0) );
	printf("\tBytes analizados en paq NoAscii: %ld / %ld (%lf)\n",numBytesSaltoNoAscii,numBytesNoAscii2, (numBytesSaltoNoAscii*1.0)/(numBytesNoAscii2*1.0) );
	printf("\tTasa de paquetes Ascii por Porcentaje: %lf (%ld / %ld)\n",tasaAsciiSaltoPC,numAsciiSaltoPC,numPaq-noAscii2);
	printf("%ld no filtrados (%ld)\n",numPaqNoFiltrados,numPaqNoFiltrados2);
	NDLTclose(tr_lectura);
	if(argc>2)NDLTcloseEscritura(tr_escritura);
	
	//Evaluacion de rendimiento leyendo la traza desde memoria
	
	printf("\n------------------\nNumero de paquetes de la traza: %ld.\n",numPaq);
	printf("Tamanio de paquetes de la traza: %ld Bytes.\n",numBytes);

	printf("Se imprimiran los Bytes/sec medios cada vez que se haga una lectura completa de la traza (se hace un gettimeofday cada vez que se lee la traza entera y se imprime el cociente de bytes leidos entre tiempo transcurrido).\n\n");
	struct timeval tini;
	struct timeval tfin;

	signal(SIGINT, capturaSenial);
	double sumTasa=0;
	double sumTasaPaq=0;
 	double tasaGbps[30]={0};
 	double tasaKpps[30]={0};
	for(i=0;!stop && i<10;i++){
		int sum=0;
		long asciipaqs=0;
		long binpaqs=0;
		//Recorremos la traza midiendo tiempos
		gettimeofday(&tini,NULL);
		for(membuf_ptr=membuf,currpaq=0;paqsize[currpaq]!=-1; ){
			#ifdef FILTRO_1
				sum=filtroRachas(membuf_ptr,MIN(N_BYTES_ANALYSIS2,paqsize[currpaq]));
			#else
				sum=filtroRachasSaltos(membuf_ptr, MIN(N_BYTES_ANALYSIS2,paqsize[currpaq]));
			#endif

			
			if(sum==0 || sum==2){
				asciipaqs++;
			}else if (sum==1){
				binpaqs++;
			}
			membuf_ptr+=paqsize[currpaq];
			currpaq++;
		}
		gettimeofday(&tfin,NULL);
		printf("%ld %lf\n",binpaqs,(binpaqs*1.0/numPaq*1.0));
		double tasa=((numBytes*8.0)/((tfin.tv_sec-tini.tv_sec)*1000000+(tfin.tv_usec-tini.tv_usec))*1000000)/1000000000;
		tasaGbps[i]=tasa;
		double tasaPaq=((currpaq)*1.0/((tfin.tv_sec-tini.tv_sec)*1000000+(tfin.tv_usec-tini.tv_usec))*1000000)/1000;
		tasaKpps[i]=tasaPaq;
		printf("\t%d: (%lf - %lf)\n",i,tasaGbps[i],tasaKpps[i]);
		sumTasa+=tasa;
		sumTasaPaq+=tasaPaq;
		//printf("%ld\n", tasa); //Tamanio de la traza en Bytes / tiempo transcurrido 
		//long t1=(long)(tini.tv_sec*1000000UL)+tini.tv_usec;
		//long t2=(long)(tfin.tv_sec*1000000UL)+tfin.tv_usec;
		//printf("Tasa (Mbps): %f \n",(float)(numBytes*8)/(float)(t2-t1));

	}

	double tasaMedia=(sumTasa*1.0/i);
	double tasaPaqMedia=(sumTasaPaq*1.0/i);
	//printf("sumTasaPaq: %lf\tMedidas: %d\ttasaPaqMedia: %lf\n",sumTasaPaq,i,tasaPaqMedia );
	double currentTasaGB=0;
	double currentTasaKp=0;
	double desvGbps=0;
	double desvKpps=0;
	printf("\n media: %lf\t",tasaMedia);
	for(i=0; (currentTasaGB=tasaGbps[i])>0 && i<30 ;i++){
		printf(" %lf (%lf) ,",currentTasaGB,(currentTasaGB-tasaMedia)*(currentTasaGB-tasaMedia));
		desvGbps+= (currentTasaGB-tasaMedia)*(currentTasaGB-tasaMedia);
	}

	desvGbps/=(i-1);
	
	for(i=0; (currentTasaKp=tasaKpps[i])>0 && i<30 ;i++){
		desvKpps+= (currentTasaKp-tasaPaqMedia)*1.0*(currentTasaKp-tasaPaqMedia);
	}
	desvKpps/=(i-1);
	
	printf("\nTasa Media registrada: %lf Gb/s +- sqrt(%lf) , %lf Kpps +- sqrt(%lf)\n",tasaMedia,desvGbps,tasaPaqMedia,desvKpps);
	

	if( access( "analisis.txt", F_OK ) != -1 ) {
	   	ff=fopen("analisis.txt","a");
	} else {
	    ff=fopen("analisis.txt","a");
	    fprintf(ff, "Traza\tNumPaqs\tTamMedio\tTamDesviacion\tNumFiltro\ttPaqASCII\ttBytesASCII\ttBytesASCIILen\ttFalsoPos\ttFalsoNeg\tGbps\tKpps\tDsvGbps^2\tDsvKpps^2\ttBytesAnalizados\ttBytesAnalizadosAscii\ttBytesAnalizadosNoAscii\ttPaqAsciiPorcentajeBasico\ttPaqAsciiPorcentajeSaltos\n" );
	}
	int len=strlen(argv[1]);
	char *fnombre=argv[1];
	for(i=0;i<len;i++){
		if('/' == argv[1][len-i]) {
			fnombre=&(argv[1][len-i+1]);
			break;
		}
	}
	
	if(ff){
		fprintf(ff, "%s\t%ld\t%lf\t%lf\t%d\t%lf\t%lf\t%lf\t%lf\t%lf\t",fnombre,numPaq,media,desv,filtroN,ratioFiltroPaq,tasaFiltroSBytes,tasaBytesAsciiLen,falsoPos,falsoNeg);
		fprintf(ff, "%lf\t%lf\t%lf\t%lf\t%lf\t%lf\t%lf\t%lf\n",tasaMedia,tasaPaqMedia,desvGbps,desvKpps,tasaBytesAnalizados,tasaBytesAnalizadosAscii,tasaBytesAnalizadosNoAscii,tasaAsciiPC,tasaAsciiSaltoPC );
		fclose(ff);
	}

	return 0;
	
}
