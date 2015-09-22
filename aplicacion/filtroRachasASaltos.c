/*Funcion que filtra por rachas (sin desviacion) y porcentaje, 
	Optimizado para buscar rachas ¡de 12 caracteres!, saltando de 3 en 3 bytes si alguno de estos no son ASCII y no puede haber racha en el medio de ellos
*/


#define COEF_LEN_RACHA = 12 ;
// u8* paq: puntero al comienzo de la carga util del paquete a filtrar.
// int len: numero de bytes a mirar para filtrar.
// devuelve 0 si el paquete es ASCII, 1 si no y debe ser cortado.
int contarCaractLegiblesNoFloat(u8* paq,int len, char *tabla_ascii){   
   int i=0,j=0,legiblesASCII=0;
    int r_ascii=0,r_ascii_max=0;
    int deviation_ascii=0;
    int num_bytes_analizados=0;
    if( unlikely(len<=0) )return 0;

    int len_ini_racha=COEF_LEN_RACHA;
busqContinua:
	if(j+len_ini_racha > len) goto fin;
    for(i=0; i<len_ini_racha ; i++){
    	if( !tabla_ascii[paq[j+i]] )//Byte i-esimo NO ASCII
    		goto busqSaltos;
    	
    }
    return 0;

busqSaltos:
	int contadorSaltos=0;
	for(j=j+i+3 ; j<len ; j+=3){
		num_bytes_analizados++;
		if( tabla_ascii[paq[j]] ){//Byte i-esimo ASCII
			contadorSaltos++;
			legiblesASCII+=100;	
			if(contadorSaltos==4){ //Posibilidad de haber detectado racha asci, los bytes 3,6,9 12 "ultimos" son ASCII
				//Vuelta atras buscando la racha asci
				
				if( !tabla_ascii[paq[j-1]] ){ 
					j=j-1;i=0
					goto busqSaltos;
				}
				if( !tabla_ascii[paq[j-2]] ){ 
					j=j-2;i=0;
					goto busqSaltos;
				}
				if( !tabla_ascii[paq[j-4]] ){ 
					j=j-4;i=0;
					goto busqSaltos;
				}
				if( !tabla_ascii[paq[j-5]] ){ 
					j=j-5;i=0;
					goto busqSaltos;
				}
				if( !tabla_ascii[paq[j-7]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-7;
					goto busqContinua;
				}
				if( !tabla_ascii[paq[j-8]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-8;
					goto busqContinua;
				}
				if( !tabla_ascii[paq[j-10]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
					j=j+1;
					len_ini_racha=COEF_LEN_RACHA-10;
					goto busqContinua;
				}
				if( !tabla_ascii[paq[j-11]] ){ //Los bytes j-7:j son ASCII busco racha continua pero de 6 mas a partir de j+1
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
        return 0;
    }

    return 1;

}