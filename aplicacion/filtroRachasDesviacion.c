/*Funcion que filtra por rachas (con desviacion minima para validar la racha) y porcentaje, 
  mira uno a uno todos los bytes del paquete
    Utilizada en el driver */


// u8* paq: puntero al comienzo de la carga util del paquete a filtrar.
// int len: numero de bytes a mirar para filtrar.
// devuelve 0 si el paquete es ASCII, 1 si no y debe ser cortado.
int contarCaractLegiblesNoFloat(u8* paq,int len){   
   int i,legiblesASCII=0;
    int r_ascii=0,r_ascii_max=0;
    int deviation_ascii=0;
    if( unlikely(len<=0) )return 0;

    for(i=0;i<len;i++){
        if( (MIN_LEGIBLE_ASCII<=paq[i]) && (paq[i]<=MAX_LEGIBLE_ASCII) ){
        	if( likely(r_ascii) )deviation_ascii+=abs(paq[i]-paq[i-1]);
            legiblesASCII+=100;
            r_ascii++;
            if(r_ascii>=COEF_LEN_RACHA && deviation_ascii>(COEF_MIN_DESVIACION_RACHA*r_ascii) )
                return 0;
            
        }else{
            r_ascii=0;
            deviation_ascii=0;
        }
        
    }
    //if(r_ascii>r_ascii_max && deviation_ascii>COEF_MIN_DESVIACION_RACHA*len) r_ascii_max=r_ascii;
    

    if(legiblesASCII>=(COEF_MIN_LEGIBLE*len) ){
        return 0;
    }
    return 1;

}