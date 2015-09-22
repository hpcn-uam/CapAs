/*Funcion que filtra por rachas (sin desviacion) y porcentaje, mira uno a uno todos los bytes del paquete
    Utilizada en el driver, para las pruebas del TMA 
    Rendimiento 2,5Gbps con la traza unmillonhttp en el driver y escribiendo */


// u8* paq: puntero al comienzo de la carga util del paquete a filtrar.
// int len: numero de bytes a mirar para filtrar.
// devuelve 0 si el paquete es ASCII, 1 si no y debe ser cortado.
int contarCaractLegiblesNoFloat(u8* paq,int len){   
   int i,legiblesASCII=0,legiblesEBCDIC=0;
    int r_ascii=0,r_ascii_max=0;
    int r_ebcdic=0,r_ebcdic_max=0;
    int deviation_ascii=0,deviation_ebcdic=0;
    if( unlikely(len<=0) )return 0;

    for(i=0;i<len;i++){
        if( (MIN_LEGIBLE_ASCII<=paq[i]) && (paq[i]<=MAX_LEGIBLE_ASCII) ){
            legiblesASCII+=100;
            r_ascii++;
            if(r_ascii>=COEF_LEN_RACHA)
                return 0;
            //if( likely(r_ascii) )deviation_ascii+=abs(paq[i]-paq[i-1]);
        }else{
            //if( unlikely(r_ascii>r_ascii_max && deviation_ascii>(COEF_MIN_DESVIACION_RACHA*r_ascii)$
            r_ascii=0;
            //deviation_ascii=0;
        }
        /*if(MIN_LEGIBLE_EBCDIC<=(unsigned short)paq[i] && (unsigned short)paq[i]<=MAX_LEGIBLE_EBCDIC$
            legiblesEBCDIC+=100;
            r_ebcdic++;
            if(r_ebcdic>0)deviation_ebcdic+=abs(paq[i]-paq[i-1]);
        }else{
            if(r_ebcdic>r_ebcdic_max && (deviation_ebcdic/len)>COEF_MIN_DESVIACION_RACHA )r_ebcdic_ma$
            r_ebcdic=0;
            deviation_ebcdic=0;
        }*/
    }
    //if(r_ascii>r_ascii_max && deviation_ascii>COEF_MIN_DESVIACION_RACHA*len) r_ascii_max=r_ascii;
    //if(r_ebcdic>r_ebcdic_max && (deviation_ebcdic/len)>COEF_MIN_DESVIACION_RACHA )r_ebcdic_max=r_eb$

    if(legiblesASCII>=(COEF_MIN_LEGIBLE*len) ){// || (r_ebcdic_max>=COEF_LEN_RACHA && legiblesEBCDIC/$
        return 0;
    }
    return 1;

}