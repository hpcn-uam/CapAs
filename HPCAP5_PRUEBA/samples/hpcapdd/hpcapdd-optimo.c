#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>
#include <pcap.h>
#include "../../include/hpcap.h"

#define MEGA (1024*1024)
#define DIRFREQ 1800

/*
 Función que se ejecuta cuando se genera la señal generada por Control+C. La idea es 
 realizar una salida "ordenada".
 Parametros de entrada:
	-int nSenial: identificador de la señal capturada.
*/
int stop=0;
void capturaSenial(int nSenial)
{
	if(stop==1)
		return;
	stop=1;
	return;
}

unsigned int process_block(struct hpcap_handle *,int fd, u_int32_t remain);


long num_paquetes=0;
long num_bytes_leidos=0;
long num_bytes_escritos=0;


inline int hpcap_procesar_paquete(struct hpcap_handle *handle, int fd, int nbytes_filter ){
	u64 aux;
	//u_char *pbuffer;
	u64 offs = handle->rdoff;
	int acks=0;
	u32 secs=0, nsecs=0;
	u16 caplen=0,hdr_info=0;
	int ret=0;
	//u32 *psecs=&secs, *pnsecs=&nsecs;
	//u16 *pcaplen=&caplen,*phdr_info=&hdr_info;


    if( unlikely( handle->acks >= handle->avail ) )
    {
        printf("hpcap_read_packet: wrong situation\n");
        //*pbuffer=NULL;
        return 0;
    }
    else if( unlikely( handle->avail <  RAW_HLEN ) )
    {
        printf("hpcap_read_packet: wrong situation (not enough avail)\n");
        //*pbuffer=NULL;
        return 0;
    }



	/***********************/
	/* Timestamp - seconds */
	/***********************/
    //u_char *phead=handle->buf + offs;
	if( unlikely( offs+sizeof(u_int32_t) > handle->bufSize ) )
	{
		aux = handle->bufSize-offs;
		memcpy( &secs, handle->buf + offs, aux);
		memcpy( ((char*)&secs)+aux, handle->buf, sizeof(u_int32_t)-aux);
	}
	else
	{
		//psecs=(u_int32_t *)handle->buf + offs;
		memcpy( &secs, handle->buf + offs, sizeof(u_int32_t));
	}
	offs = (offs+sizeof(u_int32_t)) % handle->bufSize;
	acks += sizeof(u_int32_t);

	/***************************/	
	/* Timestamp - nanoseconds */
	/***************************/
	if( unlikely( offs+sizeof(u_int32_t) > handle->bufSize ) )
	{
		aux = handle->bufSize - offs;
		memcpy( &nsecs, handle->buf + offs, aux);
		memcpy( ((char*)&nsecs)+aux, handle->buf, sizeof(u_int32_t)-aux);
	}
	else
	{
		//pnsecs=(u_int32_t *) handle->buf + offs;
		memcpy( &nsecs, handle->buf + offs, sizeof(u_int32_t));

	}
	offs = (offs+sizeof(u_int32_t)) % handle->bufSize;
	acks += sizeof(u_int32_t);

	/**********/
	/* Caplen */
	/**********/
	if( unlikely( offs+sizeof(u_int16_t) > handle->bufSize) )
	{
		aux = handle->bufSize - offs;
		memcpy( &caplen, handle->buf + offs, aux);
		memcpy( ((char*)&caplen)+aux, handle->buf, sizeof(u_int16_t)-aux);
	}
	else
	{
		//caplen=((u_int16_t *)handle->buf)[offs];
		memcpy( &caplen, handle->buf + offs, sizeof(u_int16_t));
			// printf("OFFS:%d \t CAPLEN:%d caplen:%d\n",offs,(*pcaplen),caplen );
			// printf("%02x %02x %d\n", *(handle->buf+offs),*(handle->buf+offs+1), *((u_int16_t *)handle->buf+offs));
			// printf("%02x %02x\n", *((u_int8_t*)pcaplen ),*((u_int8_t*)pcaplen+1));

	}
	
	offs = (offs+sizeof(u_int16_t)) % handle->bufSize;
	acks += sizeof(u_int16_t);

	/*****************/
	/* Packet length */
	/*****************/
	//Se ignora
	offs = (offs+sizeof(u_int16_t)) % handle->bufSize;
	acks += sizeof(u_int16_t);

	/************/
	/* hdr_info */
	/************/
	if( unlikely( offs+sizeof(u_int16_t) > handle->bufSize) )
	{
		aux = handle->bufSize - offs;
		memcpy( &hdr_info, handle->buf + offs, aux);
		memcpy( ((char*)&hdr_info)+aux, handle->buf, sizeof(u_int16_t)-aux);
	}
	else
	{
		memcpy( &hdr_info, handle->buf + offs, sizeof(u_int16_t));
		//phdr_info=(u_int16_t *)handle->buf+offs;
	}
	offs = (offs+sizeof(u_int16_t)) % handle->bufSize;
	acks += sizeof(u_int16_t);

	/************/
	/* pkt_info */
	/************/
	//se ignora
	offs = (offs+sizeof(u_int16_t)) % handle->bufSize;
	acks += sizeof(u_int16_t);


    if( unlikely( handle->avail < (handle->acks+RAW_HLEN+caplen) ) )
    {
            printf("hpcap_read_packet: wrong situation (avail < RAW_HLEN+caplen) (avail=%lu, acks=%lu, caplen=%u)\n", handle->avail, handle->acks, caplen);
            //pbuffer=NULL;
            return 0;
    }


	
	/************/
	/* Hash RSS */
	/************/
	//se ignora
	offs = (offs+sizeof(u_int32_t)) % handle->bufSize;
	acks += sizeof(u_int32_t);

	/* Padding check */
	if( unlikely( ( secs==0) && ( nsecs==0) ) )
	{
		//pbuffer = NULL;
	}
	else
	{

		num_paquetes++;
		/*****FILTRO ASCII******/
		//int ASCII_filter(void *header, u_char *pbuffer, int nbytes_filter){
		//struct raw_header *head = (struct raw_header *) header;
		int r_ascii=0,r_ascii_max=0;
		int deviation_ascii=0;
		int i,legiblesASCII=0; 
		u64 cpyoffs=offs;
		
		
			//printf("ASCII_FILTER: %d-%d-%d-",nbytes_filter,head->caplen , head->hdr_info);
		nbytes_filter=minimo( nbytes_filter, caplen - hdr_info );
			//printf("%d\n",nbytes_filter);
		if( unlikely(nbytes_filter<=0) ){
			//return 1;  ASCII
			if(fd){

				if( unlikely( handle->rdoff+RAW_HLEN+caplen > handle->bufSize) ){
					aux = handle->bufSize-handle->rdoff;
					write(fd, handle->buf+handle->rdoff, aux);
					write(fd, handle->buf, RAW_HLEN+caplen-aux);
					
				}
				else
				{
					write(fd, handle->buf+handle->rdoff, RAW_HLEN+caplen);
				}
				num_bytes_escritos+=RAW_HLEN+caplen;
				num_bytes_leidos+=RAW_HLEN+caplen;
				ret=RAW_HLEN+caplen;
			}
		}else{
			u_char lastpbyte=0;
			for(i=0;i<nbytes_filter;i++){
				if(cpyoffs + i > handle->bufSize) cpyoffs=0;
				u_char pbyte= handle->buf[cpyoffs+hdr_info+i];
				if( (MIN_LEGIBLE_ASCII<=pbyte) && (pbyte<=MAX_LEGIBLE_ASCII) ){
					if( likely(r_ascii) )deviation_ascii+=abs(pbyte-lastpbyte);
					legiblesASCII+=100;
					r_ascii++;
					
				}else{
					if( unlikely(r_ascii>r_ascii_max && deviation_ascii>(COEF_MIN_DESVIACION_RACHA*r_ascii)) ) r_ascii_max=r_ascii;
					r_ascii=0;
					deviation_ascii=0;
				}
				lastpbyte=pbyte;
			}
			if(r_ascii>r_ascii_max && deviation_ascii>COEF_MIN_DESVIACION_RACHA*nbytes_filter) r_ascii_max=r_ascii;
			
			
			if( r_ascii_max<COEF_LEN_RACHA && legiblesASCII<(COEF_MIN_LEGIBLE*nbytes_filter) ){
				//return 0; NOASCII
				if(fd){
					if( unlikely( handle->rdoff+RAW_HLEN+hdr_info > handle->bufSize) ){
						aux = handle->bufSize-handle->rdoff;
						write(fd, handle->buf+handle->rdoff, aux);
						write(fd, handle->buf, RAW_HLEN+hdr_info-aux);
					}
					else
					{
						write(fd, handle->buf+handle->rdoff, RAW_HLEN+hdr_info);
					}
					num_bytes_escritos+=RAW_HLEN+hdr_info;
					num_bytes_leidos+=RAW_HLEN+caplen;
					ret=RAW_HLEN+hdr_info;
				}
				
			}else{
				//return 1; ASCII
				if(fd){
					if( unlikely( handle->rdoff+RAW_HLEN+caplen > handle->bufSize) ){
						aux = handle->bufSize-handle->rdoff;
						write(fd, handle->buf+handle->rdoff, aux);
						write(fd, handle->buf, RAW_HLEN+caplen-aux);
					}
					else
					{
						write(fd, handle->buf+handle->rdoff, RAW_HLEN+caplen);
					}
					num_bytes_escritos+=RAW_HLEN+caplen;
					num_bytes_leidos+=RAW_HLEN+caplen;
					ret=RAW_HLEN+caplen;
				}
			}

		}
		
		
	}




	/* Packet data  
		if( unlikely( offs+caplen > handle->bufSize) )
		{
			aux = handle->bufSize-offs;
			memcpy( auxbuf, handle->buf+offs, aux);
			memcpy( auxbuf+aux, handle->buf, caplen-aux);
			pbuffer = auxbuf;
		}
		else
		{
			pbuffer = ((u_char*)handle->buf)+offs;
		}
		//read_header( header, secs, nsecs, len, caplen,hdr_info,pkt_info,hash_rss);
	//}
	
	}*/ 
	offs = (offs+caplen) % handle->bufSize;
	acks += caplen;
	
	handle->rdoff = offs;
	handle->acks += acks;
	
	return ret;
}

int main(int argc, char **argv)
{
	int fd=1;
	struct hpcap_handle hp;
	int ret=0;
	unsigned long int i=0;
	int ifindex=0,qindex=0;

	//struct timeval init, end;
	struct timeval initwr;
	//struct timeval initwr, endwr;
	//float time,wrtime;
	//struct raw_header phead;
	//uint16_t caplen = 0;
	//u_char *bp = NULL;
	//u_char auxbuf[RAW_HLEN+MAX_PACKET_SIZE];

	

	char filename[512];
	

	//gettimeofday(&init, NULL);
	if( argc != 4 )
	{
		//printf("Uso: %s <adapter index> <queue index> <fichero RAW de salida> <bs> <count>\n", argv[0]);
		printf("Uso: %s <adapter index> <queue index> <output basedir | null>\n", argv[0]);
		return HPCAP_ERR;
	}

	if( strcmp( argv[3], "null") == 0 )
	{
		printf("Warning: No output will be generated (dumb receiving)\n");
		fd = 0;
	}
		
	/* Creating HPCAP handle */
	ifindex=atoi(argv[1]);
	qindex=atoi(argv[2]);
	ret = hpcap_open(&hp, ifindex, qindex);
	if( ret != HPCAP_OK )
	{
		printf("Error when opening the HPCAP handle\n");
		hpcap_close( &hp );
		return HPCAP_ERR;
	}
	/* Map device's memory */
	ret = hpcap_map(&hp);
	if( ret != HPCAP_OK )
	{
		printf("Error when opening the mapping HPCAP memory\n");
		hpcap_close( &hp );
		hpcap_close( &hp );
		return HPCAP_ERR;
	}

	signal(SIGINT, capturaSenial);

	while( !stop )
	{
		if( fd )
		{
			gettimeofday(&initwr, NULL);
			sprintf(filename, "%s/%d", argv[3], ((int)initwr.tv_sec/DIRFREQ)*DIRFREQ);//a directory created every 1/2 hour
			mkdir(filename, S_IWUSR);//if the dir already exists, it returns -1
			sprintf(filename, "%s/%d/%d_hpcap%d_%d.raw", argv[3],((int)initwr.tv_sec/DIRFREQ)*DIRFREQ,(int)initwr.tv_sec, ifindex,qindex);
			/* Opening output file */
			fd = open(filename, O_RDWR | O_TRUNC | O_CREAT, 00666);
			printf("filename:%s (fd=%d)\n",filename, fd);
			if( fd == -1 )
			{
				printf("Error when opening output file\n");
				return HPCAP_ERR;
			}
		}
		
		i=0;
		while( (!stop) && (i < HPCAP_FILESIZE) )
		{
			if( hp.acks == hp.avail )
			{
				hpcap_ack_wait_timeout( &hp, /*BS*/1, 1000000000/*1 sec*/);
			}
			if( hp.acks < hp.avail )
			{
				i+=hpcap_procesar_paquete(&hp, fd, N_BYTES_ANALYSIS);
			}
		}
		hpcap_ack( &hp);
		//gettimeofday(&endwr, NULL);
	
		if( fd )
		{
			close(fd);
		}
		/*wrtime = endwr.tv_sec - initwr.tv_sec;
		wrtime += (endwr.tv_usec - initwr.tv_usec)*1e-6;

		printf("[%s]\n",filename);
		printf("Transfer time: %lf s (%d transfers)\n", wrtime, i);
		printf("\t%lu Mbytes transfered => %lf MBps\n", COUNT*BS/MEGA, (1.0*count*BS/MEGA) / wrtime );*/
	}
	
	/*gettimeofday(&end, NULL);
	time = end.tv_sec - init.tv_sec;
	time += (end.tv_usec - init.tv_usec)*1e-6;
	printf("Total time: %lfs\n", time );*/
	
	hpcap_unmap(&hp);
	hpcap_close(&hp);
	
	printf("Estadisticas Filtro:\n");
	printf("\tPaquetes: %ld\n",num_paquetes);
	printf("\tBytes escritos: %ld / Bytes totales: %ld\n",num_bytes_escritos,num_bytes_leidos);
	printf("\tFiltro: %lf %% \n",((num_bytes_escritos*1.0)/(num_bytes_leidos*1.0)));
	return 0;
}

#if 0
unsigned int process_block(struct hpcap_handle * hp,int fd, u_int32_t remain)
{
	u_int32_t aux;
	unsigned int ready = minimo(remain, hp->avail);
	
	#ifdef OWRITE
		/* escribir bloque a bloque */
		if( (hp->rdoff + ready ) > HPCAP_BUF_SIZE )
		{
			aux = HPCAP_BUF_SIZE - hp->rdoff;
			/* hay que hacerlo en dos transferencias */
			write( fd, &hp->buf[ hp->rdoff ], aux);
			write( fd, hp->buf, ready-aux);
		}
		else
		{	/* se hace en una transferencia */
			write( fd, &hp->buf[ hp->rdoff ], ready);
		}
	#else
	#endif
	
	return ready;
}
#endif

