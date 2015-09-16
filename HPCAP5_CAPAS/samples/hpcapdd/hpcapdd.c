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
	struct raw_header phead;
	//uint16_t caplen = 0;
	u_char *bp = NULL;
	u_char auxbuf[RAW_HLEN+MAX_PACKET_SIZE];

	long num_paquetes=0;
	long num_bytes_leidos=0;
	long num_bytes_escritos=0;

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
	char *tabla_ascii=ASCII_ini_tabla_ascii();
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
				hpcap_read_packet(&hp, &bp, auxbuf, &phead, raw_pcap_header);
				if( bp ) //not padding
				{	
					//filtro
					//struct pcap_pkthdr phead_hpcap;
					//raw_to_hpcap_pcap_header(&phead_hpcap, &phead);
					num_paquetes++;
					num_bytes_leidos+=phead.caplen;
					#if 1
					if( ASCII_filter_saltos(&phead,bp, N_BYTES_ANALYSIS,tabla_ascii) ){
						//escribir completo
						num_bytes_escritos+=phead.caplen;
						//write paquete al buffer (con padding)
					}else{
						//escribir solo la cabecera
						if(phead.caplen>phead.hdr_info){
							phead.caplen = phead.hdr_info; //corto el paquete al tamaño de las cabeceras
							num_bytes_escritos+=phead.caplen;
						}/*else{
							printf("\t%d - %d\n",phead.caplen,phead.hdr_info);
						}*/
//						if(num_paquetes<10)printf("DEBUG %d NOASCI\n",num_paquetes);

						//write paquete al buffer (con padding)
					}
					#endif
					if (fd ){
						ret = write(fd, &phead, sizeof(phead));
						ret = write(fd, bp, phead.caplen);
					}
						
					i += phead.caplen+RAW_HLEN;
				}
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
	free(tabla_ascii);	
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

