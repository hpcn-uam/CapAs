CC = gcc 
CFLAGS = -O2 -std=gnu99 
DEBUG0= -DFILTRO_0
DEBUG1= -DFILTRO_1
DEBUG4= -DFILTRO_4
DEBUG6= -DFILTRO_6
DEBUG8= -DFILTRO_8
DEBUG9= -DFILTRO_9
DEBUG10= -DFILTRO_10
DEBUG12= -DFILTRO_12

SRCS = NDleeTrazas.c
OBJS =  $(SRCS:.c=.o)
#programas ejecutables
MAIN = mainPruebas 
MAIN2 = testFilterJavi

.PHONY: clean 


all: filtro1
	@echo  Compilando $(MAIN)

filtro0: clean debug_filtro0 $(MAIN)
filtro1: clean debug_filtro1 $(MAIN)
filtro3: clean $(MAIN)
filtro4: clean debug_filtro4 $(MAIN)
filtro6: clean debug_filtro6 $(MAIN)
filtro8: clean debug_filtro8 $(MAIN)
filtro9: clean debug_filtro9 $(MAIN)
filtro10: clean debug_filtro10 $(MAIN)
filtro12: clean debug_filtro12 $(MAIN)

debug_filtro0:
	$(eval CFLAGS += $(DEBUG0))
debug_filtro1:
	$(eval CFLAGS += $(DEBUG1))
debug_filtro4:
	$(eval CFLAGS += $(DEBUG4))
debug_filtro6:
	$(eval CFLAGS += $(DEBUG6))
debug_filtro8:
	$(eval CFLAGS += $(DEBUG8))
debug_filtro9:
	$(eval CFLAGS += $(DEBUG9))
debug_filtro10:
	$(eval CFLAGS += $(DEBUG10))
debug_filtro12:
	$(eval CFLAGS += $(DEBUG12))
	
$(MAIN): $(OBJS) $(addsuffix .o, $(MAIN)) 
	@echo $^
	$(CC) $(CFLAGS) -o $@ $@.o $(OBJS)   -L/usr/lib -lpcap

changeTimestampPcap: $(OBJS) changeTimestampPcap.o
	@echo $^
	$(CC) $(CFLAGS) -o $@ $@.o $(OBJS)   -L/usr/lib -lpcap

loopPcap: $(OBJS) loopPcap.o
	@echo $^
	$(CC) $(CFLAGS) -o $@ $@.o $(OBJS)   -L/usr/lib -lpcap

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<  -L/usr/lib -lpcap


clean:
	$(RM) *.o *~ $(MAIN)
clean_result: clean
	$(RM)  $(OUTPUT) $(OUTPUT:.pcap=.raw)
pack: clean_result
	tar -zcvf ../filtroAscii.tar.gz *.c *.h Makefile analisis.* *.png *.sh *.gplt