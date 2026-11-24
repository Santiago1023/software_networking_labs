what does the Makefile in the c directory?

what is ELF?

what is a skeleton?
Skeletons is code generated that has inside the .o file and give you access with name to its programs, and maps
skel->maps. skel->progs. 


Para este tipo de ejercicios conocer los campos de cada protocolo es clave. Para cada cabecera (Ethernet, IP, TCP/UDP) necesitamos saber 3 cosas:

- cuanto mide
- donde están los campos que interesan
- qué campo te dice qué protocolo viene después

ctx->data viene el paquete con la cabecera ethernet

el campo type (EtherType), después de las MACs, nos dicen qué protocolo viene después. En struct ethhdr se llama h_proto

los bytes 0 a 13 son la cabecera ethernet (6+6+2=14) la siguiente cabecera empezaría en el offset 14, contando desde 0

los primeros 96 bits de la cabecera del protocolo ip, te dicen cual protocolo sigue,  en el campo protocol (TPC/UPD/ICMP)

la ip origen empieza en el bit 96, que es el byte 12.
las dos ip ocupan 64 bits (8 bytes)

el IHL (internet header length) es la longitud de la cabecera ocupa 4 bits, del 4 al 7.
el valor minimo de IHL es 5, y la cabecera IPv4 minima (sin options) mide 20 bytes.
