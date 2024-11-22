
# TP2 - SDN OpenFlow

| Integrante                   | Padrón | Mail                |
|------------------------------|--------|---------------------|
| Tomás Ezequiel Galián        | 104354 | tgalian@fi.uba.ar   |
| Edgardo Francisco Saez       | 104896 | esaez@fi.ubar.ar    |
| Iñaki Pujato                 | 109131 | ipujato@fi.uba.ar   |
| Mateo Lardiez                | 107992 | mlardiez@fi.uba.ar  |
| Víctor Manuel Zacarías Rojas | 107080 | vzacarias@fi.uba.ar |


# Descripción del proyecto


# Requisitos de uso
 
- Python 3.
- POX ichthyosaur.
- Mininet.
- Iperf. 

# Instrucciones de ejecución

 1. En una terminal (bash), levantar el firewall con el siguiente comando:
    ```bash
    python3 pox.py log.level --DEBUG openflow.of_01 forwarding.l2_learning firewall
    ```
    
2. En otra terminal (bash), levantar la topología de red deseada con el siguiente comando:
    ```bash
    sudo mn --custom topology.py --topo tp2,ns=n --arp --switch ovsk --controller remote
   ```

3. Luego, se pueden levantar los clientes y servidores de la simulación. Para ello es necesario usar la herramienta
Xterm integrada en mininet.
   ```bash
    >mininet xterm h1 h2 h3 h4
    ```
Se pueden levantar hasta 4 hosts (siendo uno el mínimo y cuatro el máximo).
  
|Host| IP     | Puerto                              |
|----|--------|-------------------------------------|
|H1| 10.0.0.1 | Arbitrario a fines de la simulación |
|H2| 10.0.0.2 | Arbitrario a fines de la simulación |
|H3| 10.0.0.3 | Arbitrario a fines de la simulación |
|H4| 10.0.0.4 | Arbitrario a fines de la simulación |
   
Los hosts se levantan por defecto con las Ips especificadas en la tabla anterior. Respecto a la sección de puertos,
los mismos son especificados al momento de levantar algún cliente o servidor sobre un host.

4. Se recomienda testear la configuración seleccionada junto con las herramientas de simulación.
 ```bash
    >mininet pingall
 ```
5. Finalmente, se pueden levantar los clientes y servidores para realizar la simulación.

- Para levantar un **servidor UDP** en un host (una terminal de Xterm):
    ```bash
    iperf -u -s -p <mi puerto>
    ```
   -u indica que el protocolo de la capa de transporte es UDP.
   -s indica que el host actuará como servidor.
   -p indica el puerto en el que se levantará el servidor.
   (la IP en la que se levanta el servidor es la especificada por la tabla)
  
- Para levantar un **cliente UDP** en un host (otra terminal de Xterm):
    ```bash
    iperf -u -c <IP del servidor> -p <puerto del servidor>
    ```
   -u indica que el protocolo de la capa de transporte es UDP.
   -c indica que el host actuará como cliente.
   -p indica el puerto de destino al que se enviaran los mensajes.

- Para levantar un *cliente TCP** en un host (una terminal de Xterm):
    ```bash
    iperf -c <IP del servidor>  -p <puerto del servidor> -b <x> -n <x> -l <x> -t <x>

    ```
   -c indica que el host actuará como cliente.
   -p indica el puerto de destino al que se enviaran los mensajes..
   -b Limitación del ancho de banda (bits/s).
   -n Limitación de la cantidad de paquetes.
   -l Limitación del tamaño de los paquetes.
   -t Limitación del tiempo de ejecución (tiempo de conexión). 

- Para levantar un **servidor TCP** en un host (otra terminal de Xterm):
    ```bash
    iperf -s -p <puerto> -b <x> -n <x> -l <x> -t <x>
    ```
   -s indica que el host actuará como servidor.
   -p indica el puerto en el que se levantará el servidor.
   -b Limitación del ancho de banda (bits/s).
   -n Limitación de la cantidad de paquetes.
   -l Limitación del tamaño de los paquetes.
   -t Limitación del tiempo de ejecución (tiempo de conexión). 
   (la IP en la que se levanta el servidor es la especificada por la tabla)