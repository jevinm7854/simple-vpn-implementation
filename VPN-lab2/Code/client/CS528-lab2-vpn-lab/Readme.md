Setup server first.

Compile the code: gcc -o simpletunClient simpletunClient.c -lssl -lcrypto

Run the code: sudo ./simpletunClient -i tun0 -c 192.168.15.8 -d (the IP here should be of the server).
PEM pass phrase is: Jevin
The code will be running at this point

On other terminal:

sudo ip addr add 10.0.2.1/24 dev tun0
sudo ifconfig tun0 up
sudo route add -net 10.0.1.0 netmask 255.255.255.0 dev tun0

To test- ping 10.0.1.1
