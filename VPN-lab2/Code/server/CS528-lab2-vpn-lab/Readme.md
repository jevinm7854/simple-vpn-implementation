Compile the code: gcc -o simpletun simpletun.c -lssl -lcrypto

Run the code: sudo ./simpletun -i tun0 -s -d
PEM pass phrase is: Jevin
The code will be running at this point

On other terminal:

sudo ip addr add 10.0.1.1/24 dev tun0
sudo ifconfig tun0 up
sudo route add -net 10.0.2.0 netmask 255.255.255.0 dev tun0

Then Setup client

To test- ping 10.0.2.1
