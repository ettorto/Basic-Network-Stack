
#!/bin/bash

# Function to get IP address of current machine
get_ip_address() {
    hostname -I | awk '{print $1}'
}

# Assign IP address of current machine to a variable
# server_ip=$(get_ip_address)
server_ip="192.0.2.7"
# Check if IP address is obtained successfully
if [ -z "$server_ip" ]; then
  echo "Failed to obtain IP address of the current machine."
  exit 1
fi

# Assign port from command line argument
server_port="$1"

# Check for required port argument
if [ -z "$server_port" ]; then
  echo "Usage: $0 <server_port>"
  exit 1
fi

# Run make command to compile the server binary
make

# Create TAP interface
sudo ip tuntap add mode tap user $USER name tap0

# Set IP address for TAP interface
sudo ip addr add 192.0.2.6/24 dev tap0

# Bring TAP interface up
sudo ip link set tap0 up

# Navigate to server binary directory
cd bin

# Run server with obtained IP and provided port
./server "$server_ip" "$server_port"

# Open a new terminal and run the wifi client
# gnome-terminal --command="wihotspot"

# Remove TAP interface
trap 'sudo ip tuntap del mode tap name tap0' EXIT



#     fprintf(stderr, "\x1b[33mmain app server address:\x1b[0m %s\n", SERVER_IP);
