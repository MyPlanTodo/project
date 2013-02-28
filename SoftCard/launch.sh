#! /bin/bash
#
# This script launches the server (SoftCard)
# If the user gave the option "-c", the program will first 
#
# by Emmanuel Mocquet

# Checking if an option is provided
compile=false
while getopts ":c" opt; do
    case $opt in
        c)
            compile=true
            ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

if [ $compile == true ]; then
    echo "Compiling server."
    javac -d bin -cp lib/commons-codec-1.7.jar src/Default/NetworkException.java\
    src/Default/SoftCard.java src/Default/SoftCardServer.java src/Default/TestServer.java\
    src/Default/Tunnel.java src/Default/ArrayTools.java src/Default/CryptoTools.java
fi

echo "Starting server."
java -cp bin:lib/commons-codec-1.7.jar TestServer

echo 
echo "Server halted."
