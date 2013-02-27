#!/bin/bash

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

echo -n "Verifying executability of GPShell: "
test -x /usr/bin/gpshell
if [ $? -ne 0 ]; then
    echo "GPShell is not installed... Exiting."
    exit 1
fi
echo "Done."

echo -n "Installing applets: "
gpshell installTunnel.txt &>/dev/null
if [ $? -ne 0 ]; then
    echo "Error. Exiting."
    exit 1
fi
echo "Done."

if [ $compile == true ]; then 
    echo -n "Compiling admin program: "
    javac -d bin -cp lib/commons-codec-1.7.jar src/Default/SoftCard.java\
        src/Admin/getCode.java src/Default/Tunnel.java src/Default/ArrayTools.java\
        src/Default/CryptoTools.java
fi
echo "Done."

echo -n "Getting PIN: "
pin=$(java -cp bin getCode PIN)
if [ $? -ne 0 ]; then
    echo "Error. Exiting."
    exit 1
fi
echo $pin


echo -n "Getting PUK: "
puk=$(java -cp bin getCode PUK)
if [ $? -ne 0 ]; then
    echo "Errror. Exiting."
    exit 1
fi
echo $puk
