#!/bin/bash

echo -n "Verifying executability of GPShell: "
test -x /usr/bin/gpshell
if [ $? -ne 0 ]; then
    echo "GPShell is not installed... Exiting."
    exit 1
fi
echo "Done."

echo -n "Installing applets: "
gpshell install.txt &>/dev/null
if [ $? -ne 0 ]; then
    echo "Error. Exiting."
    exit 1
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
