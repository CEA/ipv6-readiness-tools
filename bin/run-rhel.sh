#!/bin/bash

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

# configure library path
if [ `uname -m` == x86_64 ]; then
    LIB=lib-native/jnetpcap/rhel.x86_64
else
    echo "Not supported for RHEL i386" 1>&2
    exit 1
fi

# launch
java -Djava.library.path=${LIB} -jar v6App.jar
