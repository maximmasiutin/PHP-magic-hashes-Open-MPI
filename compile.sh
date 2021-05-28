#!/bin/bash

mpicxx -mtune=native -march=native -O3 phpmagic_sha1_openmpi.cpp sha1.cpp -o phpmagic_sha1_openmpi 1>./last-compile-stdout.txt 2>./last-compile-stderr.txt

if [ $? -ne 0 ]
then
    echo "The CPU does not support the SHA extensions";
    mpicxx -DDISABLE_SHA_CPU_EXTENSIONS -mtune=native -march=native -O3 phpmagic_sha1_openmpi.cpp sha1.cpp -o phpmagic_sha1_openmpi 1>>./last-compile-stdout.txt 2>>./last-compile-stderr.txt
    if [ $? -ne 0 ]
    then
        cp ./last-compile-stderr.txt /dev/stderr
        cp ./last-compile-stdout.txt /dev/stdout
    fi
else
    echo "The CPU supports the SHA extensions";
fi

