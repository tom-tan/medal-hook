#!/bin/sh

dub build -b release || exit 1

code=0

for ex in examples/*
do
    rm -f $ex/network-hooked.yml $ex/actual.txt
    ./bin/medal-hook $ex/network.yml --hook $ex/hook.yml > $ex/network-hooked.yml
    if [ $? -ne 0 ]; then
        echo "failed: $ex"
        code=1
        continue
    fi
    medal $ex/network-hooked.yml -i $ex/init.yml --workdir=$ex --quiet > $ex/actual.txt
    if [ $? -ne 0 ]; then
        echo "failed: $ex"
        code=1
        continue
    fi
    expected=$(cat $ex/expected.txt | md5sum -)
    actual=$(cat $ex/actual.txt | md5sum -)
    if [ "$expected" = "$actual" ]; then
        echo "success: $ex"
        rm -f $ex/network-hooked.yml $ex/actual.txt
    else
        echo "failed: $ex"
        code=1
    fi
done

exit $code
