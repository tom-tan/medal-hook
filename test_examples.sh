#!/bin/sh

dub build -b release || exit 1

code=0

for ex in examples/*
do
    rm -f $ex/network-hooked.yml $ex/subnetwork-hooked.yml $ex/actual.txt
    ./bin/medal-hook $ex/network.yml --hook $ex/hook.yml > $ex/network-hooked.yml
    if [ $? -ne 0 ]; then
        echo "hook failed: $ex"
        code=1
        continue
    fi

    if [ -e $ex/subnetwork.yml ]; then
        ./bin/medal-hook $ex/subnetwork.yml --hook $ex/hook.yml > $ex/subnetwork-hooked.yml
        if [ $? -ne 0 ]; then
            echo "sub hook failed: $ex"
            code=1
            continue
        fi
        sed -e 's/subnetwork.yml/subnetwork-hooked.yml/' $ex/network-hooked.yml > $ex/network-hooked1.yml
        mv $ex/network-hooked1.yml $ex/network-hooked.yml
    fi

    medal $ex/network-hooked.yml -i $ex/init.yml --workdir=$ex --quiet
    if [ $? -ne 0 ]; then
        echo "execution failed: $ex"
        code=1
        continue
    fi
    expected=$(cat $ex/expected.txt | md5sum -)
    actual=$(cat $ex/actual.txt | md5sum -)
    if [ "$expected" = "$actual" ]; then
        echo "success: $ex"
        rm -f $ex/network-hooked.yml $ex/subnetwork-hooked.yml $ex/actual.txt
    else
        echo "result failed: $ex"
        code=1
    fi
done

exit $code
