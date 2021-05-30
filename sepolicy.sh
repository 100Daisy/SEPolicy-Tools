#!/bin/bash

if [ -z "$1" ]; then
    printf "Failed: Please supply a log file\n"
    exit 1
fi

while read -r line; do
    scontext=`echo "$line" | sed 's/^.*scontext=u:r://' | sed 's/\ .*//' | cut -d':' -f1`
    tcontext=`echo "$line" | sed 's/^.*tcontext=u:object_r://' | sed 's/^.*tcontext=u:r://' | sed 's/\ .*//' | cut -d':' -f1`
    tclass=`echo "$line" | sed 's/^.*tclass=//' | sed 's/\ .*//' | cut -d':' -f1`
    permission=`echo "$line" | sed 's/^.*avc: denied { //' | sed 's/\}.*//' | cut -d' ' -f1`

    policy="allow $scontext $tcontext:$tclass { $permission };"

    if [ -z "$1" ]; then
        policies="$policy"$'\n'
    else
        policies="$policies"$'\n'"$policy"$'\n'
    fi
done < <(grep "avc: denied" "$1" | uniq)

policies=`printf "$policies" | sort | uniq`

printf "$policies\n" | ./semerge.pl
