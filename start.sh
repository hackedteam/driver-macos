#!/bin/bash

KEXT=/Users/test1/Library/Developer/Xcode/DerivedData/mchook-dbxvtdvdcdtdmrfqgacjaoqcflry/Build/Products/Release/mchook-64.kext
cp -r $KEXT /tmp

mv /tmp/mchook-64.kext/Contents/MacOS/mchook-64 /tmp/mchook-64.kext/Contents/MacOS/mchook
chmod -R 744 /tmp/mchook-64.kext/*
chown -R root:wheel /tmp/mchook-64.kext

sed -i -e s/10\.4/11\.3/g /tmp/mchook-64.kext/Contents/Info.plist
kextload -v /tmp/mchook-64.kext

