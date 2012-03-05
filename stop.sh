#!/bin/bash

KEXT=/tmp/mchook-64.kext
chmod -R 755 $KEXT/*
chown -R test1:staff $KEXT

kextunload $KEXT
