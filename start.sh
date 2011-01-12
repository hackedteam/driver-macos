#!/bin/bash

chmod -R 744 build/Release*
chown -R root:wheel build/Release*

kextload -v build/Release/mchook.kext
