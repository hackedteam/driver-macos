#!/bin/bash

chmod -R 755 build/Release*
chown -R revenge:staff build/Release*

kextunload build/Release/mchook.kext
