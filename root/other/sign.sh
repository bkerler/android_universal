#!/bin/sh
java -jar BootSignature.jar /boot boot.img verifiedboot.pk8 verifiedboot.x509.der boot_signed.img
java -jar BootSignature.jar -verify boot_signed.img
