java -jar keys\BootSignature.jar /recovery %1 keys\verity.pk8 keys\verity.x509.pem %2
java -jar keys\BootSignature.jar -verify %2

