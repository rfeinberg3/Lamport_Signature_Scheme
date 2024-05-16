gcc KeyGen.c -ltomcrypt -o CertificateAuthority
gcc Sign.c -ltomcrypt -lzmq -o Alice
gcc Verify.c -ltomcrypt -lzmq -o Bob

for i in 1 2 3
do
./CertificateAuthority Seed$i.txt >> CA$i.log
sleep 2
./Alice Message$i.txt SK.txt >> Alice$i.log &
sleep 2
if [ "$i" -eq 1 ]; then
./Bob PK.txt 45 >> Bob$i.log &
sleep 2
elif [ "$i" -eq 2 ]; then
./Bob PK.txt 297 >> Bob$i.log & 
sleep 2
elif [ "$i" -eq 3 ]; then
./Bob PK.txt 625 >> Bob$i.log &
sleep 2
fi
#=========================================
if cmp -s "SK.txt" "CorrectSK$i.txt"
then
   echo "SK$i is valid."
else
   echo "SK$i does not match!"
fi 
#=========================================
if cmp -s "PK.txt" "CorrectPK$i.txt"
then
   echo "PK$i is valid."
else
   echo "PK$i does not match!"
fi 
#=========================================
if cmp -s "Signature.txt" "CorrectSignature$i.txt"
then
   echo "Signature$i is valid."
else
   echo "Signature$i does not match!"
fi
#=========================================
echo "$(cat Verification.txt)"
#=========================================
echo "================================================="
done
