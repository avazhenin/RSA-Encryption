чтобы сгенерировать новые ключи

java -jar rsa.jar "g" 2048 "pub.txt" "modulus.txt" "priv.txt"



чтобы закодировать сообщение

java -jar rsa.jar "e" "pub.txt" "modulus.txt" "priv.txt" "message"



чтобы раскодировать сообщение, закодированное сообщение запихивай в emessage.txt

java -jar rsa.jar "d" "pub.txt" "modulus.txt" "priv.txt" "emessage.txt"