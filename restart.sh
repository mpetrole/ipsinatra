kill `cat ip.pid`
sleep 10
thin -R config.ru start 2>log.txt &
