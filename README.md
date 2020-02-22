
1. Parallel Bcrypt Engine Build

Get a copy of the geokeytool repository

  git clone https://github.com/oscar-davids/geokeytool

Run "make"

  cd geokeytool
  make
  
check engine so file 
 
 libclibhash.so.5.1.0
 
2. Python Script Test

sudo pip install -r requirements.txt
  
Install Bitcoin

  https://bitcoin.org/en/full-node
  
  start bitcoin daemon mode

Generate locol bitcoin UTXO database

  stop bitcoin daemon because can not  access bitcoin's database at once.
  bitcoin-cli stop
 
  run script
  python updatebtcdb.py $HOME/.bitcoin/chainstate
  
Generate and recovery geokey and address

  python geokeys.py --create --password donotqwerty --gps +40.73150390,-73.96328405 --round 64 --unit dm
  
  python geokeys.py --recover --password donotqwerty --gps +40.73150390,-73.96328405 --round 64 --unit dm --radius 0.5
  
Other test script

  python gengeoinfo.py --password aaaaa --gps +40.73150390,-73.96328405 --radius 0.5 --unit dm --out geoinfo.txt

  python gengeocoinkey.py --input geoinfo.txt --out coinkey.txt --round 64

  python recoverygeokey.py --input geoinfo.txt --privatekey 0067464477714b7172307450762e792e35697a584376457046623353754c4d48 --round 64

