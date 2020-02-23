
1. Build Parallel Bcrypt Engine 

- install gcc and dependency pacakges

  sudo apt install gcc
  
  sudo apt install build-essential
  
  sudo apt-get install manpages-dev
  
  sudo apt install ocl-icd-* opencl-headers

- Get a copy of the geokeytool repository

  git clone https://github.com/oscar-davids/geokeytool

- Run "make"

  cd geokeytool
  
  make
  
- check engine so file 
 
  libclibhash.so.5.1.0
 
2. Preparing for Test

- Install requirement python packages

  sudo pip install -r requirements.txt
  
- Install Bitcoin client

  https://bitcoin.org/en/full-node
  
- start bitcoin with daemon mode

3. Generate locol bitcoin UTXO database

- stop bitcoin daemon because can not  access bitcoin's database at once.
  
  bitcoin-cli stop
 
- run script
  
  python updatebtcdb.py $HOME/.bitcoin/chainstate
  
4. Generate and recovery geokey and address

  python geokeys.py --create --password donotqwerty --gps +40.73150390,-73.96328405 --round 64 --unit dm
  
  python geokeys.py --recover --password donotqwerty --gps +40.73150390,-73.96328405 --round 64 --unit dm --radius 0.5
  
5. Other test script

  python gengeoinfo.py --password aaaaa --gps +40.73150390,-73.96328405 --radius 0.5 --unit dm --out geoinfo.txt

  python gengeocoinkey.py --input geoinfo.txt --out coinkey.txt --round 64

  python recoverygeokey.py --input geoinfo.txt --privatekey 0067464477714b7172307450762e792e35697a584376457046623353754c4d48 --round 64

