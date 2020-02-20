
Build

git clone https://github.com/oscar-davids/geokeytool

cd geokeytool

make

sudo pip install -r requirements.txt

python gengeoinfo.py --password aaaaa --gps +40.73150390,-73.96328405 --radius 0.5 --unit dm --out geoinfo.txt

python gengeocoinkey.py --input geoinfo.txt --out coinkey.txt --round 64

python recoverygeokey.py --input geoinfo.txt --privatekey 0067464477714b7172307450762e792e35697a584376457046623353754c4d48 --round 64

