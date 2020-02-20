
Build

git clone https://github.com/oscar-davids/geokeytool

cd geokeytool

make

sudo pip install -r requirements.txt

python gengeoinfo.py --password aaaaa --gps +40.73150390,-73.96328405 --radius 0.5 --unit dm --out geoinfo.txt

python gengeocoinkey.py --input geoinfo.txt --out coinkey.txt --round 64

python recoverygeokey.py --input geoinfo.txt --privatekey 003242314a706869472e61567532494542394d3967495752654f50737855556a --round 64

