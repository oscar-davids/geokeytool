import math
import argparse
import struct
import binascii

#python gengeoinfo.py --password aaaaa --gps +40.73150390,-73.96328405 --radius 0.5 --unit dm --out geoinfo.txt

def main():

    parser = argparse.ArgumentParser(description='Generate key.')
    parser.add_argument('--password', type=str, help='a password')
    parser.add_argument('--gps', type=str, help='gps coordinates to use')
    parser.add_argument('--radius', type=float, help='search radius(m) to use')
    parser.add_argument('--unit', type=str, help='search unit to use')
    parser.add_argument('--out', type=str, help='search list file for brute force attack')

    
    args = parser.parse_args()

    password = args.password
    outfilename = args.out

    #here insert validation function
    gps = args.gps
    centlatlong = gps.split(",")
    if len(centlatlong) != 2:
        print("invalid gps argument")
        return

    cenlat = float(centlatlong[0])
    cenlong = float(centlatlong[1])

    searchredius = args.radius
    scanunit =  args.unit

    #earth mean radius mm
    #637813700
    earthradius = 6371008800
    #calculate real degree unit for argument unit
    earthtotallen = math.pi * 2.0 * earthradius
    #calc square step
    stepdgreepermm = 360.0 / earthtotallen
    iterator = int(searchredius * 100)
    if scanunit == "mm":
        #https://en.wikipedia.org/wiki/Decimal_degrees
        stepdgree = 0.00000001
    elif scanunit == "dm":
        stepdgree = stepdgreepermm * 10.0
        iterator = int(iterator/10)
    elif scanunit == "m":
        stepdgree = stepdgreepermm * 100.0
        iterator = int(iterator/100)
    
    #calc left top and iterator round
    k = 0
    #open out file
    try:
        fout = open(outfilename, 'w')

        for i in range(-iterator, iterator + 1):
            for j in range(-iterator, iterator + 1):
                lat = cenlat + i * stepdgree
                long = cenlong + j * stepdgree

                strlat = '%.08f' % lat
                strlong = '%.08f' % long

                if lat > 0.0:
                    strlat = "+" + strlat
                if long > 0.0:
                    strlong = "+" + strlong

                strlatlong = strlat + "," + strlong
                #print(strlatlong)
                strline = password + " " + strlatlong + '\n'
                fout.write(strline)

        fout.close()

    except IOError:
        print("Could not write file!")

    print("Compete!")

if __name__== "__main__":
    main()