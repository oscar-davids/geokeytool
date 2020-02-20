import ctypes

lib = ctypes.cdll.LoadLibrary("./libclibhash.so.5.1.0")

class clbflib:

    binit = 1
    bexit = 1
    nengincount = 0
    # Initializing  
    def __init__(self): 
        #print('clbflib created')
        if clbflib.binit == 1:
            lib.init_bcryptengine()
            clbflib.binit = 0
            clbflib.nengincount = lib.get_enginecount()
        self.chanel = 0
  
    # Calling destructor 
    def __del__(self): 
        #print("Destructor called")
        if clbflib.bexit == 1:
            lib.exit_bcryptengine()
            print("\nWait 5 minutes while release GPU opencl kernel!")
            clbflib.bexit = 0
    
    def setchanel(self, chanel): 
        #print("Destructor called")
        self.chanel = chanel
    
    def getengincount(self): 
        #print("Destructor called")
        clbflib.nengincount = lib.get_enginecount()
        return clbflib.nengincount
            
    def process(self,spass,ssalt,nround):
        
        outstr = "\0" * 100
        if self.chanel == 0:
            lib.bcrypt_hashpass(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 1:
            lib.bcrypt_hashpass01(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 2:
            lib.bcrypt_hashpass02(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 3:
            lib.bcrypt_hashpass03(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 4:
            lib.bcrypt_hashpass04(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 5:
            lib.bcrypt_hashpass05(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 6:
            lib.bcrypt_hashpass06(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 7:
            lib.bcrypt_hashpass07(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 8:
            lib.bcrypt_hashpass08(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 9:
            lib.bcrypt_hashpass09(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 10:
            lib.bcrypt_hashpass10(spass,ssalt,nround,outstr,self.chanel)
        elif self.chanel == 11:
            lib.bcrypt_hashpass11(spass,ssalt,nround,outstr,self.chanel)  
        elif self.chanel == 12:
            lib.bcrypt_hashpass12(spass,ssalt,nround,outstr,self.chanel)              
        elif self.chanel == 13:
            lib.bcrypt_hashpass13(spass,ssalt,nround,outstr,self.chanel)              
        elif self.chanel == 14:
            lib.bcrypt_hashpass14(spass,ssalt,nround,outstr,self.chanel)              
        elif self.chanel == 15:
            lib.bcrypt_hashpass15(spass,ssalt,nround,outstr,self.chanel)                          
        
        resstr = outstr[0:60]
        return resstr



#myArray = "\0" * 100

#lib.init_bcryptengine()
#lib.bcrypt_hashpass("aaa","aaa",1024,myArray,0)
#print("private key            : " + myArray)
#lib.exit_bcryptengine()


#blib = clbflib()
#blib.process("bbb","bbb",1024,myArray)
#print("private key            : " + myArray)

