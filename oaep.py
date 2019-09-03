import hashlib
import math
import binascii

def I2OSP(x, xLen):
    if x >= 256**xLen:
        return "integer too large"

    output = x.to_bytes(xLen, 'big')
    return output


def MGF1 (mgfSeed, maskLen):
    hLen = 20

    mgf = int(mgfSeed, 16).to_bytes(int(len(mgfSeed)/2), 'big')
    if maskLen > (2**32) * hLen:
        return "mask too long"
    T = ""
    for i in range (0, math.ceil(maskLen/hLen)):
        C = I2OSP(i, 4)
        T += hashlib.sha1(mgf + C).hexdigest()


    return T[0:maskLen*2]

def OAEP_encode(M, seed):
    k = 128
    mLen = int(len(M)/2.0)
    L = ""
    lHash = hashlib.sha1(L.encode('utf8')).hexdigest()
    hLen = int(len(lHash)/2.0)
    PS = "0" * (k - mLen - 2*hLen - 2)*2
    DB = lHash + PS + '01' + M
    dbMask = MGF1(seed, k-hLen-1)
    maskedDB = format(int(DB, 16) ^ int(dbMask, 16), 'x')
    seedMask = MGF1(maskedDB, hLen)
    maskedSeed = format(int(seed, 16) ^ int(seedMask, 16), 'x')
    EM = '00' + maskedSeed + maskedDB
    return EM

def OAEP_decode(EM):
    k = 128
    L = ""
    lHash = hashlib.sha1(L.encode('utf8')).hexdigest()
    hLen = int(len(lHash) / 2.0)
    Y = EM[:2]
    maskedSeed = EM[len(Y):len(Y) + hLen*2]
    maskedDB =EM[len(Y+maskedSeed): len(Y+maskedSeed) + (k-hLen-1)*2]
    seedMask = MGF1(maskedDB, hLen)
    seed = format(int(maskedSeed, 16) ^ int(seedMask, 16), 'x')
    dbMask = MGF1(seed, k-hLen-1)
    DB = format(int(maskedDB, 16) ^ int(dbMask, 16), 'x')
    split_list = DB.rpartition('01')
    M = split_list[-1]
    return M

Msg = 'c7bd4ab6a5ba9211f5a128808949eb2e3d0b27610165d01e96'
seeds = '97995ee677b1118d590a07efd9b2010905f0b898'
EM = '00451e66a5e9b51f00abe919cfa277b237008087def9d3778a18b7aa067f90b2178406fa1e1bf77f03f86629dd5607d11b9961707736c2d16e7c668b367890bc6ef1745396404ba7832b1cdfb0388ef601947fc0aff1fd2dcd279dabdf472023d44ef55c4a40d1ce16608342d9b31f7fab5270ff56cf8f962258890b9f78184c'

print ('decode',OAEP_decode(EM))
print ('encode', OAEP_encode(Msg, seeds))

print ('MGF1', MGF1('54bacfd9ce645dad640fbd5b83123c2e3fa90f3b8fcb', 22))
#print (MGF1('9b4bdfb2c796f1c16d0c0772a5848b67457e87891dbc8214', 21))

