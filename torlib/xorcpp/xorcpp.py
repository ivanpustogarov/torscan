import xorcpp
import os

#t = TestExtractor.interfaceObject()

#strlen = t.getString("Python string")

#print strlen

#x = TestExtractor.dataStructure(18)
#print x.value()

#t.getCustom(x)

a = os.urandom(20)
b = os.urandom(20)

def xorPy(x, y):
    "Compute the XOR of two strings x, y"
    return str(bytearray([a^b for a, b in zip(bytearray(x), bytearray(y))]))

def xorC(x,y):
    return xorcpp.xorcpp_inplace(a, b) # it calls xorcpp_str_inplace()

for i in range (0,1000):
     xorC(a,b)

for i in range (0,1000):
     xorPy(a,b)



