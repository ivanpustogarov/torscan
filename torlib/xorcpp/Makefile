# Name of the file(s) we're compiling

TARGET = xorcpp

# location of the Python header files

PYTHON = /usr/include/python2.7

# location of the Boost Python include files and library

BOOST_INC = /usr/include
BOOST_LIB = /usr/lib
PYUBLAS = /usr/local/lib/python2.7/dist-packages/PyUblas-2011.1-py2.7-linux-x86_64.egg/include/

$(TARGET).so: $(TARGET).o
	g++ -shared -Wl,--export-dynamic \
	$(TARGET).o -L$(BOOST_LIB) -lboost_python \
	-L/usr/lib/python2.7/config -lpython2.7 -lm \
	-o $(TARGET).so

$(TARGET).o: $(TARGET).cpp
	g++ -I$(PYTHON) -I$(BOOST_INC) -I$(PYUBLAS) -c -lm -fPIC $(TARGET).C

clean:
	rm -f *.so *.o *.dll *.a *~ core

