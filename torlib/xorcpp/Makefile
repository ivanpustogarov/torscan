# Name of the file(s) we're compiling

TARGET = xorcpp

# location of the Python header files

PYTHON_INC = /usr/include/python2.7
PYTHON_LIB = /usr/lib/python2.7
PYTHON_NUMPY = $(shell python -c "import numpy; print numpy.get_include()")

# location of the Boost Python include files and library

BOOST_INC = /usr/include
BOOST_LIB = /usr/lib
PYUBLAS = ./pyublas/src/cpp/

$(TARGET).so: $(TARGET).o
	g++ -shared -Wl,--export-dynamic \
	$(TARGET).o -L$(BOOST_LIB) -lboost_python \
	-L$($PYTHON_LIB)/config -lpython2.7 -lm \
	-o $(TARGET).so
	cp $(TARGET).so ../

$(TARGET).o: $(TARGET).cpp
	g++ -I$(PYTHON_INC) -I$(BOOST_INC) -I$(PYUBLAS) -I$(PYTHON_NUMPY) -c -lm -fPIC $(TARGET).cpp

clean:
	rm -f *.so *.o *.dll *.a *~ core

