#include <boost/python.hpp>
#include "boost/python/extract.hpp"
#include <iostream>
#include <pyublas/numpy.hpp>
#include <inttypes.h>
#include <algorithm>
#include <boost/lambda/lambda.hpp>
#include <math.h>

using namespace boost::python;

namespace { 
  namespace py = boost::python;

  template<class InputIterator, class InputIterator2, class OutputIterator>
  void
  xor_(InputIterator first, InputIterator last, 
       InputIterator2 first2, OutputIterator result) {
    // `result` migth `first` but not any of the input iterators
    namespace ll = boost::lambda;
    (void)std::transform(first, last, first2, result, ll::_1 ^ ll::_2);
  }

  template<class T>
  py::str 
  xorcpp_str_inplace(const py::str& a, py::str& b) {
    const size_t alignment = std::max<long unsigned int>(sizeof(T), 16ul);
    const size_t n         = py::len(b);
    const char* ai         = py::extract<const char*>(a);
    char* bi         = py::extract<char*>(b);
    char* end        = bi + n;

    if (n < 2*alignment) 
      xor_(bi, end, ai, bi);
    else {
      assert(n >= 2*alignment);

      // applying Marek's algorithm to align
      const ptrdiff_t head = (alignment - ((size_t)bi % alignment))% alignment;
      const ptrdiff_t tail = (size_t) end % alignment;
      xor_(bi, bi + head, ai, bi);
      xor_((const T*)(bi + head), (const T*)(end - tail), 
           (const T*)(ai + head),
           (T*)(bi + head));
      if (tail > 0) xor_(end - tail, end, ai + (n - tail), end - tail);
    }
    return b;
  }

  template<class Int>
  pyublas::numpy_vector<Int> 
  xorcpp_pyublas_inplace(pyublas::numpy_vector<Int> a, 
                         pyublas::numpy_vector<Int> b) {
    xor_(b.begin(), b.end(), a.begin(), b.begin());
    return b;
  }
}


// Expose classes and methods to Python
BOOST_PYTHON_MODULE(xorcpp) {
	py::def("xorcpp_inplace", xorcpp_str_inplace<int32_t>);     // for strings

}
