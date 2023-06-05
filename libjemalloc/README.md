libjemalloc
===========

The following command was used to obtain the third party jemalloc library:

    wget http://www.canonware.com/download/jemalloc/jemalloc-4.1.0.tar.bz2

Don't forget to "git add -f jemalloc-4.1.0/" - to avoid .gitignore'd files!

Here we wrap jemalloc and build it using the libsxe make system as a third party library.

To link without changing your malloc/realloc/free/memalign calls, include je-shim.o from
the $(DST.dir) directory (and of course the library itself).  je-shim.o is not required
if you call je_malloc/je_realloc/je_free/je_memalign directly.
