# How to compile
Only prerequisite is
'''
vcpkg install
'''
inside a vs command prompt.

If you get undefined symbols from zydis it's probably because you have installed the wrong version somehow.

# How to use
- Add SKLib.lib in "Additional Dependencies" in Librarian section for your kernel driver.
- Add your library director
- Add your include directory for SKLib header files in C/C++ -> "Additional Include Directories"
