call "%VS140COMNTOOLS%"\..\..\VC\bin\amd64\vcvars64
cl -nologo -c test.cpp
cl -I. runobj.cpp /link -map dbghelp.lib
pause