# dbfix

## About the patch
I have some IDB files from my friends who use leaked version of IDA. I really want to open these files. So that, I create this plugin to patch ida.dll and ida64.dll.

This version is compatible with IDA 7.0.170914 and 7.2.181105 only. 

## Building dbfix

64 bit binary only:

```
mkdir build64
cd build64
cmake -G"Visual Studio 15 2017 Win64" ..
cmake --build . --config Release
```

## Using dbfix

  1.Copy `dbfix.dll` into `plugin` directory
  2.Restart IDA

