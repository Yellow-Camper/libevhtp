#!/bin/bash
# This shouldn't be used by anyone but me...kthx

rm -rf libhtparse/
rm -rf evthr/
rm -rf oniguruma/

rm -rf build/libhtparse-latest*
rm -rf build/libevthr-latest*
rm -rf build/oniguruma-latest*

cd build && wget http://ackers.net/packages/libhtparse-latest.tar http://ackers.net/packages/libevthr-latest.tar http://ackers.net/packages/oniguruma-latest.tar
cd ..

httparser_dirname=`tar --to-stdout -tf build/libhtparse-latest.tar 2>&1 | head -n 1`
libevthr_dirname=`tar --to-stdout -tf build/libevthr-latest.tar 2>&1 | head -n 1`
oniguruma_dirname=`tar --to-stdout -tf build/oniguruma-latest.tar 2>&1 | head -n 1`

tar -xf build/libhtparse-latest.tar
tar -xf build/libevthr-latest.tar
tar -xf build/oniguruma-latest.tar

mv $httparser_dirname libhtparse 
mv $libevthr_dirname evthr
mv $oniguruma_dirname oniguruma

rm -rf build/libhtparse-latest*
rm -rf build/libevthr-latest*
rm -rf build/oniguruma-latest*
