#!/bin/sh -e

standard="c++20"
optimization="-O2"
libs="-lcrypto++"

compiler_primary="clang++"
compiler_secondary="g++"

src="./src"
build="./bin"

if [ $# -eq 0 ]
then
	options="-Wall -pipe $optimization -std=$standard"
else
	if [ "$1" = "DEBUG" ]
	then
		echo "Building in DEBUG Mode!"
		options="-Wall -DDEBUG -pipe $optimization -std=$standard"
	fi
fi

if [ ! -d "$build" ];
then
	mkdir "bin"
fi

compiler_path=$(which $compiler_primary 2>/dev/null || echo FALSE)

if [ "$compiler_path" = "FALSE" ];
then
	compiler_path=$(which $compiler_secondary 2>/dev/null || echo FALSE)
fi

if [ "$compiler_path" = "FALSE" ];
then
	echo "Neither $compiler_primary nor $compiler_secondary was found."
	exit
fi

echo "using: $compiler_path"

echo "building client xcc"
$compiler_path $options -DCLIENT $src/xcc.cpp -o $build/xcc $libs &

echo "building server xcd"
$compiler_path $options -DSERVER $src/xcd.cpp -o $build/xcd $libs

echo "Client (xcc) and Server (xcd) compiled to folder $build."
