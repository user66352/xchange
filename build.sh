#!/bin/sh -e

standard=c++20

compOne=g++
compTwo=clang++

src="./src"
build="./bin"

if [ ! -d "$build" ];
then
	mkdir bin
fi

compiler_path=$(which $compOne 2>/dev/null || echo FALSE)

if [ "$compiler_path" = "FALSE" ];
then
	compiler_path=$(which $compTwo 2>/dev/null || echo FALSE)
fi

if [ "$compiler_path" = "FALSE" ];
then
	echo "Neither clang++ nor g++ was found on the system."
	exit
fi

echo "using compiler: $compiler_path"

$compiler_path -Wall -std=$standard $src/xcc.cpp -o $build/xcc &
$compiler_path -Wall -std=$standard $src/xcd.cpp -o $build/xcd

echo "Client (xcc) and Server (xcd) compiled to folder 'bin'."