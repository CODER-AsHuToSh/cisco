#!/bin/bash

# The aim of the script is to move coverage reports up to the parent directory
# where the source code files reside. Without that Sonar ignores these coverage
# reports (because the path to source and report files doesn't match)

for f in $(find ./ -type f \( -name \*.gcov -o -name \*.gcno -o -name \*.gcda \)); do
    src_dir_name=$(dirname $f)
    dst_dir_name=${src_dir_name%build-linux-64-release-coverage}
    mv $f $dst_dir_name
done
