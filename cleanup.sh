#!/bin/bash
rm -rf build dist .eggs *.egg-info
find . -type f -name "*pb2*" -delete
