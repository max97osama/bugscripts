#!/bin/bash
input="urls.txt"
grep -iE "\.js(\?.*)?$" "$input" > js.txt
grep -E "\?" "$input" > parameters.txt
grep -viE "\.(js|css|jpg|jpeg|png|gif|svg|ico|webp|bmp|tiff|woff|woff2|ttf|eot|json)(\?.*)?$" "$input" > cleaned.txt