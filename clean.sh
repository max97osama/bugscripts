#!/bin/bash
 
apt-get update -y
apt-get autoremove -y --purge
apt-get autoclean -y
apt-get clean

go clean -cache
go clean -modcache

find /home/*/.cache -type f -atime +3 -delete
rm -rf /root/.cache/*
rm -rf /var/cache/*
rm -rf ~/.cache/pip
rm -rf ~/.cache/thumbnails/*
rm -rf ~/.cache/*

find /usr/local/bin -xtype l -delete
find /var/log -type f -name "*.gz" -delete
find /var/log -type f -name "*.1" -delete

journalctl --vacuum-size=50M
journalctl --vacuum-time=2d

df -h | grep '^/dev/ '



