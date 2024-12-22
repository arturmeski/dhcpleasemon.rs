#!/bin/ksh

pname="dhcpleasemon"

cargo build --release

install -o root -g wheel -d /etc/$pname
install -o root -g bin target/release/$pname /usr/local/sbin/$pname
install -o root -g wheel -m 0555 rc.d/$pname /etc/rc.d/$pname

