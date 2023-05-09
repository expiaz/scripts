#!/usr/bin/bash


rst='\033[0m'
red='\033[0;31m'
yellow='\033[0;33m'
green='\033[0;32m'
blue='\033[0;34m'

function line() {
	local color=$rst
	local delim='-'
	[[ $# == 2 ]] && color=$2
	[[ $# == 3 ]] && delim=$3
	echo -e "$2$(echo " $1 " | sed "s/./$3/g")$rst"
}

function title() {
	echo ""
	echo -en $red
	for i in $(seq 80); do echo -n "="; done
	echo -e $rst
	echo ""
	local l=$(line "   $1   " $yellow '=')
	echo $l
	echo -e "$yellow=== $1 ===$rst"
	echo $l
	echo ""

}

function section() {
	echo -e "$blue$1$rst"
}

function cmd() {
	echo -e "${blue}Command:$rst $1"
}

function output() {
	echo -e "${blue}Output:$rst $1"
}

function _whois() {
	title "WHOIS"
	cmd "whois $1"
	echo ""
	whois "$1"
}

function _amass() {
	title "AMASS"
	local out="$1.amass"
	local c="amass enum -src -d $1 -o $out"

	cmd "$c"
	#output "$out"
	echo ""
	eval $c
	echo ""

	cat $out | tr -d ' ' | cut -d] -f2 >> $2
	rm $out

#	echo ""
#	section "reverse whois"
#	c="amass intel -src -whois -d $1"
#	cmd "$c"
#	eval $c
}

_assetfinder() {
	title "ASSETFINDER"
	local out="$1.assetfinder"
	local c="assetfinder $1 | tee $out"

	cmd "$c"
	eval $c

	cat $out >> $2
	rm $out
}

_subfinder() {
	title "SUBFINDER"
	local out="$1.subfinder"
	local c="subfinder -d $1 -o $out"

	cmd "$c"
	eval $c

	cat $out >> $2
	rm $out
}

_findomain() {
	title "FINDOMAIN"
	local out="$1.txt"
	local c="findomain -o -t $1"

	cmd "$c"
	eval $c

	cat $out >> $2
	rm $out
}

_oneforall() {
	title "ONEFORALL"
	local out="/opt/tools/OneForAll/results/$1.csv"
	local c="python3 /opt/tools/OneForAll/oneforall.py --target $1 run"

	cmd "$c"
	output $1.csv
	eval $c

	cat $out | cut -d, -f6 | tail -n+2 | sort -u >> $2
	cp $out $1.csv
	rm $out
}

_gau() {
	title "GAU"
	local c="gau $1"

	cmd "$c"
	eval $c
}

_hosts() {
	title "HOSTS"

	for h in $(cat $1); do
		host $h
	done
}


domain=$1
output="$1.recon"
doms="$1.domains"
[[ $# == 2 ]] && output=$2
exec &> >(tee $output)

_whois $domain
_assetfinder $domain $doms
_subfinder $domain $doms
_findomain $domain $doms
_amass $domain $doms
_oneforall $domain $doms

# clean the domain file from duplicates
sort -u $doms > $doms.tmp
mv $doms.tmp $doms

_hosts $doms
#_gau $domain

title "RESULTS"
echo "Found $(wc -l $doms | cut -d' ' -f1) domains"
echo -e "${blue}Output file:${rst} $output"
echo -e "${blue}Result file:${rst} $doms"
