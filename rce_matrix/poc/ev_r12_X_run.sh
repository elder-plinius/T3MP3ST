#!/bin/bash
# usage: run.sh <binname> <conftag> <listen> <mode> <failfirst> <reqfile> <tag>
BIN=$1; CT=$2; L=$3; MODE=$4; FF=$5; REQ=$6; TAG=$7
UP=$((L+100)); UP2=$((L+200))
LOG=/tmp/xlog_$TAG.txt; : > $LOG
timeout 90s python3 ev_r12_X_peer.py $UP $FF $MODE $LOG flaky > /tmp/xpeer_$TAG.out 2>&1 &
timeout 90s python3 ev_r12_X_peer.py $UP2 0 healthy $LOG healthy > /tmp/xpeer2_$TAG.out 2>&1 &
sleep 0.8
timeout 40s ./bin/$BIN --config ev_r12_X_$CT.conf > /tmp/xsrv_$TAG.out 2>&1 &
sleep 0.8
echo "== ss before =="; timeout 5s ss -ltnp | grep -E ":($L|$UP|$UP2)\b" | sed 's/  */ /g'
timeout 10s python3 ev_r12_X_drive.py $L $REQ > /tmp/xcli_$TAG.txt 2>&1
sleep 1.2
echo "== PEER LOG =="; timeout 5s cat $LOG
echo "== CLIENT =="; timeout 5s cat /tmp/xcli_$TAG.txt
pkill -f "ev_r12_X_peer.py $UP "; pkill -f "ev_r12_X_peer.py $UP2 "
pkill -f "bin/$BIN --config"
sleep 0.3
