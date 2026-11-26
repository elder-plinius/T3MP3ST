#!/bin/bash
# AirScope: Wi-Fi radar for Android devices via ADB

#==================================================
# Define color escape codes
#==================================================

# Regular Colors
RED='\033[0;31m'       # Red
GREEN='\033[0;32m'     # Green
YELLOW='\033[0;33m'    # Yellow
BLUE='\033[0;34m'      # Blue
CYAN='\033[0;36m'      # Cyan
PURPLE='\033[0;35m'    # Purple
WHITE='\033[0;37m'     # White
RESET='\033[0m'        # Reset

# Bold Colors
REDB='\033[1;31m'      # Red
GREENB='\033[1;32m'    # Green
YELLOWB='\033[1;33m'   # Yellow
BLUEB='\033[1;34m'     # Blue
CYANB='\033[1;36m'     # Cyan
PURPLEB='\033[1;35m'   # Purple
WHITEB='\033[1;37m'    # White

BLINK='\e[5m'	       # Blink

# Array of color names
allcolors=("RED" "GREEN" "YELLOW" "BLUE" "CYAN" "PURPLE" "WHITE")

#==================================================
# Function to print banner with a random color
#==================================================
ascii_banner() {
    random_color="${allcolors[$((RANDOM % ${#allcolors[@]}))]}"
    case $random_color in
        "RED") color_code=$RED ;;
        "GREEN") color_code=$GREEN ;;
        "YELLOW") color_code=$YELLOW ;;
        "BLUE") color_code=$BLUE ;;
        "CYAN") color_code=$CYAN ;;
        "PURPLE") color_code=$PURPLE ;;
        "WHITE") color_code=$WHITE ;;
    esac

    echo -e "${color_code}"
    cat << "EOF"
    _    _      ____                       
   / \  (_)_ __/ ___|  ___ ___  _ __   ___ 
  / _ \ | | '__\___ \ / __/ _ \| '_ \ / _ \
 / ___ \| | |   ___) | (_| (_) | |_) |  __/
/_/   \_\_|_|  |____/ \___\___/| .__/ \___|
                               |_|    
EOF
    echo -e "${RESET}"
}

#==================================================
# Main Script
#==================================================

ascii_banner

echo -e "                  "
echo -e "${CYANB}------------------${RESET}"
echo -e "${YELLOWB}Disabling Wi-Fi...${RESET}"
adb shell svc wifi disable
sleep 2
echo -e "${GREENB}Enabling Wi-Fi...${RESET}"
echo -e "${CYANB}------------------${RESET}"
echo -e "                 "
adb shell svc wifi enable
sleep 5

# Collect Wi-Fi scan results
SCAN=$(adb shell dumpsys wifi | \
    grep "Networks filtered out due" | \
    sed 's/.*Networks filtered out due [^:]*: //' | \
    tr '/' '\n' | \
    grep -E '[0-9a-f]{2}(:[0-9a-f]{2}){5}' | \
    sed -E 's/([^:]+):([0-9a-f:]+)\(([^)]+)\)(-?[0-9]+)/\1,\2,\3,\4/' | \
    awk -F, 'NF==4 {print "SSID=" $1 ",BSSID=" $2 ",Band=" $3 ",RSSI=" $4 "dBm"}'
)

# Process, sort, and display results
echo "$SCAN" | awk -F'[=,]' '
function color_rssi(r) {
    if (r >= -70) return "\033[1;32m" r " dBm\033[0m"   # green
    if (r >= -85) return "\033[1;33m" r " dBm\033[0m"   # yellow
    return "\033[1;31m" r " dBm\033[0m"                 # red
}
{
    for(i=1;i<=NF;i++) gsub(/^ +| +$/, "", $i)
    ssid=$2; bssid=$4; band=$6; rssi=$8
    gsub(" dBm","",rssi)
    if (ssid=="" || bssid=="" || band=="" || rssi=="") next
    if (!(bssid in best) || rssi > best[bssid]) {
        best[bssid]=rssi
        data[bssid]=ssid "|" band "|" rssi "|" bssid
    }
}
END {
    print "\033[1;37m" sprintf("%-32s %-7s %-10s %s", "SSID", "BAND", "RSSI", "BSSID") "\033[0m"
    print "\033[1;37m--------------------------------------------------------------------------------\033[0m"
    for (b in data) print data[b]
}' | sort -t'|' -k3 -n -r | awk -F"|" '
function color_rssi(r){
    if (r ~ /^-?[0-9]+$/) {
        if (r >= -70) return "\033[1;32m" r " dBm\033[0m"
        if (r >= -85) return "\033[1;33m" r " dBm\033[0m"
        return "\033[1;31m" r " dBm\033[0m"
    } else {
        return r
    }
}
function color_bssid(b){ return "\033[1;35m" b "\033[0m" }  # Bright green BSSID
NR==1 {print; next}  # print header as-is
{
    printf "\033[1;37m%-32s %-7s %-10s %s\033[0m\n", $1, $2, color_rssi($3), color_bssid($4)
}'
