#!/bin/bash

# -----------------------------------------------------------
# Simple bash script that uses ADB to scan installed Android
# packages and extract any secret dialer codes, logging them
# with device info to a timestamped file.
# -----------------------------------------------------------

# -----------------------------------------------------------
# Colors
# -----------------------------------------------------------
RED='\033[1;31m'      # Red
GREEN='\033[0;32m'    # Green
YELLOW='\033[1;33m'   # Yellow
BLUE='\033[1;34m'     # Blue
CYAN='\033[1;36m'     # Cyan
PURPLE='\033[1;35m'   # Purple
WHITE='\033[1;37m'    # White
RESET='\033[0m'        # Reset

# -----------------------------------------------------------
# Trap Ctrl-C
# -----------------------------------------------------------
trap ctrl_c INT
ctrl_c() {
    echo
    echo -e "${WHITE}Ctrl-C by user${RESET}"
    exit
}

# -----------------------------------------------------------
# Timestamp & Output file
# -----------------------------------------------------------
timestamp=$(date +'%Y-%m-%d_%H:%M:%S')
output_file="Secret_Codes_${timestamp}.txt"

# -----------------------------------------------------------
# Blank line helpers
# -----------------------------------------------------------
space() { echo ""; }
double_space() { echo -e "\n"; }

# -----------------------------------------------------------
# Device Info
# -----------------------------------------------------------
man=$(adb shell getprop | grep ro.product.manufacturer | tr -d '[]' | awk '{print $NF}')
model=$(adb shell getprop ro.product.model)
os_ver=$(adb shell getprop ro.build.version.release)

# -----------------------------------------------------------
# Colored Banner
# -----------------------------------------------------------
show_banner() {
    echo -e "${WHITE}============================================================${RESET}"
    echo -e "${CYAN}          ANDROID SECRET CODE EXTRACTION TOOL${RESET}"
    echo -e "${WHITE}============================================================${RESET}"
    echo -e "${WHITE} Manufacturer: ${CYAN}${man}${RESET}"
    echo -e "${WHITE} Model:        ${CYAN}${model}${RESET}"
    echo -e "${WHITE} OS Version:   ${CYAN}${os_ver}${RESET}"
    echo -e "${WHITE} Log File:     ${CYAN}${output_file}${RESET}"
    echo -e "${WHITE}============================================================${RESET}"
    echo
}

# -----------------------------------------------------------
# FUNCTION:
# Dump all android secret codes (GREEN on screen)
# Rest of output is WHITE
# -----------------------------------------------------------
android_secret_code_dump() {

    package_name_trim=$(adb shell 'pm list packages -s -f' \
        | awk -F 'package:' '{print $2}' \
        | awk -F '=' '{print $2}')

    for pkg in ${package_name_trim}; do
        
        # package name shown in white
        echo -e "${WHITE}${pkg}${RESET}" | tee -a "${output_file}"

        adb shell pm dump "${pkg}" \
            | grep -E 'Scheme: "android_secret_code"|Authority: "[0-9].*"|Authority: "[A-Z].*"' \
            | while IFS= read -r line; do
                
                # print secret code lines in CYAN
                echo -e "${GREEN}${line}${RESET}"

                # write uncolored version to log file
                echo "${line}" >> "${output_file}"
            done
    done
}

# -----------------------------------------------------------
# Start Script
# -----------------------------------------------------------
show_banner

echo -e "${WHITE}Dumping Android secret codes...${RESET}"
android_secret_code_dump

echo
echo -e "${GREEN}✔ ${PURPLE}Output written to: ${CYAN}${output_file}${RESET}"
echo
