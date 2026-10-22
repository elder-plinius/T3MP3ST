#!/bin/bash
# ===============================================
#   ADB Data Extraction & System Snapshot Script
# ===============================================
# Author: Douglas Habian 
# Description:
#   Executes multiple adb commands to extract
#   diagnostic and user data from a connected
#   Android device, saving all outputs neatly.
# ===============================================

# ---------- COLORS ----------
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m" # No Color

SCRIPT_START=$(date +%s)

# ---------- CHECK ADB ----------
if ! command -v adb &> /dev/null; then
    echo -e "${RED}[ERROR] ADB is not installed. Please install Android Platform Tools.${NC}"
    exit 1
fi

# ---------- START ADB SERVER ----------
adb start-server &> /dev/null

# ---------- CHECK DEVICE CONNECTION ----------
DEVICE=$(adb devices | awk 'NR==2 {print $1}')
if [ -z "$DEVICE" ]; then
    echo -e "${RED}[ERROR] No device connected. Connect a device via USB and enable USB Debugging.${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Connected device: $DEVICE${NC}\n"

# ---------- CREATE OUTPUT DIRECTORY ----------
OUTPUT_DIR="ADB_Report_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# ---------- FUNCTION TO RUN COMMAND ----------
# Usage:
#   run_adb_command "Description" "command" "filename" ["silent"]
# If "silent" is passed as the 4th argument, output won't be printed to screen.
run_adb_command() {
    DESCRIPTION=$1
    COMMAND=$2
    FILENAME=$3
    SILENT=$4

    echo -e "${BLUE}[*] ${DESCRIPTION}${NC}"

    if [ "$SILENT" = "silent" ]; then
        adb shell $COMMAND > "$OUTPUT_DIR/$FILENAME" 2>&1
    else
        adb shell $COMMAND | tee "$OUTPUT_DIR/$FILENAME"
    fi

    echo -e "${YELLOW}[+] Output saved to ${OUTPUT_DIR}/${FILENAME}${NC}\n"
}

# ---------- DEVICE INFO ----------
run_adb_command "Gathering basic device information..." \
"getprop | grep -E 'ro.product.model|ro.product.manufacturer|ro.build.version.release|ro.serialno'" \
"device_info.txt"

# ---------- DEVICE STATE SNAPSHOT (SILENT) ----------
run_adb_command "Capturing device state (uptime, battery, connectivity)..." \
"echo -e '\nUptime:' && uptime && echo -e '\nBattery:' && dumpsys battery && echo -e '\nNetwork:' && dumpsys connectivity" \
"device_state.txt" \
"silent"

# ---------- NETWORK INFO (SILENT) ----------
run_adb_command "Collecting network interface configuration (ifconfig / ip addr)..." \
"ifconfig 2>/dev/null || ip addr show" \
"network_info.txt" \
"silent"

# ---------- MAIN EXTRACTION COMMANDS ----------
run_adb_command "Listing all apps you have accounts on..." \
"dumpsys account | grep -i com.*$ -o | cut -d' ' -f1 | cut -d} -f1 | grep -v com$" \
"registered.txt"

run_adb_command "Listing all email addresses registered on the device..." \
"dumpsys account | grep -E -o '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}' | sort -u" \
"emails.txt"

run_adb_command "Listing number of reboots..." \
"settings list global | grep 'boot_count=' | cut -d= -f2 | head -n 1 | xargs echo 'Booted:' | sed 's/$/ times/g'" \
"reboots.txt"

run_adb_command "Listing every contact and phone number..." \
"content query --uri content://contacts/phones/ --projection display_name:number | cut -f 3- -d ' '" \
"numbers.txt"

run_adb_command "Listing contact phone numbers..." \
"content query --uri content://contacts/phones/" \
"contacts.txt"

run_adb_command "Dumping Call Log..." \
"content query --uri content://call_log/calls" \
"call_logs.txt"

run_adb_command "Dumping SMS messages..." \
"content query --uri content://sms/" \
"sms.txt"

run_adb_command "Listing all installed packages..." \
"pm list packages" \
"packages_all.txt"

run_adb_command "Listing third-party installed packages..." \
"pm list packages -3" \
"packages_thirdparty.txt"

run_adb_command "Listing all active services..." \
"dumpsys -l" \
"services.txt"

# ---------- LOGCAT SNAPSHOT (SILENT) ----------
run_adb_command "Capturing brief system log snapshot..." \
"logcat -d -v time | head -n 1000" \
"logcat_snapshot.txt" \
"silent"

# ---------- FULL BUGREPORT (BACKGROUND) ----------
BUGREPORT_FILE="${OUTPUT_DIR}/bugreport_$(date +%Y%m%d_%H%M%S).zip"
echo -e "${BLUE}[*] Generating full bugreport in the background...${NC}"
echo -e "${YELLOW}[i] Bugreport may take several minutes. You can continue using the script.${NC}"

(
    if adb shell 'command -v bugreportz' &> /dev/null; then
        adb bugreport "$BUGREPORT_FILE"
    else
        adb bugreport > "${BUGREPORT_FILE%.zip}.txt"
        BUGREPORT_FILE="${BUGREPORT_FILE%.zip}.txt"
    fi
    echo -e "${GREEN}[✓] Bugreport completed and saved to ${BUGREPORT_FILE}${NC}"
) &

# ---------- SUMMARY REPORT ----------
SCRIPT_END=$(date +%s)
TOTAL_TIME=$((SCRIPT_END - SCRIPT_START))

echo -e "\n${GREEN}[✓] All ADB data extraction commands executed successfully!${NC}"
echo -e "${BLUE}Summary of extracted files:${NC}"
echo -e "-------------------------------------------"
ls -lh "$OUTPUT_DIR" | awk 'NR>1 {print $9, "\t", $5}'
echo -e "-------------------------------------------"
echo -e "${GREEN}Results saved in: ${OUTPUT_DIR}${NC}"
echo -e "${GREEN}Total runtime (without waiting for bugreport): ${TOTAL_TIME}s${NC}\n"
echo -e "${YELLOW}[i] Bugreport is running in the background and will save to the output directory once completed.${NC}\n"
