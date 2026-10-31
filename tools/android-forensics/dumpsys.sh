#!/bin/bash

# --- COLOR CODES ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- USAGE ---
# ./dump_adb.sh [device_serial]

TARGET_DEVICE="$1"

# --- PRE-CHECKS ---

# Check if adb is installed
if ! command -v adb &> /dev/null; then
    echo -e "${RED}ERROR: adb is not installed. Please install adb and try again.${NC}"
    exit 1
fi

# Start adb server if not running
if ! adb get-state &> /dev/null; then
    echo -e "${BLUE}Starting adb server...${NC}"
    adb start-server
    sleep 1
fi

# Wait for a device to connect
MAX_RETRIES=10
SLEEP_INTERVAL=3
DEVICE=""

for ((i=1; i<=MAX_RETRIES; i++)); do
    if [ -n "$TARGET_DEVICE" ]; then
        DEVICE="$TARGET_DEVICE"
        STATE=$(adb -s "$DEVICE" get-state 2>/dev/null)
        if [ "$STATE" == "device" ]; then
            echo -e "${GREEN}Connected device: $DEVICE${NC}"
            break
        else
            echo -e "${BLUE}Device $DEVICE not available. Waiting... ($i/$MAX_RETRIES)${NC}"
        fi
    else
        DEVICE=$(adb devices | awk 'NR>1 && $2=="device" {print $1}')
        if [ -n "$DEVICE" ]; then
            echo -e "${GREEN}Connected device: $DEVICE${NC}"
            break
        else
            echo -e "${BLUE}No device connected. Waiting for device... ($i/$MAX_RETRIES)${NC}"
        fi
    fi
    sleep $SLEEP_INTERVAL
done

if [ -z "$DEVICE" ]; then
    echo -e "${RED}ERROR: No device connected after $((MAX_RETRIES * SLEEP_INTERVAL)) seconds. Exiting.${NC}"
    exit 1
fi

# --- SETUP OUTPUT DIRECTORY ---
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="DumpSysReport_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

# Arrays to track successes and failures
SUCCESS_CMDS=()
FAILED_CMDS=()

# Function to run a command, print description, and save output
run_adb_command() {
    local index="$1"
    local total="$2"
    local cmd="$3"
    local desc="$4"
    local filename="$5"

    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}[$index/$total] $desc${NC}"
    echo -e "${BLUE}----------------------------------------${NC}"
    
    # Execute command on the selected device, save output
    if adb -s "$DEVICE" shell $cmd | tee "$OUTPUT_DIR/$filename"; then
        echo -e "${GREEN}[✔] $desc - Output saved to $OUTPUT_DIR/$filename${NC}"
        SUCCESS_CMDS+=("$desc")
    else
        echo -e "${RED}[✖] $desc - Command failed${NC}"
        FAILED_CMDS+=("$desc")
    fi
    echo
}

# List of commands and descriptions
declare -a COMMANDS=(
    "dumpsys meminfo|Showing Memory Usage Statistics|meminfo.txt"
    "dumpsys media.audio_flinger|Extracting Audio Playback History|media_audio_flinger.txt"
    "dumpsys sensorservice|Displaying Motion and Environmental Sensor Activity|sensorservice.txt"
    "dumpsys adb|Providing ADB Connection Information|adb.txt"
    "dumpsys account|Listing User Accounts on the Device|account.txt"
    "dumpsys persona|Displaying Multi-User Profile Data|persona.txt"
    "dumpsys fingerprint|Extracting Fingerprint Authentication Data|fingerprint.txt"
    "dumpsys netstats|Showing Network Usage Statistics|netstats.txt"
    "dumpsys mount|Listing Mounted Storage Volumes|mount.txt"
    "dumpsys power|Providing Device Power Management Details|power.txt"
    "dumpsys dropbox|Listing System Crash Reports and Events|dropbox.txt"
    "dumpsys location|Displaying GPS and Location Service Activity|location.txt"
    "dumpsys notification|Showing Active and Dismissed Notifications|notification.txt"
    "dumpsys telecom|Extracting Call Logs and Telephony Data|telecom.txt"
    "dumpsys lock_settings|Providing Lock Screen Settings and Credentials|lock_settings.txt"
    "dumpsys package|Retrieving Installed Package Details|package.txt"
    "dumpsys wifi|Extracting WiFi Connection and History|wifi.txt"
    "dumpsys window|Listing Active Windows and Screen State|window.txt"
    "dumpsys stats|Retrieving System Performance Metrics|stats.txt"
    "dumpsys batterystats|Showing Battery Usage History|batterystats.txt"
    "dumpsys usb|Showing USB Connection History|usb.txt"
    "dumpsys clipboard|Showing Clipboard History|clipboard.txt"
)

# Total number of commands
TOTAL=${#COMMANDS[@]}

# Loop through commands
for i in "${!COMMANDS[@]}"; do
    IFS="|" read -r cmd desc filename <<< "${COMMANDS[$i]}"
    run_adb_command $((i+1)) "$TOTAL" "$cmd" "$desc" "$filename"
done

# Print summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}SUMMARY OF EXECUTED COMMANDS${NC}"
echo -e "${BLUE}========================================${NC}"

echo -e "${GREEN}Succeeded Commands: ${#SUCCESS_CMDS[@]}${NC}"
for cmd in "${SUCCESS_CMDS[@]}"; do
    echo -e "  ${GREEN}✔ $cmd${NC}"
done

echo
echo -e "${RED}Failed Commands: ${#FAILED_CMDS[@]}${NC}"
for cmd in "${FAILED_CMDS[@]}"; do
    echo -e "  ${RED}✖ $cmd${NC}"
done

echo
echo -e "${BLUE}All outputs saved in $OUTPUT_DIR${NC}"
