

LOG_FILE="logs/alerts.log"
BASELINE_FILE="baseline/file_hashes.txt"

echo  >> $LOG_FILE
echo "IDS Scan Started on: $(date)" >> $LOG_FILE
echo  >> $LOG_FILE

FAILED_COUNT=$(grep "Failed password" /var/log/auth.log | wc -l)

if [ $FAILED_COUNT -gt 5 ]; then
    echo "ALERT: Too many failed SSH login attempts detected" >> $LOG_FILE
fi

USER_CREATED=$(grep "useradd" /var/log/auth.log)

if [ -n "$USER_CREATED" ]; then
    echo "ALERT: New user account creation detected" >> $LOG_FILE
    echo "$USER_CREATED" >> $LOG_FILE
fi

TEMP_HASH_FILE="baseline/temp_hashes.txt"
sudo find /etc -type f -exec sha256sum {} \; > $TEMP_HASH_FILE

DIFFERENCE=$(diff $BASELINE_FILE $TEMP_HASH_FILE)

if [ -n "$DIFFERENCE" ]; then
    echo "ALERT: Changes detected in system configuration files" >> $LOG_FILE
    echo "$DIFFERENCE" >> $LOG_FILE
fi

rm $TEMP_HASH_FILE

OPEN_PORTS=$(netstat -tulnp | grep LISTEN)

if echo "$OPEN_PORTS" | grep -q ":4444"; then
    echo "ALERT: Suspicious port 4444 is open" >> $LOG_FILE
fi

ROOT_LOGIN=$(grep "session opened for user root" /var/log/auth.log)

if [ -n "$ROOT_LOGIN" ]; then
    echo "ALERT: Root user login detected" >> $LOG_FILE
    echo "$ROOT_LOGIN" >> $LOG_FILE
fi

echo "IDS Scan Completed on: $(date)" >> $LOG_FILE
echo "" >> $LOG_FILE
