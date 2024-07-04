#!/bin/bash

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Log file
LOG_FILE="/var/log/user_management.log"
PASSWORD_FILE="/var/secure/user_passwords.csv"

# Create secure directory for password storage if it doesn't exist
mkdir -p /var/secure
chmod 700 /var/secure

# Function to log messages
log_message() {
    echo "$(date +"%Y-%m-%d %T") : $1" >> $LOG_FILE
}

# Check if the file exists
if [[ -z "$1" || ! -f "$1" ]]; then
    echo "Usage: $0 <path-to-username-file>"
    exit 1
fi

# Process each line of the input file
while IFS=';' read -r username groups; do
    # Remove any leading or trailing whitespace
    username=$(echo "$username" | xargs)
    groups=$(echo "$groups" | xargs)

    # Check if the user already exists
    if id "$username" &>/dev/null; then
        log_message "User $username already exists. Skipping."
        continue
    fi

    # Create user with a home directory
    useradd -m -s /bin/bash "$username"
    if [[ $? -eq 0 ]]; then
        log_message "User $username created."
    else
        log_message "Failed to create user $username."
        continue
    fi

    # Create a group with the same name as the username
    groupadd "$username" &>/dev/null
    usermod -a -G "$username" "$username"

    # Add user to additional groups
    IFS=',' read -ra ADDR <<< "$groups"
    for group in "${ADDR[@]}"; do
        group=$(echo "$group" | xargs) # Trim whitespace
        if ! getent group "$group" >/dev/null; then
            groupadd "$group"
            log_message "Group $group created."
        fi
        usermod -a -G "$group" "$username"
    done

    # Set permissions for the home directory
    chmod 700 "/home/$username"
    chown "$username:$username" "/home/$username"

    # Generate a random password
    password=$(openssl rand -base64 12)
    # Hash the password
    hashed_password=$(openssl passwd -6 "$password")

    # Set the hashed password for the user
    echo "$username:$hashed_password" | chpasswd -e

    # Log the hashed password for the CSV
    echo "$username,$password" >> $PASSWORD_FILE

    log_message "Password for $username set."
done < "$1"

# Set permissions for the password file
chmod 600 $PASSWORD_FILE
chown root:root $PASSWORD_FILE

# Set permissions for the log file
chmod 600 $LOG_FILE
chown root:root $LOG_FILE

log_message "User creation process completed."

exit 0