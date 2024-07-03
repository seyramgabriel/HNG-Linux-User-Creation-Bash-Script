# Author: Ayetor Gabriel Seyram Kofi

# Date: 3rd July, 2024

# Automating Linux user creation with bash script

Using Linux in the Cloud provides a multi-user environment where multiple people can access a server and perform tasks relevant to their jobs. However, this necessitates measures to prevent users or groups from having more access to files than necessary for their respective roles. A SysOps Engineer or Linux Administrator must regulate access according to the least privilege principle.

The least privilege principle is a security concept that states a user should only be given the minimum amount of access they require. Ensuring adherence to this principle can be tedious and error-prone, especially when managing a large number of users and groups. Manually adding users to a server and assigning them to relevant groups on a recurrent basis is not only time-consuming but also prone to mistakes.

This creates the need to automate the task of adding users, creating groups, and assigning users to groups. Automation ensures consistency, efficiency, and reduces the likelihood of errors.

Below is a bash script designed to automate the process of adding users and groups and assigning users to groups. Using this script for user and group management will ensure a consistent and efficient approach to maintaining access control in a Linux environment.

```Script
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
    groupadd "$username"
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

    # Log the plain text password for the CSV
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
```

## Requirements of the Script
- The script must be saved as a bash file (eg. create_users.sh).
- The script takes a text file as input (an argument). 
- The input file should be properly formatted, each line should present usernames and groups, as in "username;   group1,group2,..."
- The script is run as root, you must have the necessary permissions for user and group management.

## Key Features of the Script
- User and Group Creation: Each user is created with a home directory and a primary group with the same name as the user. The primary group need not be stated in the input file since it will be created using the username.
- Group Assignment: Users are assigned to additional groups as specified in the input file.
- Password Generation and Security: A random password is generated for each user, stored securely in /var/secure/- user_passwords.csv.
- Logging: All actions are logged to /var/log/user_management.log for auditing and troubleshooting.

## Summary of Script Logic
- Input Validation: The script ensures it’s run as root and the input file is provided and exists.
- Processing Input: Each line is processed to extract the username and groups. Whitespace is trimmed to avoid errors.
- User Creation: The script will check if the user already exists. If not, it creates the user and their primary group (which is same name as username), and their home directory to which the user is the owner and the only one with rwx rights to it.
- Group Management: The script ensures additional groups exist (if not, it creates them) and assigns the user to these groups.
- Password Management: The script generates a secure password, assigns it to the user, and logs it securely in /var/secure/user_passwords.csv. Only the root user would have access(read and write) to this file.
- Logging: Each step executed by the script is logged for monitoring and auditing in /var/log/user_management.log along with the timestamp. Only the root user would have access(read and write) to this file.

## Error Handling
The script includes checks to handle existing users, missing groups, and file permissions, ensuring robust operation in various scenarios.

## Script Execution:
The script is executed as follows
./create_users.sh <path-to-username-file>    # Of course, you would not need sudo since you would be running the script as a root user.
or 
bash create_users.sh <path-to-username-file>

Example of input file content:
```
light;sudo,dev,www-data
idimma;sudo
mayowa;dev,www-data
```

light, idimma, and mayowa are the usernames. 
sudo, dev, and www-data are the group names. 
Note that sudo and www-data are system wide groups and already exist, by default.

## Testing the Efficacy of the Script After Running it

### Run this command to output all current human users. 
```<awk -F: '$3 >= 1000 {print $1}' /etc/passwd>```
Do well to look out for the groups in your input text file
Note: You could also output all existing users with ```<cat /etc/passwd>```, but it will output all users, not just human users.

### Run the id command for a specific user
```id <username>```    eg. ```id idimma```
If the user exists, this will display information about the user. If not, it will show an error message.

### Run the following command to view all the home directories of the created users
```cd /home && ls```

### Run this to output all groups
```cat /etc/group```

### Run this to check the existence of specific groups 
```getent group <groupname>```  eg. ```getent group dev``` or ```getent group sudo```
Once you run it with the specific group name, it will show you the group (if it exists)
and the users assigned to it. If not, it will show no output.

### Run this to output content of log file
```cat /var/log/user_management.log```

### Run this command to verify the access permissions on /var/log/user_management.log
```ls -al /var/log/user_management.log```

### Run this command to view passwords, verify if user and password are delimited by "," and passwords are hashed
```cat /var/secure/user_passwords.csv```

### Run to output the content and verify the access permissions on /var/secure/user_passwords.csv
```ls /var/secure/user_passwords.csv```


# Deeper Dive
I believe thus far, this write up has provided enough information for a high level documentation. But I would like to dive a little deeper into the work of each block of code in the script, in case one wants to use it and must satisfy the demands of low level documentation. 

## Block 1
```#!/bin/bash```
This line specifies that the script should be run using the Bash shell.

## Block 2
```
# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi
```
EUID-Effective User ID-is the ID of the current user. The ID of the root user is 0. Hence, this line ensures that the user running the script is a root user. 
exit 1-This line exits the script with an error code of 1 if the user is
not a root user.

## Block 3
```
 # Log file
LOG_FILE="/var/log/user_management.log"
PASSWORD_FILE="/var/secure/user_passwords.csv"
```

These lines define variables for the paths of the log file and the password file. So, subsequent to this block of code, LOG_FILE is same as "/var/log/user_management.log" and PASSWORD_FILE refers to "/var/secure/user_passwords.csv

## Block 4
```
# Create secure directory for password storage if it doesn't exist
mkdir -p /var/secure
chmod 700 /var/secure
```
This creates the /var/secure directory and sets its permissions to 700 so that only the owner can read, write, and execute.
Note that /var/log directory already exists by default, so it doesn't need to be created like the /var/secure directory.

## Block 5
```
#Function to log messages
log_message() {
    echo "$(date +"%Y-%m-%d %T") : $1" >> $LOG_FILE
}
```
This defines a function called log_message that appends a timestamped message "$(date +"%Y-%m-%d %T")" to the log file along with texts that will serve as arguments ("$1") anytime the function is called. Effectively, this block of code is behind the logging to /var/log/user_management.log file.

## Block 6
```
# Check if the file exists
if [[ -z "$1" || ! -f "$1" ]]; then
    echo "Usage: $0 <path-to-username-file>"
    exit 1
fi
```
This checks if an argument (the path to the username file) was provided, if it exists, and if it is a regular file. If not, it prints usage instructions and exits.

## Block 7
```
# Process each line of the input file
while IFS=';' read -r username groups; do
    # Remove any leading or trailing whitespace
    username=$(echo "$username" | xargs)
    groups=$(echo "$groups" | xargs)
```
This ensures the script reads each line of the input file, splitting it into username and groups using ";" as the delimiter. "xargs" is used to remove leading and trailing whitespace in the input file, this helps to avoid errors in processing the file.

## Block 8
```
    # Check if the user already exists
    if id "$username" &>/dev/null; then
        log_message "User $username already exists. Skipping."
        continue
    fi
```
This checks if the user already exists and if so, logs a message and skips to the next iteration. "log_message" is used to call the log_message function, "User $username already exists. Skipping." becomes $1 as indicated in the log_message function.

## Block 9
```
    # Create user with a home directory
    useradd -m -s /bin/bash "$username"
    if [[ $? -eq 0 ]]; then
        log_message "User $username created."
    else
        log_message "Failed to create user $username."
        continue
    fi
```
This creates the user with a home directory and sets the default shell to /bin/bash. If successful, logs a message; otherwise, logs an error and skips to the next iteration. "$?" is equivalent to the exit status of the just ended action. An exit 0 means success. 

## Block 10
```
    # Create a group with the same name as the username
    groupadd "$username"
    usermod -a -G "$username" "$username"
```
This creates a group with the same name as the username and adds the user to this group. Remember, each username is used to create a primary group.

## Block 11
```
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
```
This splits the groups string by commas and processes each group. It trims whitespace, checks if the group exists, creates it if it does not exist, logs a message about the group created and adds the user to the group.

### Block 12
```
    # Set permissions for the home directory
    chmod 700 "/home/$username"
    chown "$username:$username" "/home/$username"
```
This sets the permissions of the user's home directory to 700 and changes the ownership to the user and their group. This means that only the  users can read, write, and executive within their respective home directories.

### Block 13
```
    # Generate a random password
    password=$(openssl rand -base64 12)
```
This generates a random password for the user using openssl, but the password will be in plain text.

### Block 14
```
    # Hash the password
    hashed_password=$(openssl passwd -6 "$password")
```
This hashes or encodes the plain text password

### Block 15
```
    # Set the hashed password for the user
    echo "$username:$hashed_password" | chpasswd -e
```
This sets the hashed password for the user using chpasswd. The -e flag is used to indicate.

### Block 16
```
    # Log the hashed password for the CSV
    echo "$username,$password" >> $PASSWORD_FILE
```
This logs the hashed password of the user in the format "user,password" into the /var/secure/user_passwords.csv file

### Block 17
```
    log_message "Password for $username set."
done < "$1"
```
This logs the action of password being set into /var/log/user_manangement.log file

### Block 18
```
# Set permissions for the password file
chmod 600 $PASSWORD_FILE
chown root:root $PASSWORD_FILE
```
This sets the permissions of the password file to 600 (read and write for the owner only) and changes the ownership to root. This block of code ensures that only the root user has access to /var/secure/user_passwords.csv file

### Block 19
```
# Set permissions for the log file
chmod 600 $LOG_FILE
chown root:root $LOG_FILE
```
This sets the permissions of the log file to 600 (read and write for the owner only) and changes the ownership to root. This block of code ensures that only the root user has access to /var/slog/user_management.log file

### Block 20
```
log_message "User creation process completed."

exit 0
```
This logs that the user creation process is complete and exits the script.

### Conclusion
The script simplifies user management in a Linux environment, ensuring consistency, security, and efficiency. 
By automating these tasks, SysOps engineers or Linux Administrators can focus on more critical aspects of system management.

### Disclaimer:
The script and article provide a foundation for automating user management in Linux, but remember to tailor it to your specific organizational needs.

# Acknowledgment:
This write up was inspired by a task assigned to DevOps interns in the HNG Internship Programme. Find out more on 
https://hng.tech/internship, https://hng.tech/hire, or https://hng.tech/premium.

