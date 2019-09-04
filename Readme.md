# AutoSSH
#### Simple SSH automation and backup with dotnet core.

AutoSSH is a simple dotnet core application to run automated commands and/or backup Windows and Linux over SSH. This is useful for a central control application where all the logic for automated scripts and backup can be controlled from one place.

Imagine having 100 VPS servers and being able to run a daily task to backup everything on every server to a central server, which then uses backblaze or another service to backup.

Parameters to the application are a command file and a root path to backup to.

When running for the first time, a user and password is requested and stored in a protected data file for the current user. Subsequent runs will detect the file and use the user name and password automatically. Plain text passwords are avoided. This file is saved in the root backup folder.

It is assumed that the user and password exists on all the hosts specified, this requires you to use the same user name and password on all machines, so make sure the user name is not root and the password is complex.

Example usage: `dotnet AutoSSH /backup/commands.txt /backup`

The hosts/servers to connect to can be Linux or Windows. All commands assume sudo/administrator for the given login and password.

Command file format is as follows:

```
# lines can start with a comment
# you can add a global host, all other hosts will inherit commands for this host
# adding a global host is optional
$host * *
# update packages
apt-get -q -y update

# ignore files by case insensitive regex, in this case any file called big_file[0-9]+\.bin
$ignore big_file[0-9]+\.bin

# backup files and folders, always recursive, separate multiple with |
$backup /var/www|/etc/apache2/apache2.conf|/etc/apache2/sites-enabled

# hosts have a name and an address/dns name
# when backing up, the hostname will be used for the folder name inside the root backup folder.
$host hostname hostaddress
# run custom command just on this machine
/usr/bin/customapp customparam

# multiple hosts are allowed
$host hostname2 hostaddress2

# clear global host
$host * *

# add Windows for Windows hosts to ensure correct behavior
$host hostname3 hostaddress3 Windows
$backup /C:/Backup/File.txt|/C:/Backup2/File2.txt

```

For $backup commands, the first run will be slow and backup everything. Subsequent runs will check the last write time UTC timestamp of files and compare to the local files before downloading.

Each backed up file writes to a temp file, and only upon successful completion of the download, renames to the final file name.
