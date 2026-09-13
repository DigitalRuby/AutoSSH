# AutoSSH
#### Simple SSH automation and backup with dotnet.

AutoSSH is a simple dotnet application to run automated commands and/or backup Windows and Linux over SSH. This is useful for a central control application where all the logic for automated scripts and backup can be controlled from one place.

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

# define replacement
$NEWFILES$ = newfiles

# ignore files by case insensitive regex, in this case any file called big_file[0-9]+\.bin
$ignore big_file[0-9]+\.bin

# backup files and folders, always recursive, separate multiple with |
$backup /var/www|/etc/apache2/apache2.conf|/etc/apache2/sites-enabled

# upload files and folders, always recursive, separate local and remote path with a ;
$upload c:/files/newfiles;/home/user/$NEWFILES$ # use the macro from above

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


Backups use bounded asynchronous tasks to download up to eight files concurrently per host, each task using its own SFTP connection plus a separate connection for directory scanning. Up to eight hosts are processed concurrently with asynchronous task coordination. Directory scanning overlaps downloads: the scanner connection only lists files, and transfer workers start as soon as changed files are found. Sync reuses directory-listing metadata to skip unchanged files without extra per-file metadata requests, and opens download connections only when files need downloading. Uploads remain sequential and asynchronous within each host's SFTP connection, caching remote directories already created. SSH connections send keepalives every 15 seconds. Connection and login/sudo prompt waits time out after 30 seconds; SFTP operations time out after 60 seconds, and shell commands after 30 minutes. A connection or operation timeout stops further work on that host and reports an error while other hosts continue. Run the command file again to retry; completed backups are skipped using their timestamps.

Set `AUTOSSH_DOWNLOAD_WORKERS` to a whole number from 1 to 16 to change download concurrency per host (default 8). Set it to 1 to use only the original SFTP connection for sequential transfers.

Set `AUTOSSH_HOST_WORKERS` to a whole number from 1 to 64 to change how many hosts run at once (default 8).

Set `AUTOSSH_SFTP_TIMEOUT_SECONDS` or `AUTOSSH_COMMAND_TIMEOUT_SECONDS` before starting AutoSSH to override the transfer-operation or command timeout. Values must be positive whole seconds (at most 2147483). The SFTP timeout applies to individual protocol waits, so a large file can take longer as long as the server keeps responding. The command timeout limits the entire wait for the shell prompt; increase it for long-running commands.

Failed or incomplete downloads remove their temporary file and preserve any previous backup. Uploads overwrite and truncate existing remote files and create missing parent directories.

To run regression checks without a remote server:

```text
dotnet run --project tests/AutoSSH.RegressionTests -c Release
```

To additionally test real SSH/SFTP transfers and deliberately stalled downloads, uploads, directory listings, and shell prompts on a disposable localhost server (requires Python):

```text
python -m pip install --target obj/sftp-test-python paramiko==5.0.0
python tests/run-sftp-integration.py
```

The integration server binds only to loopback on an automatically assigned port, uses temporary files and test credentials, and shuts down when the tests finish.
