# nas-cmd
A python script to interact with the Asustor ADM Portal interface

# Introduction

ASUSTOR Portal is the web interface found on ASUSTOR systems. This script is the result of a small experiment to access that interface from the command line. 

The script is probably not that useful since ASUSTOR systems can be controlled in multiple ways (AiData on mobile phones, SSH, ...).

Also, the CGI api is not documented by ASUSTOR and it is likely to be modified in future releases of their ADM OS. Simply speaking do not complain if the script breaks after updating ADM.

The script was initially developped for ADM 4.2.3.RK91.

# Installation

The script is composed a single python file.

It is known to work with Python 3.11.4 on Linux.

The python package `requests` (https://pypi.org/project/requests/) is required.

A tool to process JSON on the command line is also recommended since raw responses from ADM CGI requests are usually displayed in JSON.

# Quickstart

After installation, the first step is to insure that the script can be executed:

    # python3 nas-cmd.py
    nas-cmd.py usage: nas-cmd.py [OPTION...] ACTION ...
	  nas-cmd.py: error: the following arguments are required: ACTION

On Linux, you can probably drop the python3 command assuming that the script is make executable and is in your search $PATH.

Now, let's executed the `nop` action using the account `foobar` and password `xxxxxxxx` on the machine  `nas` at port `12345`. That action does nothing except login & logout

    # nas-cmd.py -A foobar -P xxxxxxxx -U https://nas:12345/ nop
    ok

It is also possible to store the  account, password and url in a text file (one per line) 

	  foobar
    xxxxxxxx
    https://nas:12345/
		 
and then use the `-C, --credentials` option.

	# nas-cmd.py -C credentials.txt nop
	ok
		
Last but not least, you can also edit the script and change the default values for the variables ACCOUNT, PASSWORD, and URL.  In the following, I will assume that the default credentials are used

	# nas-cmd.py nop
	ok

We can add the option `-l, --logging-debug`  before the action `nop` to make the script display the actual https requests. Similarly, the option `-d` would enable debug in the HTTPConnection module.

	# nas-cmd.py -l nop 
	[DEBUG:urllib3.connectionpool]  Starting new HTTPS connection (1): nas:12345
	[DEBUG:urllib3.connectionpool]  https://nas:12345 "POST //portal/apis/login.cgi?act=login&account=foobar HTTP/1.1" 200 None
	ok
	[DEBUG:urllib3.connectionpool]  https://nas:12345 "POST //portal/apis/login.cgi?sid=wAf-ZMLDM1RvtNwD&act=logout HTTP/1.1" 200 None
 
The first CGI request `https://nas:12345portal/apis/login.cgi` with `act=login` and `account=foobar` takes care of the connection. The password argument is passed as POST and so is not displayed here. The final CGI request   `https://nas:12345portal/apis/login.cgi`with `act=logout` takes care of closing the connection. The argument `sid` is a connection identifier provided in the login response. 

The action `login_info` can be used to display all information provided in the login response: 

	# nas-cmd.py login_info
	 { "success": true, "account": "foobar", "sid": "2Qn-ZHr0O1SQGMQ1", 
	   "isadministrators": false, "isAdminGroup": 0, "auth_type": 0, 
	   "vendor": "ASUSTOR", ... }

Be aware that this is a pretty-print representation of a python dictionary.

The actual JSON response can be obtained with the `-r, --raw` option and pretty-printed with `jq`
	   
	# nas-cmd.py login_info --raw | jq 
	{
	  "success": true,
	  "account": "foobar",
	  "sid": "Igv-ZH37QFRnTlsJ",
	  "isadministrators": false,
	  "isAdminGroup": 0,
	  ...
	}

# Simple actions

Here are a few examples of common actions implemented by the script.

## List the content of a directory 

Use action `ls` to obtain a list of files and directory

	# nas-cmd.py ls /Public/Images/
        Spring2022
        hello.jpg
        world.png

Use action `ll` or `ls -l` to get some details

        # nas-cmd.py ll /Public/Images
        total 4
        drwx------ john       users              4096 2023-07-03 10:12 Spring2022/
	-r--r--r-- root       root             276900 2023-08-22 11:36 hello.jpg
	-rwxr--r-- foobar     users             13252 2023-07-12 12:21 world.png
	-rwxr--r-- foobar     users             34455 2023-07-12 12:21 hello_world.png 

Use option `-f, --filter` to filter the output according to a string.
Remark: The filter is not a pattern or a regex but a plain string!

        # nas-cmd.py ll /Public/Images -f world
        total 2
	-rwxr--r-- foobar     users             13252 2023-07-12 12:21 world.png
	-rwxr--r-- foobar     users             34455 2023-07-12 12:21 hello_world.png

## Upload a file

Use action `upload`. The second argument must be directory in ADM format.

	# nas-cmd.py upload my_image.png /home/foobar

Add a third argument to change the name of the uploaded file.

	# nas-cmd.py upload my_image.png /home/foobar new_name.png

## Download a file

Use action `download src dest` or `download src`.
   - `src` must be the remote path to a file in ADM format.
   - `dest` is a local directory or file destination. 

	# nas-cmd.py download /Public/Images/hello_world.png
        download 34455 bytes in hello_world.png
       
	# nas-cmd.py download /Public/Images/hello_world.png  ../
        download 34455 bytes in ../hello_world.png

        # nas-cmd.py download /Public/Images/hello_world.png  MyImages/a.png
        download 34455 bytes in MyImages/a.png

# Custom queries

The `query` action can be used to perform simple queries.





