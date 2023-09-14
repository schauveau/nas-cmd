# Quick list of known queries

# File and directory operations

## Create directory DIR in PATH 

```
nas-cmd.py query /portal/apis/fileExplorer/fileExplorer.cgi act='createdir' dest_path='PATH' dest_folder='DIR'
```

## Delete a file or folder

Be aware that the same query can remove a single file or a directory with all its content. 

Also there is no way to control if OBJ will be physically deleted or moved to the `RecycleBin`. The behavior depends of the share.  

This is a two step process. The first query starts a delete task.

```
nas-cmd.py query /portal/apis/fileExplorer/fileExplorer.cgi act='delete' total='1' file:='/Public/hello'
===> {'delway': 2, 'pid': 8478, 'success': True}
```

In case of success, A second query must be performed repeateadly to track the progress of the given 'pid' until the `progress` field in teh response reaches `1.0`

```
nas-cmd.py query /portal/apis/fileExplorer/fileExplorer.cgi act='delete_progress' pid='8478'
===> {'file': '', 'pid': 8478, 'progress': 0.342421343, 'success': True }
nas-cmd.py query /portal/apis/fileExplorer/fileExplorer.cgi act='delete_progress' pid='8478'
===> {'file': '', 'pid': 8478, 'progress': 1.0, 'success': True }
```




## Rename OLDNAME to NEWNAME in directory /DIR

```
nas-cmd.py query /portal/apis/fileExplorer/fileExplorer.cgi act='rename' path='/DIR' current_filename='OLDNAME' target_filename='NEWNAME'
```

Remark: The ADM file manager is passing an additional argument `current_filename_hex` that contains an hexadecimal representation of the bytes in `current_filename`. For `OLDNAME` that would be '4F4C444E414D45'. That could be convenient for filenames with an encoding other than UTF-8.  

```
nas-cmd.py query /portal/apis/fileExplorer/fileExplorer.cgi act='rename' path='/DIR' current_filename='OLDNAME' current_filename_hex='4F4C444E414D45' target_filename='NEWNAME'
```

# Share operations

## Mount the encrypted share SHARE using the password PASSWORD

```
nas-cmd.py query /portal/apis/accessControl/share.cgi act=mount name=SHARE encrypt_key=PASSWORD
```

## Mount the encrypted share SHARE using the key file at DIR/FILE

```
nas-cmd.py query /portal/apis/accessControl/importkey.cgi  act='import_key' files@=`DIR/FILE` 
nas-cmd.py query /portal/apis/accessControl/share.cgi act='mount' import_key_file:='FILE'
```

##Unmount the encrypted share SHARE

```
nas-cmd.py query /portal/apis/accessControl/share.cgi act=unmount name_list=SHARE
```

