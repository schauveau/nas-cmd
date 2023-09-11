# Custom Queries

The python script only implements the most basic actions (list directory, download, upload) but the `query` action can be used to implement more functionalities assuming that you can figure out the arguments for the proper CGI script.

This is not that hard to do assuming that you are using a web browser with decent developers tools.

# How to proceed?


Let's do it with an example ; for instance how to mount/unmount an encrypted share.

We need a Web browser with builtin developper tools to inspect the HTTP exchanges. I am using Firefox but the procedure should basically be the same with Chrome.  

First, connect to the ADM portal in Firefox with an administrator account and open the `Shared Folders` tab in the `Access Control` window. Create a new encrypted if you do not have one.

Now use `SHIFT+CONTROL+i` to open the Web Developper Tool and select the Network tab. You can type `.cgi` in the `Filter URLS` area to only show the cgi requests (and not the other downloads). 

In the `Access Control` window, mount an encrypted folder. A few cgi requested should appear. The interesting one should look like

	https://nas.schauveau.local:49124/portal/apis/accessControl/share.cgi?sid=l8v-ZHTEMFfxGn5t&act=mount&_dc=1694421221520

Select that line to show more details about that request.

The arguments after `/portal/apis/accessControl/share.cgi` are:
  - `sid` is the connection identifier. It can be ignored since the script will take care of that.
  - `act` of value `mount` is the action identifier. Most cgi scripts require an `act` parameter.
  - `_dc` is a timestamp. It can probably be ignored.

A quick look in the `Request` tab tells us that 2 more arguments are passed as form-data (i.e. POST):
  - `name=MyEncryptedShare`
  - `encrypt_key=my_secret_password`

This is enough to reproduce that 'mount' action. Make sure that the share is not mounted and try

```
# nas-cmp.py query /portal/apis/accessControl/share.cgi act=mount name:=MyEncryptedShare encrypt_key:=my_secret_password
Response contains 20 bytes
Interpreting response as JSON
{'success': True}
```

*Remark:* If the query is not successful then the JSON answer will contain an `error_code` and an `error_msg` that may or may not help you figure out what when wrong. Remember that this API was not intended for humans and is undocumented.

In practice, most CGI scripts do not care if their arguments are passed in the URL (as `name=value`) or in form-data (as `name:=value`) but it is probably wiser to pass sensitive information in form-data where they are less visible. A notable exception is `act` that has to be passed in the URL.

The query to unmount the encrypted share is similar but with `act=unmount` and argument `name_list` instead of `name` 

```
# nas-cmd.py query /portal/apis/accessControl/share.cgi act=unmount name_list:=MyEncryptedShare 
```

Now, let's try to mount that same encrypted share using the file `MyEncryptedShare.key` produced when it was created.

The Web Developper Tool tells us that this operation involves two CGI requests:

  1. upload the key with `/portal/apis/accessControl/importkey.cgi`  
    - 'act=import_key'
    - The key file is attached in the request body 
```
-----------------------------122634777528959909511907845980
Content-Disposition: form-data; name="files"; filename="MyEncryptedShare.key"
Content-Type: application/vnd.apple.keynote

...SOME RANDOM DATA HERE... 
-----------------------------122634777528959909511907845980--

  2. perform the actual mount with `/portal/apis/accessControl/share.cgi` 
    - `act=mount`
    - `name:=MyEncryptedShare
    - `import_key_file:=MyEncryptedShare.key`

We can use a specification of the form `name@=file` to create the attachment.

*Remark:* The Content-Type is not used by `importkey.cgi`. The only thing that matters is that the imported filename should match the argument `import_key_file`.

The corresponding queries are

```
# nas-cmd.py query /portal/apis/accessControl/importkey.cgi  act=import_key files@=MyEncryptedShare.key 
Response contains 41 bytes
Interpreting response as JSON
{'name': 'ZZZZZ.key', 'success': True}
        
# nas-cmd.py query /portal/apis/accessControl/share.cgi act=mount name=MyEncryptedShare import_key_file:=MyEncryptedShare.key
Response contains 20 bytes
Interpreting response as JSON
{'success': True}
```



