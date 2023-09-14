# How to implement your own queries

The python script only implements the most basic actions (list directory, download, upload, ...) but the `query` action can be used to implement more functionalities assuming that you can figure out the CGI script and its argument.

This is not that hard to do assuming that your web browser comes with decent developers tools. I will be using Firefox but the procedure should basically be the same with Chrome.

For example, let's figure out how to mount/unmount an encrypted share.

Connect to the ADM portal in Firefox using an administrator account, open the `Access Control` window and select the `Shared Folders` tab. If you do not have any encrypted folderone then create one. I will assume that the share is `MyEncryptedShare` and the password is `my_secret_password`.

Now use `SHIFT+CONTROL+i` to open the *Web Developper Tool* and select the *Network* tab. You can fill `.cgi` in the `Filter URLS` field to only show the cgi requests (and not the other requests for images, css, javascript, ...).

*Remark:* Use the 'trash' icon to clear the list of requests and the play/pause icon to stop recording when you are done. 

In the `Access Control` window, mount an encrypted folder. A few cgi requested should appear but the interesting one should use the CGI script `/portal/apis/accessControl/share.cgi`:

```
https://nas.schauveau.local:49124/portal/apis/accessControl/share.cgi?sid=l8v-ZHTEMFfxGn5t&act=mount&_dc=1694421221520
```

Select the `share.cgi` request to display more details. The interesting tabs are `Headers`, `Request` and potentially `Response`. 

The `Headers` tab gives use the arguments passed in the URL after `/portal/apis/accessControl/share.cgi` :
  - `sid` is the connection identifier. It can be ignored since the script will take care of that.
  - `act` of value `mount` is the action identifier. Most cgi scripts require an `act` parameter.
  - `_dc` is a timestamp. It can probably be ignored.

The `Request` tab tells us that two arguments are passed as form-data (i.e. POST):
  - `name` of value 'MyEncryptedShare`. 
  - `encrypt_key` of value `my_secret_password`.

This is all we need to 'mount' the share using `nas-cmd.py`. Make sure that the share is not mounted and run the following command using your administrator credentials:

```
# nas-cmp.py query /portal/apis/accessControl/share.cgi act=mount name:=MyEncryptedShare encrypt_key:=my_secret_password
Response contains 20 bytes
Interpreting response as JSON
{'success': True}
```

*Remark:* If the query is not successful then `success` will be `False` and the response will contain an `error_code` and an `error_msg` that may or may not help you figure out what when wrong. Remember that this API is not intended for humans and is undocumented. Also, each CGI script has its own set of error codes. 

*Remark:* Most CGI scripts do not care if their arguments are passed in the URL (so as `name=value`) or in form-data (so as `name:=value`) but it is probably wiser to pass sensitive information in form-data. A notable exception is `act` and `sid` that must to be passed in the URL, probably because they are processed very early. 

The query to unmount the encrypted share is similar but with `act=unmount` and an argument `name_list` instead of `name`. 

```
# nas-cmd.py query /portal/apis/accessControl/share.cgi act=unmount name_list=MyEncryptedShare 
```

Now, let's try to mount that same encrypted share using the key file `MyEncryptedShare.key` that was produced during its creation.

The Web Developper Tool tells us that this action produces two CGI requests:

  1. upload the key file with `/portal/apis/accessControl/importkey.cgi`  
     - `act` of value `import_key'
     - and a key file attached in the request body.  
```
-----------------------------122634777528959909511907845980
Content-Disposition: form-data; name="files"; filename="MyEncryptedShare.key"
Content-Type: application/vnd.apple.keynote

[...THE KEY DATA IS HERE...] 
-----------------------------122634777528959909511907845980--
```
  2. mount the share with `/portal/apis/accessControl/share.cgi` 
     - `act` of value `mount`
     - `name` of value `MyEncryptedShare`  
     - `import_key_file` of value `MyEncryptedShare.key`


*Remark:* The Content-Type value is not used by `importkey.cgi`. The only thing that matters is that the imported filename should match the value of the argument `import_key_file`.

A file can be attached with a specification of the form `name@=file` so the corresponding queries are:

```
# nas-cmd.py query /portal/apis/accessControl/importkey.cgi  act=import_key files@=../private/MyEncryptedShare.key 
Response contains 41 bytes
Interpreting response as JSON
{'name': 'MyEncryptedShare.key', 'success': True}
        
# nas-cmd.py query /portal/apis/accessControl/share.cgi act=mount name=MyEncryptedShare import_key_file:=MyEncryptedShare.key
Response contains 20 bytes
Interpreting response as JSON
{'success': True}
```



