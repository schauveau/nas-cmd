#!/usr/bin/python3

import getopt         # For parsing the main options
import argparse       # For parsing the command arguments

import re
import pprint
import requests
import urllib3
import sys
import time
import os
import logging
import hashlib

# Will use Path for local files and directories and PurePosixPath for the remote ones 
from pathlib import Path, PurePosixPath

from http.client import HTTPConnection

LOGGER = logging.getLogger('nas-cmd')

# Disable warning when using insecure https connection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL="https://nas.schauveau.local:49124"
ACCOUNT='foobar'
PASSWORD='xxxxxxxx'

p = None

# Provide the full class name of an object 
def full_class_name(o):
    c = o.__class__
    n = c.__qualname__
    m = c.__module__
    if m == 'builtins':
        return n
    else:
        return m + '.' + n

# Simple wrapper to print to stderr instead of stdout    
def err_print(*args,**kwargs):
    if not 'file' in kwargs:
        kwargs['file']=sys.stderr
    print(*args,**kwargs)
    
class NasPortalMalformedJsonError(IOError):
    """Bad or malformed JSON found in response"""

    def __init__(self, msg,  json, response):
        self.json = json
        self.response = response
        super().__init__(msg)

class NasPortalResponseError(IOError):
    """JSON response describes an error"""

    def __init__(self, json, response):
        self.json = json
        self.response = response
        super().__init__("Portal response describes an error")

class NasPortalNotConnectedError(Exception):
    """No SID available in NasPortal (not logged in yet?)"""

class NasPortal: 

    def __init__(self):
        self.url = None
        self.sid = None
        self.account = None
        self.home = None
        
        self.session = requests.Session()
        self.session.verify = False 

    def __del__(self):

        if self.connected() :
            self.logout()
            
        
    def connected(self):
        return (self.sid != None)


    # Perform sanity checks on a Requests response and return the
    # JSON answer. 
    #
    # :param  response: a requests.Response object
    # :param  raise_on_error: If true then raises NasPortalResponseError
    #         when JSON describes an error (i.e. when 'success' is false )
    # :raises requests.exceptions.RequestException: Any exception that
    #         may be triggered by response.raise_for_status()     
    # :raises requests.JSONDecodeError: If the response body does not
    #         contain valid json.
    # :raises NasPortalMalformedJsonError: If the JSON response does not
    #         contain a boolean 'success' field.
    # :raises NasPortalResponseError: If the JSON contains an error. 
    # 
    # 
    def response_as_json(self, response, raise_on_error=True):
        #
        # TODO: Check the response headers to insure that the  
        #       response payload is not user data (e.g. a download request).
        #       We do not want to interpet user-json as adm-json
        #
        json = response.json()
        success = json.get("success",None)
        if success is None:
            raise NasPortalMalformedJsonError("No success field in JSON response",json,response)
        elif success is False:
            if raise_on_error:
                raise NasPortalResponseError(json, response)
        elif success is True:
            pass
        else:
            raise NasPortalMalformedJsonError("Unexpected value in success field of JSON response",json,response)        
        return json   

    # return the current connection SID or raise NasPortalNotConnectedError 
    def get_connection_sid(self):
        if self.sid is None:
            raise NasPortalNotConnectedError
        return self.sid

    
    # Wrapper around requests.Session.request
    #
    # The arguments are basically the same except that the second positional
    # argument url is replaced by cgi, the local path to the CGI script (e.g.
    # '/portal/apis/foobar.cgi')
    #
    # :raises Any exception raised by requests.Session.request 
    # :raises NasPortalNotConnectedError if self.sid is None and no 'sid' is found
    #         in 'params'. That typically indicates that no login was performed.
    # 
    def request(self, method, cgi, **kwargs):
        #LOGGER.debug(f"request {cgi}")
        
        # Add the sid if not already in 'params' 
        params = kwargs.get("params", None)
        if params and not 'sid' in params:
            params['sid'] = self.get_connection_sid()

        r = self.session.request(method,
                                 self.url + cgi,
                                 **kwargs) 
        
        r.raise_for_status()
        return r

    # response, json = self.request_json(method, cgi, ...)
    #
    # Similar to the self.request(...) but a json response
    # is expected. 
    #
    # The following additional named arguments are recognized
    #
    # - json_raise_on_error  (default True)
    #      if True then raise NasPortalResponseError when the
    #      JSON 'success' field is false. 
    # - json_or_attachment (default False)
    #      if True then either an attachment or JSON is possible.
    #      In the later case, The JSON probably described an
    #      error (e.g. why the download request failed). 
    #
    def request_json(self, method, cgi, **kwargs):
        json_raise_on_error = kwargs.pop("json_raise_on_error", True)
        json_or_attachment = kwargs.pop("json_or_attachment", False)
        r = self.request(method, cgi, **kwargs)

        if json_or_attachment: 
            # The response header with an attachment shall contain 
            #    Content-Disposition: attachment; ...        
            if 'Content-Disposition' in r.headers:
                if r.headers['Content-Disposition'].startswith('attachment;'):
                    return r, None
        
        j = self.response_as_json( r, json_raise_on_error )        
        return r,j
    
  
    
    def login(self, url, account, passwd):
        r"""Log in ADM portal.
        """
        self.url = url
        self.sid = None
        self.account = account
        self.home = "/home/" + account

        #resp = self.session.request(url = url+"/portal/apis/login.cgi",
        resp, json = self.request_json( 'POST',
                                        "/portal/apis/login.cgi",
                                        params = {
                                            'sid': None,  
                                            'act':'login',                                            
                                            'account':  account
                                        },
                                        data={
                                            'password': passwd
                                        }
                                       )

        self.login_info = json ;

        self.sid = self.login_info["sid"]
        self.url = url
        self.account = account
        if account=='root' :
            self.home = "/root"
        else:
            self.home = f"/home/{account}"
            
            
    def logout(self):
        r"""Log out from ADM portal.
        """
        #
        # Make sure that the sid is always cleared even if the logout request fails.
        # Of course, that means that we have to pass the 'old' sid explicitly to
        # the request.
        #
        old_sid=self.get_connection_sid() 

        self.sid=None  
        r = self.request( 'POST',
                          "/portal/apis/login.cgi",
                          params = {
                              'sid': old_sid,
                              'act':'logout'
                          }
                         )

    def dump_json_answer(self,r):
        print(f"#### {r.status_code} {r.url}")
        pprint.pprint(r.json())

    def dump_response(self,r):
        if isinstance(r, Exception):
            print(f"An exception occured : {r}" )
        elif isinstance(r, requests.Response):
            print(f"#### {r.status_code} {r.url}")        
            try:
                j = r.json()
            except Exception as ex:
                template = "An exception of type {0} occurred. Arguments:\n{1!r}"
                message = template.format(type(ex).__name__, ex.args)
                print(message)
        else:
            print("Unexpected reponse type : ",type(r))
            

def action_upload(nas, argv):
    
    parser = argparse.ArgumentParser("nas-cmd upload",
                                     description='Upload a file',
                                     epilog=\
                                     "\n"\
                                     "\n",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('src',  
                        help="Source file")
 
    parser.add_argument('dest', 
                        help="Destination directory in an accessible share")

    parser.add_argument('filename',  nargs='?', default=None,                        
                        help="The filename to create. Default is to reuse\n"\
                        "the name of the source file"
                        )

    a = parser.parse_args(argv[1:]) 

    src=Path(a.src)
    if not src.is_file() :
        err_print("specified src does not exist or is not a file")
        sys.exit(1)
        
    with src.open("rb") as f :
        payload=f.read()

    if not a.filename is None: 
        filename = a.filename
    else:
        filename = src.name
    
    files = {'file': (filename,  payload , "text/plain") }

    r, json = nas.request_json( 'POST',
                                "/portal/apis/fileExplorer/upload.cgi",
                                params = {
                                    'act': 'upload',
                                    'overwrite': 1,  # 0=skip 1=overwrite
                                    'path': a.dest,
                                    'filesize': len(payload),
                                },
                                files = { 'file': (filename,  payload , "text/plain")  } )
    
    
def action_download(nas, argv):

    parser = argparse.ArgumentParser("nas-cmd download",
                                     description='Download a file',
                                     epilog=\
                                     "\n"\
                                     "\n",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Be quiet in case of success')
    
    parser.add_argument('src',  default='share', 
                        help="")
 
    parser.add_argument('dest', nargs='?', default=None,
                        help="")
       
    a = parser.parse_args(argv[1:]) 

    # Detect an explicit directory syntax before PurePosixPath
    # simplifies it.    
    if a.src.endswith('/') or a.src.endswith('/.'):
        err_print("src must be a file ; not a directoryy")
        sys.exit(2)
    src=PurePosixPath(a.src)
    if not src.is_absolute() :
        err_print("src must be an absolute path")
        sys.exit(2)

    r, json = nas.request_json( 'POST',
                               "/portal/apis/fileExplorer/download.cgi",
                               json_raise_on_error=True,
                               json_or_attachment=True,
                               params = {
                                   'act': 'download',
                                   'path': src.parent,
                                   'total': 1,
                                   'mod_cntype': 0,                              
                                   'file': src.name,          
                               } )
    
    # The only JSON responses expected after a download request are error messages
    # and they should raise an exception. Just to be sure ...
    assert json is None


    if a.dest:
        if Path(a.dest).is_dir():
            dest=str(Path(a.dest) / src.name)
        else:
            dest=a.dest
    else:
        dest=src.name

    if not a.quiet:
        err_print(f"download {len(r.content)} bytes in {dest} \n")

    with open(dest,"wb") as output:
        output.write(r.content)

    return 0

def action_cat(nas, argv):

    cmd=argv[0]
    parser = argparse.ArgumentParser("nas-cmd cat",
                                     description='Download and print a file to stdout',
                                     epilog=\
                                     "\n"\
                                     "\n",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', '--info', action='store_true',
                        help='print summary information instead')
    parser.add_argument('src',  default='share', 
                        help="")
       
    a = parser.parse_args(argv[1:]) 

    # Detect an explicit directory syntax before it is simplified by PurePosixPath 
    if a.src.endswith('/') or a.src.endswith('/.'):
        err_print("src must be a file ; not a directoryy")
        sys.exit(2)
    src=PurePosixPath(a.src)
    if not src.is_absolute() :
        err_print("src must be an absolute path")
        sys.exit(2)

    r, json = nas.request_json( 'POST',
                                "/portal/apis/fileExplorer/download.cgi",
                                json_raise_on_error=True,
                                json_or_attachment=True,
                                params = {
                                    'act': 'download',
                                    'path': src.parent,
                                    'total': 1,
                                    'mod_cntype': 0,                              
                                    'file': src.name
                                }
                               )
    
    # The only JSON responses expected after a download request are error messages
    # and they should raise an exception. Just to be sure ...
    assert json is None

    if a.info:
        md5sum=hashlib.md5(r.content).hexdigest()
        print(f"filename={repr(src.name)}")
        print(f"directory={repr(str(src.parent))}")
        print(f"size={len(r.content)}")
        print(f"md5={md5sum}")
    else:
        sys.stdout.buffer.write(r.content)

    return 0


def action_query(nas, argv):

    cmd=argv[0]
    parser = argparse.ArgumentParser("nas-cmd query",
                                     description='Perform a custom cgi query',
                                     epilog=\
                                     "\n"\
                                     "Parameter specifications of the form name=value are sent in the query string \n"\
                                     "while those of the form name:=value are sent in the body. \n"\
                                     "\n"\
                                     "The 'sid' argument is implictly passed and should not be specified here\n"\
                                     ,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', '--info', action='store_true',
                        help='print summary information instead')
    parser.add_argument('-r', '--raw', action='store_true',
                        help="print the raw response")
    parser.add_argument('cgi',
                        help="path to the cgi file")
    parser.add_argument('spec', nargs='*',
                        help="parameter specification of the form name=value or name:=value")
       
    a = parser.parse_args(argv[1:]) 

    if not ( a.cgi.startswith('/portal/apis/') and a.cgi.endswith('.cgi') ) :
        err_print("cgi should be of the form '/portal/apis/.../FILE.cgi'")
        sys.exit(2)

    # Transform each param_spec into an entry in params or in data 
    params={}
    data={}
    re_spec=re.compile("^([a-zA-Z_][a-zA-Z_0-9]*)(=|:=)(.*)$")
    for spec in a.spec:
        m = re_spec.match(spec)
        if not m:
            err_print(f"unexpected argument {spec}. Expect name=value or name:=value")
            sys.exit(1)
        if m.group(1) == 'sid':
            err_print(f"Warning: Ignoring sid parameter")
            continue
        if m.group(2) == '=' :
            params[m.group(1)] = m.group(3) 
        elif m.group(2) == ':=' :
            data[m.group(1)] = m.group(3) 
        else:
            assert False

    r, json = nas.request_json( 'POST',
                                a.cgi,
                                json_raise_on_error=False,  
                                json_or_attachment=True,    
                                params = params,
                                data = data
                               )
    if a.raw:        
        sys.stdout.buffer.write(r.content)
    else:
        pprint.pprint(json)
        
    return 0


def action_list_directory(nas, argv):
    filter=''
    output='name'
    escape=False

    cmd=argv[0]

    if cmd=='ll' or cmd=='vdir' :
        default_mode='long'
    else:
        default_mode='short'

    parser = argparse.ArgumentParser("nas-cmd [ls|dir|ll|vdir]",
                                     description='List share content',
                                     epilog=
                                     "The location can be one of\n"
                                     "  - an absolute path within a share (e.g. /Public/my_dir)\n"
                                     "  - a path in a user home directory (e.g. /home/foobar/Photos)\n"
                                     "  - one of the following special locations:\n"
                                     "    share, share_folders, virtual_share, external_share,\n"
                                     "    cifs, ezsync, recycle_bin\n",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-e', '--escape', action='store_true',
                        help='escape special characters in filenames')
    parser.add_argument('-f', '--filter', type=str, metavar='TEXT',required=False, default=None,
                        help='show only the filenames containing TEXT')

    # Those options control the output mode
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('-s', '--short', action='store_const', dest='mode', const='short', default=default_mode,
                            help='display only the filenames')
    mode_group.add_argument('-l', '--long', action='store_const', dest='mode', const='long', default=default_mode,
                            help='use a long listing format')
    mode_group.add_argument('-j', '--json', action='store_const', dest='mode', const='json',
                            help='display the whole json response')
                            

    parser.add_argument('location', nargs='?', default='share', 
                        help="The location to list (default is '%(default)s'}")
    
    a = parser.parse_args(argv[1:]) 
    
    if True:
        page=None
        start=None
        limit=None
    else:
        page=0 
        start=0
        limit=500
                        
    
    r, ans = nas.request_json( 'GET',
                               "/portal/apis/fileExplorer/fileExplorer.cgi",
                               params = {
                                   'act': 'file_list',
                                   'path': a.location,
                                   'filter': a.filter,
                                   'page':  page,
                                   'start': start,
                                   'limit': limit,
                                   'showhome':True  # Home is not listed by default in 'shares'
                               } )
    

    if  a.mode == 'long' :
        
        octal_to_rwx={'0':'---', '1':'--x', '2':'-w-', '3':'-wx',
                      '4':'r--', '5':'r-x', '6':'rw-', '7':'rwx'}
        print("total {}".format(ans['total']) )
        for entry in ans['data'] :
        
            filename    = entry['filename']
            is_dir      = entry.get('is_dir',False)
            modify_time = entry.get('modify_time_',0)
            file_size   = entry.get('file_size','?')
            owner       = entry.get('owner','?')
            group       = entry.get('group','?')
            file_permission = entry.get('file_permission','')
        
            filename = filename.replace("\n",r'\n').replace("\t",r'\t').replace("\\",r'\\')
            
            # Truncate owner and group to 10 character using + to indicate truncation.
            if len(owner)>10 :
                owner=owner[0:9]+'+'
            if len(group)>10 :
                group=group[0:9]+'+'
                    
            if len(file_permission) ==  3:
                mode = \
                    octal_to_rwx.get(file_permission[0],'???')+\
                    octal_to_rwx.get(file_permission[1],'???')+\
                    octal_to_rwx.get(file_permission[2],'???')
            else:
                mode='?????????'
                        
            if is_dir:
                mode='d' + mode
                filename=filename+'/'
            else:
                mode='-' + mode

            print('{:10} {:10} {:10} {:12} {} {}'.format(mode, owner, group, file_size, modify_time, filename) )
        
    elif a.mode == 'short' :
        for entry in ans['data'] :
            filename    = entry['filename']
            print(filename)
    elif a.mode == 'json' :
        pprint.pprint('json')
    else:
        raise "Unhandled mode"

    #if ans['data']:
    #    pprint.pprint(ans['data'][0])
        

  
def usage_main():
    err_print("Usage: nas-cmd.py [OPTIONS] ACTION [ARGUMENTS]")
    err_print("Execute an ACTION using the ADM Portal web interface")
    err_print()
    err_print("The main OPTIONS must be specified before the ACTION and its ARGUMENTS")
    err_print("  -h, --help              Show this help")
    err_print("  -d, --debug             Enable debug output in HTTPConnection")
    err_print("  -v, --verbose           Enable debug in logging")
    err_print("  -A, --account=NAME      Set the ADM user account")
    err_print("  -P, --password=TEXT     Set the ADM password")
    err_print("  -U, --url=URL           Set the ADM url (e.g. https://hostname:port/)")
    err_print("  -C, --credentials=FILE  Read password, account, and url from a file")
    err_print("")
    err_print("The following ACTIONs are currently supported")
    err_print("")
    err_print("  login             to print the JSON response to login")
    err_print("  ls,dir,ll,vdir    to list the content of an ADM directory")
    err_print("  download          to download a file from ADM")
    err_print("  upload            to upload a file from ADM")
    err_print("  cat               print the content of an ADM file")
    err_print("")
    err_print("Most actions implement a -h or --help option in their arguments")
    err_print("")
    err_print("The credential FILE is a simple text file. The first line provides")
    err_print("the account, the second the password and the third the URL")
    err_print("")

def main():
    global URI, ACCOUNT, PASSWORD 

    try:
        # Parse the options but only up to the command name
        opts, more_args = getopt.getopt(sys.argv[1:],
                                        "hdvA:P:U:C:",
                                        [ "help",
                                          "debug",
                                          "verbose",
                                          "account=",
                                          "password=",
                                          "credentials=",
                                          "url="
                                         ])
            
        for opt, value in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit()
            elif opt in ("-d", "--debug"):
                HTTPConnection.debuglevel = 1
            elif opt in ("-v", "--verbose"):
                if True:
                    logging.basicConfig(
                        # filename='LOG.txt', filemode='w',
                        stream=sys.stderr,
                        level=logging.DEBUG,
                        format='[%(levelname)s:%(name)s]  %(message)s',
                    )
                url3_log = logging.getLogger('urllib3')
                url3_log.setLevel(logging.DEBUG)
                url3_log.propagate = True
            elif opt in ("-A", "--account"):
                ACCOUNT=value
            elif opt in ("-P", "--password"):
                PASSWORD=value
            elif opt in ("-U", "--url"):
                URL=value
            elif opt in ("-C", "--credential"):
                with open(value,"r") as f:
                    str=f.readline().rstrip('\n')
                    if str:
                        ACCOUNT=str
                    str=f.readline().rstrip('\n')
                    if str:
                        PASSWORD=str
                    str=f.readline().rstrip('\n')
                    if str:
                        URL=str
            else:
                assert False, f"Unhandled option '{opt}'"

        if not more_args:
            err_print("No action specified") 
            usage_main()
            sys.exit(1)
            
        err=0
            
        nas = NasPortal()
        nas.login(URL, ACCOUNT, PASSWORD)
            
        action = more_args[0]
        if action == "login":
            # Print the JSON response from login
            pprint.pprint(nas.login_info)
        elif action in ( "ls", "dir", 'll', 'vdir' ) :
            err = action_list_directory(nas, more_args)
        elif action == "download":
            err = action_download(nas, more_args)
        elif action == "cat":
            err = action_cat(nas, more_args)
        elif action == "upload":
            err = action_upload(nas, more_args)
        elif action == "query":
            err = action_query(nas, more_args)
        else:
            err_print(f"Unknown command '{action}' ") 
            usage_main()
            sys.exit(1)
    
        nas.logout()            
        sys.exit(err)

    except getopt.GetoptError as err:
        err_print(err) 
        usage_main()
        sys.exit(1)

    except FileNotFoundError:
        err_print(e) 
        sys.exit(2)
        
    except PermissionError:
        err_print(e) 
        sys.exit(2)
        
    except requests.exceptions.RequestException as e:
        ename = full_class_name(e)
        err_print(f"{ename}: {e}")
        sys.exit(2)

    except NasPortalResponseError as e:
        # Most error responses from ADM Portal contain only 3 fields:
        #   success=false, error_code and error_msg.
        # but a few may contain more that may need to be handled separately.
        msg="Portal error:"        
        error_code=e.json.get('error_code', None)
        error_msg=e.json.get('error_msg', None)
        if error_code:
           msg += f" #{error_code}"
        if error_msg:
           msg += f" '{error_msg}'"        
        err_print(msg)
        # Addition fields may exists. Warn about them
        more_keys=set(e.json.keys())
        more_keys.discard('success')
        more_keys.discard('error_msg')
        more_keys.discard('error_code')        
        if more_keys: 
            err_print("Warning: Unhandled data in error response: {0}".format(", ".join(more_keys)))
        sys.exit(2)

    # Other exceptions are likely programming errors 
    
if __name__ == "__main__":
    main()
    
