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
import atexit
import json

# Will use Path for local files and directories and PurePosixPath for the remote ones 
from pathlib import Path, PurePosixPath

from http.client import HTTPConnection

ACCOUNT='foobar'
PASSWORD='xxxxxxxx'
URL="https://nas.schauveau.local:49124"


LOGGER = logging.getLogger('nas-cmd')

# Disable warning when using insecure https connection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#
# Escape some characters in string str 
# 
def escape_string(str):
    #return str.replace("\n",r'\n').replace("\t",r'\t').replace("\\",r'\\')
    return repr(str[1:-1])

# Provide the full class name of an object 
def full_class_name(o):
    c = o.__class__
    n = c.__qualname__
    m = c.__module__
    if m == 'builtins':
        return n
    else:
        return m + '.' + n

# Guess the content type from a filename.
#
# This is a very crude implementation.
#
# In practice that should not matter much except for a few CGI scripts
# such as /portal/apis/wallpaper/uploadwallpaper.cgi that require a JPG
# or PNG image. 
#
def guess_content_type(filename):
    name = filename.lower()
    matches = (
        ( '.jpeg', 'image/jpeg' ),        
        ( '.jpg', 'image/jpg' ),        
        ( '.png', 'image/png' ), 
        ( '.txt', 'text/plain' ),
    )
    for case in matches:
        if name.endswith(matches[0]) :
            return matches[1]
    return 'application/octet-stream'

# Simple wrapper to print to stderr instead of stdout    
def err_print(*args,**kwargs):
    if not 'file' in kwargs:
        kwargs['file']=sys.stderr
    print(*args,**kwargs)
    
class NasSessionMalformedJsonError(IOError):
    """Bad or malformed JSON found in response"""

    def __init__(self, msg,  json, response):
        self.json = json
        self.response = response
        super().__init__(msg)

class NasSessionResponseError(IOError):
    """JSON response describes an error"""

    def __init__(self, json, response):
        self.json = json
        self.response = response
        super().__init__("Portal response describes an error")

class NasSessionNotConnectedError(Exception):
    """No SID available in NasSession (not logged in yet?)"""

    
# Perform sanity checks on a Requests response and interpret it as JSON.
#
# :param  response: a requests.Response object
# :param  raise_on_error: boolean to indicate if NasSessionResponseError should 
#         be raised when JSON response describes an error.
#         If of type integer, tuple, list then those are the error codes that
#         should NOT RAISE NasSessionResponseError.
# :raises requests.exceptions.RequestException: Any exception that
#         may be triggered by response.raise_for_status()     
# :raises requests.JSONDecodeError: If the response body does not
#         contain valid json.
# :raises NasSessionMalformedJsonError: If the JSON response does not
#         contain a boolean 'success' field.
# :raises NasSessionResponseError: If the JSON contains an error. 
# 
# 
def get_json_from_response(response, raise_on_error=True):
    #
    # TODO: Check the response headers to insure that the  
    #       response payload is not user data (e.g. a download request).
    #       We do not want to interpet user-json as adm-json
    #
    json = response.json()
    success = json.get("success",None)
    if success is None:
        raise NasSessionMalformedJsonError("No success field in JSON response",json,response)
    elif success is False:
        if type(raise_on_error) is bool :
            do_raise = raise_on_error
        elif type(raise_on_error) is tuple or type(raise_on_error) is list :
            do_raise = not ( json.get("error_code",None) in raise_on_error ) 
        elif type(raise_on_error) is int :
            do_raise = json.get("error_code",None) != raise_on_error
        if do_raise:
            raise NasSessionResponseError(json, response)
    elif success is True:
        pass
    else:
        raise NasSessionMalformedJsonError("Unexpected value in success field of JSON response",json,response)        
    return json   

#
# Provide a requests.Session to an Asustor Portal and basic login, logout and request  
# features.
#
class NasSession: 

    def __init__(self):
        self.url = None
        self.sid = None
        self.account = None
        self.home = None
        
        self.session = requests.Session()
        self.session.verify = False 

    def __del__(self):
        self.logout()
            
        
    def connected(self):
        return (self.sid != None)

    # return the current connection SID or raise NasSessionNotConnectedError 
    def get_connection_sid(self):
        if self.sid is None:
            raise NasSessionNotConnectedError
        return self.sid

    # Wrapper around requests.Session.request
    #
    # The arguments are basically the same except that the second positional
    # argument url is replaced by cgi, the local path to the CGI script (e.g.
    # '/portal/apis/foobar.cgi')
    #
    # :raises Any exception raised by requests.Session.request 
    # :raises NasSessionNotConnectedError if self.sid is None and no 'sid' is found
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
    #      if True then raise NasSessionResponseError when the
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
        
        j = get_json_from_response( r, json_raise_on_error )        
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
        self.login_content = resp.content ;

        self.sid = self.login_info["sid"]
        self.url = url
        self.account = account
        if account=='root' :
            self.home = "/root"
        else:
            self.home = f"/home/{account}"

        # If the program terminates early (e.g. with sys.exit()), the NasSession destructor may
        # be called after the connections are closed. Let's make sure that we logout as
        # soon as possible.
        atexit.register(NasSession.logout, self)
            
    def logout(self):
        r"""Log out from ADM portal.
        """
        if self.sid is None:
            return
        #
        # Make sure that the sid is always cleared even when the logout request 
        # raises an exception.
        #
        sid = self.sid
        self.sid=None  
        r = self.request( 'POST',
                          "/portal/apis/login.cgi",
                          params = {
                              'sid': sid,
                              'act':'logout'
                          }
                         )


# Base class to implement ADM actions
#
class Action:

    all_instances={}  # Will hold all instances of Action 

    def __init__(self, name, subparser, **kwargs):
        self.name = name
        self.parser = subparser.add_parser(name, **kwargs) ;
        assert not name in Action.all_instances
        Action.all_instances[self.name] = self 

    @staticmethod
    def find(name) :
        return Action.all_instances[name]

# Describe an argument     
class Argument:
    # 
    # *options are strings for the option names (e.g. '-k', '--keep', 'src'). They will later be passed to parser.add_argument()
    #
    # All remaining arguments (in **kwargs) will later be passed to parser.add_argument()
    #
    def __init__(self, *options, **kwargs):
        self.options = options
        self.kwargs = kwargs

    def add_to_parser(self, parser):
        # print("[add_to_parser]",self.options,self.kwargs)
        parser.add_argument(*self.options, **self.kwargs) 
        
        
ARG_HEADERS = Argument('--headers',
                       dest='headers',
                       action='store_true',
                       help='Print the response headers',
                       )

ARG_RAW = Argument('--raw',
                   dest='raw',
                   action='store_true',
                   help="Print the raw response content and stop"
                   )

ARG_SAVE = Argument('--save',
                    dest='save',
                    type=str,
                    metavar='FILE',
                    required=False,
                    default=None, 
                    help="Save the response content to file"
                    )
        
ARG_SAVE_HEADERS = Argument('--save-headers',
                            dest='save_headers',
                            type=str,
                            metavar='FILE',
                            required=False,
                            default=None, 
                            help="Save the response headers to file"
                            )

ARG_STOP = Argument('--stop',                                   
                    dest='stop',
                    action='store_true',
                    help='Stop after sending the CGI request'
                    ) 

#
# Used by the hooks in BasicAction.run() to describe the current state 
#
class RunState:
    def __init__(self, nas, args):
        self.nas  = nas 
        self.args = args
        self.response = None
        self.request_params = None
        self.request_data = None
        self.request_files = None
        
class BasicAction(Action):
        
    ARG_HEADERS = Argument('--headers',
                           dest='headers',
                           action='store_true',
                           help='Print the response headers',
                           )

    ARG_RAW = Argument('--raw',
                       dest='raw',
                       action='store_true',
                       help="Print the raw response content and stop"
                       )

    ARG_SAVE = Argument('--save',
                        dest='save',
                        type=str,
                        metavar='FILE',
                        required=False,
                        default=None, 
                        help="Save the response content to file"
                        )

    ARG_SAVE_HEADERS = Argument('--save-headers',
                                dest='save_headers',
                                type=str,
                                metavar='FILE',
                                required=False,
                                default=None, 
                                help="Save the response headers to file"
                                )

    ARG_STOP = Argument('--stop',                                   
                        dest='stop',
                        action='store_true',
                        help='Stop after sending the CGI request'
                        ) 

    DEFAULT_ARGS = [
        ARG_SAVE,
        ARG_SAVE_HEADERS,
        ARG_HEADERS,
        ARG_RAW,
        ARG_STOP,
    ]
    
    def __init__(self, name, subparser, cgi=None, params={} , data={}, files={}, args=DEFAULT_ARGS, **kwargs):
        super().__init__( name,
                          subparser,
                          formatter_class=argparse.RawTextHelpFormatter,
                          **kwargs
                         )
        
        self.cgi = cgi
        self.params_spec = params
        self.data_spec   = data
        self.file_spec   = files

        for a in args:
            a.add_to_parser(self.parser)


    def run(self, nas, args):
        state = RunState(nas,args)
        
        ok = self.start_hook(state)
        assert type(ok)==bool 
        if not ok:
            return False 
        
        state.request_params  = {}
        for name, spec in self.params_spec.items():
            # TODO
            state.request_params[name] = spec             

        state.request_data = {}
        for name, spec in self.data_spec.items():
            # TODO
            state.request_data[name] = spec        

        state.request_files = {}
        # TODO
        
        ok = self.before_request_hook(state) 
        assert type(ok)==bool 
        if not ok:
            return False

        if not self.cgi:
            raise Exception("No CGI specified")
        
        state.response = nas.request('POST',
                                     self.cgi,
                                     params = state.request_params,
                                     data   = state.request_data,
                                     files  = state.request_files
                                     )
        
        ok = self.after_request_hook(state)
        assert type(ok)==bool 
        if not ok:
            return False
        
        if state.args.save:
            with open(args.output, "wb") as out:
                out.write(state.response.content)
        
        if state.args.headers:
            for key in sorted(state.response.headers.keys()):
                print(f"{key}: {state.response.headers[key]}")
            print("")
            
        if state.args.save_headers:
            with open(state.args.save_headers, "w") as out:
                for key in sorted(state.response.headers.keys()):
                    print(f"{key}: {state.response.headers[key]}",file=out)
            
        if state.args.raw:
            sys.stdout.buffer.write(state.response.content)
            return 0
    
        if state.args.stop:
            return 0 
        
        ok = self.end_hook(state)
        assert type(ok)==bool 
        if not ok:
            return False
        
    # Executed at the start of self.run() 
    def start_hook(self, state: RunState):
        return True

    # Executed in self.run() before the CGI request in self.run()
    def before_request_hook(self, state: RunState):
        return True

    # Executed in self.run() after the CGI request in self.run()
    def after_request_hook(self, state: RunState):
        return True
    
    # Executed in self.run() after processing the DEFAULT_ARGS 
    def end_hook(self, state: RunState):

        r = state.response
        # Handle the two cases encountered so far
        #
        # - an file attachement indicated by the presence of
        #   a 'Content-Disposition: attachment; ...' 
        # - otherwise, no 'Content-Disposition' and
        #   'Content-type: text/plain; charset=utf-8' indicates
        #   that this is likely a JSON reply.  
        #
        content_size = len(r.content)
        
        # Look for an attached file
        content_disposition = r.headers.get('Content-Disposition','none')
        content_type = r.headers.get('Content-Type','none')
        if content_disposition.startswith('attachment;'):
            err_print(f"Attachement detected ({content_size} bytes): {content_disposition}. ")                
            return True

        # I do not think that this is possible but ... 
        if content_size == 0:
            err_print(f"Empty response")                
            return True

        if  content_disposition=='none' and \
            content_type.startswith('text/html;'):
            err_print(f"Html detected ({content_size})")                

        # Then a JSON response
        if  content_disposition=='none' and \
            content_type.startswith('text/plain; charset=utf-8'):
            # err_print(f"Interpreting response as JSON")
            j = get_json_from_response( r, False )
            json.dump(j, sys.stdout, indent=1, sort_keys=False)
            return True

        err_print("Warning: Unexpected response")
        return False
    
class QueryAction(BasicAction):
    def __init__(self, name, subparser):
        super().__init__( name,
                          subparser,
                          help='Perform a custom cgi query',
                          description='Perform a custom cgi query',
                          epilog=\
                          "\n"\
                          "Each spec should be of one of the following forms:\n"\
                          "   name=value to pass an argument in the URL\n"\
                          "   name:=value to pass an argument as form-data\n"\
                          "   name@=filename to attach a file to the request\n"\
                          "\n"\
                          "The 'sid' argument is implictly managed and should not be specified here\n"\
                          ,
                          args = [
                              BasicAction.ARG_SAVE,
                              BasicAction.ARG_SAVE_HEADERS,
                              BasicAction.ARG_HEADERS,
                              BasicAction.ARG_RAW,
                              BasicAction.ARG_STOP,
                              Argument( '-c', '--content-type',
                                        type=str,
                                        metavar='STR',
                                        required=False,
                                        default=None, 
                                        help="Set the content type for all file specifications"
                                       ),
                              Argument('cgi',
                                       help="path to the cgi file"
                                       ),
                              Argument('spec',
                                       nargs='*',
                                       help="parameter specification of the form name=value or name:=value"
                                       )
                          ]
                         )
      
    def before_request_hook(self, state: RunState):
        
        self.cgi = state.args.cgi
        if not ( self.cgi.startswith('/portal/apis/') and self.cgi.endswith('.cgi') ) :
            err_print("cgi should be of the form '/portal/apis/.../FILE.cgi'")
            return False

        # Transform each param_spec into an entry in params, data or files
        re_spec=re.compile("^([a-zA-Z_][a-zA-Z_0-9]*)(=|:=|@=)(.*)$")
        for spec in state.args.spec:
            m = re_spec.match(spec)
            if not m:
                err_print(f"Error:unexpected argument {spec}. Expect name=value or name:=value")
                return False
            name=m.group(1)
            sep=m.group(2)
            value=m.group(3)
            if name == 'sid':
                err_print(f"Warning: Ignoring sid parameter")
                continue
            if sep == '=' :
                state.request_params[m.group(1)] = m.group(3) 
            elif sep == ':=' :
                state.request_data[m.group(1)] = m.group(3) 
            elif sep == '@=' :
                filename=m.group(3)
                if args.content_type:
                    content_type=args.content_type
                else:
                    content_type=guess_content_type(filename)
                    # err_print(f"Warning: No content type specified. Guessing {content_type}")
                    
                with open(filename,"rb") as f:
                    state.request_files[m.group(1)] = ( Path(filename).name , f.read(), content_type )
            else:
                assert False  # Hoops! Something went wrong with the regex
                
        return True
                    
    def after_request_hook(self, state: RunState):
        return True
                     
class UploadAction(BasicAction):
    def __init__(self, name, subparser):
        super().__init__( name,                          
                          subparser,
                          cgi='/portal/apis/fileExplorer/upload.cgi',
                          help='Upload a file to the NAS',
                          description='Upload a file',
                          epilog=\
                          "\n"\
                          "\n",
                          args=[
                              BasicAction.ARG_SAVE,
                              BasicAction.ARG_SAVE_HEADERS,
                              BasicAction.ARG_HEADERS,
                              BasicAction.ARG_RAW,
                              BasicAction.ARG_STOP,         
                              Argument('src',
                                       help="Local source file"
                                       ),                              
                              Argument('dest', 
                                       help="Remote destination directory"
                                       ),                                     
                              Argument('filename',
                                       nargs='?',
                                       default=None,                        
                                       help="The filename to create. Default is to reuse the name of src"
                                       )
                          ],
                          params={
                              'act': 'upload',
                              'overwrite': 1,  # 0=skip 1=overwrite
                          }
                         )
        
    def before_request_hook(self, state: RunState):

        state.request_params['path'] = state.args.dest

        src = Path(state.args.src)
        if not src.is_file() :
            err_print("specified src does not exist or is not a file")
            return False

        with src.open("rb") as f :
            payload = f.read()

        if not state.args.filename is None: 
            filename = state.args.filename
        else:
            filename = src.name

        state.request_files['file'] = ( filename,  payload , "text/plain")         

        return True
        

        
class DownloadAction(Action):
    def __init__(self, name, subparser):
        super().__init__( name,
                          subparser,
                          help='Download a file',
                          description='Download a file',
                          epilog=\
                          "\n"\
                          "\n",
                          formatter_class=argparse.RawTextHelpFormatter
                         )
        self.parser.add_argument('-q', '--quiet', action='store_true',
                                 help='Be quiet in case of success')
        
        self.parser.add_argument('src',  default=None, 
                                 help="")
        
        self.parser.add_argument('dest', nargs='?', default=None,
                                 help="")
       
    def run(self, nas, args):
        # Detect an explicit directory syntax before PurePosixPath simplifies it.
        if args.src.endswith('/') or args.src.endswith('/.'):
            err_print("src must be a file ; not a directoryy")
            sys.exit(2)
        src=PurePosixPath(args.src)
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


        if args.dest:
            if Path(args.dest).is_dir():
                dest=str(Path(args.dest) / src.name)
            else:
                dest=args.dest
        else:
            dest=src.name

        if not args.quiet:
            err_print(f"download {len(r.content)} bytes in {dest} \n")

        with open(dest,"wb") as output:
            output.write(r.content)

        return 0

class CatAction(BasicAction):
    def __init__(self, name, subparser):

        super().__init__( name,
                          subparser,
                          cgi="/portal/apis/fileExplorer/download.cgi",
                          help='Download and display a file',
                          description='Download and print a file to stdout',
                          epilog=\
                          "\n"\
                          "\n",
                          args = [
                              *BasicAction.DEFAULT_ARGS ,
                              Argument('--summary',
                                       action='store_true',
                                       dest='summary',
                                       help='print summary information instead of full content'
                                       ),
                              Argument('target',
                                       help='path to a remote file'
                                       ),
                          ],
                          params={
                              'act': 'download',
                              'total': 1,
                              'mod_cntype': 0,                              
                              # 'path': src.parent,
                              # 'file': src.name
                          },
                         )
        
        self.json_raise_on_error=True,
        self.json_or_attachment=True,

    def before_request_hook(self, state: RunState):

        # We need to split the target argument into a path (i.e. the directory)
        # and a filename.

        target = PurePosixPath(state.args.target)
        
        state.request_params['path'] = target.parent,
        state.request_params['file'] = target.name,

        return True
            
    def end_hook(self, state: RunState):

        response = state.response 
        content_disposition = response.headers.get('Content-Disposition','')
        if content_disposition.startswith('attachment;'):
            sys.stdout.buffer.write(response.content)
            return True

        # The content must be a json error description.        
        j = get_json_from_response(response, True)  

        # Hummm... This is not a json error. Should not happen here
        err_print(f"Unexpected JSON response:\n")
        json.dump(j, sys.stderr, indent=1, sort_keys=False)

        return False

#
# Query the properties of the file or directory at path.
#
# In case of success, return a dict with the following fields
# 
#  'file_name'  the name of the file or directory
#  'file_size'  the overall storage size 
#  'files'      the number of files inside the directory 
#  'folder'     the number of folders inside the directory
#  'at'         the last access time (e.g. '2023-09-12 10:30')
#  'ct'         the creation time (e.g. '2023-09-12 10:30')
#  'mt'         the last modification time (e.g. '2023-09-12 10:30')
#
# If should be noted that there are no obvious ways to differentiate a file from an empty directory.
#
# Remark: Symbolic links are not counted in 'files'. 
#
# In case of failure, return None
#
def query_path_properties(nas,path):
    
        r, ans = nas.request_json( 'POST',
                                    "/portal/apis/fileExplorer/fileExplorer.cgi",
                                    params = {
                                        'act': 'get_properties',
                                        'total': 1,
                                        'file_path': path
                                    }
                                  )
        # Wait for the task completion.
        # That may take a while if path is a directory because of the recursive 
        # count of inner files and directories
        pid=ans['pid']
        while True :
            r, ans = nas.request_json( 'POST',
                                       "/portal/apis/fileExplorer/fileExplorer.cgi",
                                       params = {
                                           'act': 'get_properties_progress',
                                           'pid': pid,
                                       }
                                      )
            status = ans['status'] 
            assert status in ( 'done' , 'continue' )
            if status=='done':
                if ans['total'] == 0:
                    return None
                elif ans['total'] == 1:
                    return ans['files'][0] 
                else:
                    # That must be possible? How?
                    # Could that be when the filename encoding is ambiguous
                    # such as UTF-8 allowing multiple representation of the same character?
                    err_print('Hoops! Multiple matches in query_path_properties()')
                    sys.exit(1)
            time.sleep(0.1) 
            
        
class DeleteAction(Action):
    def __init__(self, name, subparser):
        super().__init__( name,
                          subparser,
                          help='Delete or move to the RecycleBin',
                          description='Delete or move to the RecycleBin',
                          epilog=\
                          "\n"\
                          "\n",
                          formatter_class=argparse.RawTextHelpFormatter
                         )
        self.parser.add_argument('--recursive', dest='recursive', action='store_true',
                                 help='Allow deletion of non-empty directories')
        self.parser.add_argument('--no-wait', dest='wait', action='store_false', 
                                 help='Do not wait for the task completion.')
        self.parser.add_argument('path',  default=None, 
                                 help="The file or directory to remove")

    def run(self, nas, args):

        
        if not args.recursive:
            prop = query_path_properties(nas,args.path)

            if prop is None:
                err_print("File or directory not found")
                sys.exit(1)

            if prop['files']!=0 or prop['folder']!=0 :
                err_print('Abort! Directory is not empty')
                sys.exit(0)

        # QUESTION: Is there a secret argument to force physical removal instead of moving to the RecycleBin?
        
        r, ans = nas.request_json( 'POST',
                                    "/portal/apis/fileExplorer/fileExplorer.cgi",
                                    params = {
                                        'act': 'delete',
                                        'total': 1,
                                        'file': args.path
                                    }
                                  )
        print(ans)
        # Remark: Always do at least one 'delete_progress' query to
        #         catch immediate errors such as 'No such file or directory'
        #         or 'Operation not permitted'
        if args.wait:
            print("Delete task started. Please wait.")
        pid = ans['pid']
        progress=0
        delay=0.0
        start=time.time()
        while progress < 1 :
            time.sleep(delay)                
            r2, ans2 = nas.request_json( 'POST',
                                         "/portal/apis/fileExplorer/fileExplorer.cgi",
                                         json_raise_on_error=[5011],
                                         params = {
                                             'act': 'delete_progress',
                                             'pid': pid,
                                         }
                                    )
            delay=0.25
            if ans2['success'] == False and ans2['error_code'] == 5011 :                    
                print("Warning: Some files or directories were not deleted.")
                break
            else:
                progress = ans2['progress']
            if not args.wait:
                break
        elapsed=time.time()-start
        if args.wait:
            print("Delete task completed in %.2f seconds." % elapsed)
            
        return 0                

class LoginInfoAction(Action):
    
    def __init__(self, name, subparser):
        super().__init__( name, subparser,
                          help='Print login response',
                          description='Print login response'
                          )
        self.parser.add_argument('-r', '--raw', action='store_true',
                                 help="print the raw response")
        
    def run(self, nas, args):
        if args.raw :
            sys.stdout.buffer.write(nas.login_content)
        else:
            pprint.pprint(nas.login_info)
        
class NopAction(Action):
    
    def __init__(self, name, subparser):
        super().__init__( name, subparser,
                          help='Do nothing except login/logout',
                          description='Do nothing except login/logout'
                          )
       
    def run(self, nas, args):
        print('ok')
        return 0

class ListDirectoryAction(Action):
    
    def __init__(self, name, subparser, default_mode):
        self.name = name

        epilog=\
            "slkjfsdjf sdlfj sdj flksjd flkj sdlkfj lklld lj s  fl fj l jsl  flfljl  jlj fljljs ffldl js flkf\n"\
            "sdfjlsdf jkls dfklj sdklfj kldsj lkkj skffjlsjs  sk jl lfk slflks fjslkfj lsd jsdljsfjljfk d jf d \n"\
            "\n"\
            "  - aaa\n"\
            "  - bbb\n"\
            "  - ccc\n"\
            "  - ddd\n"\
            
        super().__init__( name,
                          subparser, 
                          help="List directory",
                          description='List directory',
                          epilog=epilog,
                          #formatter_class=argparse.RawTextHelpFormatter
                          formatter_class=argparse.RawDescriptionHelpFormatter
                         )
        self.parser.add_argument('-e', '--escape', action='store_true',
                                 help='escape special characters in filenames')
        self.parser.add_argument('-f', '--filter', type=str, metavar='TEXT',required=False, default=None,
                                 help='show only the filenames containing TEXT')
        
        # Those options control the output mode
        mode_group = self.parser.add_mutually_exclusive_group()
        mode_group.add_argument('-p', '--print', action='store_const', dest='mode', const='print', default=default_mode,
                                help='display the filenames separated by a newline')
        mode_group.add_argument('-0', '--print0', action='store_const', dest='mode', const='print0', default=default_mode,
                                help='display the filenames separated by a null \'\\0\' character')
        mode_group.add_argument('-l', '--long', action='store_const', dest='mode', const='long',
                                help='display using a long listing format')
        mode_group.add_argument('-a', '--all', action='store_const', dest='mode', const='full',
                                help='display the full response in python syntax')
        mode_group.add_argument('-r', '--raw', action='store_const', dest='mode', const='raw',
                                help='display the raw response (usually json)')
        
        self.parser.add_argument('location', nargs='?', default='share', 
                            help="The location to list (default is '%(default)s'}")

    def run(self, nas, args):
        
        # TODO: For now, 'paging' is not implemented. Be aware that
        # the HTTP request may take several minutes to complete when
        # the directory contains a few thousands entries. 
        page=None  
        start=None 
        limit=None 

        r, ans = nas.request_json( 'GET',
                                   "/portal/apis/fileExplorer/fileExplorer.cgi",
                                   params = {
                                       'act': 'file_list',
                                       'path': args.location,
                                       'filter': args.filter,
                                       'page':  page,
                                       'start': start,
                                       'limit': limit,
                                       'showhome':True  # Home is not listed by default in 'shares'
                                   } )


        if  args.mode == 'long' :
        
            octal_to_rwx={'0':'---', '1':'--x', '2':'-w-', '3':'-wx',
                          '4':'r--', '5':'r-x', '6':'rw-', '7':'rwx'}
            print("total {}".format(ans['total']) )
            for entry in ans['data'] :

                filename    = entry['filename']
                is_dir      = entry.get('is_dir',False)
                modify_time = entry.get('modify_time','?')
                file_size   = entry.get('file_size','?')
                owner       = entry.get('owner','?')
                group       = entry.get('group','?')
                file_permission = entry.get('file_permission','')

                if args.escape :
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

                print('{:10} {:10} {:10} {:12} {:16} {}'.format(mode, owner, group, file_size, modify_time, filename) )

        elif args.mode == 'print' or  args.mode == 'print0' :
            end="\0" if args.mode == 'print0' else "\n"
            for entry in ans['data'] :
                filename = entry['filename']
                if args.escape :
                    filename = filename.replace("\n",r'\n').replace("\t",r'\t').replace("\\",r'\\')
                print(filename,end=end)
                
        elif args.mode == 'full' :
            pprint.pprint(ans)
        elif args.mode == 'raw' :
            sys.stdout.buffer.write(r.content)
        else:
            raise Exception(f"Unhandled mode '{args.mode}'")

# Custom argparse action to load a credential file.
# The file shall contains 3 lines for the account, password and url.
#
# When they are not empty, the values will overwrite the
# option '--account', '--password' and '--url' 
# 
class LoadCredentials(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):                    
        super().__init__(option_strings, dest, **kwargs)
    def __call__(self, parser, namespace, value, option_string=None):
        # print('%r %r %r' % (namespace, value, option_string))
        assert hasattr(namespace, "main_account")
        assert hasattr(namespace, "main_password")
        assert hasattr(namespace, "main_url")
        with open(value,"r") as f:
            account  = f.readline().rstrip('\n')
            password = f.readline().rstrip('\n')
            url      = f.readline().rstrip('\n')
            if account:
                setattr(namespace,'main_account', account)
            if password:
                setattr(namespace,'main_password', password)
            if url:
                setattr(namespace,'main_url', url)

def main():
    global URL, ACCOUNT, PASSWORD 

    try:
        parser = argparse.ArgumentParser(description='Execute actions using the ADM Portal Web interface',
                                         epilog=
                                         "Each action provides its own documentation with -h, --help",
                                         formatter_class=argparse.RawTextHelpFormatter
                                         )
        # Note: Use 'main_' prefix for all attributes to avoid conflicts with action arguments.     
        parser.add_argument('-A', '--account', type=str, metavar='NAME', required=False, default=None,
                            dest='main_account', 
                            help='Set the ADM account name')
        parser.add_argument('-P', '--password', type=str, metavar='TEXT', required=False, default=None,
                            dest='main_password',
                            help='Set the ADM password')
        parser.add_argument('-U', '--url', type=str, metavar='HTTP', required=False, default=None,
                            dest='main_url',
                            help='Set the ADM url (e.g. https://hostname:port/) ')
        parser.add_argument('-C', '--credentials', type=str, metavar='FILE', required=False, default=None,
                            action=LoadCredentials,
                            help='Read ADM account, password and url from a file')
        parser.add_argument('-d', '--http-debug', action='store_true',
                            dest='main_http_debug',
                            help='Enable debug output in HTTPConnection')
        parser.add_argument('-l', '--logging-debug', action='store_true',
                            dest='main_logging_debug',
                            help='Enable debug in logging')
        
        subparsers = parser.add_subparsers(title='with',
                                           dest='main_action',
                                           required=True,
                                           metavar='ACTION',
                                           #description=':',
                                           # help="an action amongst ",
                                           ) 

        # Instanciate all known actions and their sub-argument parser
        CatAction('cat',subparsers) 
        DeleteAction('delete',subparsers) 
        DownloadAction('download',subparsers) 
        LoginInfoAction('login_info',subparsers)
        ListDirectoryAction('ls',subparsers,'print') 
        ListDirectoryAction('ll',subparsers,'long') 
        NopAction('nop',subparsers) 
        QueryAction('query',subparsers) 
        UploadAction('upload',subparsers) 

        #
        # Below are the simple queries with constant arguments.
        #
        
        BasicAction('activity-list',
                    subparsers,
                    cgi='/portal/apis/activityMonitor/act.cgi',
                    params={ 'act': 'list' },
                    help='TO BE DOCUMENTED',
                    #description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    )

        BasicAction('sysinfo-wan',
                    subparsers,
                    cgi='/portal/apis/information/sysinfo.cgi',
                    params={ 'act': 'wan' },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    ) 

        BasicAction('sysinfo-sys',
                    subparsers,
                    cgi='/portal/apis/information/sysinfo.cgi',
                    params={ 'act': 'sys' },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    ) 

        BasicAction('sysinfo-net',
                    subparsers,
                    cgi='/portal/apis/information/sysinfo.cgi',
                    params={ 'act': 'net' },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    )
        
        BasicAction('service-terminal-get',
                    subparsers,
                    cgi='/portal/apis/services/terminal.cgi',
                    params={ 'act': 'get' },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    ) 

        
        BasicAction('service-smb-get',
                    subparsers,
                    cgi='/portal/apis/services/windows.cgi',
                    params={
                        'act': 'get',
                        'tab': 'cifs'
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    ) 

        BasicAction('service-afp-get',
                    subparsers,
                    cgi='/portal/apis/services/mac.cgi',
                    params={
                        'act': 'get'
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    ) 

        BasicAction('service-nfs-get',
                    subparsers,
                    cgi='/portal/apis/services/nfs.cgi',
                    params={
                        'act': 'get',
                        'tab': 'Nfs_Get_Enable'
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    ) 

        BasicAction('service-ftp-general-get',
                    subparsers,
                    cgi='/portal/apis/services/ftp.cgi',
                    params={
                        'act': 'get',
                        'tab': 'general' 
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    ) 

        BasicAction('service-ftp-advanced-get',
                    subparsers,
                    cgi='/portal/apis/services/ftp.cgi',
                    params={
                        'act': 'get',
                        'tab': 'advanced'
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    ) 

        BasicAction('service-http-webdav-get',
                    subparsers,
                    cgi='/portal/apis/services/http.cgi',
                    params={
                        'act': 'get',
                        'tab': 'webdav'
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    )
        
        BasicAction('service-rsync-get-modules',
                    subparsers,
                    cgi='/portal/apis/services/rsync.cgi',
                    params={
                        'act': 'get_module_list',
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    )
        
        BasicAction('service-rsync-get',
                    subparsers,
                    cgi='/portal/apis/services/rsync.cgi',
                    params={
                        'act': 'get_sets',
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    )

        BasicAction('service-tftp-get',
                    subparsers,
                    cgi='/portal/apis/services/tftp_server.cgi',
                    params={
                        'act': 'get',
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    )
        
        BasicAction('service-snmp-get',
                    subparsers,
                    cgi='/portal/apis/services/tftp_server.cgi',
                    params={
                        'act': 'get',
                        'tab': 'Get'
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    )
        
        BasicAction('service-sftp-get',
                    subparsers,
                    cgi='/portal/apis/services/sftp.cgi',
                    params={
                        'act': 'get'
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    )
        
        BasicAction('service-proxy-get-blocks',
                    subparsers,
                    cgi='/portal/apis/services/proxy.cgi',
                    params={
                        'act': 'get_server_blocks'
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    )

        BasicAction('service-proxy-get-default',
                    subparsers,
                    cgi='/portal/apis/services/proxy.cgi',
                    params={
                        'act': 'get_default_proxy_info'
                    },
                    help='TO BE DOCUMENTED',
                    description='TO BE DOCUMENTED',
                    epilog='TO BE DOCUMENTED'
                    )
        
        BasicAction('basic',
                    subparsers,
                    '/portal/apis/services/proxy.cgi',
                    params= {
                        'act': 'get_default_proxy_info'
                    },
                    help='TO BE DOCUMENTED',                    
                    )
        
        a = parser.parse_args() 

        if a.main_logging_debug :
            logging.basicConfig(
                # filename='LOG.txt', filemode='w',
                stream=sys.stderr,
                level=logging.DEBUG,
                format='[%(levelname)s:%(name)s]  %(message)s',
            )
            url3_log = logging.getLogger('urllib3')
            url3_log.setLevel(logging.DEBUG)
            url3_log.propagate = True

        if a.main_http_debug:
            HTTPConnection.debuglevel = 1

        if a.main_url:
            URL=a.main_url
        if a.main_account:
            ACCOUNT=a.main_account
        if a.main_password:
            PASSWORD=a.main_password
            
        err=0
            
        nas = NasSession()

        nas.login(URL, ACCOUNT, PASSWORD)
        action = Action.find(a.main_action)
        ok = action.run(nas,a)
        assert type(ok)==bool
        nas.logout()
 
        sys.exit(int(!ok))  # So 0 in case of success otherwise 1
  
    except FileNotFoundError as e:
        err_print(e) 
        sys.exit(1)
        
    except PermissionError as e:
        err_print(e) 
        sys.exit(1)
        
    except requests.exceptions.RequestException as e:
        ename = full_class_name(e)
        err_print(f"{ename}: {e}")
        sys.exit(2)

    except NasSessionResponseError as e:
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
        # Warn about additional fields in error response
        more_keys=set(e.json.keys())
        more_keys.discard('success')
        more_keys.discard('error_msg')
        more_keys.discard('error_code')
        # lacked_acl is usually with 'Operation not permitted'.
        # This is a number describing the missing permissions 
        more_keys.discard('lacked_acl')  
        if more_keys: 
            err_print("Warning: Unhandled data in error response: {0}".format(", ".join(more_keys)))
        
        sys.exit(2)

    # Other exceptions are likely programming errors 
    
if __name__ == "__main__":
    main()
    
