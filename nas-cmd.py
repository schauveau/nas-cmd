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
        self.login_content = resp.content ;

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
        
class UploadAction(Action):
    def __init__(self, name, subparser):
        super().__init__( name,
                          subparser,
                          help='Upload a file to the NAS',
                          description='Upload a file',
                          epilog=\
                          "\n"\
                          "\n",
                          formatter_class=argparse.RawTextHelpFormatter )
        
        self.parser.add_argument('src',
                                 help="Source file")
        
        self.parser.add_argument('dest', 
                                 help="Destination directory in an accessible share")
        
        self.parser.add_argument('filename',  nargs='?', default=None,                        
                                 help="The filename to create. Default is to reuse\n"\
                                 "the name of the source file"
                                 )
        
    def run(self, nas, args):
        src=Path(args.src)
        if not src.is_file() :
            err_print("specified src does not exist or is not a file")
            sys.exit(1)

        with src.open("rb") as f :
            payload=f.read()

        if not args.filename is None: 
            filename = args.filename
        else:
            filename = src.name

        files = {'file': (filename,  payload , "text/plain") }

        r, json = nas.request_json( 'POST',
                                    "/portal/apis/fileExplorer/upload.cgi",
                                    params = {
                                        'act': 'upload',
                                        'overwrite': 1,  # 0=skip 1=overwrite
                                        'path': args.dest,
                                        # 'filesize': len(payload),  # Not really needed?
                                    },
                                    files = { 'file': (filename,  payload , "application/octet-stream")  }
                                   )

        
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
        
        self.parser.add_argument('src',  default='share', 
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

class CatAction(Action):
    def __init__(self, name, subparser):
        super().__init__( name,
                          subparser,
                          help='Download and display a file',
                          description='Download and print a file to stdout',
                          epilog=\
                          "\n"\
                          "\n",
                          formatter_class=argparse.RawTextHelpFormatter
                         )
        self.parser.add_argument('-i', '--info', action='store_true',
                                 help='print summary information instead')
        self.parser.add_argument('src',  default='share', 
                                 help="")        
    def run(self, nas, args):

        # Detect an explicit directory syntax before it is simplified by PurePosixPath 
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
                                        'file': src.name
                                    }
                                   )

        # The only JSON responses expected after a download request are error messages
        # and they should raise an exception. Just to be sure ...
        assert json is None

        if args.info:
            md5sum=hashlib.md5(r.content).hexdigest()
            print(f"filename={repr(src.name)}")
            print(f"directory={repr(str(src.parent))}")
            print(f"size={len(r.content)}")
            print(f"md5={md5sum}")
        else:
            sys.stdout.buffer.write(r.content)

        return 0

    

class QueryAction(Action):
    def __init__(self, name, subparser):
        super().__init__( name,
                          subparser,
                          help='Perform a custom cgi query',
                          description='Perform a custom cgi query',
                          epilog=\
                          "\n"\
                          "Each spec should be of one of the following forms:\n"\
                          "   name=value to pass a argument in the URL (i.e. GET)\n"\
                          "   name:=value to pass a argument in the body (i.e. POST)\n"\
                          "   name@=filename to attach a file to the request\n"\
                          "\n"\
                          "The 'sid' argument is implictly passed and should not be specified here\n"\
                          ,
                          formatter_class=argparse.RawTextHelpFormatter
                         )
        self.parser.add_argument('-i', '--ignore-response', action='store_true',
                                help='Do not attempt to interpret response (silent)')
        self.parser.add_argument('-H', '--show-headers', action='store_true',
                                help='Print the response headers ')
        self.parser.add_argument('-r', '--raw', action='store_true',
                                 help="Print the raw response content")
        self.parser.add_argument('-o', '--output', type=str, metavar='FILE',required=False, default=None, 
                                 help="Save the response content to file")
        self.parser.add_argument('-s', '--save-headers', type=str, metavar='FILE',required=False, default=None, 
                                 help="Save the response headers to file")
        self.parser.add_argument('-c', '--content-type', type=str, metavar='STR',required=False, default=None, 
                                 help="Set the content type for all file specifications")
        self.parser.add_argument('cgi',
                                 help="path to the cgi file")
        self.parser.add_argument('spec', nargs='*',
                                 help="parameter specification of the form name=value or name:=value")
       
    def run(self, nas, args):

        cgi = args.cgi
        if not ( cgi.startswith('/portal/apis/') and cgi.endswith('.cgi') ) :
            err_print("cgi should be of the form '/portal/apis/.../FILE.cgi'")
            sys.exit(2)

        # Transform each param_spec into an entry in params, data or files
        params={}
        data={}
        files={}
        re_spec=re.compile("^([a-zA-Z_][a-zA-Z_0-9]*)(=|:=|@=)(.*)$")
        for spec in args.spec:
            m = re_spec.match(spec)
            if not m:
                err_print(f"unexpected argument {spec}. Expect name=value or name:=value")
                sys.exit(1)
            name=m.group(1)
            sep=m.group(2)
            value=m.group(3)
            if name == 'sid':
                err_print(f"Warning: Ignoring sid parameter")
                continue
            if sep == '=' :
                params[m.group(1)] = m.group(3) 
            elif sep == ':=' :
                data[m.group(1)] = m.group(3) 
            elif sep == '@=' :
                filename=m.group(3)
                if args.content_type:
                    content_type=args.content_type
                else:
                    content_type=guess_content_type(filename)
                    err_print(f"Warning: No content type specified. Guessing {content_type}")
                    
                with open(filename,"rb") as f:
                    files[m.group(1)] = ( Path(filename).name , f.read(), content_type )
            else:
                assert False

        r = nas.request('POST',
                        cgi,
                        params = params,
                        data   = data,
                        files  = files
                        )

        if args.output:
            with open(args.output, "wb") as out:
                out.write(r.content)
        
        if args.show_headers:
            for key in sorted(r.headers.keys()):
                print(f"{key}: {r.headers[key]}")
            print("")        
            
        if args.save_headers:
            with open(args.save_headers, "w") as out:
                for key in sorted(r.headers.keys()):
                    print(f"{key}: {r.headers[key]}",file=out)
            
        if args.ignore_response:
            return 0        
        
        if args.raw:        
            sys.stdout.buffer.write(r.content)
            return 0
        
        print(f"Response contains {len(r.content)} bytes")
        
        content_disposition = r.headers.get('Content-Disposition','')
        if content_disposition.startswith('attachment;'):
            print(f"Attachement detected: {content_disposition}. ")                
            return 0
        else:
            print(f"Interpreting response as JSON")                
            j = nas.response_as_json( r, False )
            pprint.pprint(j)
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
            "\n"\
            "Parameter specifications of the form name=value are sent in the query string \n"\
            "while those of the form name:=value are sent in the body. \n"\
            "\n"\
            "The 'sid' argument is implictly passed and should not be specified here\n"
            
        super().__init__( name,
                          subparser, 
                          help="List directory",
                          description='List directory',
                          epilog=epilog,
                          formatter_class=argparse.RawTextHelpFormatter
                         )
        self.parser.add_argument('-e', '--escape', action='store_true',
                                 help='escape special characters in filenames')
        self.parser.add_argument('-f', '--filter', type=str, metavar='TEXT',required=False, default=None,
                                 help='show only the filenames containing TEXT')
        self.parser.add_argument('-0', '--null', action='store_true',
                                 help='use null character as separator instead of newline (short mode only)')
        
        # Those options control the output mode
        mode_group = self.parser.add_mutually_exclusive_group()
        mode_group.add_argument('-s', '--short', action='store_const', dest='mode', const='short', default=default_mode,
                                help='display the filenames only')
        mode_group.add_argument('-l', '--long', action='store_const', dest='mode', const='long',
                                help='display using a long listing format')
        mode_group.add_argument('-a', '--all', action='store_const', dest='mode', const='full',
                                help='display the full response')
        mode_group.add_argument('-r', '--raw', action='store_const', dest='mode', const='raw',
                                help='display the raw json response ')
        
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

        elif args.mode == 'short' :
            sep=''
            for entry in ans['data'] :
                filename    = entry['filename']
                if args.escape :
                    filename = filename.replace("\n",r'\n').replace("\t",r'\t').replace("\\",r'\\')
                print(sep,end="")
                print(filename,end="")
                if args.null:
                    sep="\0"
                else:
                    sep="\n"
        elif args.mode == 'full' :
            pprint.pprint(ans)
        elif args.mode == 'raw' :
            sys.stdout.buffer.write(r.content)
        else:
            raise "Unhandled mode"

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
                                         usage='nas-cmd.py [OPTION...] ACTION ...',
                                         epilog=
                                         "Use ACTION -h for a detailed description of the arguments\n" \
                                         "supported by each action.",
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
        
        subparsers = parser.add_subparsers(title='Possible ACTIONs are',
                                           dest='main_action',
                                           required=True,
                                           metavar='ACTION',
                                           #description=':',
                                           # help="an action amongst ",
                                           ) 

        # Instanciate all known actions and their sub-argument parser
        CatAction('cat',subparsers) 
        DownloadAction('download',subparsers) 
        LoginInfoAction('login_info',subparsers)
        ListDirectoryAction('ls',subparsers,'short') 
        ListDirectoryAction('ll',subparsers,'long') 
        NopAction('nop',subparsers) 
        QueryAction('query',subparsers) 
        UploadAction('upload',subparsers) 
        
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
            
        nas = NasPortal()

        nas.login(URL, ACCOUNT, PASSWORD)
        action = Action.find(a.main_action)
        err = action.run(nas,a)
        nas.logout
 
        sys.exit(err)

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
        # Warn about additional fields in error response
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
    
