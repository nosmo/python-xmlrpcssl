#!/usr/bin/env python2.5

"""ssl XMLRPC server with pluggable authentication methods

With inspiration from
http://code.activestate.com/recipes/496786-simple-xml-rpc-server-over-https/
"""

from base64 import b64decode
import BaseHTTPServer
import SimpleXMLRPCServer
import SocketServer
import socket
import ssl

class SecureXMLRPCRequestHandler(SimpleXMLRPCServer.SimpleXMLRPCRequestHandler):
    """HTTPS XMLRPC handler class"""

    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

    def __init__(self, req, addr, server):
        SimpleXMLRPCServer.SimpleXMLRPCRequestHandler.__init__(self, req,
                                                               addr, server)

    def do_POST(self):
        """Handle HTTPS post requests"""

        try:
            data = self.rfile.read(int(self.headers["content-length"]))
            # In previous versions of SimpleXMLRPCServer, _dispatch
            # could be overridden in this class, instead of in
            # SimpleXMLRPCDispatcher. To maintain backwards compatibility,
            # check to see if a subclass implements _dispatch and dispatch
            # using that method if present.
            response = self.server._marshaled_dispatch(
                    data, getattr(self, '_dispatch', None)
                )
        except Exception, post_exception:
            self.send_response(500)
            self.end_headers()
            raise post_exception
        else:
            # Proceeding normally
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.send_header("Content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

            # shut down the connection
            self.wfile.flush()

class SecureXMLRPCServer(BaseHTTPServer.HTTPServer,
                         SimpleXMLRPCServer.SimpleXMLRPCDispatcher):

    def __init__(self, server_address, keyfile, certfile,
                 HandlerClass=SecureXMLRPCRequestHandler, logRequests=True):
        """HTTPS XMLRPC server.

         Provide a new HandlerClass to insert authentication methods!
         See below for an example.
        """
        self.logRequests = logRequests

        try:
            SimpleXMLRPCServer.SimpleXMLRPCDispatcher.__init__(self)
        except TypeError:
            # python > 2.5
            SimpleXMLRPCServer.SimpleXMLRPCDispatcher.__init__(self, False, None)

        SocketServer.BaseServer.__init__(self, server_address, HandlerClass)

        self.socket = ssl.wrap_socket(socket.socket(self.address_family,
                                                    self.socket_type),
                                      server_side=True,
                                      certfile=certfile,
                                      keyfile=keyfile,
                                      ssl_version=ssl.PROTOCOL_SSLv23)

        self.server_bind()
        self.server_activate()

class SecureThreadedXMLRPCServer(SocketServer.ThreadingMixIn,
                                 SecureXMLRPCServer):
    # Just importing the threading mixin for magic
    pass

class SecureAuthenticatedXMLRPCServer(SecureXMLRPCServer):
    # A HTTP xmlrpc server with simple HTTP authentication

    def user_verify(self, request_user, request_pass):
        if request_user == self.__username and request_pass == self.__password:
            return True

    def authenticate(self, headers):
        auth_header = headers.get('Authorization')
        if not auth_header:
            return False
        (basic, _, encoded) = auth_header.partition(' ')
        assert basic == 'Basic', 'Only basic authentication supported'
        (username, _, password) = b64decode(encoded).partition(':')
        if self.user_verify(username, password):
            return True
        else:
            return False

    def __init__(self, server_address, keyfile, certfile,
                 username="", password="", user_verify=None,
                 logRequests=True, path="/"):
        """Secure XMLRPC server.

        It it very similar to SimpleXMLRPCServer but it uses HTTPS for transporting XML data.
        """
        self.logRequests = logRequests
        self.paths = (path)

        if user_verify:
            # inserting this with an eye to plugging into LDAP
            self.user_verify = user_verify
        else:
            if not username or not password:
                raise Exception("Username or password not supplied with standard auth!")

            self.__username = username
            self.__password = password


        class VerifyingRequestHandler(SecureXMLRPCRequestHandler):
            rpc_paths = self.paths
            def parse_request(handlerself):

                # In a perfect world, handlerself, would be self, but
                # just to be clear given that we're already within
                # SecureAuthenticatedXMLRPCServer, name it awkwardly

                # Handle the request to see if it's a normal request
                if SimpleXMLRPCServer.SimpleXMLRPCRequestHandler.parse_request(handlerself):
                    if self.authenticate(handlerself.headers):
                        return True
                    else:
                        handlerself.send_error(401, 'Authentication failed')
                return False

        try:
            SimpleXMLRPCServer.SimpleXMLRPCDispatcher.__init__(self)
        except TypeError:
            # fix for python > 2.5
            SimpleXMLRPCServer.SimpleXMLRPCDispatcher.__init__(self, False, None)

        SocketServer.BaseServer.__init__(self, server_address, VerifyingRequestHandler)
	self.socket = ssl.wrap_socket(socket.socket(self.address_family,
						    self.socket_type),
				      server_side=True,
				      certfile=certfile,
				      keyfile=keyfile,
				      ssl_version=ssl.PROTOCOL_SSLv23)
        self.server_bind()
        self.server_activate()

# Messy way to avoid making python-ldap mandatory - there must be a
# nicer way to do this

SecureLDAPXMLRPCServer = None
try:
    import ldap
except ImportError:
    SecureLDAPXMLRPCServer = "ldap module not found"
else:
    import ldapserver
    SecureLDAPXMLRPCServer = ldapserver.SecureLDAPXMLRPCServer

if __name__ == '__main__':

    a = SecureXMLRPCServer(("127.0.0.1", 4433), SecureXMLRPCRequestHandler)
    def derp():
        # toy test function
        return "hurrrr"
    a.register_function(derp)
    a.serve_forever()
