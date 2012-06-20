from xmlrpcssl import *

class SecureLDAPXMLRPCServer(SecureAuthenticatedXMLRPCServer):

    def ldap_verify(self, user_to_find, password):
        """Verify that a provided username and password are in the
        provided LDAP server and DN"""

        search_filter = "cn=%s*"

        user_to_find = filter.escape_filter_chars(user_to_find)

        search_filter = search_filter % user_to_find

        con = ldap.initialize(self.ldap_server)
        con.set_option(ldap.OPT_X_TLS_DEMAND, True)

        retrieve_attributes = ["dn"]

        try:
            ldap_result_id = con.search(self.base_dn, self.search_scope,
                                        search_filter, retrieve_attributes)
            result_set = []
            while 1:
                result_type, result_data = con.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
            for result in result_set:
                find_dn = result[0][0]
                con.simple_bind(find_dn, password)
                result = con.result()

                if result[0] == 97:
                    return True
                else:
                    return False
        except ldap.LDAPError, e:
            if self.logRequests:
                logging.error("Login failed for user %s (%s) with error: %s" % (
                        user_to_find, find_dn, e[0]["desc"]))
            return False
        else:
            if self.logRequests:
                logging.info("Didn't find user %s in %s" % (user_to_find, self.base_dn))
            return False

    def __init__(self, server_address, keyfile, certfile, ldap_server,
                 base_dn, search_scope=ldap.SCOPE_SUBTREE, logRequests=True, path="/"):

        """Create a HTTPS-enabled XMLRPC server with using an LDAP server for authentication

        ldap_server is the URI for the LDAP server itself, ie ldaps://myserver
         this module forces TLS by default
        base_dn is the dn in which to base the search itself ie ou=ops,ou=Accounts,dc=example,dc=com
        search_scope is an ldap scope variable, most likely you want SCOPE_SUBTREE
        """

        self.ldap_server = ldap_server
        self.base_dn = base_dn
        self.search_scope = search_scope
        SecureAuthenticatedXMLRPCServer.__init__(self,
                                                 server_address, keyfile, certfile,
                                                 "", "", #username and password
                                                 self.ldap_verify, #user_verify
                                                 logRequests, path)
