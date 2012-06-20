python-xmlrpcssl
===========

A poorly-named set of python modules for securing Python's XMLRPC
ssl.

Coomponents
-----------

The most basic object provided by these modules is SecureXMLRPCServer,
an XMLRPC server that uses (for 2.7 and later) Python's built-in **ssl**
module to encrypt communications. This can be connected to with
xmlrpclib as usual by using a HTTPS url.

Two companion classes are provided that replace the
SecureXMLRPCRequestHandler in the server,
SecureAuthenticatedXMLRPCServer and SecureLDAPXMLRPCServer.

SecureAuthenticatedXMLRPCServer provides a server that uses simple
HTTP auth for access.

SecureLDAPXMLRPCServer provides a server that searches a given LDAP
basedn for a particular user in order to respond.

Requirements
-----------

The **ssl** module was introduced into Python's standard library in
version 2.6. This code has only been extensively tested against 2.7.

Use of SecureLDAPXMLRPCServer requires [Python-LDAP][pyldap].

License
-----------

Developed for Demonware/Activision Blizzard Inc. Released under the BSD License

[pyldap]: http://www.python-ldap.org/