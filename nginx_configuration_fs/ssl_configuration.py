#!/usr/bin/env python
# -*- coding: utf8 -*-
import	os

import 	stat

import 	re

import  threading

from    plone.synchronize       import  synchronized

from    plone.memoize       	import  volatile

import 	pprint

import 	dns.resolver

from 	contextlib   		import 	closing

import	colorama

import 	pyinotify

import  subprocess

from 	OpenSSL.crypto 		import 	load_certificate, load_privatekey, dump_privatekey, FILETYPE_PEM

import 	hashlib

import	json

import	shared_infrastructure

class SSLConfiguration():

    _configurations_lock           	=       threading.RLock()

    def __init__(
        self, 
        root_ssl_configuration,
	resolver_conf,
        ssl_certificate_filename,
        ssl_certificate_key_filename,
        restart_nginx,
    ):

        self._root_ssl_configuration		= root_ssl_configuration

	self._resolver_conf			= resolver_conf

        self._ssl_certificate_filename		= ssl_certificate_filename

        self._ssl_certificate_key_filename	= ssl_certificate_key_filename

        self._restart_nginx			= restart_nginx

        # Gestion de iNotify	
        wm 					= pyinotify.WatchManager() 
	mask 					= 				\
            pyinotify.IN_MODIFY 	|					\
            pyinotify.IN_CREATE 	| 					\
            pyinotify.IN_DELETE 	| 					\
            pyinotify.IN_ATTRIB 	| 					\
            pyinotify.IN_MOVED_TO	|					\
            pyinotify.IN_MOVED_FROM


        class EventHandler( pyinotify.ProcessEvent ):

             def process_evt( o, event ):

                 def restart_nginx():
    
                      try:
    
                          subprocess.call( self._restart_nginx, shell = True )
    
                      except: 

                          self._l_bad_configurations.append( ( '%s error' % ( self._restart_nginx ), ) )
    
                          shared_infrastructure.cache_container_ssl_configuration.clear()
                          shared_infrastructure.cache_container_nginx_fs.clear()

                 path_elements = \
                     filter( 
                         None, 
                         event.pathname[  
                             len( self._root_ssl_configuration.rstrip( os.sep ) + os.sep ):
                         ].split( os.sep )
                     )

                 if len( path_elements ) == 0 and event.mask & pyinotify.IN_ATTRIB:

                     self.load_configurations( reload_without_version_control = True )

                     return restart_nginx()

                 if 								\
                     event.dir						and	\
                     ( 
                         len( path_elements	) == 1			or	\
                         len( path_elements	) == 2
                     ):

                     if self.load_configurations( reload_without_version_control = False ):

                         return restart_nginx()


                 if len( path_elements ) != 3:

		     return None

                 if re.match( 
                     '^%s|%s$' % ( 
                         self._ssl_certificate_filename,
                         self._ssl_certificate_key_filename,
                     ),
                     path_elements[ 2 ]
                 ): 

                     if self.load_configurations( reload_without_version_control = False ):

                         return restart_nginx()

                        
             process_IN_MODIFY 		= process_evt

             process_IN_CREATE		= process_evt

             process_IN_DELETE		= process_evt

             process_IN_ATTRIB		= process_evt

             process_IN_MOVED_TO	= process_evt

             process_IN_MOVED_FROM	= process_evt

        self._notifier 				= pyinotify.ThreadedNotifier( wm, EventHandler() )

        self._notifier.coalesce_events()

        wm.add_watch( 
            self._root_ssl_configuration, 
            mask, 
            rec=True,
            auto_add=True
        )
             
        self._d_configurations 			= {}

        self._l_bad_configurations 		= []

        self.load_configurations()


    def get_notifier( self ):
        return self._notifier
    notifier 			= property( get_notifier, None, None )


    @synchronized( _configurations_lock )
    def get_d_configurations( self ):
        return self._d_configurations
    d_configurations 		= property( get_d_configurations, None, None )


    @synchronized( _configurations_lock )
    def get_l_bad_configurations( self ):
        return self._l_bad_configurations
    l_bad_configurations 	= property( get_l_bad_configurations, None, None )

    def have_ssl(
         self,
         server,
         port
    ):
         return bool( self.d_configurations.get( server ).get( port, False ) ) if self.d_configurations.get( server ) else False

    def get_ssl_configuration(
         self,
         server,
         port
    ):
         return self.d_configurations[ server ][ port ] if self.have_ssl( server, port ) else {}

    @synchronized( _configurations_lock )
    def load_configurations( self, reload_without_version_control = False ):

        d_configurations 	= {}

        l_bad_configurations	= []

        # Obtention d'un resolveur base sur le resolv_conf fouri
        self._resolver		= dns.resolver.Resolver( self._resolver_conf )
        self._resolver.query    = shared_infrastructure.catch_NoNamesservers( self._resolver.query )

        # Recherche des serveurs
        for server in [ 
                       s 
                       for s 
                       in os.listdir( self._root_ssl_configuration )
                       if os.path.isdir( self._root_ssl_configuration.rstrip( os.sep ) + os.sep + s )
                      ]:

            # Si le nom ne correspond pas a un nom resolvable
            # la configuration n'est pas prise en compte
            if not self._resolver.query( server, 'A' ) and not self._resolver.query( server, 'AAAA' ):
                l_bad_configurations.append( ( '%s not resolvable' % ( server ), self._root_ssl_configuration, server, ) )
                continue

            try:
                if not os.listdir( self._root_ssl_configuration.rstrip( os.sep ) + os.sep + server ):
                    l_bad_configurations.append( ( '%s no port definition' % ( server ), self._root_ssl_configuration, server, ) )
                    continue
            except:
                # En cas de suppression de la racine
                # entre le listdir dans la boucle
                # et l'usage du server dans la cronstrcuion
                # de chemin, le repertoire server
                # peut avoir disparu.
                continue

            # Recherche des ports
            for port in [ 
                         p
                         for p
                         in os.listdir( self._root_ssl_configuration.rstrip( os.sep ) + os.sep + server )
                      ]:

                # Si le repertoire ne correspond pas au format d'un nom de port
                # la configuration n'est pas prise en compte
                try:
                   if not( re.match( '\d{1,5}', port ) and int( p ) <= 65535 ):
                        raise Exception()
                except:
                        l_bad_configurations.append( ( '%s unvalid port format' % ( port ), self._root_ssl_configuration, server, port ) )
                        continue

                # Les 3 fichiers de configuration doivent etre present
                # n'est present, la configuration n'est
                # pas prise en compte

                ssl_certificate_filepath	=					\
                    self._root_ssl_configuration.rstrip( os.sep ) + os.sep + 		\
                    server + os.sep + 							\
                    port + os.sep + 							\
                    self._ssl_certificate_filename

                ssl_certificate_key_filepath	= 					\
                    self._root_ssl_configuration.rstrip( os.sep ) + os.sep + 		\
                    server + os.sep + 							\
                    port + os.sep + 							\
                    self._ssl_certificate_key_filename

                try:
                    if \
                        not ( 								\
                             os.path.isfile( ssl_certificate_filepath ) 	and	\
                             os.path.isfile( ssl_certificate_key_filepath )
                       ):
                       l_bad_configurations.append( 
                           ( 
                               '%s AND %s must be present' % \
                                   ( 
                                       self._ssl_certificate_filename, 
                                       self._ssl_certificate_key_filename, 
                                   ), 
                               self._root_ssl_configuration, 
                               server, 
                               port 
                           ) 
                       )
                       continue
                except:
                    # En cas de suppression de la racine
                    # entre le listdir dans la boucle
                    # et l'usage du server dans la cronstrcuion
                    # de chemin, le repertoire server
                    # peut avoir disparu.
                    continue

                st_certificate_key_filepath 	= os.stat( ssl_certificate_key_filepath )

                if \
                    bool( st_certificate_key_filepath.st_mode & stat.S_IROTH ) or	\
                    bool( st_certificate_key_filepath.st_mode & stat.S_IWOTH ) or	\
                    bool( st_certificate_key_filepath.st_mode & stat.S_IXOTH ) or	\
                    not bool( st_certificate_key_filepath.st_mode & stat.S_IRGRP )	\
                   :
                   l_bad_configurations.append( 
                       ( 
                           '%s must be -r--r-----' % \
                               ( 
                                   self._ssl_certificate_key_filename, 
                               ), 
                           self._root_ssl_configuration, 
                           server, 
                           port 
                       ) 
                   )
                   continue

                digest_ssl_certificate 		= None
                digest_ssl_certificate_key 	= None

                try:
                    with closing( open( ssl_certificate_filepath ) ) as ssl_certificates:
                        digest_ssl_certificate	= 		\
                            load_certificate(
                                FILETYPE_PEM, 
                                ssl_certificates.read()
                            ).digest( 'sha1' )

                except Exception, e:
                   l_bad_configurations.append(
                       (
                           'ssl problem with %s (%s)' % \
                               (
                                   self._ssl_certificate_filename,
                                   repr( e )
                               ),
                           self._root_ssl_configuration,
                           server,
                           port
                       )
                   )
                   continue

                try:
                    with closing( open( ssl_certificate_key_filepath ) ) as ssl_certificate_key:
                        digest_ssl_certificate_key	= 		\
                            hashlib.sha1(
                                dump_privatekey(
                                    FILETYPE_PEM,
                                    load_privatekey(
                                        FILETYPE_PEM, 
                                        ssl_certificate_key.read()
                                    )
                                )
                            ).hexdigest()

                except Exception, e:
                   l_bad_configurations.append(
                       (
                           'problem with %s (%s)' % \
                               (
                                   self._ssl_certificate_key_filename,
                                   repr( e )
                               ),
                           self._root_ssl_configuration,
                           server,
                           port
                       )
                   )
                   continue

                d_configurations.setdefault(
                    server,
                    {}
                ).setdefault(
                    port,
                    {
                         'ssl_certificate_digest'		: digest_ssl_certificate,
                         'ssl_certificate_key_digest'		: digest_ssl_certificate_key,
                         'ssl_certificate_filepath'		: ssl_certificate_filepath,
                         'ssl_certificate_key_filepath'		: ssl_certificate_key_filepath,
                    }
                )


        if  													\
                 reload_without_version_control 								\
             or													\
                 self.get_version_configurations( d_configurations ) <> self.current_version_configurations	\
             or													\
                 hashlib.sha1( repr( l_bad_configurations ) ).hexdigest() <> hashlib.sha1( repr( self._l_bad_configurations ) ).hexdigest():

            self._d_configurations         =       d_configurations
            self._l_bad_configurations     =       l_bad_configurations
            shared_infrastructure.cache_container_ssl_configuration.clear()
            shared_infrastructure.cache_container_nginx_fs.clear()

            return True

        return False

    @synchronized( _configurations_lock )
    def _get_version_configurations( self, d_configurations ):

        return \
            hashlib.sha1(
                json.dumps(
                    d_configurations,
                    sort_keys   = True,
                    cls         = shared_infrastructure.DictWithMaskableKeysEncoder,
                )
            ).hexdigest()

    get_version_configurations	= _get_version_configurations


    @synchronized( _configurations_lock )
    def get_current_version_configurations( self ):

        return \
            self._get_version_configurations(
                self.d_configurations
            )

    current_version_configurations	= 	\
        property(
            get_current_version_configurations,
            None,
            None
        )
