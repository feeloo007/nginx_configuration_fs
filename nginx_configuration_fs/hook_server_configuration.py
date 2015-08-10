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

import 	hashlib

import	json

import	shared_infrastructure

from 	jinja2 			import BaseLoader, TemplateNotFound


class HookServerConfiguration(
    shared_infrastructure.IAddToConfigurationWithMappingType
    ,
    BaseLoader
    ):

    _configurations_lock           	=       threading.RLock()

    def __init__(
        self,
        root_hook_server_configuration,
	resolver_conf,
        l_hook_server_filenames,
        restart_nginx,
    ):

        self._root_configuration		= root_hook_server_configuration

	self._resolver_conf			= resolver_conf

        self._l_hook_server_filenames		= l_hook_server_filenames

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

                          shared_infrastructure.cache_container_hook_server_configuration.clear()
                          shared_infrastructure.cache_container_nginx_fs.clear()

                 path_elements = \
                     filter(
                         None,
                         event.pathname[
                             len( self._root_configuration.rstrip( os.sep ) + os.sep ):
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
                     (
                         '^%s$' % (
                             '|'.join(
                                 [ '%s' for valid_filename in self._l_hook_server_filenames ]
                             )
                         )
                     ) % tuple( self._l_hook_server_filenames )
                     ,
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
            self._root_configuration,
            mask,
            rec=True,
            auto_add=True
        )

        self._d_configurations 			= {}

        self._l_bad_configurations 		= []

        self.load_configurations()

    # Implémentation de la méthode Laoder pour jinja2
    def get_source(
            self
            ,
            environment
            ,
            template_filepath
        ):

        # Vérifie si le template est dans un sous répertoire
        # de self._root_configuration
        if not re.search(
            '%s%s(.*)' %					\
                (
                    self._root_configuration.rstrip( os.sep )
                    ,
                    os.sep
                )
            ,
            template_filepath
        ):
            raise TemplateNotFound( template_filepath )

        if not os.path.exists( template_filepath ):

            raise TemplateNotFound( template_filepath )

        source 			=					\
            u''

        BLOCKSIZE               = 					\
            65536

        with closing( file( template_filepath ) ) as f:

            buf 		=					\
                f.read( BLOCKSIZE ).decode( 'utf-8' )

            while len( buf ) > 0:
                source 		+=					\
                    buf

                buf 		= 					\
                    f.read(BLOCKSIZE).decode( 'utf-8' )

        mtime 			=					\
            os.path.getmtime( template_filepath )

        return 								\
            source							\
            ,								\
            template_filepath						\
            ,								\
            lambda: mtime == os.path.getmtime( template_filepath )	\

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

    @synchronized( _configurations_lock )
    def load_configurations( self, reload_without_version_control = False ):

        d_configurations 	= {}

        l_bad_configurations	= []

        # Obtention d'un resolveur base sur le resolv_conf fouri
        self._resolver		= dns.resolver.Resolver( self._resolver_conf )
        self._resolver.query    = shared_infrastructure.catch_NoNamesservers( self._resolver.query )

        BLOCKSIZE 		= 65536

        def get_hook_server_filehash( filename ):
            hasher 		= hashlib.sha1()
            with closing( open( filename ) ) as f:
                buf = f.read( BLOCKSIZE )
                while len( buf ) > 0:
                    hasher.update( buf )
                    buf = f.read(BLOCKSIZE)
            return hasher.hexdigest()

        # Recherche des serveurs
        for server in [
                       s
                       for s
                       in os.listdir( self._root_configuration )
                       if os.path.isdir( self._root_configuration.rstrip( os.sep ) + os.sep + s )
                      ]:

            # Si le nom ne correspond pas a un nom resolvable
            # la configuration n'est pas prise en compte
            if not self._resolver.query( server, 'A' ) and not self._resolver.query( server, 'AAAA' ):
                l_bad_configurations.append( ( '%s not resolvable' % ( server ), self._root_configuration, server, ) )
                continue

            try:
                if not os.listdir( self._root_configuration.rstrip( os.sep ) + os.sep + server ):
                    l_bad_configurations.append( ( '%s no port definition' % ( server ), self._root_configuration, server, ) )
                    continue
            except:
                # En cas de suppression de la racine
                # entre le listdir dans la boucle
                # et l'usage du server dans la cronstrcuion
                # de chemin, le repertoire server
                # peut avoir disparu.
                continue

            # Recherche des ports
            for port in os.listdir( self._root_configuration.rstrip( os.sep ) + os.sep + server ):

                # Si le repertoire ne correspond pas au format d'un nom de port
                # la configuration n'est pas prise en compte
                try:
                   if not( re.match( '\d{1,5}', port ) and int( port ) <= 65535 ):
                        raise Exception()
                except:
                        l_bad_configurations.append( ( '%s unvalid port format' % ( port ), self._root_configuration, server, port ) )
                        continue

                d_configurations.setdefault(
                    server,
                    {}
                ).setdefault(
                    port,
                    dict(
                        [
                            (
                                hook_server_name
                                ,
                                {
                                    'path':
                                        hook_server_filepath
                                    ,
                                    'hash':
                                        get_hook_server_filehash( hook_server_filepath )
                                }
                            )
                            for hook_server_name, hook_server_filepath
                            in map(
                               lambda hook_server_name:
                                   (
                                       hook_server_name
                                       ,
                                       self._root_configuration.rstrip( os.sep ) 	+ 	\
                                       os.sep 						+ 	\
                                       server 						+ 	\
                                       os.sep 						+	\
                                       port						+ 	\
                                       os.sep 						+ 	\
                                       hook_server_name
                                   )
                               ,
                               sorted(
                                   self._l_hook_server_filenames
                               )
                            )
                            if (
                                True
                                if
                                   os.path.isfile( hook_server_filepath )
                                else
                                (
                                    l_bad_configurations.append( ( '%s is present but is not a file' % ( hook_server_name, ), self._root_configuration, server, port ) )
                                    if
                                       os.path.exists( hook_server_filepath )
                                    else
                                       False
                                )
                            )
                        ]
                    )
                )


        if  													\
                 reload_without_version_control 								\
             or													\
                 self.get_version_configurations( d_configurations ) <> self.current_version_configurations	\
             or													\
                 hashlib.sha1( repr( l_bad_configurations ) ).hexdigest() <> hashlib.sha1( repr( self._l_bad_configurations ) ).hexdigest():

            self._d_configurations         =       d_configurations
            self._l_bad_configurations     =       l_bad_configurations
            shared_infrastructure.cache_container_hook_server_configuration.clear()
            shared_infrastructure.cache_container_nginx_fs.clear()

            return True

        return False

    get_id_configurations       =                               \
        synchronized(
            _configurations_lock
        )(
            volatile.cache(
                shared_infrastructure.cache_key,
                lambda *args:                                   \
                    shared_infrastructure.cache_container_hook_server_configuration
            )(
                shared_infrastructure.get_id_configurations
            )
        )
    id_configurations   = property( get_id_configurations, None, None )


    filter_id_configurations    =                               \
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args:                                       \
                shared_infrastructure.cache_container_hook_server_configuration
        )(
            shared_infrastructure.filter_id_configurations
        )


    get_list_configurations_filenames   =                                       \
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args:                                                       \
                shared_infrastructure.cache_container_hook_server_configuration
        )(
            shared_infrastructure.get_list_configurations_filenames
        )

    get_last_time       =                                                       \
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args:                                                       \
                shared_infrastructure.cache_container_hook_server_configuration
        )(
            shared_infrastructure.get_last_time
        )


    get_last_atime      =                                                       \
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args:                                                       \
                shared_infrastructure.cache_container_hook_server_configuration
        )(
            shared_infrastructure.get_last_atime
        )


    get_last_ctime      =                                                       \
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args:                                                       \
                shared_infrastructure.cache_container_hook_server_configuration
        )(
            shared_infrastructure.get_last_ctime
        )


    get_last_mtime      =                                                       \
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args:                                                       \
                shared_infrastructure.cache_container_hook_server_configuration
        )(
            shared_infrastructure.get_last_mtime
        )

    @synchronized( _configurations_lock )
    def _get_version_configurations( self, d_configurations ):

        return \
            hashlib.sha1(
                json.dumps(
                    d_configurations,
                    sort_keys   = True,
                    cls         = shared_infrastructure.SpecificKeysEncoder,
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
