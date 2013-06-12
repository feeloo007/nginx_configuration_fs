#!/usr/bin/env python
# -*- coding: utf8 -*-
import	os

import 	re

import  regex

import  rfc3987

import  threading

from    plone.synchronize       import  synchronized

from    plone.memoize       	import  volatile

import 	pprint

import 	dns.resolver

from 	contextlib   		import closing

import	colorama

import 	pyinotify

import  subprocess

import  hashlib

import	shared_infrastructure

import 	extra_from_distrib

class AgnosticConfiguration(
    shared_infrastructure.IAddToConfigurationWithMappingType
    ):

    _configurations_lock           	=       threading.RLock()

    _comment_pattern			= 	'''^\s*(?P<comment>#+)'''

    _mount_pattern			= 	\
        '''^\s*%s\s+(?:\/\*(?P<listening_uri_extra>[^\*]*)\*\/\s+){0,1}%s(?:\s+\/\*(?P<backed_uri_extra>[^\*]*)\*\/){0,1}''' % (
            rfc3987.format_patterns(
                URI		= 'src_URI', 
            )['URI'],
            rfc3987.format_patterns(
                URI		= 'dst_URI', 
            )['URI'],
    )

    @staticmethod
    def process_uri_for_mount(
        self,
        d,
        filepath,
        line,
        server,
        port,
        mapping_type,
        d_configurations,
        l_bad_configurations,
    ):

        shared_infrastructure.common_process_uri( 
            lambda: self._root_configuration,
            d, 
            line, 
            server, 
            port,
            mapping_type, 
            l_bad_configurations, 
            'src_'
        )

        shared_infrastructure.common_process_extra(
            lambda: self._root_configuration,
            d,
            line,
            server,
            port,
            mapping_type,
            l_bad_configurations,
            'listening_uri_'
        )

        shared_infrastructure.common_process_uri( 
            lambda: self._root_configuration,
            d, 
            line, 
            server, 
            port, 
            mapping_type, 
            l_bad_configurations, 
            'dst_'
        )

        shared_infrastructure.common_process_extra(
            lambda: self._root_configuration,
            d,
            line,
            server,
            port,
            mapping_type,
            l_bad_configurations,
            'backed_uri_'
        )

        shared_infrastructure.listen_ssl_process_uri( 
            lambda: self._root_configuration,
            lambda: self._ssl_configuration,
            d, 
            line, 
            server, 
            port, 
            mapping_type,
            l_bad_configurations, 
            'src_'
        )


        def get_ips_for_upstream( host ):

            l_ips = []
            l_ips.extend( [ ip.address for ip in self._resolver.query( host, 'A' ) ] )
            l_ips.extend( [ '[%s]' % ( ip.address ) for ip in self._resolver.query( host, 'AAAA' ) ] )

            if not l_ips:
               l_bad_configurations.append( ( '%s not resolvable' % ( host ), self._root_configuration, server, port, self._mount_filename ) )

            return l_ips

        def get_upstream_name( d ):
            return '%s__%s_%s__%s' % (
                server,
                port,
                d[ 'dst_host' ],
                d[ 'dst_port' ]
        )

        def get_upstream_url( d ):
            uri = ''
            uri += d[ 'dst_scheme' ] + ':'
            uri += '//'
            if  d.get( 'dst_userinfo' ):
                uri += d[ 'dst_userinfo' ] + '@'
            uri += get_upstream_name( d )
            uri += d[ 'dst_path' ] or ''
            return uri


        def get_proxy_redirect_to_replace_url_with_port( d ):
            uri 	= ''
            uri 	+= d[ 'dst_scheme' ] + ':'
            uri 	+= '//'
            if  d.get( 'dst_userinfo' ):
                uri 	+= d[ 'dst_userinfo' ] + '@'
            uri 	+= d[ 'src_host' ]
            uri 	+= ':%s' % ( d[ 'dst_port' ] )
            uri 	+= d[ 'dst_path' ] or ''
            return uri

        def get_proxy_redirect_to_replace_url_without_port( d ):
            uri 	= ''
            uri 	+= d[ 'dst_scheme' ] + ':'
            uri 	+= '//'
            if  d.get( 'dst_userinfo' ):
                uri 	+= d[ 'dst_userinfo' ] + '@'
            uri 	+= d[ 'src_host' ]
            uri 	+= d[ 'dst_path' ] or ''
            return uri

        AgnosticConfiguration.add_to_configuration( 
            d, 
            lambda d: {
                        'src':
                            shared_infrastructure.str_with_extra(
                                d[ 'src_URI' ],
                                d[ 'listening_uri_extra' ],
   			    ), 
                        'src_scheme':
                            d[ 'src_scheme' ],
                        'src_userinfo':
                            d[ 'src_userinfo' ] or '',
                        'src_host':
                            d[ 'src_host' ],
                        'src_port':
                            str( d[ 'src_port' ] ),
                        'src_path':
                            d[ 'src_path' ] or '',
                        'src_query':
                            d[ 'src_query' ] or '',
                        'dst':
                            shared_infrastructure.str_with_extra(
                                d[ 'dst_URI' ],
                                d[ 'backed_uri_extra' ],
                            ),
                        'dst_scheme':
                            d[ 'dst_scheme' ],
                        'dst_userinfo':
                            d[ 'dst_userinfo' ] or '',
                        'dst_host':
                            d[ 'dst_host' ],
                        'dst_port':
                            str( d[ 'dst_port' ] ),
                        'dst_path':
                            d[ 'dst_path' ] or '',
                        'dst_query':
                            d[ 'dst_query' ] or '',
                        'dst_upstream_name':
                            get_upstream_name( d ),
                        'dst_upstream':
                            get_upstream_url( d ),
                        'dst_upstream_resolved_ips':
                            get_ips_for_upstream( d[ 'dst_host' ] ),
                        'proxy_redirect_to_replace_with_port':
                            get_proxy_redirect_to_replace_url_with_port( d ),
                        'proxy_redirect_to_replace_without_port':
                            get_proxy_redirect_to_replace_url_without_port( d ),
                    }, 
            d_configurations,
            filepath,
            server, 
            port, 
            mapping_type, 
            le_sort	= lambda x: ( x[ 'src' ], x[ 'dst' ] )
        )


    _unmount_pattern			= 	\
        '''^\s*%s(?:\s+\/\*(?P<listening_uri_extra>[^\*]*)\*\/){0,1}''' % (
            rfc3987.format_patterns(
                URI		= 'URI', 
            )['URI'],
    )
        
    @staticmethod
    def process_uri_for_unmount(
        self,
        d,
        filepath,
        line,
        server,
        port,
        mapping_type,
        d_configurations,
        l_bad_configurations,
    ):
        shared_infrastructure.common_process_uri( 
            lambda: self._root_configuration,
            d, 
            line, 
            server, 
            port,
            mapping_type, 
            l_bad_configurations, 
            ''
        )

        shared_infrastructure.listen_ssl_process_uri( 
            lambda: self._root_configuration,
            lambda: self._ssl_configuration,
            d, 
            line, 
            server, 
            port, 
            mapping_type,
            l_bad_configurations, 
            '' 
        )

        shared_infrastructure.common_process_extra(
            lambda: self._root_configuration,
            d,
            line,
            server,
            port,
            mapping_type,
            l_bad_configurations,
            'listening_uri_',
        )

        AgnosticConfiguration.add_to_configuration( 
            d, 
            lambda m: { 
                'uri'	:
                    shared_infrastructure.str_with_extra(
                        d[ 'URI' ],
                        d[ 'listening_uri_extra' ],
                    ),
            },
            d_configurations,
            filepath,
            server,
            port,
            mapping_type,
            le_sort     = lambda x: ( x[ 'uri' ] )
        )


    _redirect_pattern			= 	\
        '''^\s*%s\s+(?:\/\*(?P<listening_uri_extra>[^\*]*)\*\/\s+){0,1}%s(?:\s+\/\*(?P<redirected_uri_extra>[^\*]*)\*\/){0,1}''' % (
            rfc3987.format_patterns(
                URI		= 'src_URI', 
            )['URI'],
            rfc3987.format_patterns(
                URI		= 'dst_URI', 
            )['URI'],
    )

    @staticmethod
    def process_uri_for_redirect(
        self,
        d,
        filepath,
        line,
        server,
        port,
        mapping_type,
        d_configurations,
        l_bad_configurations,
    ):
        shared_infrastructure.common_process_uri( 
            lambda: self._root_configuration,
            d, 
            line, 
            server, 
            port,
            mapping_type, 
            l_bad_configurations, 
            'src_'
        )

        shared_infrastructure.common_process_extra(
            lambda: self._root_configuration,
            d,
            line,
            server,
            port,
            mapping_type,
            l_bad_configurations,
            'listening_uri_',
        )

        shared_infrastructure.common_process_uri( 
            lambda: self._root_configuration,
            d, 
            line, 
            server, 
            port, 
            mapping_type, 
            l_bad_configurations, 
            'dst_' 
        )

        shared_infrastructure.common_process_extra(
            lambda: self._root_configuration,
            d,
            line,
            server,
            port,
            mapping_type,
            l_bad_configurations,
            'redirected_uri_',
        )

        shared_infrastructure.listen_ssl_process_uri( 
            lambda: self._root_configuration,
            lambda: self._ssl_configuration,
            d, 
            line, 
            server, 
            port, 
            mapping_type,
            l_bad_configurations, 
            'src_' 
        )

        AgnosticConfiguration.add_to_configuration( 
            d, 
            lambda d: {
                        'src'		:
                             shared_infrastructure.str_with_extra(
                                 d[ 'src_URI' ],
                                 d[ 'listening_uri_extra' ],
                 	     ),
                        'dst'		:
                             shared_infrastructure.str_with_extra(
                                 d[ 'dst_URI' ],
                                 d[ 'redirected_uri_extra' ],
            		     ), 
                    }, 
            d_configurations,
            filepath,
            server,
            port,
            mapping_type,
            le_sort     = lambda x: ( x[ 'src' ], x[ 'dst' ] )
        )


    def __init__(
        self, 
        root_configuration,
        resolver_conf,
        mount_filename,
        unmount_filename,
        redirect_filename,
        restart_nginx,
        ssl_configuration
    ):

        self._root_configuration	= root_configuration

        self._resolver_conf			= resolver_conf

        self._mount_filename			= mount_filename

        self._unmount_filename			= unmount_filename

        self._redirect_filename			= redirect_filename

        self._d_l_process_uri		= 				\
            {
                self._mount_filename		: AgnosticConfiguration.process_uri_for_mount,
                self._unmount_filename		: AgnosticConfiguration.process_uri_for_unmount,
                self._redirect_filename		: AgnosticConfiguration.process_uri_for_redirect,
            }

        self._restart_nginx			= restart_nginx

        self._resolver				= None

        self._ssl_configuration			= ssl_configuration

        self._extra_from_distrib		= 				\
            extra_from_distrib.ExtraFromDistrib(
                self._restart_nginx
            )

        self._extra_from_distrib.register_cache_to_clear(
            shared_infrastructure.cache_container_agnostic_configuration
        )

        self._extra_from_distrib.register_configuration_to_reload(
            lambda: self.load_configurations( reload_without_version_control = False )
        )

        # Gestion de iNotify	
        wm 					= pyinotify.WatchManager() 
	mask 					= 				\
            pyinotify.IN_MODIFY 	| 					\
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
    
                          shared_infrastructure.cache_container_agnostic_configuration.clear()
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
                     '^%s|%s|%s$' % ( 
                         self._mount_filename, 
                         self._unmount_filename, 
                         self._redirect_filename 
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

        self._extra_from_distrib.register_notifier(
            self._notifier
        )

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
        self._resolver.query	= shared_infrastructure.catch_NoNamesservers( self._resolver.query )

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

            # Si le repertoire ne contient pas de configuration
            # de port, la configuration n'est pas prise en compte
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
            for port in [ 
                         p
                         for p
                         in os.listdir( self._root_configuration.rstrip( os.sep ) + os.sep + server )
                      ]:

                # Si le repertoire ne correspond pas au format d'un nom de port
                # la configuration n'est pas prise en compte
                try:
                    if not( re.match( '\d{1,5}', port ) and int( p ) <= 65535 ):
                        raise Exception()
                except:
                        l_bad_configurations.append( ( '%s unvalid port format' % ( port ), self._root_configuration, server, port ) )
                        continue

                # Si aucun fichier de mapping
                # n'est present, la configuration n'est
                # pas prise en compte

                mount_filepath 		= 						\
                    self._root_configuration.rstrip( os.sep ) + os.sep + 		\
                    server + os.sep + 							\
                    port + os.sep + 							\
                    self._mount_filename

                unmount_filepath	= 						\
                    self._root_configuration.rstrip( os.sep ) + os.sep + 		\
                    server + os.sep + 							\
                    port + os.sep + 							\
                    self._unmount_filename

                redirect_filepath	= 						\
                    self._root_configuration.rstrip( os.sep ) + os.sep + 		\
                    server + os.sep + 							\
                    port + os.sep + 							\
                    self._redirect_filename


                def add_to_configuration(
                    mapping_type,
                    filepath,
                    pattern,
                    ):
                    try:
                        with closing( 
                            open( filepath )
                        ) as f:
        
                            for line in [ l.rstrip() for l in f.readlines() ]:
                                if re.match( AgnosticConfiguration._comment_pattern, line ):
                                    continue
        
                                m = re.match( pattern, line )
                                if not m:
                                    l_bad_configurations.append( 
                                        ( 
                                            'invalid format %s' % ( line ), 
                                            self._root_configuration,
                                            server, 
                                            port, 
                                            mapping_type 
                                        ) 
                                    )
                                    continue
                               
                                try:
                                    self._d_l_process_uri[ mapping_type ]( 
                                        self,
                                        m.groupdict(),
                                        filepath,
                                        line,
                                        server,
                                        port, 
                                        mapping_type,
                                        d_configurations, 
                                        l_bad_configurations, 
                                    )
                                except:
                                    import traceback
                                    traceback.print_exc()
                                    continue

                                
                    except:
                        pass

                try:
                    if \
                        not os.path.isfile( mount_filepath ) 			and	\
                        not os.path.isfile( unmount_filepath ) 			and 	\
                        not os.path.isfile( redirect_filepath ):
                       l_bad_configurations.append( 
                           ( 
                               'no %s or %s or %s file' % \
                                   ( 
                                       self._mount_filename, 
                                       self._unmount_filename, 
                                       self._redirect_filename 
                                   ), 
                               self._root_configuration,
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

                add_to_configuration( 
                    self._mount_filename, 	
                    mount_filepath, 	
                    AgnosticConfiguration._mount_pattern, 		
                )

                add_to_configuration( 
                    self._unmount_filename, 	
                    unmount_filepath,	
                    AgnosticConfiguration._unmount_pattern, 	
                )

                add_to_configuration( 
                    self._redirect_filename, 	
                    redirect_filepath, 	
                    AgnosticConfiguration._redirect_pattern, 	
                )

        if len( d_configurations ) == 0:
            l_bad_configurations.append( ( 'no configuration available', self._root_configuration, ) )

        if  													\
                 reload_without_version_control 								\
             or													\
                 self.get_version_configurations( d_configurations ) <> self.current_version_configurations 	\
             or													\
                 hashlib.sha1( repr( l_bad_configurations ) ).hexdigest() <> hashlib.sha1( repr( self._l_bad_configurations ) ).hexdigest():

            self._d_configurations         =       d_configurations
            self._l_bad_configurations     =       l_bad_configurations
            shared_infrastructure.cache_container_agnostic_configuration.clear()
            shared_infrastructure.cache_container_nginx_fs.clear()

            #pprint.pprint( self._d_configurations )

            return True

        return False

        #pprint.pprint( self._d_configurations )


    get_id_configurations       =                               \
        synchronized(
            _configurations_lock
        )(
            volatile.cache(
                shared_infrastructure.cache_key,
                lambda *args:                                   \
                    shared_infrastructure.cache_container_agnostic_configuration
            )(
                shared_infrastructure.get_id_configurations
            )
        )
    id_configurations   = property( get_id_configurations, None, None )


    filter_id_configurations    =                               		\
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args:                                       		\
                shared_infrastructure.cache_container_agnostic_configuration
        )(
            shared_infrastructure.filter_id_configurations
        )

    
    get_list_configurations_filenames	=					\
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args: 							\
                shared_infrastructure.cache_container_agnostic_configuration
        )(
            shared_infrastructure.get_list_configurations_filenames
        )

    
    get_last_time	=							\
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args: 							\
                shared_infrastructure.cache_container_agnostic_configuration
        )(
            shared_infrastructure.get_last_time
        )


    get_last_atime	=							\
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args: 							\
                shared_infrastructure.cache_container_agnostic_configuration
        )(
            shared_infrastructure.get_last_atime
        )
    

    get_last_ctime	=							\
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args: 							\
                shared_infrastructure.cache_container_agnostic_configuration
        )(
            shared_infrastructure.get_last_ctime
        )


    get_last_mtime	=							\
        volatile.cache(
            shared_infrastructure.cache_key,
            lambda *args: 							\
                shared_infrastructure.cache_container_agnostic_configuration
        )(
            shared_infrastructure.get_last_mtime
        )
 

    _get_version_configurations =                                       \
        synchronized(
            _configurations_lock
        )(
            shared_infrastructure._get_version_configurations
    )
    get_version_configurations  = _get_version_configurations


    get_current_version_configurations =                                \
        synchronized(
            _configurations_lock
        )(
            shared_infrastructure.get_current_version_configurations
    )
    current_version_configurations      =                               \
        property(
            get_current_version_configurations,
            None,
            None
        )
