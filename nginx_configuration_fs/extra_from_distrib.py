#!/usr/bin/env python
# -*- coding: utf8 -*-
import  os

import  re

import  threading

from    plone.synchronize       import  synchronized

from    plone.memoize           import  volatile

import  pprint

import  dns.resolver

from    contextlib              import closing

import  colorama

import  pyinotify

import  subprocess

import  hashlib

import  shared_infrastructure

import  functools

import 	pkg_resources

import 	jsonschema

import 	json

@shared_infrastructure.Singleton
class ExtraFromDistrib:

    _configurations_lock                	= threading.RLock()

    _extra_pattern				=				\
        '^(?P<schema>[^\.].*_extra)\.schema\.json$'

    _extras_dir				=					\
        'extras'
    
    def __init__(
        self,
        restart_nginx                     	=				\
            None
    ): 

        self._l_cache_to_clear			= 				\
            [ shared_infrastructure.cache_extra_from_distrib ]

	self._l_le_configuration_to_reload	= []

        self._l_notifier			= []

        self._l_notifier_started		= []

        self._restart_nginx                     = restart_nginx

        self._provider 				= 				\
            pkg_resources.get_provider( __name__ )

        self._manager = pkg_resources.ResourceManager()

        self._root_extras			=				\
            self._provider.get_resource_filename( 				\
                self._manager, 
                self._extras_dir
            )

        # Gestion de iNotify
        wm                                      = pyinotify.WatchManager()
        mask                                    =                               \
            pyinotify.IN_MODIFY         |                                       \
            pyinotify.IN_CREATE         |                                       \
            pyinotify.IN_DELETE         |                                       \
            pyinotify.IN_ATTRIB         |                                       \
            pyinotify.IN_MOVED_TO       |                                       \
            pyinotify.IN_MOVED_FROM


        class EventHandler( pyinotify.ProcessEvent ):

             def process_evt( o, event ):

                 def restart_nginx():

                      try:

                          if self._restart_nginx:
                              subprocess.call( self._restart_nginx, shell = True )

                      except:

                          self._l_bad_configurations.append( ( '%s error' % ( self._restart_nginx ), ) )

                          map(
                              lambda cache: cache.clear(),
                              self._l_cache_to_clear
                          )

                 # On travaille sur path + os.sep + event.name plutot que pathname car 
                 # self._root_extras est valorise a une valeur relative
                 path_elements = \
                     filter( 
                         None, 
                         ( event.path + os.sep + event.name )[  
                             len( self._root_extras.rstrip( os.sep ) + os.sep ):
                         ].split( os.sep )
                     )

                 if len( path_elements ) == 0 and event.mask & pyinotify.IN_ATTRIB:

                     self.load_configurations( reload_without_version_control = True )

                     if self._restart_nginx:
                         return restart_nginx()

                 if len( path_elements ) != 1:

                     return None

                 if re.match(
                     self._extra_pattern,
                     path_elements[ 0 ]
                 ):

                     if self.load_configurations( reload_without_version_control = False ):

                         return restart_nginx()

                 else:

                     return None

             process_IN_MODIFY          = process_evt

             process_IN_CREATE          = process_evt

             process_IN_DELETE          = process_evt

             process_IN_ATTRIB          = process_evt

             process_IN_MOVED_TO        = process_evt

             process_IN_MOVED_FROM      = process_evt

        self._notifier                  = pyinotify.ThreadedNotifier( wm, EventHandler() )

        self._notifier.coalesce_events()

        wm.add_watch(
            self._root_extras.rstrip( os.sep ) + os.sep,
            mask,
            rec		=	True,
            auto_add	=	True
        )

        self._d_configurations                  = 				\
           shared_infrastructure.dict_with_default_inline_schema()

        self._l_bad_configurations              = []

        self.load_configurations()


    def get_notifier( self ):
        return self._notifier
    notifier 			= property( get_notifier, None, None )

    @synchronized( _configurations_lock )
    def get_d_configurations( self ):
        return self._d_configurations
    d_configurations 		= property( get_d_configurations, None, None )

    @volatile.cache( shared_infrastructure.cache_key, lambda *args: shared_infrastructure.cache_extra_from_distrib )
    def get_default_setter_validator( self, id_schema ):

        def set_defaults(
            validator,
            properties,
            instance,
            schema
        ):

            for error in 							\
                jsonschema.validators.validator_for(
                    self.d_configurations[ id_schema ]
                ).VALIDATORS["properties"](
                    validator,
                    properties,
                    instance,
                    schema,
                ):
                raise error

            for property, subschema in properties.iteritems():

                if 'default' in subschema:

                    instance.setdefault(
                        property,
                        subschema[ 'default' ]
                    )

        return 									\
            jsonschema.validators.extend(
                jsonschema.validators.validator_for(
                    self.d_configurations[ id_schema ]
                ),
                {
                    'properties' : set_defaults
                },
            )(
                self.d_configurations[ id_schema ],
            )


    @synchronized( _configurations_lock )
    def get_l_bad_configurations( self ):
        return self._l_bad_configurations
    l_bad_configurations 	= property( get_l_bad_configurations, None, None )


    @synchronized( _configurations_lock )
    def load_configurations( self, reload_without_version_control = False ):

        d_configurations        = 						\
           shared_infrastructure.dict_with_default_inline_schema()

        l_bad_configurations	= []

        for extra in filter(
                         lambda f: 						\
                             re.match(
                                 self._extra_pattern,
                                 f
                             ),
                         os.listdir(
                             self._root_extras.rstrip( os.sep ) + os.sep 
                         ),
                     ):

            try:

                schema_to_validate	= 					\
                    json.loads(
                        self._provider.get_resource_string(
                              self._manager,
                              self._extras_dir.rstrip( os.sep ) + os.sep + extra
                        )
                    )

                jsonschema.validators.validator_for(
                    schema_to_validate
                ).check_schema(
                    schema_to_validate
                )

                d_configurations[
                     re.match(
                         self._extra_pattern,
                         extra
                     ).group( 'schema' ) ]	=				\
                     schema_to_validate

            except Exception, e:

                # Pour qu'une exception ai lieu sur la validation du schema
                # il faut y aller vraiment fort
                l_bad_configurations.append( 
                    ( '%s : %s. Using default inline schema %r' % 						\
                        ( 
                            self._extras_dir.rstrip( os.sep ) + os.sep + extra,
                            e.message,
                            d_configurations[ 
                                re.match(
                                    self._extra_pattern,
                                    extra
                                ).group( 'schema' ) ]
                        ),
                    ) 
                )
                # On ne remplit pas l'entre du dictionnaire
                # car __getitem__ de la classe
                # shared_infrastructure.dict_with_default_inline_schema
                # renvoit un schema par defaut
                continue

        if  													\
                 reload_without_version_control 								\
             or													\
                 self.get_version_configurations( d_configurations ) <> self.current_version_configurations 	\
             or													\
                 hashlib.sha1( repr( l_bad_configurations ) ).hexdigest() <> hashlib.sha1( repr( self._l_bad_configurations ) ).hexdigest():

            self._d_configurations         =       d_configurations
            self._l_bad_configurations     =       l_bad_configurations

            map(
                lambda cache: cache.clear(),
                self._l_cache_to_clear,
            )

            map(
                lambda le: le(),
                self._l_le_configuration_to_reload,
            )

            return True

        return False


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


    @synchronized( _configurations_lock )
    def register_cache_to_clear(
        self,
        cache,
    ):
        self._l_cache_to_clear.append( cache )

    @synchronized( _configurations_lock )
    def deregister_cache_to_clear(
        self,
        cache,
    ):

        self._l_cache_to_clear.remove( cache )


    @synchronized( _configurations_lock )
    def register_configuration_to_reload(
        self,
        le_reload_configuration,
    ):
        self._l_le_configuration_to_reload.append( le_reload_configuration )

    @synchronized( _configurations_lock )
    def deregister_configuration_to_reload(
        self,
        le_reload_configuration,
    ):

        self._l_le_configuration_to_reload.remove( le_reload_configuration )

    @synchronized( _configurations_lock )
    def register_notifier(
        self,
        notifier,
    ):

        if notifier not in self._l_notifier:

            def chained_start( fct ):

                @functools.wraps( fct )
                def wrapped( *args, **kwargs ):

                    if notifier not in self._l_notifier_started:
                         
                         if not self._l_notifier_started: 
                             self.notifier.start()

                         self._l_notifier_started.append( notifier )

                    return fct( *args, **kwargs )

                return wrapped

            def chained_stop( fct ):
    
                @functools.wraps( fct )
                def wrapped( *args, **kwargs ):
    
                    if notifier in self._l_notifier_started:
    
                         self._l_notifier_started.remove( notifier )

                         if not self._l_notifier_started: 
                             self.notifier.stop()

                    return fct( *args, **kwargs )

                return wrapped

            notifier.start	= chained_start( notifier.start )
            notifier.stop	= chained_stop( notifier.stop )

            self._l_notifier.append( notifier )
