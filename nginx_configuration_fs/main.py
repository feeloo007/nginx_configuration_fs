#!/usr/bin/env python
# -*- coding: utf8 -*-
import  plac

from 	contextlib 		import closing

import 	sys

import	os

import 	json

from 	pwd 			import getpwnam

import	colorama

import	shared_infrastructure

import	nginx_configuration_fs

import	agnostic_configuration

import	ssl_configuration

import	url2app_configuration

__NGINX_CONFIGURATION_FS_CONFIG_TEMPLATE__ 	= 'nginx_configuration_fs.config.template'
__ROOT_AGNOSTIC_CONFIGURATION__			= 'root_agnostic_configuration'
__ROOT_SSL_CONFIGURATION__			= 'root_ssl_configuration'
__ROOT_URL2APP_CONFIGURATION__			= 'root_url2app_configuration'
__USER_OWNER__					= 'user_owner'
__GROUP_OWNER__					= 'group_owner'
__RESOLVER_CONF__				= 'resolver_conf'
__MOUNT_FILENAME__				= 'mount_filename'
__UNMOUNT_FILENAME__				= 'unmount_filename'
__REDIRECT_FILENAME__				= 'redirect_filename'
__ERROR_STATUS_FILENAME__			= 'error_status_filename'
__RESTART_NGINX__				= 'restart_nginx'
__SSL_CERTIFICATE_FILENAME__			= 'ssl_certificate_filename'
__SSL_CERTIFICATE_KEY_FILENAME__		= 'ssl_certificate_key_filename'
__URL2APP_FILENAME__				= 'url2app_filename'

@plac.annotations(
    configuration_path	= 						\
        'path to formated file as %s' % 				\
            ( __NGINX_CONFIGURATION_FS_CONFIG_TEMPLATE__ ),
    mountpoint				= 				\
        'mountpoint, must be empty',
    named_mount_options			= 				\
        (
            'fs_mntops formated option (see man fstab)',
            'option',
            'o',
            None,
            None,
            'fs_mntops'
        ),
    nodaemon				= 				\
        (
            'no daemonize twisted FS. Default: False',
            'flag',
            'nodaemon',
        ),
)
def main_verify(
    configuration_path,
    mountpoint,
    named_mount_options		= '',
    nodaemon			= False,
    ):
    """
    - Analyse la presence de tous les parametres necessaires
    au programme.
    - Verifie des regles fontionnelles (repertoire non montee...).
    - Modifie les valeurs de fs_mntops passees et les rend coherentes.
    - Le parametre nodaemon a True permet de ne pas detacher les
    processus de la commande de depart. Ce parametre n'est pas
    acessible lors d'un montage par /etc/fstab.
    - renvoit sous forme de dictionnaire le parametres nodaemon
    et tous les parametres necessaires a l'execution du / des
    Daemon demarrer pat twisted.
    """

    if not os.path.isfile( configuration_path ):
        print( '%s not found' % ( configuration_path ) )
        sys.exit(1)

    if not os.path.isdir( mountpoint ):
        print( '%s is not a directory' % ( mountpoint ) )
        sys.exit(2)

    if os.listdir( mountpoint ):
        print( '%s is not empty' % ( mountpoint ) )
        sys.exit(3)

    d_config = {}

    with closing( open( configuration_path ) ) as f_configuration:
        d_config = json.load( f_configuration )

    if not d_config.has_key( __USER_OWNER__ ) :
        print( '%s not found in %s' % ( __USER_OWNER__, configuration_path )  )
        sys.exit(6)

    if not d_config.has_key( __GROUP_OWNER__ ) :
        print( '%s not found in %s' % ( __GROUP_OWNER__, configuration_path )  )
        sys.exit(7)
   
    try:
        uid_owner, gid_owner = 					\
            getpwnam( d_config[ __USER_OWNER__ ] )[ 2 ], 	\
            getpwnam( d_config[ __GROUP_OWNER__ ])[ 3 ]
    except:
        print( '%s.%s does not exist' % ( d_config[ __USER_OWNER__ ], d_config[ __GROUP_OWNER__ ] )  )
        sys.exit(8)

    if not d_config.has_key( __RESOLVER_CONF__ ) :
        print( '%s not found in %s' % ( __RESOLVER_CONF__, configuration_path )  )
        sys.exit(9)

    if not os.path.isfile( d_config[ __RESOLVER_CONF__ ] ):
        print( '%s not a file' % ( d_config[ __RESOLVER_CONF__ ] ) ) 
        sys.exit(10)

    if not d_config.has_key( __MOUNT_FILENAME__ ) :
        print( '%s not found in %s' % ( __MOUNT_FILENAME__, configuration_path )  )
        sys.exit(11)

    if not d_config.has_key( __UNMOUNT_FILENAME__ ) :
        print( '%s not found in %s' % ( __UNMOUNT_FILENAME__, configuration_path )  )
        sys.exit(12)

    if not d_config.has_key( __REDIRECT_FILENAME__ ) :
        print( '%s not found in %s' % ( __REDIRECT_FILENAME__, configuration_path )  )
        sys.exit(13)

    if not d_config.has_key( __ERROR_STATUS_FILENAME__ ) :
        print( '%s not found in %s' % ( __ERROR_STATUS_FILENAME__, configuration_path )  )
        sys.exit(14)

    if not d_config.has_key( __RESTART_NGINX__ ) :
        print( '%s not found in %s' % ( __RESTART_NGINX__, configuration_path )  )
        sys.exit(15)

    if not d_config.has_key( __ROOT_SSL_CONFIGURATION__ ) :
        print( '%s not found in %s' % ( __ROOT_SSL_CONFIGURATION__, configuration_path )  )
        sys.exit(16)

    if not d_config.has_key( __SSL_CERTIFICATE_FILENAME__ ) :
        print( '%s not found in %s' % ( __SSL_CERTIFICATE_FILENAME__, configuration_path )  )
        sys.exit(17)

    if not d_config.has_key( __SSL_CERTIFICATE_KEY_FILENAME__ ) :
        print( '%s not found in %s' % ( __SSL_CERTIFICATE_KEY_FILENAME__, configuration_path )  )
        sys.exit(18)

    if not d_config.has_key( __ROOT_URL2APP_CONFIGURATION__ ) :
        print( '%s not found in %s' % ( __ROOT_URL2APP_CONFIGURATION__, configuration_path )  )
        sys.exit(19)

    if not d_config.has_key( __URL2APP_FILENAME__ ) :
        print( '%s not found in %s' % ( __URL2APP_FILENAME__, configuration_path )  )
        sys.exit(20)

    return 							\
        {							\
            'uid_owner'			: uid_owner,		\
            'gid_owner'			: gid_owner,		\
            'd_config'			: d_config,		\
            'configuration_path'	: configuration_path,   \
            'mountpoint'		: mountpoint,		\
            'named_mount_options'	: named_mount_options,	\
            'nodaemon'			: nodaemon,		\
        }

def main_process(
    uid_owner,
    gid_owner,
    d_config,
    configuration_path,
    mountpoint,
    named_mount_options,
    **kwargs
):

    ssl_conf 	= 					\
        ssl_configuration.SSLConfiguration(
            d_config[ __ROOT_SSL_CONFIGURATION__ ],
            d_config[ __RESOLVER_CONF__ ],
            d_config[ __SSL_CERTIFICATE_FILENAME__ ],
            d_config[ __SSL_CERTIFICATE_KEY_FILENAME__ ],
            d_config[ __RESTART_NGINX__ ],
        )

    fuse 		= 					\
        shared_infrastructure.ContextualizedFUSE(
            nginx_configuration_fs.NGINXConfigurationFS(
                agnostic_configuration.AgnosticConfiguration(
                    d_config[ __ROOT_AGNOSTIC_CONFIGURATION__ ],
                    d_config[ __RESOLVER_CONF__ ],
                    d_config[ __MOUNT_FILENAME__ ],
                    d_config[ __UNMOUNT_FILENAME__ ],
                    d_config[ __REDIRECT_FILENAME__ ],
                    d_config[ __RESTART_NGINX__ ],
                    ssl_conf
                ),
                mountpoint,
                uid_owner,
                gid_owner,
                d_config[ __RESOLVER_CONF__ ],
                d_config[ __MOUNT_FILENAME__ ],
                d_config[ __UNMOUNT_FILENAME__ ],
                d_config[ __REDIRECT_FILENAME__ ],
                d_config[ __ERROR_STATUS_FILENAME__ ],
                d_config[ __RESTART_NGINX__ ],
                ssl_conf,
                url2app_configuration.URL2AppConfiguration(
                    d_config[ __ROOT_URL2APP_CONFIGURATION__ ],
                    d_config[ __RESOLVER_CONF__ ],
                    d_config[ __URL2APP_FILENAME__ ],
                    d_config[ __RESTART_NGINX__ ],
                    ssl_conf
                ),
            ),
            mountpoint,
            named_mount_options,
            **kwargs
        )


if __name__ == '__main__':

    shared_infrastructure.DaemonRunner(
        le_preApplication	= 				\
            lambda: 						\
                plac.call( 					\
                    main_verify, 				\
                    eager 	= False				\
                    # eager = Falase sinon le tableau renovye
                    # devient une liste
                ),						\
        l_le_startApplication	= 				\
            [							\
                lambda startApplicationParams, l_process: 	\
                    shared_infrastructure.TwistedDaemon( 	\
                        '''
import  nginx_configuration_fs.main

kwargs = %r

nginx_configuration_fs.main.main_process(
   **kwargs
)''',								\
                        l_process,				\
                        **startApplicationParams 		\
                    ).run(),					\
            ]
    ).run()
