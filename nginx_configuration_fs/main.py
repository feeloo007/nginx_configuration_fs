#!/usr/bin/env python
# -*- coding: utf8 -*-
import 	sys

from 	fuse 			import FUSE

import	os

import 	pkg_resources

import 	json

from 	pwd 			import getpwnam

import 	pprint

import	colorama

import	shared_infrastructure

import	nginx_configuration_fs

import	agnostic_configuration

import	ssl_configuration

import	url2app_configuration

__NGINX_CONFIGURATION_FS__ 		= 'nginx_configuration_fs.config'
__ROOT_AGNOSTIC_CONFIGURATION__		= 'root_agnostic_configuration'
__ROOT_NGINX_CONFIGURATION__		= 'root_nginx_configuration'
__ROOT_SSL_CONFIGURATION__		= 'root_ssl_configuration'
__ROOT_URL2APP_CONFIGURATION__		= 'root_url2app_configuration'
__USER_OWNER__				= 'user_owner'
__GROUP_OWNER__				= 'group_owner'
__RESOLVER_CONF__			= 'resolver_conf'
__MOUNT_FILENAME__			= 'mount_filename'
__UNMOUNT_FILENAME__			= 'unmount_filename'
__REDIRECT_FILENAME__			= 'redirect_filename'
__ERROR_STATUS_FILENAME__		= 'error_status_filename'
__RESTART_NGINX__			= 'restart_nginx'
__SSL_CERTIFICATE_FILENAME__		= 'ssl_certificate_filename'
__SSL_CERTIFICATE_KEY_FILENAME__	= 'ssl_certificate_key_filename'
__URL2APP_FILENAME__			= 'url2app_filename'

if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('usage: %s' % sys.argv[0])
        sys.exit(1)

    if not os.path.isfile( __NGINX_CONFIGURATION_FS__ ):
        print( '%s not found' % ( __NGINX_CONFIGURATION_FS__ ) ) 
        sys.exit(2)

    d_config = json.loads( pkg_resources.resource_string( __name__, __NGINX_CONFIGURATION_FS__ ) )

    if not d_config.has_key( __ROOT_AGNOSTIC_CONFIGURATION__ ) :
        print( '%s not found in %s' % ( __ROOT_AGNOSTIC_CONFIGURATION__, __NGINX_CONFIGURATION_FS__ ) ) 
        sys.exit(3)

    if not os.path.isdir( d_config[ __ROOT_AGNOSTIC_CONFIGURATION__ ] ):
        print( '%s is not a directory' % ( d_config[ __ROOT_AGNOSTIC_CONFIGURATION__ ] ) )
        sys.exit(4)

    if not d_config.has_key( __ROOT_NGINX_CONFIGURATION__ ) :
        print( '%s not found in %s' % ( __ROOT_NGINX_CONFIGURATION__, __NGINX_CONFIGURATION_FS__ )  ) 
        sys.exit(5)

    if not d_config.has_key( __USER_OWNER__ ) :
        print( '%s not found in %s' % ( __USER_OWNER__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(6)

    if not d_config.has_key( __GROUP_OWNER__ ) :
        print( '%s not found in %s' % ( __GROUP_OWNER__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(7)
   
    try:
        uid_owner, gid_owner = getpwnam( d_config[ __USER_OWNER__ ] )[ 2 ], getpwnam( d_config[ __GROUP_OWNER__ ] )[ 3 ]
    except:
        print( '%s.%s does not exist' % ( d_config[ __USER_OWNER__ ], d_config[ __GROUP_OWNER__ ] )  )
        sys.exit(8)

    if not d_config.has_key( __RESOLVER_CONF__ ) :
        print( '%s not found in %s' % ( __RESOLVER_CONF__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(9)

    if not os.path.isfile( d_config[ __RESOLVER_CONF__ ] ):
        print( '%s not a file' % ( d_config[ __RESOLVER_CONF__ ] ) ) 
        sys.exit(10)

    if not d_config.has_key( __MOUNT_FILENAME__ ) :
        print( '%s not found in %s' % ( __MOUNT_FILENAME__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(11)

    if not d_config.has_key( __UNMOUNT_FILENAME__ ) :
        print( '%s not found in %s' % ( __UNMOUNT_FILENAME__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(12)

    if not d_config.has_key( __REDIRECT_FILENAME__ ) :
        print( '%s not found in %s' % ( __REDIRECT_FILENAME__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(13)

    if not d_config.has_key( __ERROR_STATUS_FILENAME__ ) :
        print( '%s not found in %s' % ( __ERROR_STATUS_FILENAME__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(14)

    if not d_config.has_key( __RESTART_NGINX__ ) :
        print( '%s not found in %s' % ( __RESTART_NGINX__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(15)

    if not d_config.has_key( __ROOT_SSL_CONFIGURATION__ ) :
        print( '%s not found in %s' % ( __ROOT_SSL_CONFIGURATION__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(16)

    if not d_config.has_key( __SSL_CERTIFICATE_FILENAME__ ) :
        print( '%s not found in %s' % ( __SSL_CERTIFICATE_FILENAME__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(17)

    if not d_config.has_key( __SSL_CERTIFICATE_KEY_FILENAME__ ) :
        print( '%s not found in %s' % ( __SSL_CERTIFICATE_KEY_FILENAME__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(18)

    if not d_config.has_key( __ROOT_URL2APP_CONFIGURATION__ ) :
        print( '%s not found in %s' % ( __ROOT_URL2APP_CONFIGURATION__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(19)

    if not d_config.has_key( __URL2APP_FILENAME__ ) :
        print( '%s not found in %s' % ( __URL2APP_FILENAME__, __NGINX_CONFIGURATION_FS__ )  )
        sys.exit(20)

    ssl_conf 	= ssl_configuration.SSLConfiguration(
        d_config[ __ROOT_SSL_CONFIGURATION__ ],
        d_config[ __RESOLVER_CONF__ ],
        d_config[ __SSL_CERTIFICATE_FILENAME__ ],
        d_config[ __SSL_CERTIFICATE_KEY_FILENAME__ ],
        d_config[ __RESTART_NGINX__ ],
    )

    fuse = FUSE(
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
            d_config[ __ROOT_NGINX_CONFIGURATION__ ], 
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
        d_config[ __ROOT_NGINX_CONFIGURATION__ ], 
        foreground=True, 
        ro		=True, 
        allow_other 	= True,
        sync_read       = True,
        sync            = True,
        encoding        = 'utf-8',
        )
