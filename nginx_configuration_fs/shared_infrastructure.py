#!/usr/bin/env python
# -*- coding: utf8 -*-

import 	pprint

import 	colorama

import	re

import  regex

import  rfc3987

def cache_key( fun, instance, *args ):

#    print( 
#        colorama.Fore.RED + 		\
#	repr( fun ) +			\
#        colorama.Fore.RESET + 		\
#        colorama.Fore.YELLOW + 		\
#	repr( instance ) +		\
#        colorama.Fore.RESET + 		\
#        colorama.Fore.CYAN + 		\
#	repr( args ) +			\
#        colorama.Fore.RESET
#    )

    return (instance.__class__,) + args

cache_container_agnostic_configuration          = {}
cache_container_ssl_configuration          	= {}
cache_container_url2app_configuration          	= {}
cache_container_nginx_fs                        = {}

URI_rfc3987                        =       rfc3987.get_compiled_pattern('^%(URI)s$')

def common_process_uri(
    le_root_configuration,
    d,
    current_line,
    current_server,
    current_port,
    current_mapping_type,
    l_bad_configurations,
    suffixwith
):
    key_uri, uri                    = [ ( k, v ) for k, v in d.items() if k.startswith( suffixwith ) and k.endswith( 'URI' ) ][ 0 ]

    d_rfc3987 = URI_rfc3987.match( uri ).groupdict()

    if not re.match(
        'http|https',
        d_rfc3987[ 'scheme' ]
    ):
        l_bad_configurations.append(
            (
                 'scheme %s invalid in %s from %s' % (
                     d_rfc3987[ 'scheme' ],
                     uri,
                     current_line
                 ),
                 le_root_configuration(),
                 current_server,
                 current_port,
                 current_mapping_type
            )
        )
        raise Exception

    if d_rfc3987[ 'port' ] is None:
        if d_rfc3987[ 'scheme' ]    == 'http':
            d_rfc3987.update( { 'port' : 80 } )
        elif d_rfc3987[ 'scheme' ] == 'https':
            d_rfc3987.update( { 'port' : 443 } )
        else:
            raise Exception


    uri = ''
    uri += d_rfc3987[ 'scheme' ] + ':'
    uri += '//'
    if  d_rfc3987.get( 'userinfo' ):
        uri += d_rfc3987[ 'userinfo' ] + '@'
    uri += d_rfc3987[ 'host' ]
    uri += ':%s' % ( d_rfc3987[ 'port' ] )
    uri += d_rfc3987[ 'path' ] or ''
    if  d_rfc3987.get( 'query' ):
        uri += '?' + d_rfc3987[ 'query' ]
    if  d_rfc3987.get( 'fragment' ):
        uri += '#' + d_rfc3987[ 'fragment' ]

    d[ key_uri ]                            = uri
    d[ '%sscheme' % ( suffixwith ) ]        = d_rfc3987[ 'scheme' ]
    d[ '%shost' % ( suffixwith ) ]          = d_rfc3987[ 'host' ]
    d[ '%sport' % ( suffixwith ) ]          = d_rfc3987[ 'port' ]
    d[ '%spath' % ( suffixwith ) ]          = d_rfc3987[ 'path' ]
    d[ '%squery' % ( suffixwith ) ]         = d_rfc3987.get( 'query' )
    d[ '%sfragment' % ( suffixwith ) ]      = d_rfc3987.get( 'fragment' )
    d[ '%suserinfo' % ( suffixwith ) ]      = d_rfc3987.get( 'userinfo' )

def listen_ssl_process_uri(
    le_root_configuration,
    le_ssl_configuration,
    d,
    current_line,
    current_server,
    current_port,
    current_mapping_type,
    l_bad_configurations,
    suffixwith
):
    """
       listen_ssl_process_uri must follow common_process_uri
    """
    key_scheme, scheme      = [ ( k, v ) for k, v in d.items() if k.startswith( suffixwith ) and k.endswith( 'scheme' ) ][ 0 ]

    key_uri, uri            = [ ( k, v ) for k, v in d.items() if k.startswith( suffixwith ) and k.endswith( 'URI' ) ][ 0 ]

    expected_scheme         = 'https' if le_ssl_configuration().have_ssl( current_server, current_port ) else 'http'

    if scheme <> expected_scheme:
        l_bad_configurations.append(
            (
                'scheme %s expected in %s from %s' % (
                     expected_scheme,
                     uri,
                     current_line
                ),
                le_root_configuration(),
                current_server,
                current_port,
                current_mapping_type
            )
        )
        raise Exception
