{% import 'redirected_uri_extra.tpl' as redirected_uri_extra with context %}
{% import 'backed_uri_extra.tpl' as backed_uri_extra with context %}
log_format access_{{ server }}-{{ port }} '$remote_addr - $remote_user [$time_local] "$request" '
                 '$status $body_bytes_sent "$http_referer" '
                 '"$http_user_agent" "$scheme://$host:$server_port$request_uri"';

{% for upstream in upstream_configuration -%}
{% if not upstream.ips -%}
# IMPOSSIBLE DE RESOUDRE {{ upstream.host }} POUR {{ upstream.name }}
# TODO - IMPLEMENTER UN SERVEUR TECHNIQUE INDIQUANT QUE LE DNS N'EST PAS RESOLVABLE

{% else %}
upstream {{ upstream.name }} {
    # resolution de {{ upstream.name }} valide au rafraichissement de FS
    {% for ip in upstream.ips -%}
    server {{ ip }}:{{ upstream.port }};
    {% endfor -%}
    keepalive 16;
}

{% endif -%}
{% endfor -%}

server {

    server_tokens 		off;

    {% for nameserver in resolver.nameservers -%}
    resolver 			{{ nameserver }};
    {% endfor -%}

    {% for r in resolver.query( server, 'A' ) -%}
    listen   			{{ r.address }}:{{ port }}{% if ssl_configuration %} ssl{% endif -%};
    {% endfor -%}
    {% for r in resolver.query( server, 'AAAA' ) -%}
    listen   			[{{ r.address }}]:{{ port }} ipv6only=on{% if ssl_configuration %} ssl{% endif -%};
    {% endfor -%}

    {% if ssl_configuration -%}
    ssl_certificate 		{{ ssl_configuration.ssl_certificate_filepath }};
    ssl_certificate_key		{{ ssl_configuration.ssl_certificate_key_filepath }};
    {% endif -%}

    access_log 			/var/log/nginx/.{{ server }}-{{ port }}.access.log access_{{ server }}-{{ port }};
    error_log 			/var/log/nginx/.{{ server }}-{{ port }}.error.log info;
     

    error_page                  404     =404       /__NO_CONFIGURATION__.html;
    error_page                  502     =503       /__BACKEND_FAILED__.html;
    error_page                  504     =503       /__BACKEND_FAILED__.html;
    error_page                  418     =503       /__NO_RESOLUTION_FOR_BACKEND__.html;

    root /home/z00_www_static/;

    location / {

        root /home/z00_www_static/;

        location = /__BACKEND_FAILED__.html {
            internal;

            try_files 	/{{server}}/{{port}}/$url_2_entity_{{ suffix_map }}/$host/$uri
                        /{{server}}/{{port}}/$url_2_entity_{{ suffix_map }}/__default__/$uri
                        /{{server}}/__default__/$url_2_entity_{{ suffix_map }}/$host/$uri
                        /{{server}}/__default__/$url_2_entity_{{ suffix_map }}/__default__/$uri
                        /{{server}}/{{port}}/__default__/$host/$uri
                        /{{server}}/{{port}}/__default__/__default__/$uri
                        /{{server}}/__default__/__default__/$host/$uri
                        /{{server}}/__default__/__default__/__default__/$uri
                        /__default__/__default__/__default__/$host/$uri
                        /__default__/__default__/__default__/__default__/$uri
                        =404;

        }

        location = /__NO_CONFIGURATION__.html {
            internal;

            try_files   /{{server}}/{{port}}/$url_2_entity_{{ suffix_map }}/$host/$uri
                        /{{server}}/{{port}}/$url_2_entity_{{ suffix_map }}/__default__/$uri
                        /{{server}}/__default__/$url_2_entity_{{ suffix_map }}/$host/$uri
                        /{{server}}/__default__/$url_2_entity_{{ suffix_map }}/__default__/$uri
                        /{{server}}/{{port}}/__default__/$host/$uri
                        /{{server}}/{{port}}/__default__/__default__/$uri
                        /{{server}}/__default__/__default__/$host/$uri
                        /{{server}}/__default__/__default__/__default__/$uri
                        /__default__/__default__/__default__/$host/$uri
                        /__default__/__default__/__default__/__default__/$uri
                        =404;

        }

        location = /__NO_RESOLUTION_FOR_BACKEND__.html {
            internal;
            ssi on;

            try_files   /{{server}}/{{port}}/$url_2_entity_{{ suffix_map }}/$host/$uri
                        /{{server}}/{{port}}/$url_2_entity_{{ suffix_map }}/__default__/$uri
                        /{{server}}/__default__/$url_2_entity_{{ suffix_map }}/$host/$uri
                        /{{server}}/__default__/$url_2_entity_{{ suffix_map }}/__default__/$uri
                        /{{server}}/{{port}}/__default__/$host/$uri
                        /{{server}}/{{port}}/__default__/__default__/$uri
                        /{{server}}/__default__/__default__/$host/$uri
                        /{{server}}/__default__/__default__/__default__/$uri
                        /__default__/__default__/__default__/$host/$uri
                        /__default__/__default__/__default__/__default__/$uri
                        =404;

        }

    {% if converted_unmount_map_filename in list_converted_map_filenames %}
        if ( $not_mapped_{{ suffix_map }} ) {
             return 		404;
        }
    {% else %}
        # Pas de configuration unmap pour ce serveur
    {% endif -%}

    {% if converted_redirect_map_filename in list_converted_map_filenames %}
        {% call( redirect_code ) redirected_uri_extra.loop_on_redirected_code() -%}
        # Redirect explicite, issue d'une regle redirect utilisant la valeur enumeree = {{ redirect_code }}
        if ( $redirect_code_{{ redirect_code }}_to_{{ suffix_map }} ) {
            return 		{{ redirect_code }} 	$redirect_to_{{ suffix_map }};
        }
        {% endcall -%}

        {% call( default_redirected_code ) redirected_uri_extra.default_redirected_code() -%}
        # redirect implicite, issue d'une regle mount, utilisant la valeur par default = {{ default_redirected_code }}
        if ( $from_mount_redirect_code_to_{{ suffix_map }} ) {
            return 		{{ default_redirected_code }} 	$redirect_to_{{ suffix_map }};
        }
        {% endcall -%}
    {% else -%}
        # Pas de configuration redirect pour ce serveur
    {% endif -%}

    {% if converted_mount_map_filename in list_converted_map_filenames %}

        # Construction permettant d'utiliser location @backend et de servir les pages d'erreurs
        # Si $uri = egal une page d'erreur, c'est la page d'erreur qui est servie
        try_files               /{{server}}/{{port}}/$url_2_entity_{{ suffix_map }}/$host/$uri
                                /{{server}}/{{port}}/$url_2_entity_{{ suffix_map }}/__default__/$uri
                                /{{server}}/__default__/$url_2_entity_{{ suffix_map }}/$host/$uri
                                /{{server}}/__default__/$url_2_entity_{{ suffix_map }}/__default__/$uri
                                /{{server}}/{{port}}/__default__/$host/$uri
                                /{{server}}/{{port}}/__default__/__default__/$uri
                                /{{server}}/__default__/__default__/$host/$uri
                                /{{server}}/__default__/__default__/__default__/$uri
                                /__default__/__default__/__default__/$host/$uri
                                /__default__/__default__/__default__/__default__/$uri
                                @backend;

    {% else %}
        # Pas de configuration mount pour ce serveur
    {% endif -%}

    }
    {% if converted_mount_map_filename in list_converted_map_filenames %}
    location @backend {

        recursive_error_pages on;
        {% call( backend_combination ) backed_uri_extra.loop_on_backend_combination() -%}
        error_page {{ backend_combination[ "index" ] }} = @backend_{{ backend_combination[ "combination" ] }};
        if ( $backend_{{ backend_combination[ "combination" ] }}_{{ suffix_map }} ) {
            return {{ backend_combination[ "index" ] }};
        }
        {% endcall -%}

        {% call( backend_combination ) backed_uri_extra.default_backend_combination() -%}
        # Si aucun $backend_ n'a matche, c'est que la configuration n'existe pas.
        # on utilise alors le backend avec toutes le valeurs par defaut qui renverra
        # l'URL de la page de maintenance (c'est de cette maniere que la page d'erreur
        # s'affichait avant d'eclater en $backend_
        return {{ backend_combination[ "index" ] }};
        {% endcall -%}
    }

    {% call( backend_combination ) backed_uri_extra.loop_on_backend_combination() %}
    location @backend_{{ backend_combination[ "combination" ] }} {

        #proxy_intercept_errors 	on;
        proxy_buffering {{ backend_combination[ "proxy_buffering" ] }};

        proxy_connect_timeout       {{ backend_combination[ "proxy_connect_timeout" ] }};
        proxy_read_timeout          {{ backend_combination[ "proxy_read_timeout" ] }};

        proxy_set_header	Host 		$host:$server_port;
        proxy_set_header    	X-Real-IP       $remote_addr;
        proxy_set_header    	X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Proto {% if ssl_configuration %}https{% else %}http{% endif -%};
        proxy_hide_header   	X-Powered-By;

        proxy_http_version              1.1;
        proxy_set_header Connection     "";

        proxy_redirect 		$proxy_redirect_to_replace_with_port_{{ suffix_map }} $prxfied_and_prefix_uri_{{ suffix_map }};
        proxy_redirect 		$proxy_redirect_to_replace_without_port_{{ suffix_map }} $prxfied_and_prefix_uri_{{ suffix_map }};

        proxy_cookie_domain     $proxy_cookie_domain_to_replace_{{ suffix_map }} $proxy_cookie_domain_replaced_by_{{ suffix_map }};

        proxy_cookie_path       $proxy_cookie_path_to_replace_{{ suffix_map }} $proxy_cookie_path_replaced_by_{{ suffix_map }};
        proxy_cookie_path       $proxy_cookie_path_to_replace_without_suffixed_slash_{{ suffix_map }} $proxy_cookie_path_replaced_by_for_without_suffixed_slash_{{ suffix_map }};

        if ( $not_resolved_backend_{{ suffix_map }} ) {
            set $not_resolved_backend_name not_resolved_backend_{{ suffix_map }};
            set $not_resolved_backend $not_resolved_backend_{{ suffix_map }};
            set $not_resolved_backend_original_url $scheme://$host:$server_port$request_uri;
            set $not_resolved_backend_resolved_url $scheme://$host:$server_port$uri;
            return 		418;
        }
        {% if backend_combination[ "mapping_symmetry" ] == 'asymmetric' -%}
        if ( $added_query_string_{{ suffix_map }} ) {
            proxy_pass     	$contextualized_upstream_{{ suffix_map }}$suffix_uri_{{ suffix_map }}?$added_query_string_{{ suffix_map }}&$query_string;
        }
        proxy_pass     	$contextualized_upstream_{{ suffix_map }}$suffix_uri_{{ suffix_map }}?$query_string;
        {% elif backend_combination[ "mapping_symmetry" ] == 'symmetric' -%}
        if ( $added_query_string_{{ suffix_map }} ) {
            proxy_pass     	$contextualized_upstream_{{ suffix_map }}?$added_query_string_{{ suffix_map }}&$query_string;
        }
        proxy_pass     	$contextualized_upstream_{{ suffix_map }}$query_string;
        {% endif -%}

    }
    {% endcall %}
    {% endif %}

}

{% if converted_unmount_map_filename in list_converted_map_filenames -%}
include {{ root_nginx_configuration }}{{ converted_unmount_map_filename }};
{% else -%}
# Pas de map unmap pour ce serveur
{% endif -%}

{% if converted_redirect_map_filename in list_converted_map_filenames -%}
include {{ root_nginx_configuration }}{{ converted_redirect_map_filename }};
{% else -%}
# Pas de map redirect pour ce serveur
{% endif -%}

{% if converted_mount_map_filename in list_converted_map_filenames -%}
include {{ root_nginx_configuration }}{{ converted_mount_map_filename }};
{% else -%}
# Pas de map mount pour ce serveur
{% endif -%}

{% if converted_url2entity_map_filename in list_converted_map_filenames -%}
include {{ root_nginx_configuration }}{{ converted_url2entity_map_filename }};
{% else -%}
# Pas de map url2entity pour ce serveur
# Creation d'une map par defaut
map $scheme://$host:$server_port$uri $url_2_entity_{{ suffix_map }} {

    default     "__default__";

}

{% endif -%}
