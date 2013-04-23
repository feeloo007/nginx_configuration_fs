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

{% if server == 'Z00-PR-D1-NGX01' and ( port == '80' or port == '1388' or port == '1389' ) %}
    access_log 			/$access_log_provisoire	combined;
{% else %}
    access_log 			/var/log/nginx/.{{ server }}-{{ port }}.access.log access_{{ server }}-{{ port }};
{% endif %}
    error_log 			/var/log/nginx/.{{ server }}-{{ port }}.error.log info;
     

    error_page                  404     =404       /__NO_CONFIGURATION__.html;
    error_page                  502     =503       /__BACKEND_FAILED__.html;
    error_page                  504     =503       /__BACKEND_FAILED__.html;
    error_page                  418     =503       /__NO_RESOLUTION_FOR_BACKEND__.html;

    root /usr/share/nginx/html/;

    location / {

    {% if server == 'Z00-PR-D1-NGX01' and ( port == '80' or port == '1388' or port == '1389' ) %}
        root /home/z00_www_static/;
    {% else %}
        root /usr/share/nginx/html/;
    {% endif -%}

        location = /__BACKEND_FAILED__.html {
            internal;

            {% if server == 'Z00-PR-D1-NGX01' and ( port == '80' or port == '1388' or port == '1389' ) %}
            try_files 	/{{server}}/{{port}}/$www_static_url_2_entity_provisoire/$host/$uri
                        /{{server}}/{{port}}/$www_static_url_2_entity_provisoire/__default__/$uri
                        /{{server}}/__default__/$www_static_url_2_entity_provisoire/$host/$uri
                        /{{server}}/__default__/$www_static_url_2_entity_provisoire/__default__/$uri
                        /{{server}}/{{port}}/__default__/$host/$uri
                        /{{server}}/{{port}}/__default__/__default__/$uri
                        /{{server}}/__default__/__default__/$host/$uri
                        /{{server}}/__default__/__default__/__default__/$uri
                        /__default__/__default__/__default__/$host/$uri
                        /__default__/__default__/__default__/__default__/$uri
                        =404;
            {% endif -%}

        }

        location = /__NO_CONFIGURATION__.html {
            internal;

            {% if server == 'Z00-PR-D1-NGX01' and ( port == '80' or port == '1388' or port == '1389' ) %}
            try_files 	/{{server}}/{{port}}/$www_static_url_2_entity_provisoire/$host/$uri
                        /{{server}}/{{port}}/$www_static_url_2_entity_provisoire/__default__/$uri
                        /{{server}}/__default__/$www_static_url_2_entity_provisoire/$host/$uri
                        /{{server}}/__default__/$www_static_url_2_entity_provisoire/__default__/$uri
                        /{{server}}/{{port}}/__default__/$host/$uri
                        /{{server}}/{{port}}/__default__/__default__/$uri
                        /{{server}}/__default__/__default__/$host/$uri
                        /{{server}}/__default__/__default__/__default__/$uri
                        /__default__/__default__/__default__/$host/$uri
                        /__default__/__default__/__default__/__default__/$uri
                        =404;
            {% endif -%}

        }

        location = /__NO_RESOLUTION_FOR_BACKEND__.html {
            internal;
            ssi on;

            {% if server == 'Z00-PR-D1-NGX01' and ( port == '80' or port == '1388' or port == '1389' ) %}
            try_files 	/{{server}}/{{port}}/$www_static_url_2_entity_provisoire/$host/$uri
                        /{{server}}/{{port}}/$www_static_url_2_entity_provisoire/__default__/$uri
                        /{{server}}/__default__/$www_static_url_2_entity_provisoire/$host/$uri
                        /{{server}}/__default__/$www_static_url_2_entity_provisoire/__default__/$uri
                        /{{server}}/{{port}}/__default__/$host/$uri
                        /{{server}}/{{port}}/__default__/__default__/$uri
                        /{{server}}/__default__/__default__/$host/$uri
                        /{{server}}/__default__/__default__/__default__/$uri
                        /__default__/__default__/__default__/$host/$uri
                        /__default__/__default__/__default__/__default__/$uri
                        =404;
            {% endif -%}

        }

    {% if converted_unmount_map_filename in list_converted_map_filenames %}
        if ( $not_mapped_{{ suffix_map }} ) {
             return 		404;
        }
    {% else %}
        # Pas de configuration unmap pour ce serveur
    {% endif -%}

    {% if converted_redirect_map_filename in list_converted_map_filenames %}
        if ( $redirect_to_{{ suffix_map }} ) {
            return 		302 	$redirect_to_{{ suffix_map }};
        }
    {% else %}
        # Pas de configuration redirect pour ce serveur
    {% endif -%}

    {% if converted_mount_map_filename in list_converted_map_filenames %}

        # Construction permettant d'utiliser location @backend et de servir les pages d'erreurs
        # Si $uri = egal une page d'erreur, c'est la page d'erreur qui est servie
        {% if server == 'Z00-PR-D1-NGX01' and ( port == '80' or port == '1388' or port == '1389' ) %}
        try_files               /{{server}}/{{port}}/$www_static_url_2_entity_provisoire/$host/$uri
                                /{{server}}/{{port}}/$www_static_url_2_entity_provisoire/__default__/$uri
                                /{{server}}/__default__/$www_static_url_2_entity_provisoire/$host/$uri
                                /{{server}}/__default__/$www_static_url_2_entity_provisoire/__default__/$uri
                                /{{server}}/{{port}}/__default__/$host/$uri
                                /{{server}}/{{port}}/__default__/__default__/$uri
                                /{{server}}/__default__/__default__/$host/$uri
                                /{{server}}/__default__/__default__/__default__/$uri
                                /__default__/__default__/__default__/$host/$uri
                                /__default__/__default__/__default__/__default__/$uri
                                @backend;
         {% else %}
         try_files		$uri	@backend;
         {% endif %}


    {% else %}
        # Pas de configuration mount pour ce serveur
    {% endif -%}

    }
    {% if converted_mount_map_filename in list_converted_map_filenames %}

    location @backend {

        #proxy_intercept_errors 	on;
        proxy_buffering on;

        proxy_connect_timeout       2s;
        proxy_read_timeout          10s;

        proxy_set_header	Host 		$host:$server_port;
        proxy_set_header    	X-Real-IP       $remote_addr;
        proxy_set_header    	X-Forwarded-For $proxy_add_x_forwarded_for;
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
        if ( $added_query_string_{{ suffix_map }} ) {
            proxy_pass     	$upstream_and_prefix_uri_{{ suffix_map }}$suffix_uri_{{ suffix_map }}?$added_query_string_{{ suffix_map }}&$query_string;
        }
        proxy_pass     	$upstream_and_prefix_uri_{{ suffix_map }}$suffix_uri_{{ suffix_map }}?$query_string;

    }
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

{% if server == 'Z00-PR-D1-NGX01' and ( port == '80' or port == '1388' or port == '1389' ) %}
include /etc/mdp/tmp.d/access_log_provisoire;
{% endif %}

{% if server == 'Z00-PR-D1-NGX01' and ( port == '80' or port == '1388' or port == '1389' ) %}
include /etc/mdp/tmp.d/www_static_url_2_entity_provisoire;
{% endif %}
