log_format access_{{ server }}-{{ port }} '$remote_addr - $remote_user [$time_local] "$request" '
                 '$status $body_bytes_sent "$http_referer" '
                 '"$http_user_agent" "$scheme://$host:$server_port$uri"';

server {

    server_tokens 		off;

    {% for nameserver in resolver.nameservers -%}
    resolver 			{{ nameserver }};
    {% endfor -%}

    listen   			{{ resolver.query( server, 'A' )[ 0 ].address }}:{{ port }}{% if ssl_configuration %} ssl{% endif -%};

    {% if ssl_configuration -%}
    ssl_certificate 		{{ ssl_configuration.ssl_certificate_filepath }};
    ssl_certificate_key		{{ ssl_configuration.ssl_certificate_key_filepath }};
    {% endif -%}

{% if server == 'Z00-PR-D1-NGX01' and port == '80' %}
    access_log 			/$access_log_Z00_PR_D1_NGX01__80	combined;
{% else %}
    access_log 			/var/log/nginx/.{{ server }}-{{ port }}.access.log access_{{ server }}-{{ port }};
{% endif %}
    error_log 			/var/log/nginx/.{{ server }}-{{ port }}.error.log info;
     

    root                        /usr/share/nginx/html/;

    error_page                  502     =       /backend_failed.txt;
    error_page                  504     =       /backend_failed.txt;

    location / {

        root /usr/share/nginx/html/;

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
        try_files               $uri 	@backend;


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

        proxy_set_header	Host 		$host;
        proxy_set_header    	X-Real-IP       $remote_addr;
        proxy_set_header    	X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_hide_header   	X-Powered-By;

        proxy_redirect 		$backprx_and_prefix_uri_{{ suffix_map }} $prxfied_and_prefix_uri_{{ suffix_map }};
        proxy_pass     		$backprx_and_prefix_uri_{{ suffix_map }}$suffix_uri_{{ suffix_map }}?$query_string;

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

{% if server == 'Z00-PR-D1-NGX01' and port == '80' %}
include /etc/mdp/tmp.d/Z00-PR-D1-NGX01-80.tmp;
{% endif %}
