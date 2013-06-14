{% import 'listening_uri_extra.tpl' as listening_uri_extra %}
map $scheme://$host:$server_port$uri $redirect_to_{{ suffix_map }} {

    default "";
 
    # REDIRECTS EXPLICITES BASE SUR redirect
    {% for redirect in redirect_configurations -%}
    {% if redirect.src.endswith( '/' ) and redirect.src.split( '/' )|length > 4 -%}
    {{ listening_uri_extra.is_case_sensitive( redirect.src.extra ) }}^{{ redirect.src.rstrip( '/' ) }}$ {{ redirect.src }};
    {% else -%}
    # Pas de reconfiguration automatique de rec -> rec/ pour redirect {{ redirect.src }} -> {{ redirect.dst }}
    {% endif -%}

    {{ listening_uri_extra.is_case_sensitive( redirect.src.extra ) }}^{{ redirect.src }}$	{{ redirect.dst }};
    {% endfor -%}

    # REDIRECTS IMPLICITES BASES SUR mount
    {% for mount in mount_configurations -%}
    {% if mount.src.endswith( '/' ) and mount.src.split( '/' )|length > 4 -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src.rstrip( '/' ) }}$ {{ mount.src }};
    {% else -%}
    # Pas de reconfiguration automatique de rec -> rec/ pour mount {{ mount.src }} -> {{ mount.dst }}
    {% endif -%}
    {% endfor -%}

}
