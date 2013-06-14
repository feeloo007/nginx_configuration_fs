{% import 'listening_uri_extra.tpl' as listening_uri_extra %}
{% import 'redirected_uri_extra.tpl' as redirected_uri_extra with context %}
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

# REDIRECTS EXPLICITES BASES SUR redirect
{% call( redirect_code ) redirected_uri_extra.loop_on_redirected_code() -%}
map $scheme://$host:$server_port$uri $redirect_code_{{ redirect_code }}_to_{{ suffix_map }} {

    default "";

    {% for redirect in redirect_configurations -%}
    {% if redirect.dst.extra.redirect_code == redirect_code -%}
    {% if redirect.src.endswith( '/' ) and redirect.src.split( '/' )|length > 4 -%}
    {{ listening_uri_extra.is_case_sensitive( redirect.src.extra ) }}^{{ redirect.src.rstrip( '/' ) }}$ {{ redirect_code }};
    {% endif -%}
    {{ listening_uri_extra.is_case_sensitive( redirect.src.extra ) }}^{{ redirect.src }}$       {{ redirect_code }};
    {% else -%}
    {% if redirect.src.endswith( '/' ) and redirect.src.split( '/' )|length > 4 -%}
    {{ listening_uri_extra.is_case_sensitive( redirect.src.extra ) }}^{{ redirect.src.rstrip( '/' ) }}$ "";
    {% endif -%}
    {{ listening_uri_extra.is_case_sensitive( redirect.src.extra ) }}^{{ redirect.src }}$       "";
    {% endif -%}
    {% endfor -%}
}
{% endcall -%}

# REDIRECTS IMPLICITES BASES SUR mount
{% call( default_redirected_code ) redirected_uri_extra.default_redirected_code() -%}
map $scheme://$host:$server_port$uri $from_mount_redirect_code_to_{{ suffix_map }} {

    default "";

    {% for mount in mount_configurations -%}
    {% if mount.src.endswith( '/' ) and mount.src.split( '/' )|length > 4 -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src.rstrip( '/' ) }}$ {{ default_redirected_code }};
    {% endif -%}
    {% endfor -%}
}
{% endcall -%}
