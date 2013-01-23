map $scheme://$host:$server_port$uri $redirect_to_{{ suffix_map }} {

    default "";
 
    {% for mount in mount_configurations -%}
    {% if mount.src.endswith( '/' ) and mount.src.split( '/' )|length > 4 -%}
    ~^{{ mount.src.rstrip( '/' ) }}$ {{ mount.src }};
    {% else -%}
    # Pas de reconfiguration automatique de rec -> rec/ pour mount {{ mount.src }} -> {{ mount.dst }}
    {% endif -%}
    {% endfor -%}

    {% for redirect in redirect_configurations -%}
    {% if redirect.src.endswith( '/' ) and redirect.src.split( '/' )|length > 4 -%}
    ~^{{ redirect.src.rstrip( '/' ) }}$ {{ redirect.src }};
    {% else -%}
    # Pas de reconfiguration automatique de rec -> rec/ pour redirect {{ redirect.src }} -> {{ redirect.dst }}
    {% endif -%}
    ~^{{ redirect.src }}$	{{ redirect.dst }};
    {% endfor -%}

}
