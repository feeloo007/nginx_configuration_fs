map $scheme://$host:$server_port$uri $not_mapped_{{ suffix_map }} {

    default "";

    {% for unmount in unmount_configurations -%}
    ~^{{ unmount.uri }}$	yes;
    {% if not unmount.uri.endswith( '/' ) -%}
    ~^{{ unmount.uri }}/$	yes;
    {% else -%}
    # Pas de demontage supplementaire base sur {{ unmount.uri }}
    {% endif -%}
    {% endfor -%}

}
