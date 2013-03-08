map $scheme://$host:$server_port$uri $not_mapped_{{ suffix_map }} {

    default "";

    {% for unmount in unmount_configurations -%}
    {% if not unmount.uri.endswith( '/' ) -%}
    ~^{{ unmount.uri }}/$	yes;
    {% else -%}
    # Pas de demontage implicite a ajouter sur {{ unmount.uri }}
    {% endif -%}
    ~^{{ unmount.uri }}$	yes;
    {% endfor -%}

}
