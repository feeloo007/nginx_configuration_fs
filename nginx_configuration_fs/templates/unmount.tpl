{% import 'listening_uri_extra.tpl' as listening_uri_extra %}
map $scheme://$host:$server_port$uri $not_mapped_{{ suffix_map }} {

    default "";

    {% for unmount in unmount_configurations -%}
    {% if not unmount.uri.endswith( '/' ) -%}
    {{ listening_uri_extra.is_case_sensitive( unmount.uri.extra ) }}^{{ unmount.uri }}/$	yes;
    {% else -%}
    # Pas de demontage implicite a ajouter sur {{ unmount.uri }}
    {% endif -%}
    {{ listening_uri_extra.is_case_sensitive( unmount.uri.extra ) }}^{{ unmount.uri }}$	yes;
    {% endfor -%}

}
