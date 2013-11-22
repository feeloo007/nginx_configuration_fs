{% import 'listening_uri_extra.tpl' as listening_uri_extra %}
map $scheme://$host:$server_port$original_uri $not_mapped_{{ suffix_map }} {

    default "";

    {% for unmount in unmount_configurations -%}
    {% if not unmount.uri.endswith( '/' ) -%}
    # On considere qu'il peut s'agir d'un repertoire. On demonte toutes les sous-ressources.
    {{ listening_uri_extra.is_case_sensitive( unmount.uri.extra ) }}^{{ unmount.uri }}/	yes;

    {% else -%}
    # {{ unmount.uri }} est un repertoire. On considere qu'il peut etre appele sans le / final.
    {{ listening_uri_extra.is_case_sensitive( unmount.uri.extra ) }}^{{ unmount.uri.rstrip( '/' ) }}$	yes;

    {{ listening_uri_extra.is_case_sensitive( unmount.uri.extra ) }}^{{ unmount.uri }}	yes;
    {% endif -%}
    # {{ unmount.uri }} demande exacte.
    {{ listening_uri_extra.is_case_sensitive( unmount.uri.extra ) }}^{{ unmount.uri }}$	yes;

    {% endfor -%}

}
