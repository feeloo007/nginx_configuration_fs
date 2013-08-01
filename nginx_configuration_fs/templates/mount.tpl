{% import 'listening_uri_extra.tpl' as listening_uri_extra %}
{% import 'backed_uri_extra.tpl' as backed_uri_extra with context %}
map $scheme://$host:$server_port$uri $not_resolved_backend_{{ suffix_map }} {

    default	"";

    {% for mount in mount_configurations -%}
    {% if not mount.dst_upstream_resolved_ips -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} 	{{mount.dst_host}};
    {%endif -%}
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $upstream_and_prefix_uri_{{ suffix_map }} {

    default 	{% if ssl_configuration %}https{% else -%}http{% endif -%}://{{ server }}:{{ port }}/__NO_CONFIGURATION__.html;
    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.dst_upstream }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $added_query_string_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    {% if mount.dst_query -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.dst_query }};
    {% endif -%}
    {% endfor %}

}

map $scheme://$host:$server_port$uri $proxy_redirect_to_replace_with_port_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.proxy_redirect_to_replace_with_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_redirect_to_replace_without_port_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.proxy_redirect_to_replace_without_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $prxfied_and_prefix_uri_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^(?<captured>{{ mount.src }}).*$	$captured;
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $suffix_uri_{{ suffix_map }} {

    default 	"";
    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }}(?<captured>.*)$ $captured;
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_domain_to_replace_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.src_host }}:{{ mount.dst_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_domain_replaced_by_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.src_host }}:{{ mount.src_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_path_to_replace_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} ~^{{ mount.dst_path }}$;
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_path_to_replace_without_suffixed_slash_{{ suffix_map }} {

    default     "#NOT_REPLACABLE#";

    {% for mount in mount_configurations -%}
    {% if mount.dst_path.endswith( '/' ) and mount.dst_path.rstrip( '/' )|length > 0 -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.dst_path.rstrip( '/' ) }};
    {% endif -%}
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_path_replaced_by_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.src_path }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_path_replaced_by_for_without_suffixed_slash_{{ suffix_map }} {

    default     "#NO_REPLACEMENT#";

    {% for mount in mount_configurations -%}
    {% if mount.src_path.endswith( '/' ) and mount.src_path.rstrip( '/' )|length > 0 -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.src_path.rstrip( '/' ) }};
    {% endif -%}
    {% endfor -%}

}

{% call( backend_combination ) backed_uri_extra.loop_on_backend_combination() -%}
map $scheme://$host:$server_port$uri $backend_{{ backend_combination[ "combination" ] }}_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    # pb {{ mount.dst.extra.proxy_buffering }} pct {{ mount.dst.extra.proxy_connect_timeout }} prt {{ mount.dst.extra.proxy_read_timeout }} ms {{ mount.dst.extra.mapping_symmetry }}
    {% if
          mount.dst.extra.proxy_buffering 		== backend_combination[ "proxy_buffering" ]
          and
          mount.dst.extra.proxy_connect_timeout 	== backend_combination[ "proxy_connect_timeout" ]
          and
          mount.dst.extra.proxy_read_timeout 		== backend_combination[ "proxy_read_timeout" ]
          and
          mount.dst.extra.mapping_symmetry 		== backend_combination[ "mapping_symmetry" ]
    -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ backend_combination[ "index" ] }};
    {% else -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} "";
    {% endif -%}
    {% endfor -%}

}
{% endcall -%}
