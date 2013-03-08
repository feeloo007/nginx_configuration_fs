map $scheme://$host:$server_port$uri $not_resolved_backend_{{ suffix_map }} {

    default	"";

    {% for mount in mount_configurations -%}
    {% if not mount.dst_upstream_resolved_ips -%}
    ~^{{ mount.src }} 	yes;
    {%endif -%}
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $upstream_and_prefix_uri_{{ suffix_map }} {

    default 	{% if ssl_configuration %}https{% else -%}http{% endif -%}://{{ server }}:{{ port }}/__NO_CONFIGURATION__.html;
    {% for mount in mount_configurations -%}
    ~^{{ mount.src }} {{ mount.dst_upstream }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $added_query_string_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    {% if mount.dst_query -%}
    ~^{{ mount.src }} {{ mount.dst_query }};
    {% endif -%}
    {% endfor %}

}

map $scheme://$host:$server_port$uri $proxy_redirect_to_replace_with_port_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    ~^{{ mount.src }} {{ mount.proxy_redirect_to_replace_with_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_redirect_to_replace_without_port_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    ~^{{ mount.src }} {{ mount.proxy_redirect_to_replace_without_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $prxfied_and_prefix_uri_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    ~^(?<captured>{{ mount.src }}).*$	$captured;
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $suffix_uri_{{ suffix_map }} {

    default 	"";
    {% for mount in mount_configurations -%}
    ~^{{ mount.src }}(?<captured>.*)$ $captured;
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_domain_to_replace_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    ~^{{ mount.src }} {{ mount.src_host }}:{{ mount.dst_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_domain_replaced_by_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    ~^{{ mount.src }} {{ mount.src_host }}:{{ mount.src_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_path_to_replace_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    ~^{{ mount.src }} ~^{{ mount.dst_path }}$;
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_path_to_replace_without_suffixed_slash_{{ suffix_map }} {

    default     "#NOT_REPLACABLE#";

    {% for mount in mount_configurations -%}
    {% if mount.dst_path.endswith( '/' ) and mount.dst_path.rstrip( '/' )|length > 0 -%}
    ~^{{ mount.src }} {{ mount.dst_path.rstrip( '/' ) }};
    {% endif -%}
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_path_replaced_by_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    ~^{{ mount.src }} {{ mount.src_path }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_cookie_path_replaced_by_for_without_suffixed_slash_{{ suffix_map }} {

    default     "#NO_REPLACEMENT#";

    {% for mount in mount_configurations -%}
    {% if mount.src_path.endswith( '/' ) and mount.src_path.rstrip( '/' )|length > 0 -%}
    ~^{{ mount.src }} {{ mount.src_path.rstrip( '/' ) }};
    {% endif -%}
    {% endfor -%}

}
