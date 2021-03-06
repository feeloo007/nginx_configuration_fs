{% import 'listening_uri_extra.tpl' as listening_uri_extra %}
{% import 'backed_uri_extra.tpl' as backed_uri_extra with context %}
map $scheme://$host:$server_port$original_uri $not_resolved_backend_{{ suffix_map }} {

    default	"";

    {% for mount in mount_configurations -%}
    {% if not mount.dst_upstream_resolved_ips -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} 	{{mount.dst_host}};
    {%endif -%}
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $upstream_{{ suffix_map }} {

    default 	{% if ssl_configuration %}https{% else -%}http{% endif -%}://{{ server }}:{{ port }}/__NO_CONFIGURATION__.html;
    {% for mount in mount_configurations -%}
    {% if not mount.dst.extra.balanced_sticky_style or mount.dst_upstream_reversed_names|length == 1 -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.dst_upstream }}_with_connect_defined_to_;
    {% else -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} $upstream_{{ mount.dst_upstream_name }}_with_scheme_defined_to_{{ mount.dst_scheme }}_with_balanced_sticky_defined_to_{{ mount.dst.extra.balanced_sticky_style }}_with_connect_defined_to_;
    {% endif -%}
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $not_mounted_{{ suffix_map }} {

    default 	"YES";
    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} "";
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $prefix_uri_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    {% if mount.src.endswith( '/' ) and mount.dst_path.endswith( '/' ) -%}
    # Montage d'un repertoire dans un repertoire, le / sera contenu dans $suffix_uri_{{ suffix_map }}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} "{{ mount.dst_path.rstrip( '/' ) }}";

    {% elif not mount.src.endswith( '/' ) and not mount.dst_path.endswith( '/' ) -%}
    # Montage d'un non repertoire dans un non repertoire, le potentiel / sera contenu dans $suffix_uri_{{ suffix_map }}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} "{{ mount.dst_path.rstrip( '/' ) }}";

    {% elif mount.src.endswith( '/' ) and not mount.dst_path.endswith( '/' ) -%}
    # Danger ! Montage d'un repertoire dans un non repertoire, comportement inattendu
    # le premier / ne sera ni dans dans $prefix_uri_{{ suffix_map }} ni dans $suffix_uri_{{ suffix_map }}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} "{{ mount.dst_path.rstrip( '/' ) }}";

    {% elif not mount.src.endswith( '/' ) and mount.dst_path.endswith( '/' ) -%}
    # Danger ! Montage d'un non repertoire dans un repertoire, comportement inattendu
    # le / est contenu dans $prefix_uri_{{ suffix_map }}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} "{{ mount.dst_path }}";

    {% endif -%}
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $added_query_string_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    {% if mount.dst_query -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.dst_query }};
    {% else %}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} "";
    {% endif -%}
    {% endfor %}

}

map $scheme://$host:$server_port$original_uri $proxy_redirect_to_replace_with_port_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.proxy_redirect_to_replace_with_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $proxy_redirect_to_replace_without_port_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.proxy_redirect_to_replace_without_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $prxfied_and_prefix_uri_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^(?<captured>{{ mount.src }}).*$	$captured;
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $suffix_uri_{{ suffix_map }} {

    default 	"/";
    {% for mount in mount_configurations -%}
    {% if mount.src.endswith( '/' ) and mount.dst_path.endswith( '/' ) -%}
    # Montage d'un repertoire dans un repertoire, le / sera contenu dans $suffix_uri_{{ suffix_map }}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src.rstrip( '/' ) }}(?<captured>/.*)$ $captured;

    {% elif not mount.src.endswith( '/' ) and not mount.dst_path.endswith( '/' ) -%}
    # Montage d'un non repertoire dans un non repertoire, le / sera contenu dans $suffix_uri_{{ suffix_map }}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }}(?<captured>.*)$ $captured;

    {% elif mount.src.endswith( '/' ) and not mount.dst_path.endswith( '/' ) -%}
    # Danger ! Montage d'un repertoire dans un non repertoire, comportement inattendu
    # le / ne sera ni dans dans $prefix_uri_{{ suffix_map }} ni dans $suffix_uri_{{ suffix_map }}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }}(?<captured>.*)$ $captured;

    {% elif not mount.src.endswith( '/' ) and mount.dst_path.endswith( '/' ) -%}
    # Danger ! Montage d'un non repertoire dans un repertoire, comportement inattendu
    # le / est contenu dans $prefix_uri_{{ suffix_map }}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }}(?<captured>.*)$ $captured;

    {% endif -%}
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $proxy_cookie_domain_to_replace_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.src_host }}:{{ mount.dst_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $proxy_cookie_domain_replaced_by_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.src_host }}:{{ mount.src_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $proxy_cookie_path_to_replace_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} ~^{{ mount.dst_path }}$;
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $proxy_cookie_path_to_replace_without_suffixed_slash_{{ suffix_map }} {

    default     "#NOT_REPLACABLE#";

    {% for mount in mount_configurations -%}
    {% if mount.dst_path.endswith( '/' ) and mount.dst_path.rstrip( '/' )|length > 0 -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.dst_path.rstrip( '/' ) }};
    {% endif -%}
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $proxy_cookie_path_replaced_by_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.src_path }};
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $proxy_cookie_path_replaced_by_for_without_suffixed_slash_{{ suffix_map }} {

    default     "#NO_REPLACEMENT#";

    {% for mount in mount_configurations -%}
    {% if mount.src_path.endswith( '/' ) and mount.src_path.rstrip( '/' )|length > 0 -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.src_path.rstrip( '/' ) }};
    {% endif -%}
    {% endfor -%}

}

map $scheme://$host:$server_port$original_uri $connection_{{ suffix_map }} {

    default     "{{ extra_from_distrib_configurations.backed_uri_extra.properties.client_http_connect.default }}";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} "{{ mount.dst.extra.client_http_connect }}";
    {% endfor -%}
}

map $scheme://$host:$server_port$original_uri $mdp_service_redirector_new_http_host_{{ suffix_map }} {

    default     "{{ extra_from_distrib_configurations.backed_uri_extra.properties.mdp_service_redirector_new_http_host.default }}";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} "{{ mount.dst.extra.mdp_service_redirector_new_http_host }}";
    {% endfor -%}
}

map $mdp_service_redirector_new_http_host_{{ suffix_map }} $mdp_service_redirector_new_http_host_http_redirected_code_{{ suffix_map }} {

    default     $mdp_service_redirector_new_http_host_http_redirected_code_ACTIVATED_{{ suffix_map }};

    ""		"";

}

map $scheme://$host:$server_port$original_uri $mdp_service_redirector_new_http_host_http_redirected_code_ACTIVATED_{{ suffix_map }} {

    default     "{{ extra_from_distrib_configurations.backed_uri_extra.properties.mdp_service_redirector_new_http_host_http_redirected_code.default }}";

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ mount.dst.extra.mdp_service_redirector_new_http_host_http_redirected_code }};
    {% endfor -%}
}

map $mdp_service_redirector_new_http_host_{{ suffix_map }} $mdp_service_redirector_new_http_host_http_redirected_port_{{ suffix_map }} {

    default     $mdp_service_redirector_new_http_host_http_redirected_port_ACTIVATED_{{ suffix_map }};

    ""		"";

}

map $scheme://$host:$server_port$original_uri $mdp_service_redirector_new_http_host_http_redirected_port_ACTIVATED_{{ suffix_map }} {

    default     {% if extra_from_distrib_configurations.backed_uri_extra.properties.mdp_service_redirector_new_http_host_http_redirected_port.default == 'same' -%}$server_port{% else -%}"{{ extra_from_distrib_configurations.backed_uri_extra.properties.mdp_service_redirector_new_http_host_http_redirected_port.default }}"{% endif -%};

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {% if mount.dst.extra.mdp_service_redirector_new_http_host_http_redirected_port == 'same' -%}$server_port{% else -%}"{{ mount.dst.extra.mdp_service_redirector_new_http_host_http_redirected_port }}"{% endif -%};
    {% endfor -%}
}

map $mdp_service_redirector_new_http_host_{{ suffix_map }} $mdp_service_redirector_new_http_host_http_redirected_proto_{{ suffix_map }} {

    default     $mdp_service_redirector_new_http_host_http_redirected_proto_ACTIVATED_{{ suffix_map }};

    ""		"";

}

map $scheme://$host:$server_port$original_uri $mdp_service_redirector_new_http_host_http_redirected_proto_ACTIVATED_{{ suffix_map }} {

    default     {% if extra_from_distrib_configurations.backed_uri_extra.properties.mdp_service_redirector_new_http_host_http_redirected_proto.default == 'same' -%}$scheme{% else -%}"{{ extra_from_distrib_configurations.backed_uri_extra.properties.mdp_service_redirector_new_http_host_http_redirected_proto.default }}"{% endif -%};

    {% for mount in mount_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {% if mount.dst.extra.mdp_service_redirector_new_http_host_http_redirected_proto == 'same' -%}$scheme{% else -%}"{{ mount.dst.extra.mdp_service_redirector_new_http_host_http_redirected_proto }}"{% endif -%};
    {% endfor -%}
}

{% call( backend_combination ) backed_uri_extra.loop_on_backend_combination() -%}
map $scheme://$host:$server_port$original_uri $backend_{{ backend_combination[ "combination" ] }}_{{ suffix_map }} {

    default     "";

    {% for mount in mount_configurations -%}
    # pb {{ mount.dst.extra.proxy_buffering }} pct {{ mount.dst.extra.proxy_connect_timeout }} prt {{ mount.dst.extra.proxy_read_timeout }}
    {% if
          mount.dst.extra.proxy_buffering 		== backend_combination[ "proxy_buffering" ]
          and
          mount.dst.extra.proxy_connect_timeout 	== backend_combination[ "proxy_connect_timeout" ]
          and
          mount.dst.extra.proxy_read_timeout 		== backend_combination[ "proxy_read_timeout" ]
    -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} {{ backend_combination[ "index" ] }};
    {% else -%}
    {{ listening_uri_extra.is_case_sensitive( mount.src.extra ) }}^{{ mount.src }} "";
    {% endif -%}
    {% endfor -%}

}
{% endcall -%}
