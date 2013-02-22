map $scheme://$host:$server_port$uri $upstream_and_prefix_uri_{{ suffix_map }} {

    default 	{% if ssl_configuration %}https{% else -%}http{% endif -%}://{{ server }}:{{ port }}/no_configuration.txt;
    {% for mount in mount_configurations -%}
    ~^{{ mount.src }} {{ mount.dst_upstream }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_redirect_to_replace_with_port_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    # {{ mount }}
    ~^{{ mount.src }} {{ mount.proxy_redirect_to_replace_with_port }};
    {% endfor -%}

}

map $scheme://$host:$server_port$uri $proxy_redirect_to_replace_without_port_{{ suffix_map }} {

    default 	"";

    {% for mount in mount_configurations -%}
    # {{ mount }}
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
