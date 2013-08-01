{% macro loop_on_backend_combination() -%}
    {% for proxy_buffering		in extra_from_distrib_configurations.backed_uri_extra.properties.proxy_buffering.enum|sort -%}
    {% set proxy_buffering_index	= loop.index0 -%}
    {% set proxy_buffering_length	= loop.length -%}
    {% for proxy_connect_timeout 	in extra_from_distrib_configurations.backed_uri_extra.properties.proxy_connect_timeout.enum|sort -%}
    {% set proxy_connect_timeout_index	= loop.index0 -%}
    {% set proxy_connect_timeout_length	= loop.length -%}
    {% for proxy_read_timeout 		in extra_from_distrib_configurations.backed_uri_extra.properties.proxy_read_timeout.enum|sort -%}
    {% set proxy_read_timeout_index	= loop.index0 -%}
    {% set proxy_read_timeout_length	= loop.length -%}
    {% for mapping_symmetry 		in extra_from_distrib_configurations.backed_uri_extra.properties.mapping_symmetry.enum|sort -%}
    {% set mapping_symmetry_index	= loop.index0 -%}
    {% set mapping_symmetry_length	= loop.length -%}
    {{ caller(
           {
            "combination" 		: 'pb_' ~ proxy_buffering ~ '_pct_' ~ proxy_connect_timeout ~ '_prt_' ~ proxy_read_timeout ~ '_ms_' ~ mapping_symmetry,
            "proxy_buffering" 		: proxy_buffering,
            "proxy_connect_timeout" 	: proxy_connect_timeout,
            "proxy_read_timeout" 	: proxy_read_timeout,
            "mapping_symmetry" 		: mapping_symmetry,
            "index" 			: 511 + ( proxy_buffering_index * proxy_connect_timeout_length * proxy_read_timeout_length * mapping_symmetry_length ) + ( proxy_connect_timeout_index * proxy_read_timeout_length * mapping_symmetry_length ) + ( proxy_read_timeout_index * mapping_symmetry_length ) + mapping_symmetry_index
           }
       )
    }}
    {% endfor -%}
    {% endfor -%}
    {% endfor -%}
    {% endfor -%}
{% endmacro %}

{% macro default_backend_combination() -%}
    {% for proxy_buffering		in extra_from_distrib_configurations.backed_uri_extra.properties.proxy_buffering.enum|sort -%}
    {% set proxy_buffering_index	= loop.index0 -%}
    {% set proxy_buffering_length	= loop.length -%}
    {% for proxy_connect_timeout 	in extra_from_distrib_configurations.backed_uri_extra.properties.proxy_connect_timeout.enum|sort -%}
    {% set proxy_connect_timeout_index	= loop.index0 -%}
    {% set proxy_connect_timeout_length	= loop.length -%}
    {% for proxy_read_timeout 		in extra_from_distrib_configurations.backed_uri_extra.properties.proxy_read_timeout.enum|sort -%}
    {% set proxy_read_timeout_index	= loop.index0 -%}
    {% set proxy_read_timeout_length	= loop.length -%}
    {% for mapping_symmetry 		in extra_from_distrib_configurations.backed_uri_extra.properties.mapping_symmetry.enum|sort -%}
    {% set mapping_symmetry_index	= loop.index0 -%}
    {% set mapping_symmetry_length	= loop.length -%}
    {% if
         proxy_buffering	== extra_from_distrib_configurations.backed_uri_extra.properties.proxy_buffering.default and
         proxy_connect_timeout 	== extra_from_distrib_configurations.backed_uri_extra.properties.proxy_connect_timeout.default and
         proxy_read_timeout	== extra_from_distrib_configurations.backed_uri_extra.properties.proxy_read_timeout.default and
         mapping_symmetry	== extra_from_distrib_configurations.backed_uri_extra.properties.mapping_symmetry.default
    -%}
    {{ caller(
           {
            "combination" 		: 'pb_' ~ proxy_buffering ~ '_pct_' ~ proxy_connect_timeout ~ '_prt_' ~ proxy_read_timeout ~ '_ms_' ~ mapping_symmetry,
            "proxy_buffering" 		: proxy_buffering,
            "proxy_connect_timeout" 	: proxy_connect_timeout,
            "proxy_read_timeout" 	: proxy_read_timeout,
            "mapping_symmetry" 		: mapping_symmetry,
            "index" 			: 511 + ( proxy_buffering_index * proxy_connect_timeout_length * proxy_read_timeout_length * mapping_symmetry_length ) + ( proxy_connect_timeout_index * proxy_read_timeout_length * mapping_symmetry_length ) + ( proxy_read_timeout_index * mapping_symmetry_length ) + mapping_symmetry_index
           }
       )
    }}
    {% endif -%}
    {% endfor -%}
    {% endfor -%}
    {% endfor -%}
    {% endfor -%}
{% endmacro %}
